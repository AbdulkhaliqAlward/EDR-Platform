// Package collectors — Real-time network connection monitoring via Windows IP Helper API.
//
// REPLACES the previous PowerShell polling approach (30s gap) with direct
// kernel-level table reads using GetExtendedTcpTable/GetExtendedUdpTable.
//
// Advantages over PowerShell polling:
//   - ~1s scan interval (vs 30s) — 30x faster detection
//   - Zero process spawning overhead (no powershell.exe child)
//   - UDP connection tracking (PowerShell only had TCP)
//   - Direct PID attribution from kernel table
//   - No telemetry feedback loop (agent doesn't spawn visible child processes)
//
// Architecture: Uses Go's syscall to call iphlpapi.dll directly.
// The GetExtendedTcpTable API returns the kernel's TCP connection table
// with per-connection owning PID — the same data source used by netstat.exe.
//
//go:build windows
// +build windows

package collectors

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
)

// =====================================================================
// Windows IP Helper API — iphlpapi.dll
// =====================================================================

var (
	iphlpapi           = windows.NewLazyDLL("iphlpapi.dll")
	getExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	getExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

// TCP_TABLE_OWNER_PID_ALL = 5 — returns all TCP connections with PIDs
const tcpTableOwnerPidAll = 5

// UDP_TABLE_OWNER_PID = 1 — returns all UDP listeners with PIDs
const udpTableOwnerPid = 1

// AF_INET = 2 (IPv4)
const afInet = 2

// TCP states that indicate active connections
const (
	tcpStateEstablished = 5
	tcpStateListen      = 2
	tcpStateSynSent     = 3
	tcpStateSynRcvd     = 4
	tcpStateFinWait1    = 6
	tcpStateFinWait2    = 7
	tcpStateCloseWait   = 8
)

// MIB_TCPROW_OWNER_PID — one row from GetExtendedTcpTable
type tcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_UDPROW_OWNER_PID — one row from GetExtendedUdpTable
type udpRowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// rfc1918 defines the private IPv4 address ranges (RFC 1918).
// Used to filter internal LAN connections that generate high volume
// with near-zero security signal for EDR.
var rfc1918 = []struct{ prefix string; bits int }{
	{"10.", 8},
	{"172.16.", 12}, {"172.17.", 12}, {"172.18.", 12}, {"172.19.", 12},
	{"172.20.", 12}, {"172.21.", 12}, {"172.22.", 12}, {"172.23.", 12},
	{"172.24.", 12}, {"172.25.", 12}, {"172.26.", 12}, {"172.27.", 12},
	{"172.28.", 12}, {"172.29.", 12}, {"172.30.", 12}, {"172.31.", 12},
	{"192.168.", 16},
}

// =====================================================================
// Network Collector
// =====================================================================

// NetworkCollector monitors network connections via Windows IP Helper API.
type NetworkCollector struct {
	logger    *logging.Logger
	eventChan chan<- *event.Event
	filter    *Filter

	// filterPrivateNetworks, when true, drops connections where BOTH
	// endpoints are RFC 1918 private IPs (e.g. 192.168.x ↔ 192.168.x).
	// Controlled by config.Filtering.FilterPrivateNetworks.
	filterPrivateNetworks bool

	// State
	running atomic.Bool

	// Connection cache to detect new connections (key = "proto:local→remote")
	connCache map[string]time.Time
	cacheMu   sync.RWMutex

	// Metrics
	connectionsFound atomic.Uint64
	eventsGenerated  atomic.Uint64
	dropped          atomic.Uint64
}

// NewNetworkCollector creates a new network collector.
func NewNetworkCollector(eventChan chan<- *event.Event, filter *Filter, filterPrivateNetworks bool, logger *logging.Logger) *NetworkCollector {
	return &NetworkCollector{
		logger:                logger,
		eventChan:             eventChan,
		filter:                filter,
		filterPrivateNetworks: filterPrivateNetworks,
		connCache:             make(map[string]time.Time, 128),
	}
}

// Start begins network monitoring.
func (c *NetworkCollector) Start(ctx context.Context) error {
	if c.running.Load() {
		return nil
	}

	c.logger.Info("[NET] Starting network collector (IP Helper API — direct kernel table)...")
	c.running.Store(true)

	go c.monitorLoop(ctx)

	c.logger.Info("[NET] Network collector started (1s scan interval)")
	return nil
}

// Stop stops network monitoring.
func (c *NetworkCollector) Stop() error {
	if !c.running.Load() {
		return nil
	}

	c.logger.Info("[NET] Stopping network collector...")
	c.running.Store(false)

	c.logger.Infof("[NET] Stats: found=%d generated=%d dropped=%d",
		c.connectionsFound.Load(),
		c.eventsGenerated.Load(),
		c.dropped.Load())

	return nil
}

// monitorLoop polls the kernel TCP/UDP tables every 1 second.
// This is 30x faster than the old PowerShell approach and spawns zero
// child processes.
func (c *NetworkCollector) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Cache cleanup ticker — remove stale entries every 60s
	cleanupTicker := time.NewTicker(60 * time.Second)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-cleanupTicker.C:
			c.cleanupCache()
		case <-ticker.C:
			if !c.running.Load() {
				return
			}
			c.scanTcpTable()
			c.scanUdpTable()
		}
	}
}

// cleanupCache removes entries older than 5 minutes to prevent memory leak.
func (c *NetworkCollector) cleanupCache() {
	now := time.Now()
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	for k, ts := range c.connCache {
		if now.Sub(ts) > 5*time.Minute {
			delete(c.connCache, k)
		}
	}
}

// scanTcpTable reads the kernel TCP connection table.
func (c *NetworkCollector) scanTcpTable() {
	// First call to get required buffer size
	var size uint32
	getExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1,
		afInet, tcpTableOwnerPidAll, 0)

	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := getExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,     // sort by remote addr
		afInet,
		tcpTableOwnerPidAll,
		0,
	)

	if ret != 0 {
		return
	}

	// Parse: first 4 bytes = dwNumEntries
	if len(buf) < 4 {
		return
	}
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(tcpRowOwnerPid{}))

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}

		row := (*tcpRowOwnerPid)(unsafe.Pointer(&buf[offset]))

		// Only report active/interesting states
		state := row.State
		if state != tcpStateEstablished && state != tcpStateListen &&
			state != tcpStateSynSent && state != tcpStateSynRcvd {
			continue
		}

		localIP := uint32ToIP(row.LocalAddr)
		remoteIP := uint32ToIP(row.RemoteAddr)
		localPort := ntohs(uint16(row.LocalPort))
		remotePort := ntohs(uint16(row.RemotePort))
		pid := row.OwningPid

		// Skip system/idle PIDs
		if pid <= 4 {
			continue
		}

		// Skip zero-address connections
		if remoteIP == "0.0.0.0" || remoteIP == "255.255.255.255" {
			continue
		}

		c.processConnection("tcp", localIP, localPort, remoteIP, remotePort, pid, tcpStateToString(state))
	}
}

// scanUdpTable reads the kernel UDP listener table.
func (c *NetworkCollector) scanUdpTable() {
	var size uint32
	getExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1,
		afInet, udpTableOwnerPid, 0)

	if size == 0 {
		return
	}

	buf := make([]byte, size)
	ret, _, _ := getExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		afInet,
		udpTableOwnerPid,
		0,
	)

	if ret != 0 {
		return
	}

	if len(buf) < 4 {
		return
	}
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(udpRowOwnerPid{}))

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}

		row := (*udpRowOwnerPid)(unsafe.Pointer(&buf[offset]))
		localIP := uint32ToIP(row.LocalAddr)
		localPort := ntohs(uint16(row.LocalPort))
		pid := row.OwningPid

		if pid <= 4 {
			continue
		}

		// UDP listeners listening on all interfaces (0.0.0.0) with common
		// system ports are noise — skip them
		if localIP == "0.0.0.0" && (localPort == 5353 || localPort == 5355 || localPort == 1900) {
			continue
		}

		c.processConnection("udp", localIP, localPort, "", 0, pid, "listening")
	}
}

// processConnection checks if a connection is new and emits an event.
func (c *NetworkCollector) processConnection(protocol, localIP string, localPort uint16,
	remoteIP string, remotePort uint16, pid uint32, state string) {

	// Build cache key
	connKey := fmt.Sprintf("%s:%s:%d→%s:%d", protocol, localIP, localPort, remoteIP, remotePort)

	// Check cache — skip already-seen connections
	c.cacheMu.RLock()
	_, exists := c.connCache[connKey]
	c.cacheMu.RUnlock()

	if exists {
		return
	}

	// Mark as seen
	c.cacheMu.Lock()
	c.connCache[connKey] = time.Now()
	c.cacheMu.Unlock()

	// RFC 1918 filtering: skip private-to-private (LAN) connections
	if c.filterPrivateNetworks && remoteIP != "" && isPrivateIP(localIP) && isPrivateIP(remoteIP) {
		return
	}

	c.connectionsFound.Add(1)

	// Process attribution
	processName := baseName(getImagePath(pid))
	processPath := getImagePath(pid)
	if processName == "" {
		processName = fmt.Sprintf("pid:%d", pid)
	}

	// Skip agent's own processes
	if isSelfPID(pid) {
		return
	}

	// Determine direction
	direction := "outbound"
	action := "connection_established"
	if state == "listening" {
		direction = "inbound"
		action = "listening"
	} else if state == "SYN_SENT" || state == "SYN_RCVD" {
		action = "connection_attempted"
	}

	evt := event.NewEvent(event.EventTypeNetwork, event.SeverityLow, map[string]interface{}{
		"action":           action,
		"direction":        direction,
		"protocol":         protocol,
		"source_ip":        localIP,
		"source_port":      int(localPort),
		"destination_ip":   remoteIP,
		"destination_port": int(remotePort),
		"pid":              pid,
		"process_name":     processName,
		"state":            state,
		// Sigma-compatible fields
		"Image":            processPath,
		"SourceIp":         localIP,
		"SourcePort":       int(localPort),
		"DestinationIp":    remoteIP,
		"DestinationPort":  int(remotePort),
		"Protocol":         protocol,
	})

	// Apply filter
	if c.filter == nil || !c.filter.ShouldFilter(evt) {
		c.sendEvent(evt)
	}
}

// sendEvent sends an event to the channel.
func (c *NetworkCollector) sendEvent(evt *event.Event) {
	select {
	case c.eventChan <- evt:
		c.eventsGenerated.Add(1)
	default:
		c.dropped.Add(1)
	}
}

// Stats returns collector statistics.
func (c *NetworkCollector) Stats() NetworkStats {
	return NetworkStats{
		Running:          c.running.Load(),
		ConnectionsFound: c.connectionsFound.Load(),
		EventsGenerated:  c.eventsGenerated.Load(),
	}
}

// NetworkStats holds network collector statistics.
type NetworkStats struct {
	Running          bool
	ConnectionsFound uint64
	EventsGenerated  uint64
}

// =====================================================================
// Helper Functions
// =====================================================================

// uint32ToIP converts a uint32 network-order IP to dotted-decimal string.
func uint32ToIP(addr uint32) string {
	ip := net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	)
	return ip.String()
}

// ntohs converts a network-order uint16 port to host order.
func ntohs(port uint16) uint16 {
	return (port>>8) | (port<<8)
}

// tcpStateToString maps MIB_TCP_STATE values to human-readable strings.
func tcpStateToString(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case tcpStateListen:
		return "listening"
	case tcpStateSynSent:
		return "SYN_SENT"
	case tcpStateSynRcvd:
		return "SYN_RCVD"
	case tcpStateEstablished:
		return "ESTABLISHED"
	case tcpStateFinWait1:
		return "FIN_WAIT1"
	case tcpStateFinWait2:
		return "FIN_WAIT2"
	case tcpStateCloseWait:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}

// isPrivateIP returns true if the IP address is in an RFC 1918 private range.
// Uses fast string-prefix matching (no net.ParseIP) for zero-allocation performance.
func isPrivateIP(ip string) bool {
	for _, r := range rfc1918 {
		if strings.HasPrefix(ip, r.prefix) {
			return true
		}
	}
	return false
}

// parseCSVLine splits a CSV line into fields (kept for compatibility).
func parseCSVLine(line string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false

	for _, char := range line {
		switch char {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(char)
		case ',':
			if inQuotes {
				current.WriteRune(char)
			} else {
				result = append(result, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(char)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}
