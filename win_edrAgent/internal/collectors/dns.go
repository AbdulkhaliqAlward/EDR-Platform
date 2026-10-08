// Package collectors — DNS query telemetry via ETW (Microsoft-Windows-DNS-Client).
//
// Captures real-time DNS resolution events at the kernel level, enabling
// detection of:
//   - C2 domain lookups (Cobalt Strike, Metasploit staging domains)
//   - DGA (Domain Generation Algorithm) patterns
//   - DNS tunneling / exfiltration
//   - Sigma dns_query rules (50+ rules previously non-functional)
//
// Architecture: The DNS-Client ETW provider is a user-mode manifest-based
// provider (not a kernel trace flag), so it runs in its own ETW session
// separate from the kernel process/file/imageload session.
//
//go:build windows
// +build windows

package collectors

/*
#include "etw_cgo.h"
*/
import "C"

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
)

// DNS record type code → human-readable string (RFC 1035 + extensions).
var dnsTypeMap = map[uint32]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	12:  "PTR",
	15:  "MX",
	16:  "TXT",
	28:  "AAAA",
	33:  "SRV",
	35:  "NAPTR",
	43:  "DS",
	46:  "RRSIG",
	47:  "NSEC",
	48:  "DNSKEY",
	52:  "TLSA",
	65:  "HTTPS",
	255: "ANY",
}

// DNS response status → human-readable string (RFC 1035).
var dnsStatusMap = map[uint32]string{
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
	9: "NOTAUTH",
}

// Domains that produce extreme noise with zero security signal.
// These are hard-coded because they represent Microsoft infrastructure
// that fires on EVERY Windows system continuously.
var trustedDNSDomains = map[string]bool{
	"wpad":                            true,
	"localhost":                       true,
	"isatap":                          true,
	"_ldap._tcp":                      true,
	"dns.msftncsi.com":                true,
	"www.msftconnecttest.com":         true,
	"msftconnecttest.com":             true,
	"settings-win.data.microsoft.com": true,
	"watson.microsoft.com":            true,
	"v10.events.data.microsoft.com":   true,
	"self.events.data.microsoft.com":  true,
}

// =====================================================================
// DNS Collector
// =====================================================================

// DNSCollector captures DNS query events via ETW Microsoft-Windows-DNS-Client.
type DNSCollector struct {
	logger    *logging.Logger
	eventChan chan<- *event.Event
	session   string
	running   atomic.Bool
	collected atomic.Uint64
	dropped   atomic.Uint64
	errors    atomic.Uint64
}

var globalDNSCollector atomic.Pointer[DNSCollector]

// NewDNSCollector creates a new ETW DNS collector.
func NewDNSCollector(ch chan<- *event.Event, l *logging.Logger) *DNSCollector {
	return &DNSCollector{
		logger:    l,
		eventChan: ch,
		session:   "EDRDnsTrace",
	}
}

// Start begins the DNS ETW session in a background goroutine.
func (c *DNSCollector) Start(ctx context.Context) error {
	if c.running.Load() {
		return fmt.Errorf("DNS collector already running")
	}
	c.running.Store(true)
	globalDNSCollector.Store(c)
	go c.run(ctx)
	return nil
}

// Stop signals the DNS collector to shut down.
func (c *DNSCollector) Stop() error {
	c.running.Store(false)
	c.logger.Infof("[DNS] Stats: collected=%d dropped=%d errors=%d",
		c.collected.Load(), c.dropped.Load(), c.errors.Load())
	return nil
}

func (c *DNSCollector) run(ctx context.Context) {
	c.logger.Info("[DNS] Starting ETW DNS-Client session...")

	// DNS-Client provider GUID (matches the C code)
	dnsGUID := C.GUID{
		Data1: 0x1C95126E, Data2: 0x7EEA, Data3: 0x49A9,
		Data4: [8]C.uchar{0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D},
	}

	for ctx.Err() == nil && c.running.Load() {
		name16, err := windows.UTF16FromString(c.session)
		if err != nil {
			c.logger.Errorf("[DNS] Session name encode error: %v", err)
			return
		}
		np := (*C.wchar_t)(unsafe.Pointer(&name16[0]))

		// Start user-mode ETW session for DNS-Client provider
		// Level 4 = Informational (captures query completed events)
		ret := C.StartUserModeSession(np, &dnsGUID, 4, 0xFFFFFFFFFFFFFFFF)
		if ret != 0 {
			c.errors.Add(1)
			c.logger.Errorf("[DNS] StartUserModeSession failed: error %d — retrying in 5s", ret)
			time.Sleep(5 * time.Second)
			continue
		}
		c.logger.Info("[DNS] ETW DNS-Client session ACTIVE — capturing real-time DNS queries")

		// Block on ProcessUserModeEvents until session stops
		go func() {
			<-ctx.Done()
			C.KillNamedSession(np)
		}()

		ret = C.ProcessUserModeEvents(np, nil)
		if ret != 0 && ctx.Err() != nil {
			break // Graceful shutdown
		}
		if ret != 0 {
			c.logger.Errorf("[DNS] ProcessUserModeEvents error %d — restarting in 3s", ret)
			time.Sleep(3 * time.Second)
		}
	}
	c.logger.Info("[DNS] Collector stopped")
}

// send delivers a DNS event to the agent's event pipeline.
func (c *DNSCollector) send(evt *event.Event) {
	select {
	case c.eventChan <- evt:
		c.collected.Add(1)
	default:
		c.dropped.Add(1)
	}
}

// =====================================================================
// C → Go callback for DNS events
// =====================================================================

//export goDnsEvent
func goDnsEvent(evt *C.ParsedDnsEvent) {
	collector := globalDNSCollector.Load()
	if collector == nil || !collector.running.Load() {
		return
	}

	pid := uint32(evt.processId)
	queryName := wcharToGo(&evt.queryName[0], 512)
	queryResults := wcharToGo(&evt.queryResults[0], 2048)
	queryType := uint32(evt.queryType)
	queryStatus := uint32(evt.queryStatus)

	if queryName == "" {
		return
	}

	// Normalize domain name for filtering
	queryNameLow := strings.ToLower(strings.TrimSuffix(queryName, "."))

	// ── Noise filtering ──────────────────────────────────────
	// 1. Hard-coded trusted domains (zero security signal)
	if trustedDNSDomains[queryNameLow] {
		return
	}

	// 2. Skip reverse DNS lookups (PTR for internal IPs)
	if strings.HasSuffix(queryNameLow, ".in-addr.arpa") ||
		strings.HasSuffix(queryNameLow, ".ip6.arpa") {
		return
	}

	// 3. Skip Windows telemetry subdomains
	if strings.HasSuffix(queryNameLow, ".microsoft.com") &&
		(strings.Contains(queryNameLow, "telemetry") ||
			strings.Contains(queryNameLow, "data.microsoft.com") ||
			strings.Contains(queryNameLow, "update.microsoft.com")) {
		return
	}

	// 4. Process attribution — resolve caller process image
	processName := baseName(getImagePath(pid))
	if processName == "" {
		processName = fmt.Sprintf("pid:%d", pid)
	}

	// Skip DNS queries from the agent's own processes
	if isSelfPID(pid) {
		return
	}

	// Map query type and status to strings
	typeStr := dnsTypeMap[queryType]
	if typeStr == "" {
		typeStr = fmt.Sprintf("TYPE%d", queryType)
	}
	statusStr := dnsStatusMap[queryStatus]
	if statusStr == "" {
		statusStr = fmt.Sprintf("RCODE%d", queryStatus)
	}

	// Parse answers from semicolon-separated results string
	var answers []string
	if queryResults != "" {
		for _, ans := range strings.Split(queryResults, ";") {
			ans = strings.TrimSpace(ans)
			if ans != "" {
				answers = append(answers, ans)
			}
		}
	}

	// Construct event with all fields needed by Sigma dns_query rules
	// and the SecBERT-CAD model's network context dimension
	go func() {
		data := map[string]interface{}{
			"action":        "dns_query",
			"query_name":    queryNameLow,
			"query_type":    typeStr,
			"response_code": statusStr,
			"pid":           pid,
			"process_name":  processName,
			// Sigma-required fields (field names match Sysmon EventID 22)
			"QueryName":    queryNameLow,
			"QueryStatus":  queryStatus,
			"QueryResults": queryResults,
		}
		if len(answers) > 0 {
			data["answers"] = answers
			data["answer_count"] = len(answers)
		}

		// Process path for Sigma Image field
		processPath := getImagePath(pid)
		if processPath != "" {
			data["process_path"] = processPath
			data["Image"] = processPath
		}

		collector.send(event.NewEvent(event.EventTypeDNS, event.SeverityLow, data))
		collector.logger.Debugf("[DNS] Query: pid=%d process=%s domain=%s type=%s status=%s answers=%d",
			pid, processName, queryNameLow, typeStr, statusStr, len(answers))
	}()
}

// IsRunning returns whether the DNS collector is active.
func (c *DNSCollector) IsRunning() bool { return c.running.Load() }
