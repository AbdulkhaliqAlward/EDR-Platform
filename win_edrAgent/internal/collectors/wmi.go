// Package collectors provides WMI-based event collection and system inventory.
//go:build windows
// +build windows

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
)

// WMICollector collects system inventory and events via WMI.
type WMICollector struct {
	logger    *logging.Logger
	eventChan chan<- *event.Event
	interval  time.Duration

	// State
	running atomic.Bool
	mu      sync.Mutex

	// Cache
	processCache map[uint32]string // PID -> process name
	cacheMu      sync.RWMutex

	// Metrics
	queriesRun  atomic.Uint64
	eventsFound atomic.Uint64
	errors      atomic.Uint64
}

// NewWMICollector creates a new WMI collector.
func NewWMICollector(interval time.Duration, eventChan chan<- *event.Event, logger *logging.Logger) *WMICollector {
	if interval <= 0 {
		interval = 60 * time.Minute
	}

	return &WMICollector{
		logger:       logger,
		eventChan:    eventChan,
		interval:     interval,
		processCache: make(map[uint32]string),
	}
}

// Start begins WMI event collection.
func (c *WMICollector) Start(ctx context.Context) error {
	if c.running.Load() {
		return fmt.Errorf("WMI collector already running")
	}

	c.logger.Info("Starting WMI collector...")
	c.logger.Infof("Inventory interval: %v", c.interval)

	c.running.Store(true)

	// Initial inventory
	go c.collectInventory()

	// Start periodic collection
	go c.collectLoop(ctx)

	c.logger.Info("WMI collector started")
	return nil
}

// Stop stops WMI collection.
func (c *WMICollector) Stop() error {
	if !c.running.Load() {
		return nil
	}

	c.logger.Info("Stopping WMI collector...")
	c.running.Store(false)

	c.logger.Infof("WMI stats: queries=%d events=%d errors=%d",
		c.queriesRun.Load(),
		c.eventsFound.Load(),
		c.errors.Load())

	return nil
}

// collectLoop runs periodic inventory collection.
func (c *WMICollector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !c.running.Load() {
				return
			}
			c.collectInventory()
		}
	}
}

// collectInventory gathers system information via WMI.
func (c *WMICollector) collectInventory() {
	c.logger.Debug("Collecting system inventory...")

	// Collect running processes
	c.collectProcesses()

	// Collect system info
	c.collectSystemInfo()

	// Collect network adapters
	c.collectNetworkAdapters()

	// Collect installed software inventory
	c.collectInstalledSoftware()

	c.logger.Debug("Inventory collection complete")
}

// collectProcesses gets running processes via PowerShell/WMI.
func (c *WMICollector) collectProcesses() {
	c.queriesRun.Add(1)

	// Using PowerShell for WMI query (Go WMI packages require CGO)
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json -Compress`)

	output, err := cmd.Output()
	if err != nil {
		c.errors.Add(1)
		c.logger.Debugf("Failed to query processes: %v", err)
		return
	}

	// Parse JSON output (simplified - in production use proper JSON parsing)
	processes := c.parseProcessOutput(string(output))

	c.cacheMu.Lock()
	newCache := make(map[uint32]string)
	c.cacheMu.Unlock()

	for _, proc := range processes {
		pid, _ := strconv.ParseUint(proc["ProcessId"], 10, 32)
		ppid, _ := strconv.ParseUint(proc["ParentProcessId"], 10, 32)
		name := proc["Name"]
		cmdLine := proc["CommandLine"]

		// Check if this is a new process
		c.cacheMu.RLock()
		_, exists := c.processCache[uint32(pid)]
		c.cacheMu.RUnlock()

		if !exists && pid > 4 { // Skip System and Idle
			// WMI process discovery is a fallback for hosts where the ETW
			// kernel tracer is not running: with ETW active it would only
			// duplicate (lower-fidelity) process-creation events and alerts.
			// The agent's own helper tree is excluded by process ancestry.
			if !isSelfPID(uint32(pid)) && !etwProcessTracerActive() {
				evt := event.NewEvent(event.EventTypeProcess, event.SeverityLow, map[string]interface{}{
					"action":       "created",
					"pid":          pid,
					"ppid":         ppid,
					"name":         name,
					"executable":   proc["ExecutablePath"],
					"command_line": cmdLine,
				})
				c.sendEvent(evt)
			}
		}

		newCache[uint32(pid)] = name
	}

	// Update cache
	c.cacheMu.Lock()
	c.processCache = newCache
	c.cacheMu.Unlock()
}

// wmiProcessRecord represents a single process from PowerShell JSON output.
// All fields are json.RawMessage so we can handle null, string, number, and
// nested-object types (e.g. CreationDate is an object with "value" key).
type wmiProcessRecord struct {
	ProcessId       json.Number `json:"ProcessId"`
	ParentProcessId json.Number `json:"ParentProcessId"`
	Name            string      `json:"Name"`
	ExecutablePath  *string     `json:"ExecutablePath"`
	CommandLine     *string     `json:"CommandLine"`
}

// parseProcessOutput parses the PowerShell ConvertTo-Json output using
// encoding/json for correct handling of all field values (including
// command lines that contain commas, colons, and special characters).
func (c *WMICollector) parseProcessOutput(output string) []map[string]string {
	output = strings.TrimSpace(output)
	if output == "" || output == "null" {
		return nil
	}

	var records []wmiProcessRecord

	// PowerShell returns a single object (not wrapped in []) when there is
	// only one result. Try array first, fall back to single object.
	if err := json.Unmarshal([]byte(output), &records); err != nil {
		var single wmiProcessRecord
		if err2 := json.Unmarshal([]byte(output), &single); err2 != nil {
			c.errors.Add(1)
			c.logger.Debugf("Failed to parse WMI process JSON: %v", err)
			return nil
		}
		records = []wmiProcessRecord{single}
	}

	results := make([]map[string]string, 0, len(records))
	for _, r := range records {
		m := map[string]string{
			"ProcessId":       r.ProcessId.String(),
			"ParentProcessId": r.ParentProcessId.String(),
			"Name":            r.Name,
		}
		if r.ExecutablePath != nil {
			m["ExecutablePath"] = *r.ExecutablePath
		}
		if r.CommandLine != nil {
			m["CommandLine"] = *r.CommandLine
		}
		if m["ProcessId"] != "" && m["ProcessId"] != "0" {
			results = append(results, m)
		}
	}

	return results
}

// collectSystemInfo gathers system information.
func (c *WMICollector) collectSystemInfo() {
	c.queriesRun.Add(1)

	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,Manufacturer,Model,TotalPhysicalMemory | ConvertTo-Json -Compress`)

	output, err := cmd.Output()
	if err != nil {
		c.errors.Add(1)
		c.logger.Debugf("Failed to query system info: %v", err)
		return
	}

	c.logger.Debugf("System info collected: %d bytes", len(output))
}

// collectNetworkAdapters gathers network adapter information.
func (c *WMICollector) collectNetworkAdapters() {
	c.queriesRun.Add(1)

	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name,InterfaceDescription,MacAddress,LinkSpeed | ConvertTo-Json -Compress`)

	output, err := cmd.Output()
	if err != nil {
		c.errors.Add(1)
		c.logger.Debugf("Failed to query network adapters: %v", err)
		return
	}

	c.logger.Debugf("Network adapters collected: %d bytes", len(output))
}

// sendEvent sends an event to the channel.
func (c *WMICollector) sendEvent(evt *event.Event) {
	select {
	case c.eventChan <- evt:
		c.eventsFound.Add(1)
	default:
		c.errors.Add(1)
	}
}

// Stats returns collector statistics.
func (c *WMICollector) Stats() WMIStats {
	return WMIStats{
		Running:     c.running.Load(),
		QueriesRun:  c.queriesRun.Load(),
		EventsFound: c.eventsFound.Load(),
		Errors:      c.errors.Load(),
	}
}

// WMIStats holds WMI collector statistics.
type WMIStats struct {
	Running     bool
	QueriesRun  uint64
	EventsFound uint64
	Errors      uint64
}

// IsRunning returns whether the collector is running.
func (c *WMICollector) IsRunning() bool {
	return c.running.Load()
}

// ForceInventory triggers an immediate inventory collection.
func (c *WMICollector) ForceInventory() {
	go c.collectInventory()
}

// softwareRecord represents one installed application from registry uninstall keys.
type softwareRecord struct {
	DisplayName    *string `json:"DisplayName"`
	DisplayVersion *string `json:"DisplayVersion"`
	Publisher      *string `json:"Publisher"`
	InstallDate    *string `json:"InstallDate"`
	InstallSource  *string `json:"InstallSource"`
}

// collectInstalledSoftware queries the Windows Registry uninstall keys
// for installed applications and emits software_inventory events.
// This is more reliable than Win32_Product (which is slow and can trigger repairs)
// and covers both 32-bit and 64-bit applications.
func (c *WMICollector) collectInstalledSoftware() {
	c.queriesRun.Add(1)

	// Query both 64-bit and 32-bit registry uninstall keys, filter blanks
	psCmd := `
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' } |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallSource -Unique |
  ConvertTo-Json -Compress
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)

	output, err := cmd.Output()
	if err != nil {
		c.errors.Add(1)
		c.logger.Debugf("Failed to query installed software: %v", err)
		return
	}

	raw := strings.TrimSpace(string(output))
	if raw == "" || raw == "null" {
		return
	}

	var records []softwareRecord
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		// PowerShell returns a single object when only one result
		var single softwareRecord
		if err2 := json.Unmarshal([]byte(raw), &single); err2 != nil {
			c.errors.Add(1)
			c.logger.Debugf("Failed to parse software inventory JSON: %v", err)
			return
		}
		records = []softwareRecord{single}
	}

	for _, r := range records {
		if r.DisplayName == nil {
			continue
		}
		data := map[string]interface{}{
			"action": "inventory",
			"name":   *r.DisplayName,
		}
		if r.DisplayVersion != nil {
			data["version"] = *r.DisplayVersion
		}
		if r.Publisher != nil {
			data["publisher"] = *r.Publisher
		}
		if r.InstallDate != nil {
			data["install_date"] = *r.InstallDate
		}
		if r.InstallSource != nil {
			data["install_source"] = *r.InstallSource
		}

		evt := event.NewEvent(event.EventTypeSoftwareInventory, event.SeverityLow, data)
		c.sendEvent(evt)
	}

	c.logger.Infof("Software inventory collected: %d applications", len(records))
}
