// Package collectors — Named Pipe telemetry via ETW kernel FileIo interception.
//
// Captures real-time named pipe create/connect events, enabling detection of:
//   - Cobalt Strike beacon default pipes (\\.\pipe\msagent_*)
//   - Metasploit/Meterpreter named pipe communication
//   - PsExec lateral movement (\\.\pipe\PSEXESVC)
//   - SMB-based lateral movement and C2 channels
//   - Sigma pipe_created / pipe_connected rules (previously non-functional)
//
// Architecture: Pipe events are intercepted from the existing kernel
// FileIo ETW session — when a file path starts with \Device\NamedPipe\,
// the C callback routes it to goPipeEvent() instead of goFileIoEvent().
// This means NO additional ETW session is needed for pipe telemetry.
//
//go:build windows
// +build windows

package collectors

/*
#include "etw_cgo.h"
*/
import "C"

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
)

// =====================================================================
// Noise Filters — Pipes with zero security signal
// =====================================================================

// Well-known OS infrastructure pipes that fire continuously.
// These are kernel/system pipes that CANNOT be abused by attackers
// because they are managed by protected system processes.
var trustedPipes = map[string]bool{
	// Windows core infrastructure
	"lsass":    true,
	"ntsvcs":   true,
	"scerpc":   true,
	"wkssvc":   true,
	"srvsvc":   true,
	"samr":     true,
	"netlogon": true,
	"browser":  true,

	// COM / RPC infrastructure (extremely noisy)
	"epmapper":        true,
	"LSM_API_service": true,
	"InitShutdown":    true,

	// Print spooler
	"spoolss": true,

	// Windows Update / BITS
	"DAV RPC SERVICE": true,
}

// Pipe name prefixes that indicate OS plumbing (not attack activity).
var trustedPipePrefixes = []string{
	"PIPE_EVENTROOT\\", // Windows Event system
	"MsFteWds",         // Windows Search indexer
	"atsvc",            // Task scheduler
	"trkwks",           // Distributed Link Tracking
	"W32TIME",          // Windows Time
	"winspool\\",       // Print spooler
}

// =====================================================================
// Suspicious Pipe Patterns — High-value detection indicators
// =====================================================================

// Known C2 framework default pipe patterns.
// If a pipe matches ANY of these, the event is promoted to Medium severity.
var suspiciousPipePatterns = []string{
	"msagent_",   // Cobalt Strike default
	"MSSE-",      // Cobalt Strike named pipe variant
	"postex_",    // Cobalt Strike post-exploitation
	"status_",    // Cobalt Strike alternate
	"mojo.",      // Chrome/Electron abuse
	"crashpad_",  // Chrome/Electron abuse
	"PSHost.",    // PowerShell remoting
	"PSEXESVC",   // PsExec lateral movement
	"RemCom_",    // RemCom (open-source PsExec alternative)
	"csexec",     // CsExec lateral movement tool
	"gruntsvc",   // Covenant C2 framework
	"demoagent_", // Sliver C2 default
}

// PipeCollector handles named pipe event processing.
// The actual ETW event capture is done by the kernel ETW collector —
// this struct provides the processing/filtering/sending logic.
type PipeCollector struct {
	logger    *logging.Logger
	eventChan chan<- *event.Event
	enabled   atomic.Bool
	collected atomic.Uint64
	dropped   atomic.Uint64
}

var globalPipeCollector atomic.Pointer[PipeCollector]

// NewPipeCollector creates a new pipe event processor.
// Note: This does NOT start a separate ETW session. Pipe events
// are routed from the existing kernel FileIo session via the C layer.
func NewPipeCollector(ch chan<- *event.Event, l *logging.Logger) *PipeCollector {
	return &PipeCollector{
		logger:    l,
		eventChan: ch,
	}
}

// Enable activates pipe event processing.
func (c *PipeCollector) Enable() {
	c.enabled.Store(true)
	globalPipeCollector.Store(c)
	c.logger.Info("[PIPE] Named pipe monitoring enabled (via kernel FileIo ETW)")
}

// Disable deactivates pipe event processing.
func (c *PipeCollector) Disable() {
	c.enabled.Store(false)
	c.logger.Infof("[PIPE] Stats: collected=%d dropped=%d",
		c.collected.Load(), c.dropped.Load())
}

// send delivers a pipe event to the agent's event pipeline.
func (c *PipeCollector) send(evt *event.Event) {
	select {
	case c.eventChan <- evt:
		c.collected.Add(1)
	default:
		c.dropped.Add(1)
	}
}

// IsRunning returns whether pipe event processing is active.
func (c *PipeCollector) IsRunning() bool { return c.enabled.Load() }

// =====================================================================
// C → Go callback for Pipe events
// =====================================================================

//export goPipeEvent
func goPipeEvent(evt *C.ParsedPipeEvent) {
	collector := globalPipeCollector.Load()
	if collector == nil || !collector.enabled.Load() {
		return
	}

	pid := uint32(evt.processId)
	opcode := uint8(evt.opcode)
	pipeName := wcharToGo(&evt.pipeName[0], 512)

	if pipeName == "" {
		return
	}

	// Normalize pipe name
	pipeNameLow := strings.ToLower(pipeName)

	// ── Noise filtering ──────────────────────────────────────
	// 1. Skip trusted OS infrastructure pipes
	if trustedPipes[pipeNameLow] {
		return
	}

	// 2. Skip trusted prefixes
	for _, prefix := range trustedPipePrefixes {
		if strings.HasPrefix(pipeNameLow, strings.ToLower(prefix)) {
			return
		}
	}

	// 3. Skip agent's own processes
	processName := baseName(getImagePath(pid))
	if isSelfPID(pid) {
		return
	}

	// Determine action from opcode
	action := "pipe_created"
	if opcode != 64 { // 64 = FileIo Create
		action = "pipe_connected"
	}

	if processName == "" {
		processName = fmt.Sprintf("pid:%d", pid)
	}

	// Check for suspicious C2 pipe patterns → promote severity
	severity := event.SeverityLow
	for _, pattern := range suspiciousPipePatterns {
		if strings.Contains(pipeNameLow, strings.ToLower(pattern)) {
			severity = event.SeverityMedium
			break
		}
	}

	// Construct event with all fields needed by Sigma pipe_created/pipe_connected rules
	go func() {
		processPath := getImagePath(pid)

		data := map[string]interface{}{
			"action":       action,
			"pipe_name":    pipeName, // Original case preserved
			"pid":          pid,
			"process_name": processName,
			// Sigma-required fields (match Sysmon EventID 17/18)
			"PipeName": `\\.\pipe\` + pipeName,
			"Image":    processPath,
		}
		if processPath != "" {
			data["process_path"] = processPath
		}

		// Add user context for ML model
		_, userName, _, _ := getPrivileges(pid)
		if userName != "" {
			data["user_name"] = userName
		}

		collector.send(event.NewEvent(event.EventTypePipe, severity, data))
		collector.logger.Debugf("[PIPE] %s: pid=%d process=%s pipe=%s severity=%s",
			action, pid, processName, pipeName, severity.String())
	}()
}
