// Package collectors — Process Access telemetry via ETW Kernel Audit API Calls.
//
// Captures real-time OpenProcess calls with sensitive access rights,
// enabling detection of:
//   - LSASS credential dumping (Mimikatz T1003.001, comsvcs.dll T1003.001)
//   - Process injection (T1055.001 DLL Injection, T1055.012 Process Hollowing)
//   - Process memory reading (T1003 Credential Access)
//   - Anti-debug / anti-analysis evasion (T1622)
//   - Sigma process_access rules (previously non-functional)
//
// Architecture: Uses the Microsoft-Windows-Kernel-Audit-API-Calls provider
// which traces all NtOpenProcess calls with their access masks. This runs
// in its own user-mode ETW session (not the kernel trace session).
//
// IMPORTANT: Only SUCCESSFUL access attempts with DANGEROUS access masks
// are reported to avoid flooding the pipeline. The filter logic is
// security-critical and mirrors Sysmon's process access filtering.
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

// =====================================================================
// Access Mask Constants (Windows NT)
// These represent the access rights that are security-relevant.
// =====================================================================

const (
	// PROCESS_VM_READ — read process memory (credential dumping)
	processVMRead uint32 = 0x0010
	// PROCESS_VM_WRITE — write to process memory (injection)
	processVMWrite uint32 = 0x0020
	// PROCESS_VM_OPERATION — modify virtual memory (injection)
	processVMOperation uint32 = 0x0008
	// PROCESS_CREATE_THREAD — create remote thread (injection)
	processCreateThread uint32 = 0x0002
	// PROCESS_DUP_HANDLE — duplicate handles (privilege escalation)
	processDupHandle uint32 = 0x0040
	// PROCESS_ALL_ACCESS — full access (0x1F0FFF or 0x001FFFFF)
	processAllAccess uint32 = 0x1F0FFF
	// PROCESS_QUERY_INFORMATION — query process info
	processQueryInfo uint32 = 0x0400
	// PROCESS_QUERY_LIMITED_INFORMATION — limited query
	processQueryLimited uint32 = 0x1000
)

// suspiciousAccessMask returns true if the access mask includes rights
// commonly used by credential dumpers and process injectors.
// This filter is deliberately conservative — we only alert on access
// combinations that have genuine security signal.
func suspiciousAccessMask(mask uint32) bool {
	// PROCESS_ALL_ACCESS — always suspicious
	if mask&processAllAccess == processAllAccess {
		return true
	}
	// Memory read + operation = credential dump signature
	if mask&processVMRead != 0 && mask&processVMOperation != 0 {
		return true
	}
	// Memory write + operation = injection signature
	if mask&processVMWrite != 0 && mask&processVMOperation != 0 {
		return true
	}
	// Create thread + VM operation = remote thread injection
	if mask&processCreateThread != 0 && mask&processVMOperation != 0 {
		return true
	}
	// Create thread + VM write = classic DLL injection
	if mask&processCreateThread != 0 && mask&processVMWrite != 0 {
		return true
	}
	// DUP_HANDLE alone can be used for privilege escalation
	if mask&processDupHandle != 0 && mask&processVMRead != 0 {
		return true
	}
	return false
}

// =====================================================================
// High-Value Target Processes
// =====================================================================

// Processes that are high-value targets for credential access / injection.
// Access to these processes with suspicious masks is always reported
// regardless of the caller.
var sensitiveTargets = map[string]bool{
	"lsass.exe":    true, // T1003.001 — LSASS credential dumping
	"csrss.exe":    true, // T1055 — Process injection
	"winlogon.exe": true, // T1134 — Access Token Manipulation
	"svchost.exe":  true, // T1055 — Common injection target
	"spoolsv.exe":  true, // T1055 — Print spooler injection
}

// =====================================================================
// Self-Access Noise Filter
// =====================================================================

// Processes that legitimately open handles to other processes as part
// of normal OS operation. Access FROM these callers is filtered OUT
// unless the target is a high-value sensitive process.
var trustedCallers = map[string]bool{
	// Anti-virus / security products (they scan all processes)
	"msmpeng.exe":              true,
	"mpcmdrun.exe":             true,
	"securityhealthservice.exe": true,
	"sgrmbroker.exe":            true,

	// OS infrastructure
	"taskmgr.exe":              true,
	"tasklist.exe":             true,
	"wmiprvse.exe":             true,
	"wmi performance adapter":  true,

	// Development tools (common in dev environments)
	"devenv.exe":               true,
	"perfmon.exe":              true,
}

// =====================================================================
// Process Access Collector
// =====================================================================

// ProcessAccessCollector captures cross-process handle operations via ETW.
type ProcessAccessCollector struct {
	logger    *logging.Logger
	eventChan chan<- *event.Event
	session   string
	running   atomic.Bool
	collected atomic.Uint64
	dropped   atomic.Uint64
	errors    atomic.Uint64
}

var globalProcessAccessCollector atomic.Pointer[ProcessAccessCollector]

// NewProcessAccessCollector creates a new ETW Process Access collector.
func NewProcessAccessCollector(ch chan<- *event.Event, l *logging.Logger) *ProcessAccessCollector {
	return &ProcessAccessCollector{
		logger:    l,
		eventChan: ch,
		session:   "EDRProcAccessTrace",
	}
}

// Start begins the Process Access ETW session.
func (c *ProcessAccessCollector) Start(ctx context.Context) error {
	if c.running.Load() {
		return fmt.Errorf("ProcessAccess collector already running")
	}
	c.running.Store(true)
	globalProcessAccessCollector.Store(c)
	go c.run(ctx)
	return nil
}

// Stop signals the collector to shut down.
func (c *ProcessAccessCollector) Stop() error {
	c.running.Store(false)
	c.logger.Infof("[PROCACCESS] Stats: collected=%d dropped=%d errors=%d",
		c.collected.Load(), c.dropped.Load(), c.errors.Load())
	return nil
}

func (c *ProcessAccessCollector) run(ctx context.Context) {
	c.logger.Info("[PROCACCESS] Starting ETW Kernel-Audit-API-Calls session...")

	// Kernel-Audit-API-Calls provider GUID
	auditGUID := C.GUID{
		Data1: 0xE02A841C, Data2: 0x75A3, Data3: 0x4FA7,
		Data4: [8]C.uchar{0xAF, 0xC8, 0xAE, 0x09, 0xCF, 0x9B, 0x7F, 0x23},
	}

	for ctx.Err() == nil && c.running.Load() {
		name16, err := windows.UTF16FromString(c.session)
		if err != nil {
			c.logger.Errorf("[PROCACCESS] Session name encode error: %v", err)
			return
		}
		np := (*C.wchar_t)(unsafe.Pointer(&name16[0]))

		// Start user-mode ETW session for Kernel-Audit-API-Calls
		// Level 5 = Verbose (to capture all OpenProcess events)
		ret := C.StartUserModeSession(np, &auditGUID, 5, 0xFFFFFFFFFFFFFFFF)
		if ret != 0 {
			c.errors.Add(1)
			c.logger.Errorf("[PROCACCESS] StartUserModeSession failed: error %d — retrying in 5s", ret)
			time.Sleep(5 * time.Second)
			continue
		}
		c.logger.Info("[PROCACCESS] ETW Kernel-Audit-API-Calls session ACTIVE — monitoring process access")

		go func() {
			<-ctx.Done()
			C.KillNamedSession(np)
		}()

		ret = C.ProcessUserModeEvents(np, nil)
		if ret != 0 && ctx.Err() != nil {
			break
		}
		if ret != 0 {
			c.logger.Errorf("[PROCACCESS] ProcessUserModeEvents error %d — restarting in 3s", ret)
			time.Sleep(3 * time.Second)
		}
	}
	c.logger.Info("[PROCACCESS] Collector stopped")
}

// send delivers a process access event to the agent's event pipeline.
func (c *ProcessAccessCollector) send(evt *event.Event) {
	select {
	case c.eventChan <- evt:
		c.collected.Add(1)
	default:
		c.dropped.Add(1)
	}
}

// IsRunning returns whether the collector is active.
func (c *ProcessAccessCollector) IsRunning() bool { return c.running.Load() }

// =====================================================================
// C → Go callback for Process Access events
// =====================================================================

//export goProcessAccessEvent
func goProcessAccessEvent(evt *C.ParsedProcessAccessEvent) {
	collector := globalProcessAccessCollector.Load()
	if collector == nil || !collector.running.Load() {
		return
	}

	callerPid := uint32(evt.callerPid)
	targetPid := uint32(evt.targetPid)
	desiredAccess := uint32(evt.desiredAccess)

	// Skip self-access (process opening a handle to itself)
	if callerPid == targetPid {
		return
	}

	// ── Access mask filter ───────────────────────────────────
	// Only report access attempts with DANGEROUS access masks.
	// Benign access (PROCESS_QUERY_LIMITED_INFORMATION, etc.) is ignored.
	if !suspiciousAccessMask(desiredAccess) {
		return
	}

	// Resolve process names
	callerPath := getImagePath(callerPid)
	targetPath := getImagePath(targetPid)
	callerName := baseName(callerPath)
	targetName := baseName(targetPath)

	if callerName == "" {
		callerName = fmt.Sprintf("pid:%d", callerPid)
	}
	if targetName == "" {
		targetName = fmt.Sprintf("pid:%d", targetPid)
	}

	callerNameLow := strings.ToLower(callerName)
	targetNameLow := strings.ToLower(targetName)

	// Skip agent's own processes
	if isSelfPID(callerPid) {
		return
	}

	// ── Noise filter: trusted callers ────────────────────────
	// Skip known OS/security processes UNLESS the target is sensitive
	isTargetSensitive := sensitiveTargets[targetNameLow]
	if trustedCallers[callerNameLow] && !isTargetSensitive {
		return
	}

	// Determine severity based on target and access type
	severity := event.SeverityMedium
	if isTargetSensitive {
		severity = event.SeverityHigh
		// LSASS with PROCESS_ALL_ACCESS = critical (Mimikatz)
		if targetNameLow == "lsass.exe" && desiredAccess&processAllAccess == processAllAccess {
			severity = event.SeverityCritical
		}
	}

	// Format access mask as hex string (matches Sysmon format)
	accessMaskStr := fmt.Sprintf("0x%X", desiredAccess)

	go func() {
		data := map[string]interface{}{
			"action":              "process_access",
			"source_pid":          callerPid,
			"source_process_name": callerName,
			"source_process_path": callerPath,
			"target_pid":          targetPid,
			"target_process_name": targetName,
			"target_process_path": targetPath,
			"access_mask":         accessMaskStr,
			"access_mask_int":     desiredAccess,
			// Sigma-required fields (match Sysmon EventID 10)
			"SourceImage":         callerPath,
			"TargetImage":         targetPath,
			"GrantedAccess":       accessMaskStr,
			"SourceProcessId":     callerPid,
			"TargetProcessId":     targetPid,
		}

		// Add user context for ML model
		callerSid, callerUser, _, _ := getPrivileges(callerPid)
		if callerUser != "" {
			data["user_name"] = callerUser
			data["user_sid"] = callerSid
		}

		collector.send(event.NewEvent(event.EventTypeProcessAccess, severity, data))
		collector.logger.Infof("[PROCACCESS] %s (pid:%d) → %s (pid:%d) access=%s severity=%s",
			callerName, callerPid, targetName, targetPid, accessMaskStr, severity.String())
	}()
}
