// Package collectors — File I/O event handler for the ETW kernel tracer.
//
// Handles FileIo events delivered real-time from the Windows Kernel
// ETW session (EVENT_TRACE_FLAG_FILE_IO_INIT). Every event contains the
// exact PID that initiated the I/O, enabling process-to-file attribution.
//
// MITRE coverage: T1005 (Data from Local System), T1565 (Data Manipulation),
// T1486 (Data Encrypted for Impact / Ransomware).
//
//go:build windows
// +build windows

package collectors

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/edr-platform/win-agent/internal/event"
)

// fileDedup suppresses duplicate file events for the same (path+opcode)
// within a 30-second window.  The first event always passes through so
// Sigma rules can still match; only the thousands of repeated accesses
// to the same path are dropped.
var fileDedup = NewDedupCache(30*time.Second, 15*time.Second)

// FileIo opcode constants from the Windows Kernel Trace.
const (
	fileIoCreate = 64
	fileIoWrite  = 68
	fileIoDelete = 70
	fileIoRename = 71
)

// handleFileIo processes a single file I/O event from the kernel ETW callback.
// This method runs in its own goroutine (spawned by goFileIoEvent) so it is
// safe to call enrichment APIs that may block briefly.
func (c *ETWCollector) handleFileIo(pid uint32, opcode uint8, filePath string) {
	// --- Noise filter: skip high-volume, low-value file paths ---
	lower := strings.ToLower(filePath)
	if isNoisyFilePath(lower) {
		return
	}

	// --- Directory open filter: bare directory paths have no security signal ---
	if opcode == fileIoCreate && isDirectoryOpen(lower) {
		return
	}

	// --- DLL/EXE read filter: file-access of System32 binaries is noise ---
	// (image_load events cover actual DLL loading; file reads are just stat/open)
	if opcode == fileIoCreate && isSystemBinaryRead(lower) {
		return
	}

	// --- Self-filter: drop the agent's own file I/O ---
	procPath := getImagePath(pid)
	procName := baseName(procPath)
	if procName == "" {
		procName = "unknown"
	}
	if isSelfPID(pid) {
		return
	}

	// --- AUTO-RESPONSE: MUST run BEFORE dedup so quarantine is NEVER skipped ---
	// The dedup cache suppresses repeated telemetry events to reduce noise, but
	// it must NOT gate the security response path. A file written twice (e.g.
	// OneDrive sync touching a newly-written file, or a restore-then-rewrite)
	// must still be evaluated for hash matches on every Create/Write.
	if c.fileAutoResp != nil && (opcode == fileIoCreate || opcode == fileIoWrite) {
		name := filepath.Base(filePath)
		dir := filepath.Dir(filePath)
		ext := filepath.Ext(name)
		sid, user, elevated, integrity := getPrivileges(pid)
		cmdLine := getCmdLine(pid)
		base := map[string]interface{}{
			"action":          "",
			"path":            filePath,
			"name":            name,
			"directory":       dir,
			"extension":       ext,
			"pid":             pid,
			"process_name":    procName,
			"process_path":    procPath,
			"user_name":       user,
			"user_sid":        sid,
			"command_line":    cmdLine,
			"is_elevated":     elevated,
			"integrity_level": integrity,
		}
		if alt, stop := c.fileAutoResp.EvaluateAndAct(context.Background(), filePath, opcode, pid, base); stop {
			if alt != nil {
				if c.filter != nil && c.filter.ShouldFilter(alt) {
					return
				}
				c.send(alt)
			}
			c.fileEvents.Add(1)
			return
		}
	}

	// --- Time-windowed deduplication (telemetry-only, AFTER auto-response) ---
	// Same path+opcode within 30s → suppress the upstream telemetry event.
	// Auto-response above has already run, so we only gate the Sigma/analytics
	// feed here, not the security enforcement path.
	dedupKey := fmt.Sprintf("%s|%d", lower, opcode)
	if fileDedup.IsDuplicate(dedupKey) {
		return
	}

	// Map kernel opcode → human-readable action + severity.
	var action string
	var severity event.Severity

	switch opcode {
	case fileIoCreate:
		action = "created"
		severity = event.SeverityLow
	case fileIoWrite:
		action = "modified"
		severity = event.SeverityLow
	case fileIoDelete:
		action = "deleted"
		severity = event.SeverityMedium
	case fileIoRename:
		action = "renamed"
		severity = event.SeverityLow
	default:
		return
	}

	name := filepath.Base(filePath)
	dir := filepath.Dir(filePath)
	ext := filepath.Ext(name)
	sid, user, elevated, integrity := getPrivileges(pid)
	cmdLine := getCmdLine(pid)

	evt := event.NewEvent(event.EventTypeFile, severity, map[string]interface{}{
		"action":          action,
		"path":            filePath,
		"name":            name,
		"directory":       dir,
		"extension":       ext,
		"pid":             pid,
		"process_name":    procName,
		"process_path":    procPath,
		"user_name":       user,
		"user_sid":        sid,
		"command_line":    cmdLine,
		"is_elevated":     elevated,
		"integrity_level": integrity,
	})

	// Apply configurable filter.
	if c.filter != nil && c.filter.ShouldFilter(evt) {
		return
	}

	c.send(evt)
	c.fileEvents.Add(1)
}

// isNoisyFilePath filters out high-volume, low-value file I/O noise.
// This is critical for performance — kernel file I/O generates thousands
// of events per second from OS services, antivirus, indexing, etc.
//
// These are hard-coded because they represent immutable OS behavior —
// no real-world attack depends on writing to these paths/extensions.
// The configurable ExcludePaths list in FilterConfig handles user-defined
// exclusions and is checked after event creation in the filter pipeline.
func isNoisyFilePath(lower string) bool {
	// Skip common temp/cache/OS-internal file extensions.
	noisySuffixes := []string{
		".tmp", ".log", ".etl", ".blf", ".regtrans-ms",
		"~rf", ".pf", "thumbs.db", "desktop.ini",
		// Windows Event Log / diagnostics
		".evtx", ".pma", ".sdi",
		// ESE / transaction journaling (used by Search, BITS, etc.)
		".jrs", ".chk",
		// WMI / COM metadata
		".mof",
		// Catalog files (driver signing verification)
		".cat",
		// Side-by-side assembly manifests
		".manifest",
		// MUI resource files (language packs — no security signal)
		".mui",
		// Oracle / database trace files (extremely noisy on DB servers)
		".trc", ".aud",
		// NGen / ReadyToRun native image metadata
		".ni.dll",
	}
	for _, s := range noisySuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}

	// Skip high-noise OS directories.
	noisyDirs := []string{
		`\windows\softwaredistribution`,
		`\windows\temp`,
		`\windows\prefetch`,
		`\windows\servicing`,
		`\appdata\local\temp`,
		`\appdata\local\microsoft\windows\inetcache`,
		`\windows\logs\cbs`,
		`\programdata\microsoft\windows\wer`,
		`\$extend`,
		`\system volume information`,
		// .NET / Assembly (Global Assembly Cache)
		`\windows\assembly`,
		`\windows\winsxs`,
		`\windows\microsoft.net`,
		// Installer cache
		`\windows\installer`,
		// Application Compatibility (shim database)
		`\windows\appcompat`,
		// Windows Defender real-time scan artifacts
		`\programdata\microsoft\windows defender`,
		// Office telemetry
		`\appdata\local\microsoft\office`,
		// UWP app containers (extremely noisy on Win10/11)
		`\appdata\local\packages`,
		// Font cache
		`\windows\fonts`,
		// Windows Search index
		`\programdata\microsoft\search`,
		// Agent internals (self-generated I/O, no attacker signal)
		`\programdata\edr\queue`,
		`\programdata\edr\logs`,
		`\programdata\edr\quarantine`,
		// PowerShell module directory (read-only, extremely noisy)
		`\windowspowershell\v1.0\modules`,
		`\powershell\7\modules`,
		// Oracle / database runtime noise
		`\diag\rdbms\`,
		`\app\diag\`,
		// CLR / .NET JIT temp artifacts
		`\clr\`,
	}
	for _, d := range noisyDirs {
		if strings.Contains(lower, d) {
			return true
		}
	}

	// Skip kernel/driver device paths (not real filesystem paths).
	if strings.HasPrefix(lower, `\device\`) && !strings.Contains(lower, `\harddiskvolume`) {
		return true
	}

	return false
}

// isDirectoryOpen returns true if the path looks like a bare directory open
// rather than a file access.  Directory traversals (C:\, C:\Windows,
// C:\Windows\system32) fire thousands of FileIo Create events with zero
// security value.
func isDirectoryOpen(lower string) bool {
	// Paths with no extension AND ending with a known directory name
	ext := filepath.Ext(lower)
	if ext != "" {
		return false
	}
	// If the path is just a drive root (C:, C:\) or well-known directory
	if len(lower) <= 3 {
		return true // e.g. "c:\"
	}
	// Heuristic: paths ending without an extension that are under System32,
	// Windows, or ProgramData are likely directory opens.
	knownDirs := []string{
		`c:\windows`, `c:\windows\system32`, `c:\windows\syswow64`,
		`c:\programdata`, `c:\program files`, `c:\program files (x86)`,
		`c:\users`, `c:\`,
	}
	for _, d := range knownDirs {
		if lower == d || lower == d+`\` {
			return true
		}
	}
	return false
}

// isSystemBinaryRead returns true if this is a file-open of a system
// binary (.dll/.exe/.sys) in System32.  These are file-ACCESS events,
// not image_load events — the image_load handler already covers actual
// module loading.  Repeated file reads of system DLLs are pure noise.
func isSystemBinaryRead(lower string) bool {
	if !strings.Contains(lower, `\windows\system32\`) &&
		!strings.Contains(lower, `\windows\syswow64\`) {
		return false
	}
	ext := filepath.Ext(lower)
	return ext == ".dll" || ext == ".exe" || ext == ".sys" || ext == ".drv" ||
		ext == ".ocx" || ext == ".cpl" || ext == ".config"
}
