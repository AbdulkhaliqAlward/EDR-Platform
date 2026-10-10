// Package collectors — File I/O event handler for the ETW kernel tracer.
//
// Kernel FileIo semantics (NT Kernel Logger, EVENT_TRACE_FLAG_FILE_IO_INIT):
//   - Create (64) is IRP_MJ_CREATE: it fires for EVERY open of a file,
//     including read-only opens of existing files. Only its CreateDisposition
//     (high byte of CreateOptions) and the file's creation time tell whether
//     a file was really created. Reporting every open as "created" flooded the
//     platform and made Sigma file_event rules ("file created in …") fire on
//     plain reads.
//   - Delete (70) / Rename (71) carry no path, only the FILE_OBJECT, which is
//     resolved from the path seen when that FILE_OBJECT was opened.
//   - Write (68) carries no path and is not collected.
//
// Emitted actions: created, overwritten, deleted, renamed (old name).
//
// MITRE coverage: T1105 (Ingress Tool Transfer), T1486 (Data Encrypted for
// Impact), T1547 (Startup folder persistence), T1070.004 (File Deletion).
//
//go:build windows
// +build windows

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/edr-platform/win-agent/internal/event"
)

// fileDedup suppresses the same (path, action) within 30 s (e.g. a file
// rewritten repeatedly by an installer).
var fileDedup = NewDedupCache(30*time.Second, 15*time.Second)

// FileIo opcode constants from the Windows Kernel Trace.
const (
	fileIoCreate = 64
	fileIoWrite  = 68
	fileIoDelete = 70
	fileIoRename = 71
)

// CreateDisposition values (high byte of CreateOptions).
const (
	fileSupersede   = 0
	fileOpen        = 1
	fileCreate      = 2
	fileOpenIf      = 3
	fileOverwrite   = 4
	fileOverwriteIf = 5
)

// createdTolerance: a file whose creation time is this close to the open
// event (or later) was created by that open.
const createdTolerance = 5 * time.Second

// fileIoOp is one kernel FileIo record handed to the worker pool.
type fileIoOp struct {
	pid           uint32
	opcode        uint8
	path          string // Create only
	createOptions uint32
	fileObject    uint64
	ttid          uint64
	at            time.Time
}

// classifyCreate decides whether a Create/Open was a file creation.
// exists/created describe the file when the worker examined it.
func classifyCreate(disposition uint32, exists bool, created, at time.Time) (string, bool) {
	isNew := !exists || !created.Before(at.Add(-createdTolerance))
	switch disposition {
	case fileOpen:
		return "", false // opening an existing file is not a creation
	case fileCreate:
		return "created", true
	case fileSupersede, fileOverwrite, fileOverwriteIf:
		if isNew {
			return "created", true
		}
		return "overwritten", true
	case fileOpenIf:
		if isNew {
			return "created", true
		}
		return "", false // existing file opened (e.g. appending to a log)
	default:
		return "", false
	}
}

// fileObjectPaths maps kernel FILE_OBJECT addresses to the opened path so
// Delete/Rename records (which carry no name) can be attributed. Two
// generations bound memory: when the current one is full or old, it becomes
// the previous one and a fresh map starts.
type fileObjectPaths struct {
	mu        sync.Mutex
	cur, prev map[uint64]string
	limit     int
	rotatedAt time.Time
	maxAge    time.Duration
}

func newFileObjectPaths(limit int, maxAge time.Duration) *fileObjectPaths {
	return &fileObjectPaths{cur: make(map[uint64]string), prev: map[uint64]string{}, limit: limit, maxAge: maxAge, rotatedAt: time.Now()}
}

func (m *fileObjectPaths) put(fo uint64, path string) {
	if fo == 0 || path == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cur) >= m.limit || time.Since(m.rotatedAt) > m.maxAge {
		m.prev, m.cur, m.rotatedAt = m.cur, make(map[uint64]string, len(m.cur)), time.Now()
	}
	m.cur[fo] = path
}

func (m *fileObjectPaths) get(fo uint64) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.cur[fo]; ok {
		return p
	}
	return m.prev[fo]
}

func (m *fileObjectPaths) forget(fo uint64) {
	m.mu.Lock()
	delete(m.cur, fo)
	delete(m.prev, fo)
	m.mu.Unlock()
}

var fileObjects = newFileObjectPaths(32768, 10*time.Minute)

var (
	kernel32File             = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessIdOfThread = kernel32File.NewProc("GetProcessIdOfThread")
)

// processOfThread resolves the process of the thread that issued the I/O
// (the kernel logger reports some FileIo records without a valid header PID).
func processOfThread(tid uint64) uint32 {
	if tid == 0 || tid > 0xFFFFFFFF {
		return 0
	}
	h, err := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION, false, uint32(tid))
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	r, _, _ := procGetProcessIdOfThread.Call(uintptr(h))
	return uint32(r)
}

// fileCreationTime returns whether the file exists and its creation time.
func fileCreationTime(path string) (bool, time.Time) {
	st, err := os.Stat(path)
	if err != nil {
		return false, time.Time{}
	}
	if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
		return true, time.Unix(0, d.CreationTime.Nanoseconds())
	}
	return true, st.ModTime()
}

// handleFileIo processes one kernel FileIo record (worker pool).
func (c *ETWCollector) handleFileIo(op fileIoOp) {
	pid := op.pid
	if pid == 0 || pid == 0xFFFFFFFF {
		pid = processOfThread(op.ttid)
		if pid <= 4 {
			return
		}
	}

	var action, filePath string
	switch op.opcode {
	case fileIoCreate:
		filePath = op.path
		fileObjects.put(op.fileObject, filePath)
		disposition := op.createOptions >> 24
		if disposition == fileOpen {
			return // fast path: plain open of an existing file
		}
		lower := strings.ToLower(filePath)
		if isDirectoryOpen(lower) || isSystemBinaryRead(lower) {
			return
		}
		exists, created := fileCreationTime(filePath)
		if exists {
			if st, err := os.Stat(filePath); err == nil && st.IsDir() {
				return // directory creation/open
			}
		}
		a, ok := classifyCreate(disposition, exists, created, op.at)
		if !ok {
			return
		}
		action = a
	case fileIoDelete:
		filePath = fileObjects.get(op.fileObject)
		fileObjects.forget(op.fileObject)
		action = "deleted"
	case fileIoRename:
		filePath = fileObjects.get(op.fileObject)
		action = "renamed"
	default:
		return
	}
	if filePath == "" {
		return
	}
	lower := strings.ToLower(filePath)
	if isNoisyFilePath(lower) {
		return
	}
	if isSelfPID(pid) {
		return
	}
	procPath := getImagePath(pid)
	procName := baseName(procPath)
	if procName == "" {
		procName = "unknown"
	}

	name := filepath.Base(filePath)
	sid, user, elevated, integrity := getPrivileges(pid)
	cmdLine := getCmdLine(pid)
	data := map[string]interface{}{
		"action":          action,
		"path":            filePath,
		"target_filename": filePath,
		"name":            name,
		"directory":       filepath.Dir(filePath),
		"extension":       filepath.Ext(name),
		"pid":             pid,
		"process_name":    procName,
		"process_path":    procPath,
		"user_name":       user,
		"user_sid":        sid,
		"command_line":    cmdLine,
		"is_elevated":     elevated,
		"integrity_level": integrity,
	}

	// AUTO-RESPONSE runs before de-duplication so a rewritten file is still
	// evaluated; only real creations/overwrites can carry new content.
	if c.fileAutoResp != nil && (action == "created" || action == "overwritten") {
		base := make(map[string]interface{}, len(data))
		for k, v := range data {
			base[k] = v
		}
		base["action"] = ""
		if alt, stop := c.fileAutoResp.EvaluateAndAct(context.Background(), filePath, fileIoCreate, pid, base); stop {
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

	if fileDedup.IsDuplicate(lower + "|" + action) {
		return
	}
	severity := event.SeverityLow
	if action == "deleted" {
		severity = event.SeverityMedium
	}
	evt := event.NewEvent(event.EventTypeFile, severity, data)
	if c.filter != nil && c.filter.ShouldFilter(evt) {
		return
	}
	c.send(evt)
	c.fileEvents.Add(1)
}

// riskyExtensions are file types attackers drop and run. Their creation is
// reported even in high-churn locations such as Temp.
var riskyExtensions = map[string]bool{
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".com": true, ".cpl": true,
	".ps1": true, ".psm1": true, ".bat": true, ".cmd": true, ".vbs": true, ".vbe": true,
	".js": true, ".jse": true, ".wsf": true, ".wsh": true, ".hta": true, ".lnk": true,
	".msi": true, ".msp": true, ".jar": true, ".iso": true, ".img": true, ".vhd": true,
	".vhdx": true, ".url": true, ".chm": true, ".xll": true, ".appx": true, ".msix": true,
}

// isNoisyFilePath filters high-volume, low-value file paths. Temp
// directories are filtered EXCEPT for executable/script content, the classic
// drop-and-run pattern.
func isNoisyFilePath(lower string) bool {
	ext := filepath.Ext(lower)
	if isTempPath(lower) && !riskyExtensions[ext] {
		return true
	}
	if isTempPath(lower) {
		return false
	}
	return isNoisyNonTempPath(lower)
}

func isTempPath(lower string) bool {
	return strings.Contains(lower, `\windows\temp\`) || strings.Contains(lower, `\appdata\local\temp\`)
}

// isNoisyNonTempPath filters out high-volume, low-value file I/O noise.
// This is critical for performance — kernel file I/O generates thousands
// of events per second from OS services, antivirus, indexing, etc.
//
// These are hard-coded because they represent immutable OS behavior —
// no real-world attack depends on writing to these paths/extensions.
// The configurable ExcludePaths list in FilterConfig handles user-defined
// exclusions and is checked after event creation in the filter pipeline.
func isNoisyNonTempPath(lower string) bool {
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
		`\windows\prefetch`,
		`\windows\servicing`,
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
