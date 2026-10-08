// Package collectors — DLL / Image Load event handler for the ETW kernel tracer.
//
// Handles Image Load events delivered real-time from the Windows Kernel
// ETW session (EVENT_TRACE_FLAG_IMAGE_LOAD). Every event fires the instant
// a DLL/EXE is mapped into a process address space, with the exact PID and
// full image path. This catches reflective DLL injection and side-loading
// that a polling approach would miss entirely.
//
// MITRE coverage: T1055 (Process Injection), T1574 (Hijack Execution
// Flow / DLL Side-Loading), T1129 (Shared Modules).
//
// OPTIMIZATION (Phase 2 W-8): SHA256 hashing is now asynchronous.
// Events are emitted IMMEDIATELY without waiting for the hash.
// A background worker pool computes hashes and enriches events
// after the fact. This prevents blocking the ETW callback goroutine
// for files up to 50MB.
//
//go:build windows
// +build windows

package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
)

// =====================================================================
// Async Hash Worker Pool
// =====================================================================

// hashRequest represents a file that needs its SHA256 computed.
type hashRequest struct {
	filePath string
	evt      *event.Event // Event to enrich with the hash
}

// hashWorkerPool manages background hash computation workers.
type hashWorkerPool struct {
	queue   chan hashRequest
	wg      sync.WaitGroup
	running atomic.Bool
	logger  *logging.Logger

	// Metrics
	completed atomic.Uint64
	skipped   atomic.Uint64
}

// newHashWorkerPool creates a pool of hash workers.
// workerCount controls parallelism (2 is optimal — matches typical SSD I/O depth).
// queueSize controls backpressure (when full, hashing is skipped).
func newHashWorkerPool(workerCount, queueSize int, logger *logging.Logger) *hashWorkerPool {
	p := &hashWorkerPool{
		queue:  make(chan hashRequest, queueSize),
		logger: logger,
	}
	p.running.Store(true)

	for i := 0; i < workerCount; i++ {
		p.wg.Add(1)
		go p.worker()
	}

	if logger != nil {
		logger.Infof("[IMAGELOAD] Hash worker pool started: workers=%d queue=%d", workerCount, queueSize)
	}
	return p
}

// submit enqueues a hash request. Returns false if the queue is full (hash skipped).
func (p *hashWorkerPool) submit(req hashRequest) bool {
	select {
	case p.queue <- req:
		return true
	default:
		p.skipped.Add(1)
		return false
	}
}

// stop shuts down the worker pool gracefully.
func (p *hashWorkerPool) stop() {
	p.running.Store(false)
	close(p.queue)
	p.wg.Wait()
}

// worker processes hash requests from the queue.
func (p *hashWorkerPool) worker() {
	defer p.wg.Done()
	for req := range p.queue {
		if !p.running.Load() {
			return
		}
		hash := computeFileHash(req.filePath)
		if hash != "" {
			// Enrich the event with the computed hash.
			// This is safe because the event has already been sent to the pipeline
			// and this field is only used for Sigma rule matching and later enrichment.
			req.evt.Data["hash_sha256"] = hash
			// Also set in Sigma-compatible format
			req.evt.Data["Hashes"] = "SHA256=" + hash
		}
		p.completed.Add(1)
	}
}

// =====================================================================
// Global hash pool (initialized by ETW collector)
// =====================================================================

var (
	globalHashPool     *hashWorkerPool
	globalHashPoolOnce sync.Once
)

// initHashPool initializes the global hash worker pool (once).
func initHashPool(logger *logging.Logger) {
	globalHashPoolOnce.Do(func() {
		// 2 workers, 256 queue depth — keeps I/O impact low
		globalHashPool = newHashWorkerPool(2, 256, logger)
	})
}

// =====================================================================
// Image Load Handler
// =====================================================================

// handleImageLoad processes a single image/DLL load event from the kernel
// ETW callback. This fires in real-time the instant a module is mapped —
// there is zero polling window for malware to exploit.
//
// OPTIMIZATION: Hashing is NON-BLOCKING. The event is sent immediately
// with hash_sha256="" and a background worker enriches it asynchronously.
func (c *ETWCollector) handleImageLoad(pid uint32, imagePath string) {
	lower := strings.ToLower(imagePath)

	// --- Noise filter: skip core OS DLLs that load in every process ---
	if isNoisyModule(lower) {
		return
	}

	// --- Microsoft-signed System32 fast-path ---
	// A System32 DLL whose Authenticode signature (embedded or catalog)
	// verifies to Microsoft is a stock OS module: skip it. This is the
	// biggest volume reducer for image-load telemetry. Presence of a
	// signature blob alone is NOT trusted (it can be forged/appended).
	if strings.Contains(lower, `\windows\system32\`) && FileIdentityOf(imagePath).SignatureStatus == "microsoft" {
		return
	}

	modName := baseName(imagePath)

	// Enrich: process that loaded this module.
	procPath := getImagePath(pid)
	procName := baseName(procPath)
	if procName == "" {
		procName = "unknown"
	}

	// Self-exclusion: ignore image loads inside the agent itself or any
	// helper process it spawned. Without this gate, the agent generates a
	// burst of DLL-load events on every PowerShell helper invocation.
	if isSelfPID(pid) {
		return
	}

	// Verified Authenticode status (cached per file version).
	sig := FileIdentityOf(imagePath).SignatureStatus
	isSigned := sig == "microsoft" || sig == "trusted"

	// Create event IMMEDIATELY — no blocking on hash computation.
	evt := event.NewEvent(event.EventTypeImageLoad, event.SeverityMedium, map[string]interface{}{
		"action":       "loaded",
		"path":         imagePath,
		"name":         modName,
		"hash_sha256":  "", // Will be enriched asynchronously by hash worker
		"pid":          pid,
		"process_name": procName,
		"process_path": procPath,
		"is_signed":    isSigned,
		// Sigma-compatible fields
		"ImageLoaded": imagePath,
		"Image":       procPath,
		"Signed":      isSigned,
	})

	// Apply configurable filter.
	if c.filter != nil && c.filter.ShouldFilter(evt) {
		return
	}

	c.send(evt)
	c.imageLoadEvents.Add(1)

	// Submit hash computation to background worker pool.
	// The event is already in the pipeline — the worker will enrich it
	// asynchronously. If the queue is full, hashing is simply skipped
	// (the event still has all other fields for detection).
	initHashPool(c.logger)
	globalHashPool.submit(hashRequest{
		filePath: imagePath,
		evt:      evt,
	})
}

// isNoisyModule filters out very common OS modules that load in every process.
// These generate enormous volume with zero security signal.
//
// This list covers the Windows loader chain (ntdll → kernel32 → kernelbase),
// the C runtime, COM infrastructure, GDI/USER32, cryptography, networking,
// and other modules that are mapped into virtually every process. Total: ~45.
func isNoisyModule(lower string) bool {
	noisyExact := []string{
		// Core loader chain
		`\windows\system32\ntdll.dll`,
		`\windows\system32\kernel32.dll`,
		`\windows\system32\kernelbase.dll`,

		// C Runtime
		`\windows\system32\msvcrt.dll`,
		`\windows\system32\ucrtbase.dll`,
		`\windows\system32\msvcp_win.dll`,
		`\windows\system32\vcruntime140.dll`,

		// Security / Auth
		`\windows\system32\advapi32.dll`,
		`\windows\system32\sechost.dll`,
		`\windows\system32\sspicli.dll`,
		`\windows\system32\bcrypt.dll`,
		`\windows\system32\bcryptprimitives.dll`,
		`\windows\system32\crypt32.dll`,
		`\windows\system32\wintrust.dll`,

		// RPC / COM
		`\windows\system32\rpcrt4.dll`,
		`\windows\system32\combase.dll`,
		`\windows\system32\ole32.dll`,
		`\windows\system32\oleaut32.dll`,

		// Graphics / UI
		`\windows\system32\user32.dll`,
		`\windows\system32\gdi32.dll`,
		`\windows\system32\gdi32full.dll`,
		`\windows\system32\win32u.dll`,
		`\windows\system32\uxtheme.dll`,
		`\windows\system32\imm32.dll`,
		`\windows\system32\msctf.dll`,

		// Shell
		`\windows\system32\shell32.dll`,
		`\windows\system32\shlwapi.dll`,
		`\windows\system32\clbcatq.dll`,
		`\windows\system32\propsys.dll`,

		// Networking
		`\windows\system32\ws2_32.dll`,
		`\windows\system32\wininet.dll`,
		`\windows\system32\nsi.dll`,

		// Device / Power / Setup
		`\windows\system32\cfgmgr32.dll`,
		`\windows\system32\devobj.dll`,
		`\windows\system32\powrprof.dll`,
		`\windows\system32\setupapi.dll`,
		`\windows\system32\wldp.dll`,

		// Profiling / Version
		`\windows\system32\profapi.dll`,
		`\windows\system32\version.dll`,
		`\windows\system32\cabinet.dll`,

		// Additional Networking
		`\windows\system32\iphlpapi.dll`,
		`\windows\system32\dnsapi.dll`,
		`\windows\system32\mswsock.dll`,
		`\windows\system32\winhttp.dll`,

		// UI / Shell / WinRT (top offenders in telemetry data)
		`\windows\system32\wintypes.dll`,
		`\windows\system32\kernel.appcore.dll`,
		`\windows\system32\shcore.dll`,
		`\windows\system32\coremessaging.dll`,
		`\windows\system32\coreuicomponents.dll`,
		`\windows\system32\textinputframework.dll`,
		`\windows\system32\dwmapi.dll`,
		`\windows\system32\ntmarta.dll`,
		`\windows\system32\atl.dll`,
		`\windows\system32\mscoree.dll`,
		`\windows\system32\mscoreei.dll`,

		// .NET CLR / Framework (loaded by every .NET process)
		`\windows\system32\ucrtbase_clr0400.dll`,
		`\windows\system32\vcruntime140_clr0400.dll`,
	}
	for _, n := range noisyExact {
		if strings.HasSuffix(lower, n) {
			return true
		}
	}
	return false
}

// computeFileHash computes SHA256 of a file (best-effort, returns "" on error).
// Skips files > 50 MB to prevent performance impact on the agent.
func computeFileHash(path string) string {
	info, err := os.Stat(path)
	if err != nil || info.Size() > 50*1024*1024 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
