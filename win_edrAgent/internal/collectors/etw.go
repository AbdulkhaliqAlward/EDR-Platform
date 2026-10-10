// Package collectors — ETW kernel process tracer.
//go:build windows
// +build windows

package collectors

/*
#cgo LDFLAGS: -ltdh -ladvapi32

#include "etw_cgo.h"
*/
import "C"

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/edr-platform/win-agent/internal/processlineage"
	"golang.org/x/sys/windows"
)

// Unused GUID kept for session compat parameter.
var kernelProcessGUID = C.GUID{
	Data1: 0x22FB2CD6, Data2: 0x0FE7, Data3: 0x4212,
	Data4: [8]C.uchar{0xA2, 0x96, 0x1F, 0x7F, 0x7D, 0x3B, 0x40, 0x0C},
}

func (c *ETWCollector) session_(ctx context.Context) error {
	ctx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()
	name16, err := windows.UTF16FromString(c.session)
	if err != nil {
		return err
	}
	np := (*C.wchar_t)(unsafe.Pointer(&name16[0]))
	C.KillNamedSession(np)
	time.Sleep(200 * time.Millisecond)

	ret := C.StartKernelProcessSession(np, &kernelProcessGUID, 0xFF, 0x10)
	if ret != 0 {
		c.errors.Add(1)
		return fmt.Errorf("StartKernelProcessSession: error %d", ret)
	}
	c.logger.Info("[ETW] Session ACTIVE — SYSTEM_LOGGER_MODE + EnableFlags=PROCESS|IMAGE_LOAD|FILE_IO_INIT")
	processlineage.Default.BeginCoverage(time.Now())

	var diag atomic.Uint64
	globalDiag.Store(&diag)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		c.logger.Infof("[ETW] Diagnostic: %d events in first 5s", diag.Load())
	}()

	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		<-ctx.Done()
		C.StopKernelSession(&kernelProcessGUID)
	}()
	defer func() { sessionCancel(); <-stopDone }()

	ret = C.ProcessKernelEvents(np, nil)
	if ret != 0 && ctx.Err() != nil {
		return nil
	}
	if ret != 0 {
		return fmt.Errorf("ProcessKernelEvents: error %d", ret)
	}
	return nil
}

// =====================================================================
// C → Go callbacks (no goroutines here: jobs go to bounded worker pools)
// =====================================================================

var globalDiag atomic.Pointer[atomic.Uint64]

//export goProcessEvent
func goProcessEvent(evt *C.ParsedProcessEvent) {
	collector := globalCollector.Load()
	if collector == nil {
		return
	}

	pid := uint32(evt.processId)
	ppid := uint32(evt.parentId)
	opcode := uint8(evt.opcode)

	// Convert C strings to Go strings (copies — safe after the callback)
	imageName := C.GoString(&evt.imageFileName[0])
	cmdLine := wcharToGo(&evt.commandLine[0], 4096)

	// Diagnostic
	if d := globalDiag.Load(); d != nil {
		n := d.Add(1)
		if n <= 20 {
			collector.logger.Infof("[ETW-DBG] #%d Op=%d PID=%d Img=%s Cmd=%s",
				n, opcode, pid, imageName, truncStr(cmdLine, 60))
		}
	}

	ft := uint64(evt.eventTime)
	eventTime := time.Unix(0, (&windows.Filetime{LowDateTime: uint32(ft), HighDateTime: uint32(ft >> 32)}).Nanoseconds()).UTC()
	if ft == 0 {
		processlineage.Default.Gap(time.Now())
		eventTime = time.Now()
	}
	collector.enqueueProcess(procJob{start: opcode == 1, pid: pid, ppid: ppid, img: imageName, cmd: cmdLine, at: eventTime})
}

//export goImageLoadEvent
func goImageLoadEvent(evt *C.ParsedImageLoadEvent) {
	collector := globalCollector.Load()
	if collector == nil || !collector.imageLoadEnabled {
		return
	}

	pid := uint32(evt.processId)
	opcode := uint8(evt.opcode)
	imagePath := wcharToGo(&evt.imagePath[0], 1024)

	// Only care about loads (opcode 10), not unloads.
	if imagePath == "" || opcode != 10 {
		return
	}

	collector.enqueueAsync(func() { collector.handleImageLoad(pid, imagePath) })
}

//export goFileIoEvent
func goFileIoEvent(evt *C.ParsedFileIoEvent) {
	collector := globalCollector.Load()
	if collector == nil || !collector.fileEnabled {
		return
	}

	op := fileIoOp{
		pid:           uint32(evt.processId),
		opcode:        uint8(evt.opcode),
		createOptions: uint32(evt.createOptions),
		fileObject:    uint64(evt.fileObject),
		ttid:          uint64(evt.ttid),
		at:            time.Now(),
	}
	if p := wcharToGo(&evt.filePath[0], 1024); p != "" {
		// ETW kernel events report paths in device namespace:
		// \Device\HarddiskVolume3\Users\foo\file.txt → C:\Users\foo\file.txt
		op.path = kernelPathToWin32(p)
	} else if op.opcode == fileIoCreate {
		return
	}

	collector.enqueueAsync(func() { collector.handleFileIo(op) })
}

// kernelPathToWin32 converts a kernel device path to a Win32 drive-letter path.
// ETW FileIo events use NT device paths; os.Stat/os.Rename require Win32 paths.
//
// The device map is refreshed every 60 seconds via a background goroutine so
// that volumes mounted AFTER agent startup (e.g. OneDrive Known Folder Move,
// network drives, USB insertions) are always covered. Using sync.Once caused
// Desktop paths to fail conversion when the OneDrive volume appeared after
// the initial snapshot, returning the raw \Device\HarddiskVolumeN path which
// did NOT match monitoredPath() → responder was silently skipped for Desktop.
var (
	devMapMu   sync.RWMutex
	devMap     map[string]string // lowercase \device\harddiskvolumen → "C:"
	devMapInit sync.Once         // ensures the refresh goroutine starts exactly once
)

// startDevMapRefresher starts a goroutine that refreshes the device map
// immediately and then every 60 seconds. Must be called once.
func startDevMapRefresher() {
	devMapInit.Do(func() {
		refreshDevMap() // populate synchronously before first use
		go func() {
			ticker := time.NewTicker(60 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				refreshDevMap()
			}
		}()
	})
}

func refreshDevMap() {
	m := make(map[string]string, 26)
	var buf [512]uint16
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		drivePtr, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		n, err := windows.QueryDosDevice(drivePtr, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		dev := windows.UTF16ToString(buf[:n])
		if dev != "" {
			m[strings.ToLower(dev)] = drive
		}
	}
	devMapMu.Lock()
	devMap = m
	devMapMu.Unlock()
}

func kernelPathToWin32(p string) string {
	low := strings.ToLower(p)

	// Already a Win32 path (e.g. "C:\...")
	if len(p) >= 3 && p[1] == ':' {
		return p
	}

	// NT global-root prefix \??\C:\... or \\?\\C:\...
	if strings.HasPrefix(low, `\??\`) && len(p) > 4 {
		rest := p[4:]
		if len(rest) >= 3 && rest[1] == ':' {
			return rest
		}
	}
	if strings.HasPrefix(low, `\\?\`) && len(p) > 4 {
		rest := p[4:]
		if len(rest) >= 3 && rest[1] == ':' {
			return rest
		}
	}

	// Kernel device path \Device\HarddiskVolumeN\...
	if !strings.HasPrefix(low, `\device\`) {
		return p // UNC or unknown — return as-is
	}

	// Ensure the map is populated (and the refresh goroutine is running).
	startDevMapRefresher()

	devMapMu.RLock()
	m := devMap
	devMapMu.RUnlock()
	for dev, drive := range m {
		if strings.HasPrefix(low, dev) {
			return drive + p[len(dev):]
		}
	}
	// Fallback: volume not yet in map — trigger an immediate refresh and retry.
	refreshDevMap()
	devMapMu.RLock()
	m = devMap
	devMapMu.RUnlock()
	for dev, drive := range m {
		if strings.HasPrefix(low, dev) {
			return drive + p[len(dev):]
		}
	}
	return p // still unmapped — return kernel path unchanged
}

func wcharToGo(p *C.WCHAR, max int) string {
	if p == nil || max <= 0 {
		return ""
	}
	// The callback supplies a fixed C buffer of this size. Keep its pointer
	// intact while copying; uintptr arithmetic cannot retain pointer lifetime.
	return windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(p)), max))
}
