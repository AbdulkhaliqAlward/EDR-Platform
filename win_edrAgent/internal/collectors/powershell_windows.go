//go:build windows
// +build windows

package collectors

// PowerShell telemetry (Script Block Logging, EventID 4104; Module Logging,
// EventID 4103).
//
// Commands typed into an interactive PowerShell, or run by a script, execute
// inside the existing powershell.exe process — no new process is created, so
// process-creation telemetry can never show them. Windows records them in the
// "Microsoft-Windows-PowerShell/Operational" log (and "PowerShellCore/
// Operational" for PowerShell 7) once Script Block Logging is enabled by
// policy (CIS Benchmark recommendation). This collector:
//   - enables Script Block Logging by policy when it is not configured (and
//     records that it did, so uninstall restores the original state);
//   - subscribes to those logs with a persisted bookmark (events written
//     while the agent was stopped are read on restart, none twice);
//   - emits event_type "powershell" (action "script_block" / "module"), which
//     the detection engine maps to the Sigma ps_script / ps_module rules.

import (
	"context"
	"crypto/sha1"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
	"github.com/edr-platform/win-agent/internal/pslogging"
)

const (
	psChannelWindows = "Microsoft-Windows-PowerShell/Operational"
	psChannelCore    = "PowerShellCore/Operational"
	psQuery          = "*[System[(EventID=4104 or EventID=4103)]]"

	// maxScriptBlockChars bounds one event (PowerShell already splits large
	// scripts into parts, MessageNumber/MessageTotal).
	maxScriptBlockChars = 512 * 1024
	psDedupWindow       = time.Minute
	psBatch             = 64
)

var (
	modWevtapi            = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe      = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext           = modWevtapi.NewProc("EvtNext")
	procEvtRender         = modWevtapi.NewProc("EvtRender")
	procEvtClose          = modWevtapi.NewProc("EvtClose")
	procEvtCreateBookmark = modWevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = modWevtapi.NewProc("EvtUpdateBookmark")
)

const (
	evtSubscribeToFutureEvents     = 1
	evtSubscribeStartAfterBookmark = 3
	evtRenderEventXML              = 1
	evtRenderBookmark              = 2
	errNoMoreItems                 = windows.Errno(259)
	errInsufficientBuffer          = windows.Errno(122)
	errEvtChannelNotFound          = windows.Errno(15007)
)

// PowerShellCollector reads PowerShell script-block and module events.
type PowerShellCollector struct {
	eventChan    chan<- *event.Event
	logger       *logging.Logger
	stateDir     string
	enablePolicy bool

	running   atomic.Bool
	collected atomic.Uint64
	dropped   atomic.Uint64

	dedupMu    sync.Mutex
	dedup      map[[20]byte]time.Time
	assemblyMu sync.Mutex
	assemblies map[string]*scriptAssembly
}

// NewPowerShellCollector creates the collector. enablePolicy turns on Script
// Block Logging by policy when the host has not configured it.
func NewPowerShellCollector(ch chan<- *event.Event, l *logging.Logger, stateDir string, enablePolicy bool) *PowerShellCollector {
	if stateDir == "" {
		stateDir = `C:\ProgramData\EDR\state`
	}
	return &PowerShellCollector{eventChan: ch, logger: l, stateDir: stateDir, enablePolicy: enablePolicy,
		dedup: map[[20]byte]time.Time{}}
}

// Dropped returns events lost because the pipeline was full.
func (c *PowerShellCollector) Dropped() uint64 { return c.dropped.Load() }

// IsRunning reports whether at least one subscription is active.
func (c *PowerShellCollector) IsRunning() bool { return c.running.Load() }

// Start enables logging (if allowed) and subscribes to the PowerShell logs.
func (c *PowerShellCollector) Start(ctx context.Context) error {
	if err := procEvtSubscribe.Find(); err != nil {
		return fmt.Errorf("wevtapi unavailable: %w", err)
	}
	if c.enablePolicy {
		for _, key := range pslogging.PolicyKeys {
			changed, err := pslogging.EnsureScriptBlockLogging(key)
			if err != nil {
				c.logger.Warnf("[PowerShell] Could not enable Script Block Logging (%s): %v", key, err)
			} else if changed {
				c.logger.Infof("[PowerShell] Script Block Logging enabled by policy (%s)", key)
			}
		}
	}
	_ = os.MkdirAll(c.stateDir, 0o700)
	started := 0
	for _, ch := range []string{psChannelWindows, psChannelCore} {
		sub, err := c.subscribe(ch)
		if err != nil {
			if ch == psChannelCore && err == errEvtChannelNotFound {
				continue // PowerShell 7 not installed
			}
			c.logger.Warnf("[PowerShell] Subscription to %s failed: %v", ch, err)
			continue
		}
		started++
		go c.loop(ctx, ch, sub)
	}
	if started == 0 {
		return fmt.Errorf("no PowerShell event log could be subscribed")
	}
	c.running.Store(true)
	go c.sweepDedup(ctx)
	return nil
}

type psSubscription struct {
	handle   windows.Handle
	signal   windows.Handle
	bookmark windows.Handle
}

func (c *PowerShellCollector) bookmarkPath(channel string) string {
	name := strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(channel)
	return filepath.Join(c.stateDir, "evt_bookmark_"+name+".xml")
}

func (c *PowerShellCollector) subscribe(channel string) (*psSubscription, error) {
	signal, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	sub := &psSubscription{signal: signal}
	chPtr, _ := windows.UTF16PtrFromString(channel)
	qPtr, _ := windows.UTF16PtrFromString(psQuery)

	flags := uintptr(evtSubscribeToFutureEvents)
	var bm uintptr
	if data, rerr := os.ReadFile(c.bookmarkPath(channel)); rerr == nil && len(data) > 0 {
		if xmlPtr, perr := windows.UTF16PtrFromString(string(data)); perr == nil {
			if h, _, _ := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(xmlPtr))); h != 0 {
				bm = h
				flags = evtSubscribeStartAfterBookmark
			}
		}
	}
	if bm == 0 {
		h, _, _ := procEvtCreateBookmark.Call(0)
		bm = h
	}
	sub.bookmark = windows.Handle(bm)

	h, _, callErr := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(chPtr)), uintptr(unsafe.Pointer(qPtr)),
		bm*boolToUintptr(flags == evtSubscribeStartAfterBookmark), 0, 0, flags)
	if h == 0 && flags == evtSubscribeStartAfterBookmark {
		// Stale/invalid bookmark (log cleared): start from now.
		h, _, callErr = procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(chPtr)), uintptr(unsafe.Pointer(qPtr)),
			0, 0, 0, evtSubscribeToFutureEvents)
	}
	if h == 0 {
		windows.CloseHandle(signal)
		if bm != 0 {
			procEvtClose.Call(bm)
		}
		if e, ok := callErr.(windows.Errno); ok {
			return nil, e
		}
		return nil, callErr
	}
	sub.handle = windows.Handle(h)
	return sub, nil
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func (c *PowerShellCollector) loop(ctx context.Context, channel string, sub *psSubscription) {
	defer func() {
		c.saveBookmark(channel, sub.bookmark)
		procEvtClose.Call(uintptr(sub.handle))
		procEvtClose.Call(uintptr(sub.bookmark))
		windows.CloseHandle(sub.signal)
	}()
	c.logger.Infof("[PowerShell] Collecting script-block/module events from %s", channel)
	lastSave := time.Now()
	handles := make([]windows.Handle, psBatch)
	for ctx.Err() == nil {
		ev, _ := windows.WaitForSingleObject(sub.signal, 1000)
		if ev != windows.WAIT_OBJECT_0 && ev != uint32(windows.WAIT_TIMEOUT) {
			time.Sleep(time.Second)
		}
		for ctx.Err() == nil {
			var returned uint32
			r, _, err := procEvtNext.Call(uintptr(sub.handle), psBatch, uintptr(unsafe.Pointer(&handles[0])), 0, 0, uintptr(unsafe.Pointer(&returned)))
			if r == 0 {
				if err != errNoMoreItems {
					c.logger.Debugf("[PowerShell] EvtNext: %v", err)
				}
				break
			}
			for i := uint32(0); i < returned; i++ {
				h := handles[i]
				if xmlText, rerr := renderXML(h, evtRenderEventXML); rerr == nil {
					c.handle(channel, xmlText)
				}
				procEvtUpdateBookmark.Call(uintptr(sub.bookmark), uintptr(h))
				procEvtClose.Call(uintptr(h))
			}
		}
		if time.Since(lastSave) > 10*time.Second {
			c.saveBookmark(channel, sub.bookmark)
			lastSave = time.Now()
		}
	}
}

func (c *PowerShellCollector) saveBookmark(channel string, bm windows.Handle) {
	if bm == 0 {
		return
	}
	text, err := renderXML(bm, evtRenderBookmark)
	if err != nil || text == "" {
		return
	}
	tmp := c.bookmarkPath(channel) + ".tmp"
	if os.WriteFile(tmp, []byte(text), 0o600) == nil {
		_ = os.Rename(tmp, c.bookmarkPath(channel))
	}
}

// renderXML renders an event or bookmark handle as XML.
func renderXML(h windows.Handle, flags uintptr) (string, error) {
	var used, props uint32
	buf := make([]uint16, 4096)
	for attempt := 0; attempt < 2; attempt++ {
		r, _, err := procEvtRender.Call(0, uintptr(h), flags, uintptr(len(buf)*2),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString(buf), nil
		}
		if err != errInsufficientBuffer || used == 0 || used > 16<<20 {
			return "", err
		}
		buf = make([]uint16, used/2+1)
	}
	return "", fmt.Errorf("EvtRender: buffer too small")
}

// ── XML → event ──────────────────────────────────────────────────────────────

type psEventXML struct {
	System struct {
		EventID     int `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Execution struct {
			ProcessID uint32 `xml:"ProcessID,attr"`
		} `xml:"Execution"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func (c *PowerShellCollector) handle(channel, text string) {
	var x psEventXML
	if err := xml.Unmarshal([]byte(text), &x); err != nil {
		return
	}
	fields := map[string]string{}
	for _, d := range x.EventData.Data {
		fields[d.Name] = d.Value
	}
	pid := x.System.Execution.ProcessID
	var eventAt time.Time
	if t, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime); err == nil {
		eventAt = t.UTC()
	}
	if isSelfPID(pid) {
		return // the agent's own PowerShell helpers
	}

	data := map[string]interface{}{
		"channel":    channel,
		"event_code": x.System.EventID,
		"pid":        pid,
		"user_sid":   x.System.Security.UserID,
	}
	var body string
	switch x.System.EventID {
	case 4104:
		body = fields["ScriptBlockText"]
		var complete bool
		body, complete = c.assembleScript(channel, pid, fields["ScriptBlockId"], atoiOr(fields["MessageNumber"], 1), atoiOr(fields["MessageTotal"], 1), body)
		data["script_block_complete"] = complete
		if complete && atoiOr(fields["MessageTotal"], 1) > 1 {
			data["reassembled"] = true
		}
		data["action"] = "script_block"
		data["script_block_id"] = fields["ScriptBlockId"]
		data["script_path"] = fields["Path"]
		data["message_number"] = atoiOr(fields["MessageNumber"], 1)
		data["message_total"] = atoiOr(fields["MessageTotal"], 1)
		if len(body) > maxScriptBlockChars {
			body = body[:maxScriptBlockChars]
			data["truncated"] = true
		}
		data["script_block_text"] = body
	case 4103:
		body = fields["Payload"]
		data["action"] = "module"
		if len(body) > maxScriptBlockChars {
			body = body[:maxScriptBlockChars]
			data["truncated"] = true
		}
		data["payload"] = body
		data["context_info"] = fields["ContextInfo"]
	default:
		return
	}
	if strings.TrimSpace(body) == "" || c.isDuplicate(pid, x.System.EventID, body, fields["MessageNumber"]) {
		return
	}
	// Replayed records must not be enriched with a newer owner of the PID.
	if started := processCreateTime(pid); !started.IsZero() && !eventAt.IsZero() && !started.After(eventAt) {
		if img := getImagePath(pid); img != "" && processCreateTime(pid).Equal(started) {
			data["executable"] = img
			data["process_name"] = baseName(img)
			data["process_start_time"] = started.UTC().Format(time.RFC3339Nano)
		}
	}
	if !eventAt.IsZero() {
		data["event_time"] = eventAt.Format(time.RFC3339Nano)
	}

	evt := event.NewEvent(event.EventTypePowerShell, event.SeverityLow, data)
	if !eventAt.IsZero() {
		evt.Timestamp = eventAt
	}
	select {
	case c.eventChan <- evt:
		c.collected.Add(1)
	case <-time.After(2 * time.Second):
		c.dropped.Add(1)
	}
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// isDuplicate drops an identical block from the same process within a
// minute (e.g. a module re-imported in a loop).
func (c *PowerShellCollector) isDuplicate(pid uint32, id int, body, part string) bool {
	key := sha1.Sum([]byte(fmt.Sprintf("%d|%d|%s|%s", pid, id, part, body)))
	now := time.Now()
	c.dedupMu.Lock()
	defer c.dedupMu.Unlock()
	if t, ok := c.dedup[key]; ok && now.Sub(t) < psDedupWindow {
		return true
	}
	c.dedup[key] = now
	return false
}

func (c *PowerShellCollector) sweepDedup(ctx context.Context) {
	t := time.NewTicker(psDedupWindow)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.dedupMu.Lock()
			for k, v := range c.dedup {
				if now.Sub(v) > psDedupWindow {
					delete(c.dedup, k)
				}
			}
			c.dedupMu.Unlock()
		}
	}
}
