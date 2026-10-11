//go:build windows
// +build windows

package collectors

// Windows Event Log forwarding (Security, System, Defender and a few
// operational channels).
//
// ETW gives the agent process/file/registry/network telemetry, but many
// detections only exist as Windows Event Log records: service installation
// (System 7045), account and group changes (Security 4720/4732…), scheduled
// task registration (4698), audit log clearing (1102), Defender detections and
// configuration changes (1116, 5001, 5007…). SigmaHQ's service rules
// (logsource service: security / system / windefend / …) are written against
// those records. This collector subscribes to an explicit list of event IDs —
// the IDs the shipped rules reference — and forwards each record as
// event_type "eventlog" with:
//   - channel, provider_name, EventID/event_code, record_id, computer
//   - every EventData/UserData field under its original Windows name
//     (TargetUserName, ServiceName, ImagePath, …), which is how Sigma names them.
// The engine derives the Sigma service from the channel.
//
// Volume is bounded by design: only listed IDs are read (high-volume IDs that
// the agent already covers through ETW, such as 4688/5156/DNS 3008, are not),
// 4624 is limited to the logon types the rules use, every channel has a token
// bucket, and values/field counts are capped. Each subscription keeps a
// persisted bookmark so records written while the agent was down are read
// once on restart.

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
)

const (
	eventLogMaxValue  = 8 * 1024 // per field
	eventLogMaxFields = 128
	eventLogIDsPerSub = 15 // keep each XPath small; Windows rejects very long OR chains
)

// EventLogChannel is one forwarded channel: the IDs to read and its rate limit.
type EventLogChannel struct {
	Channel string
	IDs     []int
	// Extra are complete XPath queries for records that need an EventData
	// filter (e.g. 4624 restricted to logon types).
	Extra      []string
	RatePerSec float64
	Burst      float64
}

// DefaultEventLogChannels lists the records the shipped Sigma service rules
// use. High-volume records with no rules, or already covered by ETW
// telemetry, are deliberately absent.
var DefaultEventLogChannels = []EventLogChannel{
	{Channel: "Security", RatePerSec: 50, Burst: 500, IDs: []int{
		// services, tasks, accounts, groups, policy, log clearing
		4697, 4698, 4699, 4700, 4701, 4702, 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4765, 4766,
		4767, 4781, 4794, 4728, 4729, 4732, 4733, 4756, 4757, 4719, 4704, 4706, 4692, 4649, 4611,
		4825, 4898, 4899, 4742, 5136, 1102,
		// credential use / failed logons / explicit credentials / NTLM validation
		4625, 4648, 4776, 5379,
		// object and share access (only produced where auditing/SACLs are enabled)
		4656, 4657, 4658, 4661, 4662, 4663, 5145,
		// firewall/WFP policy changes
		5441, 5447, 5449,
	}, Extra: []string{
		// Runas /netonly (9) and remote interactive (10) logons only.
		"*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']=9 or Data[@Name='LogonType']=10]]",
	}},
	{Channel: "System", RatePerSec: 20, Burst: 200, IDs: []int{
		7045, 7040, 7023, 7034, 104, 16, 26, 39, 41, 55, 1031, 1032, 1033, 1034, 5723, 5805, 5829, 6038, 6039, 10001,
	}},
	{Channel: "Microsoft-Windows-Windows Defender/Operational", RatePerSec: 20, Burst: 200, IDs: []int{
		1006, 1007, 1008, 1009, 1015, 1116, 1117, 1118, 1119, 1121, 1122, 3002, 3007,
		5001, 5004, 5007, 5010, 5012, 5013, 5101,
	}},
	{Channel: "Microsoft-Windows-TaskScheduler/Operational", RatePerSec: 10, Burst: 100, IDs: []int{106, 129, 140, 141}},
	{Channel: "Microsoft-Windows-Bits-Client/Operational", RatePerSec: 10, Burst: 100, IDs: []int{3, 59, 60, 16403}},
	{Channel: "Microsoft-Windows-WMI-Activity/Operational", RatePerSec: 10, Burst: 100, IDs: []int{5859, 5861}},
	{Channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", RatePerSec: 10, Burst: 100, IDs: []int{
		2004, 2005, 2006, 2033, 2052, 2059, 2071, 2097,
	}},
	{Channel: "Microsoft-Windows-CodeIntegrity/Operational", RatePerSec: 10, Burst: 100, IDs: []int{
		3001, 3021, 3022, 3023, 3032, 3035, 3036, 3037, 3077, 3082, 3083, 3104,
	}},
	{Channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", RatePerSec: 10, Burst: 100, IDs: []int{21, 24, 25}},
}

// highSeverityRecords are forwarded as high severity events (not rule
// verdicts; the detection engine still decides alerts).
var highSeverityRecords = map[string]map[int]bool{
	"security": {1102: true, 4719: true},
	"system":   {104: true},
	"microsoft-windows-windows defender/operational": {1006: true, 1015: true, 1116: true, 1117: true, 1119: true, 5001: true, 5010: true, 5012: true, 5013: true},
}

// EventLogQueries splits one channel's IDs into bounded XPath queries.
func EventLogQueries(ch EventLogChannel) []string {
	var out []string
	for start := 0; start < len(ch.IDs); start += eventLogIDsPerSub {
		end := min(start+eventLogIDsPerSub, len(ch.IDs))
		terms := make([]string, 0, end-start)
		for _, id := range ch.IDs[start:end] {
			terms = append(terms, "EventID="+strconv.Itoa(id))
		}
		out = append(out, "*[System[("+strings.Join(terms, " or ")+")]]")
	}
	return append(out, ch.Extra...)
}

// EventLogCollector forwards selected Windows Event Log records.
type EventLogCollector struct {
	eventChan chan<- *event.Event
	logger    *logging.Logger
	stateDir  string
	channels  []EventLogChannel

	running   atomic.Bool
	collected atomic.Uint64
	dropped   atomic.Uint64 // pipeline full or rate limited

	limitMu  sync.Mutex
	limiters map[string]*tokenBucket
}

// NewEventLogCollector creates the collector for the given channels
// (DefaultEventLogChannels when nil).
func NewEventLogCollector(ch chan<- *event.Event, l *logging.Logger, stateDir string, channels []EventLogChannel) *EventLogCollector {
	if stateDir == "" {
		stateDir = `C:\ProgramData\EDR\state`
	}
	if channels == nil {
		channels = DefaultEventLogChannels
	}
	c := &EventLogCollector{eventChan: ch, logger: l, stateDir: stateDir, channels: channels, limiters: map[string]*tokenBucket{}}
	now := time.Now()
	for _, cfg := range channels {
		c.limiters[strings.ToLower(cfg.Channel)] = &tokenBucket{tokens: cfg.Burst, maxTokens: cfg.Burst, refillRate: cfg.RatePerSec, lastRefill: now}
	}
	return c
}

// Dropped returns records not forwarded (rate limit or full pipeline).
func (c *EventLogCollector) Dropped() uint64 { return c.dropped.Load() }

// IsRunning reports whether at least one subscription is active.
func (c *EventLogCollector) IsRunning() bool { return c.running.Load() }

// Start subscribes to every configured channel. Missing optional channels
// (not installed / disabled) are skipped; Start fails only when nothing works.
func (c *EventLogCollector) Start(ctx context.Context) error {
	if err := procEvtSubscribe.Find(); err != nil {
		return fmt.Errorf("wevtapi unavailable: %w", err)
	}
	_ = os.MkdirAll(c.stateDir, 0o700)
	started := 0
	for _, ch := range c.channels {
		for i, q := range EventLogQueries(ch) {
			key := fmt.Sprintf("eventlog_%s_%d", ch.Channel, i)
			sub, err := subscribeChannel(ch.Channel, q, bookmarkFile(c.stateDir, key))
			if err != nil {
				if err == errEvtChannelNotFound {
					c.logger.Debugf("[EventLog] Channel %s not present; skipped", ch.Channel)
					break
				}
				c.logger.Warnf("[EventLog] Subscription to %s (query %d) failed: %v", ch.Channel, i, err)
				continue
			}
			started++
			go c.loop(ctx, ch.Channel, key, sub)
		}
	}
	if started == 0 {
		return fmt.Errorf("no Windows event log channel could be subscribed")
	}
	c.running.Store(true)
	c.logger.Infof("[EventLog] Forwarding %d subscriptions (Security/System/Defender and operational channels)", started)
	return nil
}

func bookmarkFile(stateDir, key string) string {
	name := strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(key)
	return stateDir + `\evt_bookmark_` + name + ".xml"
}

// subscribeChannel opens a pull subscription resuming after the saved bookmark.
func subscribeChannel(channel, query, bookmarkPath string) (*psSubscription, error) {
	signal, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	sub := &psSubscription{signal: signal}
	chPtr, _ := windows.UTF16PtrFromString(channel)
	qPtr, _ := windows.UTF16PtrFromString(query)
	flags := uintptr(evtSubscribeToFutureEvents)
	var bm uintptr
	if data, rerr := os.ReadFile(bookmarkPath); rerr == nil && len(data) > 0 {
		if xmlPtr, perr := windows.UTF16PtrFromString(string(data)); perr == nil {
			if h, _, _ := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(xmlPtr))); h != 0 {
				bm, flags = h, evtSubscribeStartAfterBookmark
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

func (c *EventLogCollector) loop(ctx context.Context, channel, key string, sub *psSubscription) {
	path := bookmarkFile(c.stateDir, key)
	defer func() {
		saveBookmarkFile(path, sub.bookmark)
		procEvtClose.Call(uintptr(sub.handle))
		procEvtClose.Call(uintptr(sub.bookmark))
		windows.CloseHandle(sub.signal)
	}()
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
					c.logger.Debugf("[EventLog] EvtNext %s: %v", channel, err)
				}
				break
			}
			for i := uint32(0); i < returned; i++ {
				h := handles[i]
				if text, rerr := renderXML(h, evtRenderEventXML); rerr == nil {
					if !c.forward(ctx, channel, text) {
						// Not handed off (shutdown): do not advance; replay on restart.
						for j := i; j < returned; j++ {
							procEvtClose.Call(uintptr(handles[j]))
						}
						return
					}
				}
				procEvtUpdateBookmark.Call(uintptr(sub.bookmark), uintptr(h))
				procEvtClose.Call(uintptr(h))
			}
		}
		if time.Since(lastSave) > 10*time.Second {
			saveBookmarkFile(path, sub.bookmark)
			lastSave = time.Now()
		}
	}
}

func saveBookmarkFile(path string, bm windows.Handle) {
	if bm == 0 {
		return
	}
	text, err := renderXML(bm, evtRenderBookmark)
	if err != nil || text == "" {
		return
	}
	if os.WriteFile(path+".tmp", []byte(text), 0o600) == nil {
		_ = os.Rename(path+".tmp", path)
	}
}

// forward converts one record and hands it to the pipeline. It returns false
// only when the context ended before the hand-off.
func (c *EventLogCollector) forward(ctx context.Context, channel, text string) bool {
	data, at, ok := ParseEventLogRecord(channel, text)
	if !ok {
		return true
	}
	if !c.allow(channel) {
		c.dropped.Add(1)
		return true
	}
	sev := event.SeverityMedium
	if highSeverityRecords[strings.ToLower(channel)][data["EventID"].(int)] {
		sev = event.SeverityHigh
	}
	evt := event.NewEvent(event.EventTypeEventLog, sev, data)
	if !at.IsZero() {
		evt.Timestamp = at
	}
	select {
	case c.eventChan <- evt:
		c.collected.Add(1)
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *EventLogCollector) allow(channel string) bool {
	c.limitMu.Lock()
	defer c.limitMu.Unlock()
	tb := c.limiters[strings.ToLower(channel)]
	return tb == nil || tb.tryConsume(time.Now())
}

// ── XML → event data ─────────────────────────────────────────────────────────

type eventLogXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID       int    `xml:"EventID"`
		EventRecordID uint64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Execution struct {
			ProcessID uint32 `xml:"ProcessID,attr"`
		} `xml:"Execution"`
		Channel  string `xml:"Channel"`
		Computer string `xml:"Computer"`
		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"UserData"`
}

// ParseEventLogRecord converts a rendered record into event data: system
// metadata plus every EventData/UserData field under its original name.
func ParseEventLogRecord(channel, text string) (map[string]interface{}, time.Time, bool) {
	var x eventLogXML
	if err := xml.Unmarshal([]byte(text), &x); err != nil || x.System.EventID == 0 {
		return nil, time.Time{}, false
	}
	if x.System.Channel != "" {
		channel = x.System.Channel
	}
	data := map[string]interface{}{
		"action":        "eventlog",
		"channel":       channel,
		"provider_name": x.System.Provider.Name,
		"EventID":       x.System.EventID,
		"event_code":    x.System.EventID,
		"record_id":     x.System.EventRecordID,
		"computer":      x.System.Computer,
	}
	if x.System.Execution.ProcessID != 0 {
		data["pid"] = x.System.Execution.ProcessID
	}
	if x.System.Security.UserID != "" {
		data["user_sid"] = x.System.Security.UserID
	}
	fields := 0
	put := func(name, value string) {
		name = strings.TrimSpace(name)
		if name == "" || fields >= eventLogMaxFields {
			return
		}
		if _, reserved := data[name]; reserved {
			name = "EventData_" + name
		}
		if len(value) > eventLogMaxValue {
			value = value[:eventLogMaxValue]
			data["truncated"] = true
		}
		data[name] = strings.TrimSpace(value)
		fields++
	}
	for i, d := range x.EventData.Data {
		name := d.Name
		if name == "" { // classic records with unnamed <Data> values
			name = "param" + strconv.Itoa(i+1)
		}
		put(name, d.Value)
	}
	for name, value := range userDataLeaves(x.UserData.Inner) {
		put(name, value)
	}
	data["summary"] = eventLogSummary(channel, x.System.EventID, data)
	var at time.Time
	if t, err := time.Parse(time.RFC3339Nano, x.System.TimeCreated.SystemTime); err == nil {
		at = t.UTC()
		data["event_time"] = at.Format(time.RFC3339Nano)
	}
	return data, at, true
}

// eventLogSummary is the one-line description shown in event lists.
func eventLogSummary(channel string, id int, d map[string]interface{}) string {
	s := fmt.Sprintf("%s %d", channel, id)
	if title := eventLogTitles[id]; title != "" && (strings.EqualFold(channel, "Security") || strings.EqualFold(channel, "System") || strings.Contains(channel, "Defender")) {
		s += " — " + title
	}
	for _, k := range []string{"ServiceName", "TaskName", "TargetUserName", "Threat Name", "MemberName", "ObjectName"} {
		if v, ok := d[k].(string); ok && v != "" && v != "-" {
			return s + ": " + v
		}
	}
	return s
}

var eventLogTitles = map[int]string{
	1102: "audit log cleared", 104: "event log cleared", 7045: "service installed", 7040: "service start type changed",
	4697: "service installed", 4698: "scheduled task created", 4699: "scheduled task deleted", 4702: "scheduled task updated",
	4720: "user account created", 4722: "user account enabled", 4724: "password reset", 4725: "user account disabled",
	4726: "user account deleted", 4732: "member added to local group", 4728: "member added to global group",
	4756: "member added to universal group", 4719: "audit policy changed", 4625: "failed logon", 4648: "logon with explicit credentials",
	4624: "logon", 1116: "malware detected", 1117: "malware action taken", 5001: "real-time protection disabled",
	5007: "configuration changed", 5010: "malware scanning disabled", 5012: "virus scanning disabled", 5013: "tamper protection blocked a change",
}

// userDataLeaves flattens <UserData><Wrapper><Field>value</Field>…</Wrapper>
// (used by e.g. Security 1102 and System 104) into leaf name → text.
func userDataLeaves(inner []byte) map[string]string {
	out := map[string]string{}
	if len(inner) == 0 {
		return out
	}
	dec := xml.NewDecoder(strings.NewReader(string(inner)))
	var stack []string
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if len(stack) > 1 { // skip the wrapper element itself
				if v := strings.TrimSpace(text.String()); v != "" {
					out[t.Name.Local] = v
				}
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			text.Reset()
		}
	}
}
