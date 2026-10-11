//go:build windows
// +build windows

package collectors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/win-agent/internal/event"
)

const sample7045 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}"/><EventID Qualifiers="16384">7045</EventID><TimeCreated SystemTime="2026-10-11T09:00:00.5000000Z"/><EventRecordID>9912</EventRecordID><Execution ProcessID="760" ThreadID="1"/><Channel>System</Channel><Computer>WS-01</Computer><Security UserID="S-1-5-18"/></System><EventData><Data Name="ServiceName">updater</Data><Data Name="ImagePath">C:\ProgramData\u.exe</Data><Data Name="ServiceType">user mode service</Data><Data Name="StartType">auto start</Data><Data Name="AccountName">LocalSystem</Data></EventData></Event>`

const sample1102 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><TimeCreated SystemTime="2026-10-11T09:01:00Z"/><EventRecordID>1</EventRecordID><Channel>Security</Channel><Computer>WS-01</Computer></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid><SubjectUserName>Administrator</SubjectUserName><SubjectDomainName>WS-01</SubjectDomainName></LogFileCleared></UserData></Event>`

func TestParseEventLogRecordEventData(t *testing.T) {
	d, at, ok := ParseEventLogRecord("System", sample7045)
	if !ok {
		t.Fatal("record not parsed")
	}
	want := map[string]interface{}{"channel": "System", "provider_name": "Service Control Manager", "EventID": 7045, "event_code": 7045,
		"ServiceName": "updater", "ImagePath": `C:\ProgramData\u.exe`, "AccountName": "LocalSystem", "action": "eventlog", "computer": "WS-01"}
	for k, v := range want {
		if d[k] != v {
			t.Fatalf("%s = %v, want %v", k, d[k], v)
		}
	}
	if d["record_id"] != uint64(9912) || d["pid"] != uint32(760) || d["user_sid"] != "S-1-5-18" {
		t.Fatalf("system metadata missing: %+v", d)
	}
	if !at.Equal(time.Date(2026, 10, 11, 9, 0, 0, 500000000, time.UTC)) {
		t.Fatalf("original time not kept: %v", at)
	}
	if s := d["summary"].(string); !strings.Contains(s, "service installed") || !strings.Contains(s, "updater") {
		t.Fatalf("summary %q", s)
	}
}

func TestParseEventLogRecordUserData(t *testing.T) {
	d, _, ok := ParseEventLogRecord("Security", sample1102)
	if !ok || d["SubjectUserName"] != "Administrator" || d["SubjectUserSid"] != "S-1-5-21-1-2-3-500" || d["EventID"] != 1102 {
		t.Fatalf("UserData not flattened: %+v", d)
	}
	if _, wrapper := d["LogFileCleared"]; wrapper {
		t.Fatal("wrapper element must not become a field")
	}
}

func TestParseEventLogRecordBounds(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<Event><System><EventID>4663</EventID><Channel>Security</Channel></System><EventData>`)
	for i := 0; i < eventLogMaxFields+20; i++ {
		b.WriteString(`<Data Name="F` + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + `">v</Data>`)
	}
	b.WriteString(`<Data Name="EventID">spoofed</Data><Data Name="Big">` + strings.Repeat("z", eventLogMaxValue+10) + `</Data></EventData></Event>`)
	d, _, ok := ParseEventLogRecord("Security", b.String())
	if !ok || d["EventID"] != 4663 {
		t.Fatalf("EventData must not overwrite system metadata: %v", d["EventID"])
	}
	if _, _, ok := ParseEventLogRecord("Security", "<Event><System></System></Event>"); ok {
		t.Fatal("record without EventID accepted")
	}
	if _, _, ok := ParseEventLogRecord("Security", "not xml"); ok {
		t.Fatal("garbage accepted")
	}
	for k, v := range d {
		if s, isStr := v.(string); isStr && len(s) > eventLogMaxValue {
			t.Fatalf("%s exceeds the value cap", k)
		}
	}
}

func TestEventLogQueriesBounded(t *testing.T) {
	for _, ch := range DefaultEventLogChannels {
		qs := EventLogQueries(ch)
		if len(qs) == 0 {
			t.Fatalf("%s has no query", ch.Channel)
		}
		total := 0
		for _, q := range qs {
			n := strings.Count(q, "EventID=")
			if n > eventLogIDsPerSub && !strings.Contains(q, "EventData") {
				t.Fatalf("%s query has %d terms", ch.Channel, n)
			}
			total += n
		}
		if total != len(ch.IDs)+len(ch.Extra) {
			t.Fatalf("%s: %d IDs queried, want %d", ch.Channel, total, len(ch.IDs)+len(ch.Extra))
		}
	}
}

func TestEventLogForwardRateLimitAndSeverity(t *testing.T) {
	ch := make(chan *event.Event, 10)
	c := NewEventLogCollector(ch, testLogger(t), t.TempDir(), []EventLogChannel{{Channel: "System", IDs: []int{7045}, RatePerSec: 0.0001, Burst: 2}})
	for i := 0; i < 5; i++ {
		if !c.forward(context.Background(), "System", sample7045) {
			t.Fatal("hand-off failed")
		}
	}
	if len(ch) != 2 || c.Dropped() != 3 {
		t.Fatalf("burst 2 must pass 2 and drop 3: got %d, dropped %d", len(ch), c.Dropped())
	}
	ev := <-ch
	if ev.Type != event.EventTypeEventLog || ev.Severity != event.SeverityMedium {
		t.Fatalf("type/severity %v/%v", ev.Type, ev.Severity)
	}
	c2 := NewEventLogCollector(ch, testLogger(t), t.TempDir(), []EventLogChannel{{Channel: "Security", IDs: []int{1102}, RatePerSec: 10, Burst: 10}})
	<-ch
	c2.forward(context.Background(), "Security", sample1102)
	if got := <-ch; got.Severity != event.SeverityHigh {
		t.Fatal("log clearing must be forwarded as high severity")
	}
	// A cancelled context reports the record as not handed off (bookmark not advanced).
	full := make(chan *event.Event)
	c3 := NewEventLogCollector(full, testLogger(t), t.TempDir(), []EventLogChannel{{Channel: "System", IDs: []int{7045}, RatePerSec: 10, Burst: 10}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c3.forward(ctx, "System", sample7045) {
		t.Fatal("undelivered record reported as delivered")
	}
}
