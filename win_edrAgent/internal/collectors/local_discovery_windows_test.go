//go:build windows

package collectors

import (
	"fmt"
	"html"
	"testing"

	"github.com/edr-platform/win-agent/internal/event"
)

func TestPowerShellLocalDiscoveryEvidence(t *testing.T) {
	for _, tc := range []struct {
		code                     int
		field, body, action, key string
	}{
		{4104, "ScriptBlockText", "net user\nget-localuser\nget-localgroupmember -group Users\ncmdkey.exe /list", "script_block", "script_block_text"},
		{4103, "Payload", `CommandInvocation(Get-LocalUser): "Get-LocalUser"`, "module", "payload"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			ch := make(chan *event.Event, 1)
			c := NewPowerShellCollector(ch, testLogger(t), t.TempDir(), false)
			xml := fmt.Sprintf(`<Event><System><EventID>%d</EventID><Execution ProcessID="424242"/><TimeCreated SystemTime="2026-10-10T08:31:35Z"/></System><EventData><Data Name="%s">%s</Data><Data Name="ScriptBlockId">discovery-fixture</Data></EventData></Event>`, tc.code, tc.field, html.EscapeString(tc.body))
			c.handle(psChannelWindows, xml)
			select {
			case ev := <-ch:
				if ev.Type != event.EventTypePowerShell || ev.Data["action"] != tc.action || ev.Data[tc.key] != tc.body || ev.Data["event_code"] != tc.code {
					t.Fatalf("lost source/evidence: %+v", ev)
				}
				if ev.Timestamp.UTC().Format("2006-01-02T15:04:05Z") != "2026-10-10T08:31:35Z" {
					t.Fatal("record time must survive collection")
				}
			default:
				t.Fatal("local discovery evidence was dropped")
			}
		})
	}
}
