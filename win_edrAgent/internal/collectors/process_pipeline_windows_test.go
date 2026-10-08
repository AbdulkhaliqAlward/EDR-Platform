//go:build windows
// +build windows

package collectors

import (
	"context"
	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/processlineage"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProcessTableLateExitCannotMarkReplacementExited(t *testing.T) {
	now := time.Now()
	tbl := &processTable{m: map[uint32]*procRecord{}}
	newOwner := &procRecord{pid: 100, created: now, creationMeasured: true}
	tbl.put(newOwner)
	if tbl.markExited(100, now.Add(-time.Second)) != nil {
		t.Fatal("late exit matched replacement")
	}
	tbl.put(&procRecord{pid: 100, created: now.Add(-time.Minute)})
	if got := tbl.get(100); !got.created.Equal(now) || !got.exited.IsZero() {
		t.Fatal("older worker overwrote replacement")
	}
	newOwner.self = true
	if tbl.get(100).self {
		t.Fatal("table owns caller's mutable pointer")
	}
}

func TestProcessDedupUsesMeasuredGeneration(t *testing.T) {
	old := processlineage.Identity{PID: 654321, Started: time.Now().UnixNano()}
	if isDuplicate(old) {
		t.Fatal("first event duplicated")
	}
	if !isDuplicate(old) {
		t.Fatal("same generation not deduplicated")
	}
	newOwner := old
	newOwner.Started += 100
	if isDuplicate(newOwner) {
		t.Fatal("PID reuse suppressed a different process")
	}
}

func sys32(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}

func TestFileIdentityMicrosoftBinaries(t *testing.T) {
	for _, name := range []string{"cmd.exe", "notepad.exe", "kernel32.dll"} {
		p := sys32(name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		id := FileIdentityOf(p)
		if id.SignatureStatus != "microsoft" {
			t.Errorf("%s: status %q signer %q, want microsoft", name, id.SignatureStatus, id.Signer)
		}
		if len(id.SHA256) != 64 {
			t.Errorf("%s: missing SHA-256", name)
		}
	}
	id := FileIdentityOf(sys32("cmd.exe"))
	if !strings.EqualFold(id.OriginalFileName, "cmd.exe") || id.Company == "" {
		t.Errorf("cmd.exe version info: %+v", id)
	}
}

func TestFileIdentityUnsignedAndTampered(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.exe")
	if err := os.WriteFile(junk, []byte("not a PE file at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := FileIdentityOf(junk).SignatureStatus; st != "unsigned" {
		t.Errorf("non-PE file: status %q, want unsigned", st)
	}

	// A modified copy of a Microsoft binary must never be trusted as such.
	src, err := os.ReadFile(sys32("cmd.exe"))
	if err != nil {
		t.Skip("cmd.exe not readable")
	}
	src[len(src)/2] ^= 0xFF
	tampered := filepath.Join(dir, "cmd.exe")
	if err := os.WriteFile(tampered, src, 0o644); err != nil {
		t.Fatal(err)
	}
	if st := FileIdentityOf(tampered).SignatureStatus; st == "microsoft" || st == "trusted" {
		t.Errorf("tampered binary verified as %q", st)
	}
}

func TestTrustedOSProcessRequiresGenuineLocation(t *testing.T) {
	if !isTrustedOSProcess(sys32("conhost.exe")) {
		t.Error("conhost.exe in System32 is trusted")
	}
	if isTrustedOSProcess(`C:\Users\bob\AppData\Local\Temp\conhost.exe`) {
		t.Error("a look-alike conhost.exe outside System32 must stay visible")
	}
	if isTrustedOSProcess("conhost.exe") {
		t.Error("a bare name cannot be verified and must not be trusted")
	}
}

func TestImageFromCommandLine(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\App\app.exe" --x`: `C:\Program Files\App\app.exe`,
		`C:\Windows\System32\cmd.exe /c dir`: `C:\Windows\System32\cmd.exe`,
		`cmd.exe /c dir`:                     "",
		`"C:\tools\script.ps1"`:              "",
	}
	for in, want := range cases {
		if got := imageFromCommandLine(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestParentResolutionRespectsPIDReuse(t *testing.T) {
	tbl := &processTable{m: map[uint32]*procRecord{}}
	now := time.Now()
	tbl.put(&procRecord{pid: 100, created: now.Add(-time.Minute), image: `C:\a\parent.exe`})
	if p := tbl.parentOf(100, now); p == nil || p.image != `C:\a\parent.exe` {
		t.Fatal("a live, older parent must resolve")
	}
	// PID 100 reused by a process created AFTER the child.
	tbl.put(&procRecord{pid: 100, created: now.Add(time.Minute), image: `C:\b\new.exe`})
	if p := tbl.parentOf(100, now); p != nil {
		t.Fatalf("a newer owner of the PID is not the parent: %+v", p)
	}
	// Parent exited long before the child started: not the parent.
	tbl.put(&procRecord{pid: 200, created: now.Add(-time.Hour), exited: now.Add(-30 * time.Minute)})
	if p := tbl.parentOf(200, now); p != nil {
		t.Fatal("a parent that exited before the child started cannot be its parent")
	}
	// Short-lived parent that exited right after starting the child: resolved
	// from its tombstone.
	tbl.put(&procRecord{pid: 300, created: now.Add(-time.Second), exited: now.Add(time.Millisecond), image: `C:\x\dropper.exe`})
	if p := tbl.parentOf(300, now); p == nil {
		t.Fatal("tombstone of a short-lived parent must resolve")
	}
}

func TestSelfTrackingByAncestry(t *testing.T) {
	recs := seedProcessTable()
	found := false
	for _, r := range recs {
		if r.pid == agentPID {
			found = true
			if !r.self {
				t.Fatal("the agent's own process must be self")
			}
		}
	}
	if !found {
		t.Skip("own process not in snapshot")
	}
	if !isSelfPID(agentPID) {
		t.Fatal("isSelfPID(agent)")
	}
	if isSelfPID(4) {
		t.Fatal("System is not self")
	}
}

func TestETWWorkerPoolsStopOnCancellation(t *testing.T) {
	c := NewETWCollector("", make(chan *event.Event), testLogger(t), nil, false, false)
	ctx, cancel := context.WithCancel(context.Background())
	c.startWorkers(ctx)
	cancel()
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers remained blocked after cancellation")
	}
}
