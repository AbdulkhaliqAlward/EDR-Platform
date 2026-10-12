//go:build windows
// +build windows

package collectors

import (
	"testing"
	"time"
)

// Fake PIDs far above real ones: OpenProcess fails for them, so only the
// process table can attribute the events (as for an exited process).
const (
	ctxPID    = 4_000_001
	ctxParent = 4_000_002
	ctxReused = 4_000_003
)

func TestEnrichProcessContextFromTableAfterExit(t *testing.T) {
	start := time.Now().Add(-10 * time.Second)
	procTable.put(&procRecord{pid: ctxParent, created: start.Add(-time.Minute), image: `C:\Windows\explorer.exe`})
	procTable.put(&procRecord{pid: ctxPID, ppid: ctxParent, created: start, image: `C:\Tools\loader.exe`,
		cmdline: `"C:\Tools\loader.exe" -x`, user: `WS\alice`, userSid: "S-1-5-21-1-2-3-1001", integrity: "High", elevated: true})
	procTable.markExited(ctxPID, start.Add(2*time.Second))
	t.Cleanup(func() {
		procTable.mu.Lock()
		delete(procTable.m, ctxPID)
		delete(procTable.m, ctxParent)
		procTable.mu.Unlock()
	})

	// The image load happened while the process was alive; it is handled after exit.
	data := map[string]interface{}{"ImageLoaded": `C:\Tools\dbghelp.dll`, "pid": uint32(ctxPID)}
	enrichProcessContext(data, ctxPID, start.Add(time.Second))
	want := map[string]interface{}{
		"executable": `C:\Tools\loader.exe`, "process_path": `C:\Tools\loader.exe`, "Image": `C:\Tools\loader.exe`,
		"process_name": "loader.exe", "command_line": `"C:\Tools\loader.exe" -x`, "ppid": uint32(ctxParent),
		"parent_executable": `C:\Windows\explorer.exe`, "parent_name": "explorer.exe",
		"user_name": `WS\alice`, "user_sid": "S-1-5-21-1-2-3-1001", "integrity_level": "High", "is_elevated": true,
	}
	for k, v := range want {
		if data[k] != v {
			t.Fatalf("%s = %v, want %v", k, data[k], v)
		}
	}
	if s, _ := data["process_start_time"].(string); s == "" {
		t.Fatal("process start time (generation identity) missing")
	}
}

func TestEnrichProcessContextRejectsReusedPID(t *testing.T) {
	// The table holds a NEWER process that reused the PID after the event.
	eventAt := time.Now().Add(-time.Minute)
	procTable.put(&procRecord{pid: ctxReused, created: eventAt.Add(30 * time.Second), image: `C:\Windows\System32\notepad.exe`})
	t.Cleanup(func() { procTable.mu.Lock(); delete(procTable.m, ctxReused); procTable.mu.Unlock() })
	data := map[string]interface{}{}
	enrichProcessContext(data, ctxReused, eventAt)
	if _, wrong := data["executable"]; wrong {
		t.Fatalf("event attributed to the process that reused the PID: %v", data)
	}
}

func TestEnrichProcessContextNeverOverwrites(t *testing.T) {
	start := time.Now().Add(-5 * time.Second)
	procTable.put(&procRecord{pid: ctxPID, created: start, image: `C:\Tools\loader.exe`, user: `WS\alice`, userSid: "S-1"})
	t.Cleanup(func() { procTable.mu.Lock(); delete(procTable.m, ctxPID); procTable.mu.Unlock() })
	data := map[string]interface{}{"process_name": "collector-value.exe", "user_name": `WS\bob`, "process_path": "unknown"}
	enrichProcessContext(data, ctxPID, start.Add(time.Second))
	if data["process_name"] != "collector-value.exe" || data["user_name"] != `WS\bob` {
		t.Fatalf("existing collector values overwritten: %v", data)
	}
	if data["process_path"] != `C:\Tools\loader.exe` {
		t.Fatalf("placeholder value not replaced: %v", data["process_path"])
	}
}

// A process that starts, writes a file and exits within milliseconds: the
// kernel start event registers it synchronously, so the file event (handled
// on another queue, possibly before the process pipeline) is attributed.
func TestProvisionalRecordAttributesMillisecondProcess(t *testing.T) {
	const pid, parent = 4_000_011, 4_000_012
	t.Cleanup(func() {
		procTable.mu.Lock()
		delete(procTable.m, pid)
		delete(procTable.m, parent)
		procTable.mu.Unlock()
	})
	start := time.Now().Add(-2 * time.Second)
	procTable.put(&procRecord{pid: parent, created: start.Add(-time.Hour), image: `C:\Windows\explorer.exe`})
	procTable.registerProvisional(pid, parent, start, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`powershell.exe -NoProfile -c "x"`, "S-1-5-18")
	procTable.markExited(pid, start.Add(time.Millisecond)) // exits in the same millisecond window

	data := map[string]interface{}{"pid": uint32(pid), "path": `C:\Windows\SystemTemp\__PSScriptPolicyTest_x.ps1`}
	enrichProcessContext(data, pid, start.Add(500*time.Microsecond))
	if data["process_name"] != "powershell.exe" || data["command_line"] != `powershell.exe -NoProfile -c "x"` ||
		data["user_sid"] != "S-1-5-18" || data["parent_executable"] != `C:\Windows\explorer.exe` {
		t.Fatalf("fast process not attributed: %v", data)
	}
	if u, _ := data["user_name"].(string); u == "" {
		t.Fatal("SID from the kernel event not resolved to an account")
	}

	// The pipeline later completes the same generation (measured creation a
	// little earlier than the event time, no token: already exited).
	procTable.put(&procRecord{pid: pid, ppid: parent, created: start.Add(-3 * time.Millisecond), creationMeasured: true,
		image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`})
	r := procTable.get(pid)
	if r == nil || r.provisional || r.userSid != "S-1-5-18" || r.exited.IsZero() || r.cmdline == "" {
		t.Fatalf("measured record lost provisional facts: %+v", r)
	}
}

func TestProvisionalNeverReplacesNewerGeneration(t *testing.T) {
	const pid = 4_000_013
	t.Cleanup(func() { procTable.mu.Lock(); delete(procTable.m, pid); procTable.mu.Unlock() })
	now := time.Now()
	procTable.put(&procRecord{pid: pid, created: now, creationMeasured: true, image: `C:\new.exe`})
	// A late, older start event for the same PID must not overwrite the new owner.
	procTable.registerProvisional(pid, 0, now.Add(-time.Minute), `C:\old.exe`, "old", "")
	if r := procTable.get(pid); r == nil || r.image != `C:\new.exe` {
		t.Fatalf("newer generation replaced: %+v", r)
	}
	// And a measured record of an OLDER generation never replaces a newer provisional one.
	procTable.registerProvisional(pid, 0, now.Add(time.Minute), `C:\newer.exe`, "newer", "")
	procTable.put(&procRecord{pid: pid, created: now.Add(-time.Hour), creationMeasured: true, image: `C:\older.exe`})
	if r := procTable.get(pid); r == nil || r.image != `C:\newer.exe` {
		t.Fatalf("older generation replaced the newer provisional record: %+v", r)
	}
}
