//go:build windows
// +build windows

package command

import (
	"context"
	"github.com/edr-platform/win-agent/internal/processlineage"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRetainedDescendantsExcludeReusedGenerations(t *testing.T) {
	now := time.Now().UTC()
	oldChild := &procEntry{pid: 200, ppid: 100, created: filetimeOf(now.Add(-time.Minute))}
	grandchild := &procEntry{pid: 300, ppid: 200, created: filetimeOf(now.Add(-30 * time.Second))}
	foreign := &procEntry{pid: 400, ppid: 100, created: filetimeOf(now)}
	tree := processlineage.Tree{Found: true, Descendants: []processlineage.Identity{
		processIdentity(grandchild.pid, grandchild.created), processIdentity(oldChild.pid, oldChild.created),
	}}
	procs := map[uint32]*procEntry{200: oldChild, 300: grandchild, 400: foreign}
	got := retainedDescendants(procs, tree)
	if len(got) != 2 || got[0] != grandchild || got[1] != oldChild {
		t.Fatalf("verified orphans were not selected: %+v", got)
	}
	procs[200] = &procEntry{pid: 200, ppid: 100, created: filetimeOf(now)}
	if got := retainedDescendants(procs, tree); len(got) != 1 || got[0] != grandchild {
		t.Fatalf("reused child PID selected: %+v", got)
	}
}

func TestCollectDescendantsRejectsReusedParentPIDs(t *testing.T) {
	const sec = int64(10_000_000) // FILETIME units per second
	base := filetimeOf(time.Now())
	procs := map[uint32]*procEntry{
		100: {pid: 100, ppid: 1, name: "root.exe", created: base},
		200: {pid: 200, ppid: 100, name: "child.exe", created: base + sec},
		300: {pid: 300, ppid: 200, name: "grandchild.exe", created: base + 2*sec},
		// Created an hour before the root: its ppid 100 belonged to an
		// earlier owner of that PID — it is NOT the root's child.
		400: {pid: 400, ppid: 100, name: "unrelated.exe", created: base - 3600*sec},
		// Unknown creation time: cannot be attributed safely.
		500: {pid: 500, ppid: 100, name: "unknown.exe", created: 0},
	}
	got := collectDescendants(procs, map[uint32]int64{100: base})
	var names []string
	for _, p := range got {
		names = append(names, p.name)
	}
	if strings.Join(names, ",") != "grandchild.exe,child.exe" {
		t.Fatalf("descendants (deepest first) = %v", names)
	}
}

func TestCollectDescendantsFindsOrphansOfKilledProcesses(t *testing.T) {
	// 200 was terminated; its child 300 still points at the dead PID.
	procs := map[uint32]*procEntry{
		300: {pid: 300, ppid: 200, name: "orphan.exe", created: 3000},
	}
	got := collectDescendants(procs, map[uint32]int64{100: 1000, 200: 2000})
	if len(got) != 1 || got[0].pid != 300 {
		t.Fatalf("orphan of a terminated process must be found: %+v", got)
	}
}

func TestDescendantsExcludeReusedLiveAnchor(t *testing.T) {
	procs := map[uint32]*procEntry{
		100: {pid: 100, ppid: 1, name: "new.exe", created: 9000},
		200: {pid: 200, ppid: 100, name: "unrelated.exe", created: 10000},
	}
	if got := collectDescendants(procs, map[uint32]int64{100: 1000}); len(got) != 0 {
		t.Fatalf("children of a reused live anchor must not be killed: %+v", got)
	}
}

func TestSameStartTime(t *testing.T) {
	base := filetimeOf(time.Now())
	if !sameStartTime(base, base) || sameStartTime(0, base) || sameStartTime(base+1, base) {
		t.Fatal("unknown or reused same-image PID creation times must not match")
	}
}

func TestSameImage(t *testing.T) {
	if !sameImage(`C:\Windows\System32\cmd.exe`, `c:/windows/system32/CMD.EXE`) {
		t.Fatal("paths are case-insensitive and separator-agnostic")
	}
	if sameImage(`C:\Windows\System32\cmd.exe`, `C:\Users\x\cmd.exe`) {
		t.Fatal("different directories must not match")
	}
	if !sameImage(`C:\Windows\System32\cmd.exe`, `cmd.exe`) {
		t.Fatal("a bare name is compared by file name")
	}
}

func alive(pid int) bool {
	procs, err := snapshotProcesses()
	if err != nil {
		return false
	}
	_, ok := procs[uint32(pid)]
	return ok
}

// startTree starts cmd.exe that starts ping.exe (a two-level tree).
func startTree(t *testing.T) (*exec.Cmd, uint32) {
	t.Helper()
	if os.Getenv("EDR_RUN_LIVE_TESTS") != "1" {
		t.Skip("live endpoint testing requires explicit EDR_RUN_LIVE_TESTS=1")
	}
	cmd := exec.Command("cmd.exe", "/c", "ping -n 60 127.0.0.1 >nul")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start test processes: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		procs, _ := snapshotProcesses()
		for _, p := range procs {
			if p.ppid == uint32(cmd.Process.Pid) && strings.EqualFold(p.name, "PING.EXE") {
				return cmd, p.pid
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("child ping.exe did not start")
	return nil, 0
}

func TestTerminateProcessTreeKillsDescendants(t *testing.T) {
	h := &Handler{}
	cmd, child := startTree(t)
	out, err := h.terminateProcess(context.Background(), map[string]string{
		"pid": strconv.Itoa(cmd.Process.Pid), "kill_tree": "true", "process_path": `C:\Windows\System32\cmd.exe`,
	})
	if err != nil {
		t.Fatalf("tree kill failed: %v", err)
	}
	if alive(cmd.Process.Pid) || alive(int(child)) {
		t.Fatalf("root or child still alive after tree kill: %s", out)
	}
	if !strings.Contains(out, "terminated 2") {
		t.Fatalf("unexpected summary: %s", out)
	}
}

func TestTerminateSingleLeavesChild(t *testing.T) {
	h := &Handler{}
	cmd, child := startTree(t)
	t.Cleanup(func() {
		_, _ = h.terminateProcess(context.Background(), map[string]string{"pid": strconv.Itoa(int(child))})
	})
	if _, err := h.terminateProcess(context.Background(), map[string]string{"pid": strconv.Itoa(cmd.Process.Pid)}); err != nil {
		t.Fatal(err)
	}
	if alive(cmd.Process.Pid) {
		t.Fatal("target still alive")
	}
	if !alive(int(child)) {
		t.Fatal("process-only mode must not kill the child")
	}
}

func TestTerminateIdentityAndExitedTarget(t *testing.T) {
	h := &Handler{}
	cmd, _ := startTree(t)
	pid := strconv.Itoa(cmd.Process.Pid)
	// Wrong expected image: treated as a reused PID — never terminated.
	out, err := h.terminateProcess(context.Background(), map[string]string{"pid": pid, "process_path": `C:\Users\x\evil.exe`})
	if err != nil || !strings.Contains(out, "Nothing was terminated") || !alive(cmd.Process.Pid) {
		t.Fatalf("identity mismatch must not kill: out=%q err=%v", out, err)
	}
	// Kill it, then a second request reports "already exited" as success.
	if _, err := h.terminateProcess(context.Background(), map[string]string{"pid": pid, "kill_tree": "true"}); err != nil {
		t.Fatal(err)
	}
	out, err = h.terminateProcess(context.Background(), map[string]string{"pid": pid})
	if err != nil || !strings.Contains(out, "not running") {
		t.Fatalf("an exited target is the desired state: out=%q err=%v", out, err)
	}
}
