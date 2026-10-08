//go:build windows
// +build windows

package command

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/edr-platform/win-agent/internal/processlineage"
	"golang.org/x/sys/windows"
)

// ─────────────────────────────────────────────────────────────────────────────
// Process termination (TERMINATE_PROCESS)
//
// Parameters:
//   pid                 required — target process
//   kill_tree           "true" = the process and every process it started
//   process_path        optional — expected image; a live PID whose image
//                       differs is a reused PID and is never terminated
//   process_started_at  optional RFC 3339 — measured target creation time;
//                       rejects PID reuse, including the same image
//
// Semantics (desired state: "the target is not running"):
//   - target already exited          → process-only succeeds; tree reports
//                                      unverified lineage without killing
//   - PID reused by another program  → success, nothing terminated
//   - tree: descendants are found by parent links that are consistent in
//     time (child created at/after its parent), suspended first so they cannot
//     spawn more, terminated deepest-first, root last; the snapshot is
//     repeated until no new descendant appears.
//   - any targeted process still alive at the end → failure with details.
// ─────────────────────────────────────────────────────────────────────────────

const (
	processSuspendResume = 0x0800
	maxTreePasses        = 4
	terminateWaitMs      = 3000
)

var (
	ntdllTerminate       = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProcess = ntdllTerminate.NewProc("NtSuspendProcess")
	procNtResumeProcess  = ntdllTerminate.NewProc("NtResumeProcess")
)

type procEntry struct {
	pid, ppid uint32
	name      string
	created   int64 // FILETIME (100 ns since 1601); 0 = unknown
}

func (p *procEntry) label() string { return fmt.Sprintf("%d %s", p.pid, p.name) }

func filetimeOf(t time.Time) int64 {
	ft := windows.NsecToFiletime(t.UnixNano())
	return int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
}

func processCreationTime(pid uint32) int64 {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return 0
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime)
}

// processImagePath returns the full Win32 image path of a live process.
func processImagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func snapshotProcesses() (map[uint32]*procEntry, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)
	out := make(map[uint32]*procEntry, 256)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}
	for {
		p := &procEntry{pid: e.ProcessID, ppid: e.ParentProcessID, name: windows.UTF16ToString(e.ExeFile[:])}
		if p.pid > 4 {
			p.created = processCreationTime(p.pid)
		}
		out[p.pid] = p
		if windows.Process32Next(snap, &e) != nil {
			break
		}
	}
	return out, nil
}

// collectDescendants walks parent links from each anchor (the root and every
// process already terminated, whose orphans keep the dead PID as ppid). A
// child is accepted only when its creation time is known and not earlier than
// its parent's: an older process whose ppid equals the anchor's PID belongs to
// a previous owner of that PID. Result is deepest-first.
func collectDescendants(procs map[uint32]*procEntry, anchors map[uint32]int64) []*procEntry {
	children := make(map[uint32][]*procEntry, len(procs))
	for _, p := range procs {
		if p.pid != p.ppid {
			children[p.ppid] = append(children[p.ppid], p)
		}
	}
	var out []*procEntry
	seen := map[uint32]bool{}
	var walk func(pid uint32, created int64)
	walk = func(pid uint32, created int64) {
		for _, c := range children[pid] {
			if seen[c.pid] || c.created == 0 || created == 0 || c.created < created {
				continue
			}
			seen[c.pid] = true
			walk(c.pid, c.created)
			out = append(out, c)
		}
	}
	pids := make([]uint32, 0, len(anchors))
	for pid := range anchors {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	for _, pid := range pids {
		seen[pid] = true
	}
	for _, pid := range pids {
		// A surviving orphan may still name a dead parent PID. If that PID
		// now has a different live owner, its new children cannot be safely
		// attributed to the old tree.
		if live := procs[pid]; live != nil && live.created != anchors[pid] {
			continue
		}
		walk(pid, anchors[pid])
	}
	return out
}

func normalizeImage(p string) string {
	p = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(p, "/", `\`)))
	return strings.TrimPrefix(p, `\\?\`)
}

// sameImage compares an actual image with the expected one (full path when
// the expectation has a directory, otherwise the file name).
func sameImage(actual, expected string) bool {
	a, e := normalizeImage(actual), normalizeImage(expected)
	if a == "" || e == "" {
		return true // nothing to compare against
	}
	if strings.Contains(e, `\`) && strings.Contains(a, `\`) {
		return a == e
	}
	return filepath.Base(a) == filepath.Base(e)
}

type killReport struct {
	killed, skipped, failed []string
}

// protectedTarget explains why a process must never be terminated.
func protectedTarget(p *procEntry) string {
	if p.pid <= 4 {
		return "system process"
	}
	if int(p.pid) == os.Getpid() {
		return "EDR agent"
	}
	if criticalSystemProcesses[strings.ToLower(p.name)] {
		return "critical system process"
	}
	return ""
}

func ntCall(proc *windows.LazyProc, h windows.Handle) error {
	if err := proc.Find(); err != nil {
		return err
	}
	if r, _, _ := proc.Call(uintptr(h)); r != 0 {
		return fmt.Errorf("NTSTATUS 0x%x", r)
	}
	return nil
}

// suspend freezes a process so it cannot start new children while the tree
// is being terminated. The returned handle resumes it if the kill fails.
func suspend(p *procEntry) windows.Handle {
	h, err := windows.OpenProcess(processSuspendResume|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid)
	if err != nil {
		return 0
	}
	if created, err := handleCreationTime(h); err != nil || p.created == 0 || created != p.created || ntCall(procNtSuspendProcess, h) != nil {
		windows.CloseHandle(h)
		return 0
	}
	return h
}

func handleCreationTime(h windows.Handle) (int64, error) {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, err
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime), nil
}

func sameStartTime(actual, expected int64) bool {
	return actual != 0 && actual == expected
}

// terminate kills one process after re-checking its identity (creation time)
// and waits until it has exited.
func terminate(p *procEntry) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid)
	if err != nil {
		if err == windows.ERROR_INVALID_PARAMETER {
			return nil // already gone
		}
		return fmt.Errorf("open: %v (protected process or access denied)", err)
	}
	defer windows.CloseHandle(h)
	created, err := handleCreationTime(h)
	if err != nil || p.created == 0 {
		return fmt.Errorf("cannot verify process creation time; termination refused")
	}
	if created != p.created {
		return nil // the PID now belongs to a different process: ours is gone
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("TerminateProcess: %v", err)
	}
	if ev, _ := windows.WaitForSingleObject(h, terminateWaitMs); ev != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("process did not exit within %d ms", terminateWaitMs)
	}
	return nil
}

func (r *killReport) kill(p *procEntry, h windows.Handle) {
	if err := terminate(p); err != nil {
		r.failed = append(r.failed, fmt.Sprintf("%s (%v)", p.label(), err))
		if h != 0 {
			_ = ntCall(procNtResumeProcess, h) // never leave a process frozen
		}
	} else {
		r.killed = append(r.killed, p.label())
	}
	if h != 0 {
		windows.CloseHandle(h)
	}
}

func (h *Handler) terminateProcess(ctx context.Context, params map[string]string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	pidStr := strings.TrimSpace(params["pid"])
	pid64, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil || pid64 <= 4 {
		return "", fmt.Errorf("invalid PID %q (must be a process ID greater than 4)", pidStr)
	}
	pid := uint32(pid64)
	killTree := strings.EqualFold(params["kill_tree"], "true") || strings.EqualFold(params["killTree"], "true")
	expected := strings.TrimSpace(params["process_path"])
	var notBefore int64
	if s := strings.TrimSpace(params["process_started_at"]); s != "" {
		if t, perr := time.Parse(time.RFC3339Nano, s); perr == nil {
			notBefore = filetimeOf(t)
		} else {
			return "", fmt.Errorf("invalid process_started_at: %w", perr)
		}
	}

	procs, err := snapshotProcesses()
	if err != nil {
		return "", err
	}
	root := procs[pid]
	if root != nil && root.created == 0 {
		return "", fmt.Errorf("cannot verify creation time for PID %d; termination refused", pid)
	}
	if root != nil && notBefore != 0 && !sameStartTime(root.created, notBefore) {
		if !killTree {
			return fmt.Sprintf("Target already exited: PID %d has a different creation time. Nothing was terminated.", pid), nil
		}
		root = nil // keep the replacement alive, but look up the original tree
	}
	if root != nil {
		img := processImagePath(pid)
		if img == "" {
			if expected != "" {
				return "", fmt.Errorf("cannot verify image path for PID %d; termination refused", pid)
			}
			img = root.name
		}
		if expected != "" && !sameImage(img, expected) {
			if killTree {
				return "", fmt.Errorf("tree identity is unverified: PID %d image differs from expected; no processes terminated", pid)
			}
			return fmt.Sprintf("Target already exited: PID %d now belongs to %s (expected %s). Nothing was terminated.",
				pid, img, expected), nil
		}
		root.name = filepath.Base(img)
		if why := protectedTarget(root); why != "" {
			return "", fmt.Errorf("refused: PID %d (%s) is a %s", pid, root.name, why)
		}
	}

	if !killTree {
		if root == nil {
			return fmt.Sprintf("Process %d is not running (already exited). Nothing to terminate.", pid), nil
		}
		var rep killReport
		rep.kill(root, 0)
		if len(rep.failed) > 0 {
			return "", fmt.Errorf("could not terminate %s", rep.failed[0])
		}
		return fmt.Sprintf("Terminated process %s.", root.label()), nil
	}

	// ── Process tree ─────────────────────────────────────────────────────
	rootTime := notBefore
	if root != nil {
		rootTime = root.created
	}
	rootID := processIdentity(pid, rootTime)
	retained := processlineage.Default.Tree(rootID, time.Now())
	if root == nil && (rootTime == 0 || !retained.Found) {
		return fmt.Sprintf("Process %d already exited; no processes terminated.", pid),
			fmt.Errorf("tree completion is unverified: measured retained root identity is unavailable")
	}
	anchors := map[uint32]int64{}
	if root != nil {
		anchors[pid] = root.created
	}
	done := map[uint32]bool{}
	var rep killReport
	for pass := 0; pass < maxTreePasses; pass++ {
		if err := ctx.Err(); err != nil {
			rep.failed = append(rep.failed, err.Error())
			break
		}
		if pass > 0 {
			if procs, err = snapshotProcesses(); err != nil {
				rep.failed = append(rep.failed, "could not verify remaining descendants: "+err.Error())
				break
			}
		}
		var targets []*procEntry
		retained = processlineage.Default.Tree(rootID, time.Now())
		candidates := retainedDescendants(procs, retained)
		candidates = append(candidates, collectDescendants(procs, anchors)...)
		for _, p := range candidates {
			if done[p.pid] {
				continue
			}
			done[p.pid] = true
			if why := protectedTarget(p); why != "" {
				rep.skipped = append(rep.skipped, fmt.Sprintf("%s (%s)", p.label(), why))
				continue
			}
			targets = append(targets, p)
		}
		if pass == 0 && root != nil {
			targets = append(targets, root) // root last
		}
		if len(targets) == 0 {
			break
		}
		// Freeze everything first so nothing spawns new children, then
		// terminate deepest-first.
		handles := make([]windows.Handle, len(targets))
		for i, p := range targets {
			handles[i] = suspend(p)
		}
		for i, p := range targets {
			if ctx.Err() != nil {
				if handles[i] != 0 {
					_ = ntCall(procNtResumeProcess, handles[i])
					windows.CloseHandle(handles[i])
				}
				rep.failed = append(rep.failed, p.label()+" interrupted before termination")
				continue
			}
			rep.kill(p, handles[i])
			anchors[p.pid] = p.created
		}
	}
	if remaining, err := snapshotProcesses(); err != nil {
		rep.failed = append(rep.failed, "could not verify tree completion: "+err.Error())
	} else {
		for _, p := range remaining {
			if _, knownParent := anchors[p.ppid]; knownParent && p.created == 0 {
				rep.failed = append(rep.failed, p.label()+" has an unknown creation time; tree completion is unverified")
			}
		}
		for _, p := range collectDescendants(remaining, anchors) {
			rep.failed = append(rep.failed, p.label()+" remains running")
		}
		for _, p := range retainedDescendants(remaining, processlineage.Default.Tree(rootID, time.Now())) {
			rep.failed = append(rep.failed, p.label()+" remains running (retained lineage)")
		}
	}
	if root == nil {
		rep.failed = append(rep.failed, "verified descendants were targeted; full tree completeness is unverified after root exit (retained observations are bounded and ETW loss cannot be excluded)")
	}

	summary := fmt.Sprintf("Process tree of PID %d: terminated %d", pid, len(rep.killed))
	if len(rep.killed) > 0 {
		summary += ": " + strings.Join(rep.killed, ", ")
	}
	if len(rep.skipped) > 0 {
		summary += "; skipped: " + strings.Join(rep.skipped, ", ")
	}
	if len(rep.failed) > 0 {
		return summary, fmt.Errorf("%s; FAILED: %s", summary, strings.Join(rep.failed, ", "))
	}
	return summary + ".", nil
}

func processIdentity(pid uint32, ft int64) processlineage.Identity {
	if ft == 0 {
		return processlineage.Identity{}
	}
	t := windows.Filetime{LowDateTime: uint32(ft), HighDateTime: uint32(uint64(ft) >> 32)}
	return processlineage.Identity{PID: pid, Started: t.Nanoseconds()}
}

// Only the same live generation may be selected from historical lineage.
// A reused parent PID never substitutes its new descendants for old orphans.
func retainedDescendants(procs map[uint32]*procEntry, tree processlineage.Tree) []*procEntry {
	var out []*procEntry
	for _, id := range tree.Descendants {
		if p := procs[id.PID]; p != nil && processIdentity(p.pid, p.created) == id {
			out = append(out, p)
		}
	}
	return out
}
