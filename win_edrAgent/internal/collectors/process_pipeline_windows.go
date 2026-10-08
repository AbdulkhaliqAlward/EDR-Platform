//go:build windows
// +build windows

package collectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/edr-platform/win-agent/internal/event"
	"github.com/edr-platform/win-agent/internal/logging"
	"github.com/edr-platform/win-agent/internal/processlineage"
)

// =====================================================================
// Collector (the CGO kernel-session part lives in etw.go)
// =====================================================================

const (
	procQueueSize  = 8192 // process start/end jobs (detection-critical)
	procWorkers    = 4
	asyncQueueSize = 8192 // image-load / file-I/O jobs (high volume)
	asyncWorkers   = 4
)

type procJob struct {
	start     bool
	pid, ppid uint32
	img, cmd  string
	at        time.Time
}

type ETWCollector struct {
	logger    *logging.Logger
	eventChan chan<- *event.Event
	filter    *Filter
	session   string
	running   atomic.Bool
	collected atomic.Uint64
	dropped   atomic.Uint64
	errors    atomic.Uint64

	// Config toggles for event types handled by the same kernel session.
	fileEnabled      bool
	imageLoadEnabled bool

	// Optional autonomous file response (local hash DB + quarantine).
	fileAutoResp FileAutoResponse
	// Optional autonomous process response (rule-pack driven terminate).
	processAutoResp ProcessAutoResponse

	// Per-type metrics
	fileEvents      atomic.Uint64
	imageLoadEvents atomic.Uint64

	// Bounded worker pools: the ETW callback never blocks and never spawns
	// unbounded goroutines; a full queue drops (and counts) the job.
	procQueue    chan procJob
	asyncQueue   chan func()
	queueDropped atomic.Uint64
	lifecycleMu  sync.Mutex
	workerCtx    context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	done         chan struct{}
}

var globalCollector atomic.Pointer[ETWCollector]

func NewETWCollector(session string, ch chan<- *event.Event, l *logging.Logger, filter *Filter, fileEnabled, imageLoadEnabled bool) *ETWCollector {
	if session == "" {
		session = "EDRKernelTrace"
	}
	return &ETWCollector{
		logger:           l,
		eventChan:        ch,
		filter:           filter,
		session:          session,
		fileEnabled:      fileEnabled,
		imageLoadEnabled: imageLoadEnabled,
		procQueue:        make(chan procJob, procQueueSize),
		asyncQueue:       make(chan func(), asyncQueueSize),
	}
}

// SetFileAutoResponse registers optional local hash-match quarantine (nil disables).
func (c *ETWCollector) SetFileAutoResponse(h FileAutoResponse) {
	c.fileAutoResp = h
}

// SetProcessAutoResponse registers optional local process auto-response (nil disables).
func (c *ETWCollector) SetProcessAutoResponse(h ProcessAutoResponse) {
	c.processAutoResp = h
}

func (c *ETWCollector) Start(ctx context.Context) error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.running.Load() {
		return fmt.Errorf("already running")
	}
	if c.done != nil {
		select {
		case <-c.done:
		default:
			return fmt.Errorf("previous ETW workers are still stopping")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.procQueue = make(chan procJob, procQueueSize)
	c.asyncQueue = make(chan func(), asyncQueueSize)
	ctx, c.cancel = context.WithCancel(ctx)
	c.workerCtx = ctx
	c.running.Store(true)
	globalCollector.Store(c)
	c.startWorkers(ctx)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer c.running.Store(false)
		defer globalCollector.CompareAndSwap(c, nil)
		c.run(ctx)
	}()
	c.done = make(chan struct{})
	done := c.done
	go func() { c.wg.Wait(); close(done) }()
	return nil
}

func (c *ETWCollector) Stop() error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.running.Store(false)
	globalCollector.CompareAndSwap(c, nil)
	if c.cancel != nil {
		c.cancel()
	}
	if c.done != nil {
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("ETW shutdown timed out; workers still stopping")
		}
	}
	c.logger.Infof("ETW stats: process=%d imageload=%d fileio=%d dropped=%d (queue-full=%d) errors=%d",
		c.collected.Load(), c.imageLoadEvents.Load(), c.fileEvents.Load(),
		c.dropped.Load(), c.queueDropped.Load(), c.errors.Load())
	return nil
}

func (c *ETWCollector) startWorkers(ctx context.Context) {
	for i := 0; i < procWorkers; i++ {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-c.procQueue:
					if ctx.Err() != nil {
						return
					}
					c.safely(func() {
						if j.start {
							c.processStart(j)
						} else {
							c.processEnd(j)
						}
					})
				}
			}
		}()
	}
	for i := 0; i < asyncWorkers; i++ {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case fn := <-c.asyncQueue:
					if ctx.Err() != nil {
						return
					}
					c.safely(fn)
				}
			}
		}()
	}
	c.wg.Add(1)
	go func() { defer c.wg.Done(); procTable.sweepLoop(ctx) }()
}

func (c *ETWCollector) safely(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			processlineage.Default.Gap(time.Now())
			c.errors.Add(1)
			c.logger.Errorf("[ETW] worker panic recovered: %v", r)
		}
	}()
	fn()
}

// enqueueProcess hands a process start/end to the worker pool (never blocks
// the ETW consumer thread).
func (c *ETWCollector) enqueueProcess(j procJob) {
	select {
	case c.procQueue <- j:
	default:
		c.queueDropped.Add(1)
		c.dropped.Add(1)
		processlineage.Default.Gap(time.Now())
	}
}

// enqueueAsync hands an image-load / file job to the worker pool.
func (c *ETWCollector) enqueueAsync(fn func()) {
	select {
	case c.asyncQueue <- fn:
	default:
		c.queueDropped.Add(1)
		c.dropped.Add(1)
	}
}

func (c *ETWCollector) run(ctx context.Context) {
	c.logger.Info("[BASELINE] Seeding process table from a live snapshot...")
	snap := seedProcessTable()
	c.logger.Infof("[BASELINE] %d running processes recorded; snapshot events are emitted in the background", len(snap))
	c.wg.Add(1)
	go func() { defer c.wg.Done(); c.emitSnapshot(ctx, snap) }()

	c.logger.Infof("[ETW] Starting kernel tracer (Process=ON, ImageLoad=%v, FileIO=%v)",
		c.imageLoadEnabled, c.fileEnabled)
	for ctx.Err() == nil && c.running.Load() {
		if err := c.session_(ctx); err != nil && ctx.Err() == nil && c.running.Load() {
			c.logger.Errorf("[ETW] Session error: %v — restarting in 3s", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
	c.logger.Info("[ETW] Tracer stopped")
}

// =====================================================================
// Process table and self (agent) tracking
// =====================================================================

// procRecord is what the agent knows about a process. Records of exited
// processes are kept briefly (tombstones) so the parent of a process started
// by a short-lived parent can still be resolved.
type procRecord struct {
	pid, ppid        uint32
	created          time.Time
	creationMeasured bool
	image            string
	cmdline          string
	self             bool // the EDR agent or a process it (transitively) started
	exited           time.Time
}

const (
	tombstoneTTL      = 3 * time.Minute
	creationTolerance = 2 * time.Second
	maxProcTableSize  = 65536
)

type processTable struct {
	mu sync.RWMutex
	m  map[uint32]*procRecord
}

var procTable = &processTable{m: make(map[uint32]*procRecord, 1024)}

var (
	agentPID     = uint32(os.Getpid())
	agentExePath = func() string {
		p, err := os.Executable()
		if err != nil {
			return ""
		}
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		return strings.ToLower(p)
	}()
)

func isAgentImage(path string) bool {
	return agentExePath != "" && strings.EqualFold(path, agentExePath)
}

func (t *processTable) put(r *procRecord) {
	t.mu.Lock()
	if len(t.m) >= maxProcTableSize {
		t.pruneLocked(time.Now(), true)
	}
	// Late workers for an older PID generation must not replace its new owner.
	if old := t.m[r.pid]; old != nil && old.created.After(r.created) {
		t.mu.Unlock()
		return
	}
	copy := *r
	t.m[r.pid] = &copy
	t.mu.Unlock()
}

func (t *processTable) get(pid uint32) *procRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	r := t.m[pid]
	if r == nil {
		return nil
	}
	copy := *r
	return &copy
}

func (t *processTable) markExited(pid uint32, at time.Time) *procRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.m[pid]
	if r != nil && r.created.After(at) {
		return nil
	}
	if r != nil && r.exited.IsZero() {
		r.exited = at
	}
	if r == nil {
		return nil
	}
	copy := *r
	return &copy
}

// parentOf returns the record of ppid only if it is consistent in time with
// a child created at childCreated: the parent existed before the child (PIDs
// are reused, so a newer process with that PID is not the parent).
func (t *processTable) parentOf(ppid uint32, childCreated time.Time) *procRecord {
	r := t.get(ppid)
	if r == nil {
		return nil
	}
	if !r.created.IsZero() && r.created.After(childCreated.Add(creationTolerance)) {
		return nil
	}
	if !r.exited.IsZero() && r.exited.Before(childCreated.Add(-creationTolerance)) {
		return nil
	}
	return r
}

func (t *processTable) pruneLocked(now time.Time, aggressive bool) {
	ttl := tombstoneTTL
	if aggressive {
		ttl = 0
	}
	for pid, r := range t.m {
		if !r.exited.IsZero() && now.Sub(r.exited) > ttl {
			delete(t.m, pid)
		}
	}
}

func (t *processTable) sweepLoop(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			t.mu.Lock()
			t.pruneLocked(now, false)
			t.mu.Unlock()
		}
	}
}

// etwProcessTracerActive reports whether the ETW kernel process tracer runs
// (then other collectors must not emit duplicate process-creation events).
func etwProcessTracerActive() bool {
	c := globalCollector.Load()
	return c != nil && c.IsRunning()
}

// isSelfPID reports whether pid is the agent or a process it started. It is
// based on process ancestry recorded from kernel events, never on names or
// command-line content (both are attacker-controllable).
func isSelfPID(pid uint32) bool {
	if pid == 0 {
		return false
	}
	if pid == agentPID {
		return true
	}
	if r := procTable.get(pid); r != nil {
		return r.self && r.exited.IsZero() && r.creationMeasured && processCreateTime(pid).Equal(r.created)
	}
	return false
}

// processCreateTime returns the creation time of a live process.
func processCreateTime(pid uint32) time.Time {
	if pid <= 4 {
		return time.Time{}
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return time.Time{}
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return time.Time{}
	}
	return time.Unix(0, c.Nanoseconds())
}

// seedProcessTable records every running process (fast: no file I/O beyond
// image path / command line) and resolves the agent's own process tree.
func seedProcessTable() []*procRecord {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var recs []*procRecord
	if windows.Process32First(snap, &e) == nil {
		for {
			r := &procRecord{pid: e.ProcessID, ppid: e.ParentProcessID, created: processCreateTime(e.ProcessID)}
			r.creationMeasured = !r.created.IsZero()
			r.image = getImagePath(r.pid)
			if r.image == "" {
				r.image = windows.UTF16ToString(e.ExeFile[:])
			}
			r.cmdline = getCmdLine(r.pid)
			r.self = r.pid == agentPID || isAgentImage(r.image)
			recs = append(recs, r)
			if windows.Process32Next(snap, &e) != nil {
				break
			}
		}
	}
	byPID := make(map[uint32]*procRecord, len(recs))
	for _, r := range recs {
		byPID[r.pid] = r
	}
	// Propagate "self" down the tree (children created after their parent).
	for changed := true; changed; {
		changed = false
		for _, r := range recs {
			if r.self {
				continue
			}
			if p := byPID[r.ppid]; p != nil && p.self && p.pid != r.pid &&
				(p.created.IsZero() || r.created.IsZero() || !p.created.After(r.created.Add(creationTolerance))) {
				r.self = true
				changed = true
			}
		}
	}
	for _, r := range recs {
		procTable.put(r)
		recordProcessLineage(r, byPID[r.ppid], time.Now())
	}
	return recs
}

// =====================================================================
// Trusted OS processes (verified by location, not by name)
// =====================================================================

// trustedOSProcesses are Windows shell / OS infrastructure processes that
// start constantly with no security signal. A process is trusted ONLY when
// it runs from its genuine Windows location: malware named "conhost.exe" in
// a user directory must remain fully visible.
var trustedOSProcesses = func() map[string][]string {
	root := strings.ToLower(os.Getenv("SystemRoot"))
	if root == "" {
		root = `c:\windows`
	}
	sys32 := root + `\system32\`
	pf86 := strings.ToLower(os.Getenv("ProgramFiles(x86)"))
	if pf86 == "" {
		pf86 = `c:\program files (x86)`
	}
	return map[string][]string{
		"conhost.exe":               {sys32},
		"wmiprvse.exe":              {sys32 + `wbem\`},
		"backgroundtaskhost.exe":    {sys32},
		"applicationframehost.exe":  {sys32},
		"gamebarpresencewriter.exe": {sys32},
		"textinputhost.exe":         {root + `\systemapps\microsoftwindows.client.cbs_cw5n1h2txyewy\`, root + `\systemapps\microsoftwindows.client.core_cw5n1h2txyewy\`},
		"systemsettings.exe":        {root + `\immersivecontrolpanel\`},
		"searchprotocolhost.exe":    {sys32},
		"searchfilterhost.exe":      {sys32},
		"audiodg.exe":               {sys32},
		"fontdrvhost.exe":           {sys32},
		"dashost.exe":               {sys32},
		"ctfmon.exe":                {sys32},
		"sihost.exe":                {sys32},
		"compattelrunner.exe":       {sys32},
		"musnotification.exe":       {sys32},
		"wuauclt.exe":               {sys32},
		"microsoftedgeupdate.exe":   {pf86 + `\microsoft\edgeupdate\`},
	}
}()

func isTrustedOSProcess(exePath string) bool {
	if !strings.Contains(exePath, `\`) {
		return false // location unknown: cannot be verified
	}
	low := strings.ToLower(exePath)
	dirs := trustedOSProcesses[filepath.Base(low)]
	dir := filepath.Dir(low) + `\`
	for _, d := range dirs {
		if dir == d {
			return true
		}
	}
	return false
}

// =====================================================================
// Process events
// =====================================================================

var (
	dedupMu    sync.Mutex
	dedupCache = make(map[processlineage.Identity]int64, 64)
	dedupSweep int64
)

// isDuplicate suppresses a second start event for the same PID within 2 s
// (the kernel provider can deliver DCStart/Start pairs).
func isDuplicate(id processlineage.Identity) bool {
	if id.Started <= 0 {
		return false
	}
	now := time.Now().UnixNano()
	dedupMu.Lock()
	defer dedupMu.Unlock()
	if now-dedupSweep > 1_000_000_000 {
		for k, ts := range dedupCache {
			if now-ts > 2_000_000_000 {
				delete(dedupCache, k)
			}
		}
		dedupSweep = now
	}
	if t, ok := dedupCache[id]; ok && now-t < 2_000_000_000 {
		return true
	}
	dedupCache[id] = now
	return false
}

// imageFromCommandLine extracts an absolute executable path from the first
// command-line token (used when a short-lived process exited before its
// image could be queried and ETW supplied only the short image name).
func imageFromCommandLine(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	var tok string
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			tok = cmd[1 : end+1]
		}
	} else if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		tok = cmd[:i]
	} else {
		tok = cmd
	}
	if len(tok) > 3 && tok[1] == ':' && tok[2] == '\\' && strings.HasSuffix(strings.ToLower(tok), ".exe") {
		return tok
	}
	return ""
}

func (c *ETWCollector) processStart(j procJob) {
	pid, ppid := j.pid, j.ppid
	created := processCreateTime(pid)
	creationMeasured := !created.IsZero() && !created.After(j.at)
	if creationMeasured && isDuplicate(processlineage.Identity{PID: pid, Started: created.UnixNano()}) {
		return
	}
	exePath, cmdLine := "", ""
	if creationMeasured {
		exePath, cmdLine = getImagePath(pid), getCmdLine(pid)
		// Do not attach a replacement process's image/command to older ETW data.
		if again := processCreateTime(pid); !again.Equal(created) {
			creationMeasured = false
			exePath, cmdLine = "", ""
		}
	}
	if exePath == "" {
		exePath = j.img
	}
	if cmdLine == "" {
		cmdLine = j.cmd
	}
	if !strings.Contains(exePath, `\`) {
		if p := imageFromCommandLine(cmdLine); p != "" {
			exePath = p
		}
	}
	if !creationMeasured {
		created = j.at
	}

	parent := procTable.parentOf(ppid, created)
	rec := &procRecord{pid: pid, ppid: ppid, created: created, creationMeasured: creationMeasured, image: exePath, cmdline: cmdLine}
	rec.self = isAgentImage(exePath) || (parent != nil && parent.self) || ppid == agentPID
	procTable.put(rec)
	if creationMeasured {
		// Only a measured parent generation born before this child is used.
		parentCreated := processCreateTime(ppid)
		if !parentCreated.IsZero() && !parentCreated.After(created) {
			parentID := processlineage.Identity{PID: ppid, Started: parentCreated.UnixNano()}
			processlineage.Default.Record(parentID, processlineage.Identity{}, j.at)
			processlineage.Default.Record(processlineage.Identity{PID: pid, Started: created.UnixNano()}, parentID, j.at)
		} else {
			// A retained parent with a measured start and an observed exit
			// after this birth also proves the generation of a short-lived parent.
			if parent != nil && !parent.exited.IsZero() {
				recordProcessLineage(rec, parent, j.at)
			} else {
				recordProcessLineage(rec, nil, j.at)
			}
		}
	} else {
		processlineage.Default.Gap(j.at)
	}
	if rec.self {
		return // the agent's own helper tree: no telemetry
	}
	if isTrustedOSProcess(exePath) {
		return
	}

	name := baseName(exePath)
	if name == "" {
		name = exePath
	}
	if cmdLine == "" {
		cmdLine = exePath
	}

	parentImage, parentCmd := "", ""
	if parent != nil {
		parentImage, parentCmd = parent.image, parent.cmdline
	} else if pc := processCreateTime(ppid); !pc.IsZero() && !pc.After(created.Add(creationTolerance)) {
		// Parent not seen yet (e.g. agent restart) but alive and older than
		// the child: it is the real parent.
		parentImage, parentCmd = getImagePath(ppid), getCmdLine(ppid)
	}

	userSid, userName, isElevated, integrity := getPrivileges(pid)
	id := FileIdentityOf(exePath)

	data := map[string]interface{}{
		"action":              "process_creation",
		"pid":                 pid,
		"ppid":                ppid,
		"name":                name,
		"executable":          exePath,
		"command_line":        cmdLine,
		"parent_executable":   parentImage,
		"parent_name":         baseName(parentImage),
		"parent_command_line": parentCmd,
		"user_sid":            userSid,
		"user_name":           userName,
		"is_elevated":         isElevated,
		"integrity_level":     integrity,
		"signature_status":    id.SignatureStatus,
		"signature_issuer":    id.Signer,
		"original_file_name":  id.OriginalFileName,
		"company":             id.Company,
		"product":             id.Product,
		"description":         id.Description,
	}
	if creationMeasured {
		data["process_start_time"] = created.UTC().Format(time.RFC3339Nano)
	}
	if id.SHA256 != "" {
		data["sha256"] = id.SHA256
		data["hashes"] = "SHA256=" + strings.ToUpper(id.SHA256)
	}
	evt := event.NewEvent(event.EventTypeProcess, event.SeverityLow, data)

	// Apply configurable process filtering BEFORE local autonomous response.
	// This ensures server-pushed allow exceptions (exclude_process) prevent
	// both telemetry noise and accidental auto-terminate decisions.
	if c.filter != nil && c.filter.ShouldFilter(evt) {
		return
	}

	if c.processAutoResp != nil {
		actionCtx := c.workerCtx
		if actionCtx == nil {
			actionCtx = context.Background()
		}
		actionCtx, cancel := context.WithTimeout(actionCtx, 30*time.Second)
		defer cancel()
		if alt, stop := c.processAutoResp.EvaluateAndAct(actionCtx, evt.Data); stop {
			if alt != nil {
				if c.filter != nil && c.filter.ShouldFilter(alt) {
					return
				}
				c.send(alt)
			}
			return
		}
	}
	c.sendPriority(evt)
	c.logger.Debugf("[ETW] Process START: pid=%d ppid=%d name=%s cmd=%s",
		pid, ppid, name, truncStr(cmdLine, 80))
}

func recordProcessLineage(r, parent *procRecord, at time.Time) {
	if r == nil || !r.creationMeasured {
		return
	}
	var parentID processlineage.Identity
	if parent != nil && parent.creationMeasured && !parent.created.After(r.created) &&
		(parent.exited.IsZero() || !parent.exited.Before(r.created)) {
		parentID = processlineage.Identity{PID: parent.pid, Started: parent.created.UnixNano()}
	}
	processlineage.Default.Record(processlineage.Identity{PID: r.pid, Started: r.created.UnixNano()}, parentID, at)
}

func (c *ETWCollector) processEnd(j procJob) {
	rec := procTable.markExited(j.pid, j.at)
	if rec != nil && rec.self {
		return
	}
	img := ""
	if rec != nil {
		img = rec.image
	}
	if img == "" {
		img = j.img
	}
	name := baseName(img)
	if name == "" || isTrustedOSProcess(img) {
		return
	}
	evt := event.NewEvent(event.EventTypeProcess, event.SeverityLow, map[string]interface{}{
		"action":     "process_termination",
		"pid":        j.pid,
		"ppid":       j.ppid,
		"name":       name,
		"executable": img,
	})
	if c.filter != nil && c.filter.ShouldFilter(evt) {
		return
	}
	c.sendPriority(evt)
}

// emitSnapshot sends one "snapshot" event per running process (inventory at
// agent start; not counted as executions by UEBA).
func (c *ETWCollector) emitSnapshot(ctx context.Context, recs []*procRecord) {
	byPID := make(map[uint32]*procRecord, len(recs))
	for _, r := range recs {
		byPID[r.pid] = r
	}
	for _, r := range recs {
		if ctx.Err() != nil {
			return
		}
		if r.self || r.pid <= 4 || isTrustedOSProcess(r.image) {
			continue
		}
		var pimg, pcmd string
		if p := byPID[r.ppid]; p != nil && (p.created.IsZero() || !p.created.After(r.created.Add(creationTolerance))) {
			pimg, pcmd = p.image, p.cmdline
		}
		cmd := r.cmdline
		if cmd == "" {
			cmd = r.image
		}
		sid, user, elev, integ := getPrivileges(r.pid)
		id := FileIdentityOf(r.image)
		data := map[string]interface{}{
			"action": "snapshot", "pid": r.pid, "ppid": r.ppid,
			"name": baseName(r.image), "executable": r.image, "command_line": cmd,
			"parent_name": baseName(pimg), "parent_executable": pimg, "parent_command_line": pcmd,
			"user_sid": sid, "user_name": user,
			"is_elevated": elev, "integrity_level": integ,
			"signature_status": id.SignatureStatus, "signature_issuer": id.Signer,
			"original_file_name": id.OriginalFileName, "company": id.Company,
			"product": id.Product, "description": id.Description,
		}
		if r.creationMeasured {
			data["process_start_time"] = r.created.UTC().Format(time.RFC3339Nano)
		}
		if id.SHA256 != "" {
			data["sha256"] = id.SHA256
			data["hashes"] = "SHA256=" + strings.ToUpper(id.SHA256)
		}
		c.send(event.NewEvent(event.EventTypeProcess, event.SeverityLow, data))
	}
}

// =====================================================================
// Windows API Helpers
// =====================================================================

func getImagePath(pid uint32) string {
	if pid == 0 || pid == 4 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	sz := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &sz) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:sz])
}

var (
	ntdll = windows.NewLazyDLL("ntdll.dll")
	ntqip = ntdll.NewProc("NtQueryInformationProcess")
)

func getCmdLine(pid uint32) string {
	if pid == 0 || pid == 4 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	const infoCls = 60 // ProcessCommandLineInformation
	var retLen uint32
	buf := make([]byte, 1024)
	r, _, _ := ntqip.Call(uintptr(h), infoCls,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)))

	if r == 0xC0000004 && retLen > 0 && retLen < 65536 {
		buf = make([]byte, retLen)
		r, _, _ = ntqip.Call(uintptr(h), infoCls,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&retLen)))
	}
	if r != 0 || retLen < 8 {
		return ""
	}

	length := *(*uint16)(unsafe.Pointer(&buf[0]))
	if length == 0 || int(length)+16 > len(buf) {
		return ""
	}
	ptr := *(*uintptr)(unsafe.Pointer(&buf[8]))
	base := uintptr(unsafe.Pointer(&buf[0]))
	off := int(ptr - base)
	if off < 0 || off+int(length) > len(buf) {
		return ""
	}
	s := make([]uint16, length/2)
	for i := range s {
		s[i] = *(*uint16)(unsafe.Pointer(&buf[off+i*2]))
	}
	return windows.UTF16ToString(s)
}

func getPrivileges(pid uint32) (sid, user string, elevated bool, integrity string) {
	if pid == 0 || pid == 4 {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)

	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) != nil {
		return
	}
	defer tok.Close()

	if u, err := tok.GetTokenUser(); err == nil {
		sid = u.User.Sid.String()
		if acct, dom, _, err := u.User.Sid.LookupAccount(""); err == nil {
			user = dom + `\` + acct
		}
	}
	elevated = tok.IsElevated()

	var isz uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &isz)
	if isz > 0 {
		ib := make([]byte, isz)
		if windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &ib[0], isz, &isz) == nil {
			tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&ib[0]))
			switch tml.Label.Sid.String() {
			case "S-1-16-4096":
				integrity = "Low"
			case "S-1-16-8192":
				integrity = "Medium"
			case "S-1-16-12288":
				integrity = "High"
			case "S-1-16-16384":
				integrity = "System"
			default:
				integrity = tml.Label.Sid.String()
			}
		}
	}
	return
}

// =====================================================================
// Utility
// =====================================================================

func (c *ETWCollector) send(evt *event.Event) {
	select {
	case c.eventChan <- evt:
		c.collected.Add(1)
	default:
		c.dropped.Add(1)
	}
}

// sendPriority sends a high-value event (process creation, registry) with a
// blocking timeout instead of dropping immediately. This prevents the flood of
// file I/O events from silently drowning out security-critical process telemetry.
func (c *ETWCollector) sendPriority(evt *event.Event) {
	select {
	case c.eventChan <- evt:
		c.collected.Add(1)
	case <-time.After(2 * time.Second):
		c.dropped.Add(1)
		c.logger.Warnf("[ETW] Priority event DROPPED after 2s timeout (channel full): type=%s", evt.Type)
	}
}

func baseName(p string) string {
	if i := strings.LastIndex(p, `\`); i >= 0 {
		return p[i+1:]
	}
	if i := strings.LastIndex(p, `/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Public API for agent
func (c *ETWCollector) IsRunning() bool { return c.running.Load() }
func (c *ETWCollector) Stats() ETWStats {
	return ETWStats{c.running.Load(), c.collected.Load(), c.dropped.Load(), c.errors.Load()}
}

type ETWStats struct {
	Running         bool
	EventsCollected uint64
	EventsDropped   uint64
	Errors          uint64
}
