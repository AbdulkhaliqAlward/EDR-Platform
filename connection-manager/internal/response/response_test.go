package response

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeStore struct {
	mu         sync.Mutex
	alerts     map[uuid.UUID]*repository.SigmaAlertRecord
	executions map[uuid.UUID]*repository.ExecutionRecord
	reserved   map[string]bool
	inbox      map[uuid.UUID]string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		alerts:     map[uuid.UUID]*repository.SigmaAlertRecord{},
		executions: map[uuid.UUID]*repository.ExecutionRecord{},
		reserved:   map[string]bool{},
		inbox:      map[uuid.UUID]string{},
	}
}

func (f *fakeStore) GetSigmaAlert(_ context.Context, id uuid.UUID) (*repository.SigmaAlertRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.alerts[id]; ok {
		return a, nil
	}
	return nil, repository.ErrNotFound
}
func (f *fakeStore) ListUnclaimedSigmaAlerts(context.Context, time.Time, time.Duration, int) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []uuid.UUID
	for id := range f.alerts {
		if _, done := f.inbox[id]; !done {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
func (f *fakeStore) ClaimSigmaAlert(_ context.Context, id uuid.UUID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.inbox[id]; ok {
		return false, nil
	}
	f.inbox[id] = ""
	return true, nil
}
func (f *fakeStore) CompleteInbox(_ context.Context, id uuid.UUID, outcome string) error {
	f.mu.Lock()
	f.inbox[id] = outcome
	f.mu.Unlock()
	return nil
}
func (f *fakeStore) CleanupInbox(context.Context, time.Duration) (int64, error) { return 0, nil }
func (f *fakeStore) GetOrInitState(_ context.Context, _, def string) (string, error) {
	return def, nil
}
func (f *fakeStore) ReserveRule(_ context.Context, id, agent uuid.UUID, _ int) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := id.String() + "|" + agent.String()
	if f.reserved[key] {
		return false, nil
	}
	f.reserved[key] = true
	return true, nil
}
func (f *fakeStore) RefreshRuleSuccessRate(context.Context, uuid.UUID) error { return nil }
func (f *fakeStore) CreateExecution(_ context.Context, e *repository.ExecutionRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.executions {
		if e.RuleID != nil && x.RuleID != nil && *x.RuleID == *e.RuleID && e.AlertID != nil && x.AlertID != nil && *x.AlertID == *e.AlertID {
			return repository.ErrDuplicateExecution
		}
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	e.StartedAt = time.Now()
	cp := *e
	f.executions[e.ID] = &cp
	return nil
}
func (f *fakeStore) UpdateExecution(_ context.Context, e *repository.ExecutionRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *e
	f.executions[e.ID] = &cp
	return nil
}
func (f *fakeStore) FailOrphanedExecutions(context.Context, time.Duration) (int64, error) {
	return 0, nil
}
func (f *fakeStore) get(id uuid.UUID) *repository.ExecutionRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *f.executions[id]
	return &cp
}

type fakeCommands struct {
	repository.CommandRepository
	mu   sync.Mutex
	cmds map[uuid.UUID]*models.Command
}

func (f *fakeCommands) Create(_ context.Context, c *models.Command) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c.ExpiresAt = c.IssuedAt.Add(time.Duration(c.TimeoutSeconds) * time.Second)
	cp := *c
	f.cmds[c.ID] = &cp
	return nil
}
func (f *fakeCommands) GetByID(_ context.Context, id uuid.UUID) (*models.Command, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.cmds[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	cp := *c
	return &cp, nil
}
func (f *fakeCommands) UpdateStatus(_ context.Context, id uuid.UUID, st models.CommandStatus, res map[string]any, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.cmds[id]; ok {
		c.Status, c.ErrorMessage = st, msg
		if res != nil {
			c.Result = res
		}
	}
	return nil
}

// fakeDispatcher simulates the agent: after Send, it reports a result
// (through the command store, as the gRPC result handler does).
type fakeDispatcher struct {
	mu       sync.Mutex
	online   bool
	cmds     *fakeCommands
	failType map[string]bool // command types the "agent" fails
	sent     []*edrv1.Command
}

func (d *fakeDispatcher) IsOnline(string) bool { return d.online }
func (d *fakeDispatcher) Send(_ string, c *edrv1.Command) error {
	d.mu.Lock()
	d.sent = append(d.sent, c)
	d.mu.Unlock()
	id, _ := uuid.Parse(c.CommandId)
	go func() {
		time.Sleep(5 * time.Millisecond)
		cmd, _ := d.cmds.GetByID(context.Background(), id)
		if d.failType[string(cmd.CommandType)] {
			_ = d.cmds.UpdateStatus(context.Background(), id, models.CommandStatusFailed, map[string]any{"output": "boom"}, "agent: boom")
			return
		}
		_ = d.cmds.UpdateStatus(context.Background(), id, models.CommandStatusCompleted, map[string]any{"output": "ok"}, "")
	}()
	return nil
}

type fakePlaybooks struct {
	repository.ResponsePlaybookRepository
	items map[uuid.UUID]*models.ResponsePlaybook
}

func (f *fakePlaybooks) GetByID(_ context.Context, id uuid.UUID) (*models.ResponsePlaybook, error) {
	if p, ok := f.items[id]; ok {
		return p, nil
	}
	return nil, repository.ErrNotFound
}

type fakeRules struct {
	repository.AutomationRuleRepository
	items []*models.AutomationRule
}

func (f *fakeRules) List(context.Context) ([]*models.AutomationRule, error) { return f.items, nil }

type fakeScripts struct {
	items map[uuid.UUID]*repository.ResponseScript
}

func (f *fakeScripts) GetByID(_ context.Context, id uuid.UUID) (*repository.ResponseScript, error) {
	if s, ok := f.items[id]; ok {
		return s, nil
	}
	return nil, repository.ErrNotFound
}

type fakeAgents struct{ items map[uuid.UUID]*models.Agent }

func (f *fakeAgents) GetByID(_ context.Context, id uuid.UUID) (*models.Agent, error) {
	if a, ok := f.items[id]; ok {
		return a, nil
	}
	return nil, repository.ErrNotFound
}

// ── fixture ──────────────────────────────────────────────────────────────────

type fixture struct {
	e        *Engine
	store    *fakeStore
	cmds     *fakeCommands
	disp     *fakeDispatcher
	pbs      *fakePlaybooks
	rules    *fakeRules
	scripts  *fakeScripts
	agentID  uuid.UUID
	alertID  uuid.UUID
	scriptID uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	f := &fixture{
		store:    newFakeStore(),
		cmds:     &fakeCommands{cmds: map[uuid.UUID]*models.Command{}},
		pbs:      &fakePlaybooks{items: map[uuid.UUID]*models.ResponsePlaybook{}},
		rules:    &fakeRules{},
		agentID:  uuid.New(),
		alertID:  uuid.New(),
		scriptID: uuid.New(),
	}
	f.disp = &fakeDispatcher{online: true, cmds: f.cmds, failType: map[string]bool{}}
	f.scripts = &fakeScripts{items: map[uuid.UUID]*repository.ResponseScript{
		f.scriptID: {ID: f.scriptID, Name: "List tasks", Cmd: `powershell -Command "Get-ScheduledTask"`, Enabled: true},
	}}
	agents := &fakeAgents{items: map[uuid.UUID]*models.Agent{f.agentID: {ID: f.agentID, Hostname: "WS-01", Status: "online"}}}
	f.store.alerts[f.alertID] = &repository.SigmaAlertRecord{
		ID: f.alertID.String(), AgentID: "agent-" + f.agentID.String(), RuleID: "r1",
		RuleTitle: "Suspicious Ransomware Activity", Severity: "critical", RiskScore: 92,
		MitreTechniques: []string{"T1486"}, CreatedAt: time.Now(),
		ContextData: map[string]any{
			"event_type": "process",
			"data": map[string]any{
				"name": "evil.exe", "pid": float64(4242), "executable": `C:\Users\a\evil.exe`,
				"command_line": `evil.exe --encrypt`,
			},
		},
	}
	f.e = New(Config{AutoExecute: true, GRPCAddress: "srv:47051"}, logger, f.store, f.cmds, f.pbs, f.rules, f.scripts, agents, f.disp)
	f.e.commandPoll = 2 * time.Millisecond
	return f
}

func (f *fixture) addPlaybook(steps string) uuid.UUID {
	id := uuid.New()
	f.pbs.items[id] = &models.ResponsePlaybook{ID: id, Name: "PB", Enabled: true, Category: "containment",
		SeverityFilter: []string{"critical"}, RulePattern: "ransom", MITRETechiques: []string{"T1486"},
		Commands: json.RawMessage(steps)}
	return id
}

func waitDone(t *testing.T, f *fixture, id uuid.UUID) *repository.ExecutionRecord {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rec := f.store.get(id)
		if rec.CompletedAt != nil {
			return rec
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("execution did not finish")
	return nil
}

func steps(rec *repository.ExecutionRecord) []BoundStep {
	var s []BoundStep
	_ = json.Unmarshal(rec.Steps, &s)
	return s
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestConditions(t *testing.T) {
	a := &repository.SigmaAlertRecord{Severity: "High", RuleTitle: "LSASS Dump", RiskScore: 75}
	c, ok := ParseConditions(json.RawMessage(`{"severity":["critical","high"],"rule_patterns":["lsass"],"min_risk_score":70}`))
	if !ok || !c.Matches(a) {
		t.Fatal("AND of satisfied conditions must match")
	}
	c, _ = ParseConditions(json.RawMessage(`{"severity":["critical"],"rule_patterns":["lsass"]}`))
	if c.Matches(a) {
		t.Fatal("AND with one failing condition must not match")
	}
	c, _ = ParseConditions(json.RawMessage(`{"severity":["critical"],"rule_patterns":["lsass"],"logic_operator":"OR"}`))
	if !c.Matches(a) {
		t.Fatal("OR with one satisfied condition must match")
	}
	if _, ok := ParseConditions(json.RawMessage(`{"condition":"RuleName == 'x'"}`)); ok {
		t.Fatal("legacy free-text conditions must not be usable")
	}
	if _, ok := ParseConditions(json.RawMessage(`{}`)); ok {
		t.Fatal("empty conditions must never match everything")
	}
}

func TestPrepareBindsAlertContext(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[
	  {"type":"terminate_process","params":{"process_name":"vssadmin.exe","kill_tree":"true"},"timeout":60},
	  {"type":"quarantine_file","params":{"file_path":"{{alert.file_path}}"},"timeout":60},
	  {"type":"collect_forensics","params":{"log_types":"System,Security"},"timeout":60}
	]`)
	plan, err := f.e.Prepare(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready {
		t.Fatalf("plan should be ready: %+v", plan.Steps)
	}
	if plan.AgentID != f.agentID.String() {
		t.Fatalf("target must be the alert's agent (prefix stripped), got %s", plan.AgentID)
	}
	if got := plan.Steps[0].Params["pid"]; got != "4242" {
		t.Fatalf("terminate_process must bind the alert PID, got %q", got)
	}
	if got := plan.Steps[1].Params["file_path"]; got != `C:\Users\a\evil.exe` {
		t.Fatalf("template must resolve to the alert's file, got %q", got)
	}
	if _, ok := plan.Steps[0].Params["process_name"]; ok {
		t.Fatal("undeclared parameters must not reach the agent")
	}

	// Overrides may change declared parameters only.
	plan, err = f.e.Prepare(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID,
		Overrides: map[int]map[string]string{0: {"pid": "5000", "authz_tier": "library"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Steps[0].Params["pid"]; got != "5000" {
		t.Fatalf("override of a declared parameter must apply, got %q", got)
	}
	if _, ok := plan.Steps[0].Params["authz_tier"]; ok {
		t.Fatal("override must not inject undeclared parameters")
	}
}

func TestPrepareValidation(t *testing.T) {
	f := newFixture(t)
	// No PID on this alert → terminate cannot be bound.
	delete(f.store.alerts[f.alertID].ContextData["data"].(map[string]any), "pid")
	pb := f.addPlaybook(`[{"type":"terminate_process","timeout":60}, {"type":"run_cmd","params":{"cmd":"cmd /c del {{alert.file_path}}"}}]`)
	plan, err := f.e.Prepare(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ready || len(plan.Steps[0].Errors) == 0 {
		t.Fatal("missing PID must make the plan not ready")
	}
	if len(plan.Steps[1].Errors) == 0 || !strings.Contains(plan.Steps[1].Errors[0], "not allowed") {
		t.Fatalf("alert values must never be templated into command lines: %+v", plan.Steps[1])
	}

	other := uuid.New().String()
	if _, err := f.e.Prepare(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID, AgentID: other}); !errors.Is(err, ErrAgentMismatch) {
		t.Fatalf("running alert-bound steps on another host must be refused, got %v", err)
	}
	f.pbs.items[pb].Enabled = false
	if _, err := f.e.Prepare(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID}); !errors.Is(err, ErrPlaybookDisabled) {
		t.Fatalf("disabled playbooks must not run, got %v", err)
	}
}

func TestExecuteStatuses(t *testing.T) {
	cases := []struct {
		name   string
		steps  string
		fail   string
		status string
		want   []string
	}{
		{"all succeed", `[{"type":"isolate_network"},{"type":"collect_logs"}]`, "", "completed", []string{"success", "success"}},
		{"continue after failure", `[{"type":"collect_logs","on_failure":"continue"},{"type":"isolate_network"}]`, "collect_logs", "partial", []string{"failed", "success"}},
		{"stop on failure", `[{"type":"collect_logs"},{"type":"isolate_network"}]`, "collect_logs", "failed", []string{"failed", "skipped"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.fail != "" {
				f.disp.failType[tc.fail] = true
			}
			pb := f.addPlaybook(tc.steps)
			rec, _, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID, Username: "alice"})
			if err != nil {
				t.Fatal(err)
			}
			done := waitDone(t, f, rec.ID)
			if done.Status != tc.status {
				t.Fatalf("status %s, want %s (%s)", done.Status, tc.status, done.ErrorMessage)
			}
			for i, s := range steps(done) {
				if s.Status != tc.want[i] {
					t.Fatalf("step %d status %s, want %s", i, s.Status, tc.want[i])
				}
			}
		})
	}
}

func TestExecuteDispatchesLibraryScriptAtLibraryTier(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[{"type":"run_script","script_id":"` + f.scriptID.String() + `","timeout":30},{"type":"isolate_network"}]`)
	rec, _, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID})
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, f, rec.ID)
	f.disp.mu.Lock()
	defer f.disp.mu.Unlock()
	if len(f.disp.sent) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(f.disp.sent))
	}
	p := f.disp.sent[0].Parameters
	if p["cmd"] != `powershell -Command "Get-ScheduledTask"` || p["authz_tier"] != "library" {
		t.Fatalf("script must be loaded server-side at the library tier: %v", p)
	}
	if f.disp.sent[1].Parameters["server_address"] != "srv:47051" {
		t.Fatal("isolation must carry the server address so the agent keeps its connection")
	}
}

func TestStartRefusesOfflineAgent(t *testing.T) {
	f := newFixture(t)
	f.disp.online = false
	pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
	if _, _, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID}); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("expected offline error, got %v", err)
	}
}

func TestTriggerRunsMatchingAutoRuleOnce(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
	matching := &models.AutomationRule{ID: uuid.New(), Name: "ransom", PlaybookID: pb, Enabled: true, AutoExecute: true,
		TriggerConditions: json.RawMessage(`{"severity":["critical"],"rule_patterns":["ransomware"]}`)}
	manualOnly := &models.AutomationRule{ID: uuid.New(), Name: "manual", PlaybookID: pb, Enabled: true, AutoExecute: false,
		TriggerConditions: json.RawMessage(`{"severity":["critical"]}`)}
	nonMatching := &models.AutomationRule{ID: uuid.New(), Name: "low", PlaybookID: pb, Enabled: true, AutoExecute: true,
		TriggerConditions: json.RawMessage(`{"severity":["low"]}`)}
	f.rules.items = []*models.AutomationRule{matching, manualOnly, nonMatching}

	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute)) // re-delivery is a no-op

	f.store.mu.Lock()
	n := len(f.store.executions)
	outcome := f.store.inbox[f.alertID]
	var exec *repository.ExecutionRecord
	for _, e := range f.store.executions {
		exec = e
	}
	f.store.mu.Unlock()
	if n != 1 {
		t.Fatalf("exactly one automated execution expected, got %d (%s)", n, outcome)
	}
	if exec.RuleID == nil || *exec.RuleID != matching.ID || exec.TriggerSource != "automation" {
		t.Fatalf("execution must be attributed to the matching auto rule: %+v", exec)
	}
	waitDone(t, f, exec.ID)
}

func TestTriggerDisabledDoesNothing(t *testing.T) {
	f := newFixture(t)
	f.e.cfg.AutoExecute = false
	pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
	f.rules.items = []*models.AutomationRule{{ID: uuid.New(), PlaybookID: pb, Enabled: true, AutoExecute: true,
		TriggerConditions: json.RawMessage(`{"severity":["critical"]}`)}}
	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
	if len(f.store.executions) != 0 {
		t.Fatal("no automated run may start when auto-execution is disabled")
	}
}

func TestSuggestRanking(t *testing.T) {
	f := newFixture(t)
	a := f.store.alerts[f.alertID]
	good := &models.ResponsePlaybook{ID: uuid.New(), Name: "Ransomware", Enabled: true, Category: "containment",
		SeverityFilter: []string{"critical"}, RulePattern: "ransom|encrypt", MITRETechiques: []string{"T1486"}}
	excluded := &models.ResponsePlaybook{ID: uuid.New(), Name: "Low only", Enabled: true, SeverityFilter: []string{"low"}, RulePattern: "ransom"}
	disabled := &models.ResponsePlaybook{ID: uuid.New(), Name: "Off", Enabled: false, RulePattern: "ransom"}
	weak := &models.ResponsePlaybook{ID: uuid.New(), Name: "Generic", Enabled: true, Category: "containment"}
	rule := &models.AutomationRule{ID: uuid.New(), Name: "r", PlaybookID: weak.ID, Enabled: true,
		TriggerConditions: json.RawMessage(`{"severity":["critical"]}`)}

	got := Suggest(a, []*models.ResponsePlaybook{good, excluded, disabled, weak}, []*models.AutomationRule{rule}, 5)
	if len(got) != 2 {
		t.Fatalf("expected 2 suggestions (excluded/disabled filtered), got %+v", got)
	}
	if got[0].PlaybookID != good.ID.String() {
		t.Fatalf("best metadata match should rank first: %+v", got)
	}
	if got[1].RuleID != rule.ID.String() {
		t.Fatal("a matching automation rule must be reported on its playbook")
	}
}

func TestTriggerCooldownIsPerEndpoint(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
	f.rules.items = []*models.AutomationRule{{ID: uuid.New(), Name: "crit", PlaybookID: pb, Enabled: true, AutoExecute: true,
		CooldownMinutes: 60, TriggerConditions: json.RawMessage(`{"severity":["critical"]}`)}}

	// A second critical alert on another host, while the rule cools down for the first.
	hostB := uuid.New()
	f.e.agents.(*fakeAgents).items[hostB] = &models.Agent{ID: hostB, Hostname: "WS-02", Status: "online"}
	second := uuid.New()
	cp := *f.store.alerts[f.alertID]
	cp.ID, cp.AgentID = second.String(), hostB.String()
	f.store.alerts[second] = &cp

	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))

	f.store.mu.Lock()
	n := len(f.store.executions)
	var ids []uuid.UUID
	for id := range f.store.executions {
		ids = append(ids, id)
	}
	f.store.mu.Unlock()
	if n != 2 {
		t.Fatalf("each endpoint must get its own response, got %d executions", n)
	}
	for _, id := range ids {
		waitDone(t, f, id)
	}
}
