package response

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
)

func TestEndpointGateCoordinatesRawCommandsAndQueuedRuns(t *testing.T) {
	f := newFixture(t)
	release, err := f.e.TryAcquireEndpoint(f.agentID.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.e.TryAcquireEndpoint("agent-" + f.agentID.String()); !errors.Is(err, ErrEndpointBusy) {
		t.Fatal("raw command bypassed endpoint owner", err)
	}
	pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
	rec, _, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID})
	if err != nil {
		release()
		t.Fatal(err)
	}
	f.disp.mu.Lock()
	n := len(f.disp.sent)
	f.disp.mu.Unlock()
	if n != 0 {
		release()
		t.Fatal("queued run dispatched while raw command held endpoint")
	}
	release()
	release() // idempotent release must not consume someone else's token
	if got := waitDone(t, f, rec.ID); got.Status != "completed" {
		t.Fatalf("queued run failed: %+v", got)
	}
	f.e.Stop(time.Second)
	f.e.agentLocksMu.Lock()
	defer f.e.agentLocksMu.Unlock()
	if len(f.e.agentLocks) != 0 {
		t.Fatal("idle endpoint entries leaked")
	}
}

func TestCancelledEndpointWaitAndShutdownAdmission(t *testing.T) {
	f := newFixture(t)
	release, _ := f.e.TryAcquireEndpoint(f.agentID.String())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.e.AcquireEndpoint(ctx, f.agentID.String()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	release()
	f.e.Stop(time.Second)
	if f.e.admitWork() {
		t.Fatal("work admitted after Wait completed")
	}
	if _, err := f.e.TryAcquireEndpoint(f.agentID.String()); err == nil {
		t.Fatal("endpoint gate admitted work after shutdown")
	}
}

func TestAutomaticTerminationAlwaysBindsTreeScope(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[{"type":"terminate_process","parameters":{"kill_tree":"false"}}]`)
	auto, err := f.e.Prepare(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID, Trigger: "automation"})
	if err != nil || !auto.Ready || auto.Steps[0].Params["kill_tree"] != "true" {
		t.Fatalf("automatic response must bind tree scope: plan=%+v err=%v", auto, err)
	}
	manual, err := f.e.Prepare(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID})
	if err != nil || manual.Steps[0].Params["kill_tree"] != "false" {
		t.Fatalf("manual process scope must be preserved: plan=%+v err=%v", manual, err)
	}
}

func TestQueuedAutomationRechecksSwitchAndAlertVerdict(t *testing.T) {
	for _, change := range []string{"disabled", "closed"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			unlock, _ := f.e.lockAgent(f.agentID.String())
			pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
			rec, plan, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID, Trigger: "automation"})
			if err != nil {
				unlock()
				t.Fatal(err)
			}
			if change == "disabled" {
				_, err = f.e.SetAutoResponse(context.Background(), false, "admin")
				if err != nil {
					unlock()
					t.Fatal(err)
				}
			} else {
				f.store.mu.Lock()
				f.store.alerts[f.alertID].Status = "false_positive"
				f.store.mu.Unlock()
			}
			unlock()
			done := waitDone(t, f, rec.ID)
			if done.Status != "cancelled" {
				t.Fatalf("queued automation must be cancelled: %+v", done)
			}
			f.disp.mu.Lock()
			n := len(f.disp.sent)
			f.disp.mu.Unlock()
			if n != 0 {
				t.Fatalf("dispatched %d commands after policy changed", n)
			}
			if rec.Status != "pending" || plan.Steps[0].Status != "pending" {
				t.Fatal("returned API snapshots must not be mutated by asynchronous work")
			}
		})
	}
}

func TestInvalidAutomationSettingFailsClosed(t *testing.T) {
	f := newFixture(t)
	_ = f.store.SetState(context.Background(), stateAutoResponse, "invalid JSON")
	if f.e.autoResponseEnabled(context.Background()) {
		t.Fatal("corrupt persisted settings must fail closed")
	}
}

func TestAutomationRefusesUnmeasuredProcessIdentity(t *testing.T) {
	f := newFixture(t)
	delete(f.store.alerts[f.alertID].ContextData["data"].(map[string]any), "process_start_time")
	pb := f.addPlaybook(`[{"type":"terminate_process"}]`)
	plan, err := f.e.Prepare(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID, Trigger: "automation"})
	if err != nil || plan.Ready {
		t.Fatalf("automatic termination without measured identity must be refused: plan=%+v err=%v", plan, err)
	}
}

func TestAPIPlanSnapshotIsNotUpdatedByWorker(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
	rec, plan, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID})
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, f, rec.ID)
	if rec.Status != "pending" || plan.Steps[0].Status != "pending" || plan.Steps[0].CommandID != "" {
		t.Fatal("Start must return independent snapshots safe for JSON encoding")
	}
}

func TestRuntimeRefusesBroadContainmentEvenForHighAlert(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[{"type":"isolate_network"}]`)
	addAutoRule(f, pb, `{"rule_patterns":["ransom"]}`)
	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
	f.disp.mu.Lock()
	n := len(f.disp.sent)
	f.disp.mu.Unlock()
	if n != 0 {
		t.Fatal("legacy broad triggers cannot bypass save-time containment policy")
	}
}

func TestConditionsRuleIDsMitreAndScope(t *testing.T) {
	a := &repository.SigmaAlertRecord{Severity: "medium", RuleID: "ABC-1", RuleTitle: "x",
		MitreTechniques: []string{"T1059.001"}}
	c, ok := ParseConditions(json.RawMessage(`{"rule_ids":["abc-1"],"mitre_techniques":["t1059"]}`))
	if !ok || !c.Matches(a) {
		t.Fatal("rule id (case-insensitive) and parent technique must match")
	}
	if !c.ScopedForContainment() || !c.ContainmentAllowedFor(a) {
		t.Fatal("an explicitly listed rule is an opt-in for containment")
	}
	broad, _ := ParseConditions(json.RawMessage(`{"min_risk_score":70}`))
	if broad.ScopedForContainment() {
		t.Fatal("a risk score alone must not drive automated containment")
	}
	mixed, _ := ParseConditions(json.RawMessage(`{"severity":["high","medium"]}`))
	if mixed.ScopedForContainment() {
		t.Fatal("medium severity must not drive automated containment")
	}
	or, _ := ParseConditions(json.RawMessage(`{"severity":["critical"],"rule_ids":["x"],"logic_operator":"OR"}`))
	if or.ScopedForContainment() {
		t.Fatal("OR logic broadens the trigger and must not drive containment")
	}
	hi, _ := ParseConditions(json.RawMessage(`{"severity":["critical","high"]}`))
	if !hi.ScopedForContainment() || hi.ContainmentAllowedFor(a) {
		t.Fatal("high/critical scope is allowed, but not for a medium alert")
	}
}

// Two runs on one endpoint must execute one after the other, never
// interleaving their commands.
func TestRunsOnOneEndpointAreSerialised(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[{"type":"collect_logs"},{"type":"agent_integrity_check"},{"type":"persistence_scan"}]`)
	r1, _, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID})
	if err != nil {
		t.Fatal(err)
	}
	r2, _, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID, Trigger: "automation"})
	if err != nil {
		t.Fatal(err)
	}
	waitDone(t, f, r1.ID)
	waitDone(t, f, r2.ID)

	// Map each dispatched command back to its run; the run IDs must form two
	// contiguous blocks.
	f.disp.mu.Lock()
	defer f.disp.mu.Unlock()
	var order []string
	for _, c := range f.disp.sent {
		id, _ := uuid.Parse(c.CommandId)
		cmd, _ := f.cmds.GetByID(context.Background(), id)
		order = append(order, cmd.Metadata["playbook_execution_id"].(string))
	}
	if len(order) != 6 {
		t.Fatalf("expected 6 commands, got %d", len(order))
	}
	for i := 1; i < 3; i++ {
		if order[i] != order[0] || order[3+i] != order[3] || order[0] == order[3] {
			t.Fatalf("runs interleaved on one endpoint: %v", order)
		}
	}
}

func TestIsolateIsSkippedWhenAlreadyIsolated(t *testing.T) {
	f := newFixture(t)
	f.agents.items[f.agentID].IsIsolated = true
	pb := f.addPlaybook(`[{"type":"isolate_network"},{"type":"collect_logs"}]`)
	rec, _, err := f.e.Start(context.Background(), RunRequest{PlaybookID: pb, AlertID: &f.alertID})
	if err != nil {
		t.Fatal(err)
	}
	done := waitDone(t, f, rec.ID)
	if done.Status != "completed" {
		t.Fatalf("status %s", done.Status)
	}
	st := steps(done)
	if st[0].Status != "success" || !strings.Contains(st[0].Output, "already isolated") || st[0].CommandID != "" {
		t.Fatalf("isolation of an isolated host must succeed without a command: %+v", st[0])
	}
	f.disp.mu.Lock()
	n := len(f.disp.sent)
	f.disp.mu.Unlock()
	if n != 1 {
		t.Fatalf("only the second step may be dispatched, got %d commands", n)
	}
}

func addAutoRule(f *fixture, pb uuid.UUID, cond string) {
	f.rules.items = append(f.rules.items, &models.AutomationRule{
		ID: uuid.New(), Name: "auto", PlaybookID: pb, Enabled: true, AutoExecute: true,
		Priority: 1, TriggerConditions: json.RawMessage(cond),
	})
}

func TestGuardrailBlocksContainmentForMediumAlert(t *testing.T) {
	f := newFixture(t)
	f.store.alerts[f.alertID].Severity = "medium"
	pb := f.addPlaybook(`[{"type":"isolate_network"}]`)
	addAutoRule(f, pb, `{"rule_patterns":["ransom"]}`)

	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))

	f.disp.mu.Lock()
	n := len(f.disp.sent)
	f.disp.mu.Unlock()
	if n != 0 {
		t.Fatal("no containment may be dispatched for a medium alert")
	}
	var found *repository.ExecutionRecord
	for id := range f.store.executions {
		found = f.store.get(id)
	}
	if found == nil || found.Status != "cancelled" || !strings.Contains(found.ErrorMessage, "guardrail") {
		t.Fatalf("the refused run must be recorded for the analyst: %+v", found)
	}
}

func TestGuardrailAllowsExplicitlyListedRule(t *testing.T) {
	f := newFixture(t)
	f.store.alerts[f.alertID].Severity = "medium"
	pb := f.addPlaybook(`[{"type":"isolate_network"}]`)
	addAutoRule(f, pb, `{"rule_ids":["r1"]}`)

	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
	for id := range f.store.executions {
		if rec := waitDone(t, f, id); rec.Status != "completed" {
			t.Fatalf("explicit per-rule opt-in must run: %s %s", rec.Status, rec.ErrorMessage)
		}
		return
	}
	t.Fatal("no execution recorded")
}

func TestOperatorSwitchStopsAutomation(t *testing.T) {
	f := newFixture(t)
	pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
	addAutoRule(f, pb, `{"severity":["critical"]}`)
	if _, err := f.e.SetAutoResponse(context.Background(), false, "admin"); err != nil {
		t.Fatal(err)
	}
	st, _ := f.e.AutomationSettings(context.Background())
	if st.Enabled || st.Configured || st.Locked {
		t.Fatalf("unexpected settings %+v", st)
	}

	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
	if len(f.store.executions) != 0 {
		t.Fatal("nothing may run while automated response is off")
	}
	if got := f.store.inbox[f.alertID]; got != "automated response disabled" {
		t.Fatalf("alert must be claimed (no replay later), outcome=%q", got)
	}

	// Re-enabling does not replay the alert that arrived while off.
	_, _ = f.e.SetAutoResponse(context.Background(), true, "admin")
	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
	if len(f.store.executions) != 0 {
		t.Fatal("alerts that arrived while automation was off must not be replayed")
	}
}

func TestClosedAlertIsNotAutomated(t *testing.T) {
	f := newFixture(t)
	f.store.alerts[f.alertID].Status = "false_positive"
	pb := f.addPlaybook(`[{"type":"collect_logs"}]`)
	addAutoRule(f, pb, `{"severity":["critical"]}`)
	f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
	if len(f.store.executions) != 0 {
		t.Fatal("an alert closed by an analyst must not trigger automation")
	}
}

func TestSettingsLockedByServerConfig(t *testing.T) {
	f := newFixture(t)
	f.e.cfg.AutoExecute = false
	_, _ = f.e.SetAutoResponse(context.Background(), true, "admin")
	st, _ := f.e.AutomationSettings(context.Background())
	if st.Enabled || !st.Locked || !st.Configured {
		t.Fatalf("server lock must win over the operator switch: %+v", st)
	}
}

func TestDefinitionIsDestructive(t *testing.T) {
	if DefinitionIsDestructive([]byte(`[{"type":"collect_logs"},{"type":"process_tree_snapshot"}]`)) {
		t.Fatal("investigation-only playbook is not destructive")
	}
	for _, s := range []string{`[{"type":"kill_process"}]`, `[{"type":"run_script"}]`, `not json`} {
		if !DefinitionIsDestructive([]byte(s)) {
			t.Fatalf("%s must count as destructive", s)
		}
	}
}
