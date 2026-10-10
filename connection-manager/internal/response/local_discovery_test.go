package response

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/google/uuid"
)

// Load the actual shipped migration payloads, so dispatch tests cannot silently
// diverge from the policy deployed by the database migrator. No real dispatcher.
func TestLocalDiscoveryInvestigationPolicy(t *testing.T) {
	data, err := os.ReadFile("../database/migrations/063_local_discovery_investigation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	steps := regexp.MustCompile(`'(\[\{"type"[^']+\])'::jsonb`).FindSubmatch(data)
	conditions := regexp.MustCompile(`'(\{"rule_ids"[^']+\})'::jsonb`).FindSubmatch(data)
	if len(steps) != 2 || len(conditions) != 2 {
		t.Fatal("missing migration JSON definitions")
	}
	var cond struct {
		RuleIDs []string `json:"rule_ids"`
	}
	if err := json.Unmarshal(conditions[1], &cond); err != nil {
		t.Fatal(err)
	}
	if len(cond.RuleIDs) != 3 {
		t.Fatalf("expected three source-specific rule IDs: %v", cond)
	}
	for _, ruleID := range append(cond.RuleIDs, "unrelated-rule") {
		for _, enabled := range []bool{true, false} {
			t.Run(ruleID+"/enabled="+map[bool]string{true: "yes", false: "no"}[enabled], func(t *testing.T) {
				f := newFixture(t)
				f.e.cfg.AutoExecute = enabled
				a := f.store.alerts[f.alertID]
				a.RuleID = ruleID
				a.RelatedRuleIDs = []string{ruleID}
				a.Severity = "medium"
				a.RiskScore = 0
				a.RuleTitle = "Local account discovery"
				a.MitreTechniques = []string{"T1087.001"}
				pb := f.addPlaybook(string(steps[1]))
				f.pbs.items[pb].Category = "investigation"
				f.rules.items = []*models.AutomationRule{{ID: uuid.New(), Name: "discovery evidence", Enabled: true, AutoExecute: true, PlaybookID: pb, CooldownMinutes: 30, TriggerConditions: json.RawMessage(conditions[1])}}
				f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
				f.e.pollOnce(context.Background(), time.Now().Add(-time.Minute))
				f.store.mu.Lock()
				var ids []uuid.UUID
				for id := range f.store.executions {
					ids = append(ids, id)
				}
				f.store.mu.Unlock()
				if !enabled || ruleID == "unrelated-rule" {
					if len(ids) != 0 {
						t.Fatal("unmatched/disabled policy must not run")
					}
					return
				}
				if len(ids) != 1 {
					t.Fatalf("expected one audited execution after replay; got %d", len(ids))
				}
				rec := waitDone(t, f, ids[0])
				if rec.Status != "completed" || rec.TriggerSource != "automation" {
					t.Fatalf("unexpected result: %+v", rec)
				}
				f.cmds.mu.Lock()
				defer f.cmds.mu.Unlock()
				if len(f.cmds.cmds) != 1 {
					t.Fatal("one bounded collection command expected")
				}
				for _, cmd := range f.cmds.cmds {
					if string(cmd.CommandType) != "collect_logs" {
						t.Fatalf("unexpected endpoint mutation: %s", cmd.CommandType)
					}
					// Payload is checked below through the serialized command parameters.
					params, _ := json.Marshal(cmd.Parameters)
					if !regexp.MustCompile(`"max_events":"200"`).Match(params) || !regexp.MustCompile(`"time_range":"15m"`).Match(params) {
						t.Fatalf("collection must stay bounded: %s", params)
					}
				}
			})
		}
	}
}
