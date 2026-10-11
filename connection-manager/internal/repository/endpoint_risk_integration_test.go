package repository

import (
	"context"
	"testing"
	"time"
)

// Endpoint risk must reflect only current, actionable risk on endpoints that
// still exist: deleted/unknown agents, suppressed/resolved/false-positive
// alerts and alerts idle beyond the window never contribute.
func TestEndpointRiskSummaryPostgres(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
ALTER TABLE agents ADD COLUMN hostname text, ADD COLUMN os_type text, ADD COLUMN status text NOT NULL DEFAULT 'online', ADD COLUMN metadata jsonb DEFAULT '{}';
CREATE TABLE sigma_alerts(id uuid PRIMARY KEY DEFAULT gen_random_uuid(), agent_id text, risk_score int NOT NULL DEFAULT 0,
  status text NOT NULL, timestamp timestamptz NOT NULL, last_seen_at timestamptz);
INSERT INTO agents(id, hostname, os_type, status, metadata) VALUES
  ('00000000-0000-4000-8000-000000000001','live-host','windows','online','{"device_criticality":"high"}'),
  ('00000000-0000-4000-8000-000000000002','deleted-host','windows','deleted','{}'),
  ('00000000-0000-4000-8000-000000000003','reenrolled-host','windows','offline','{"previous_agent_id":"old-agent-id"}');`); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	recent, stale := now.Add(-time.Hour), now.Add(-30*24*time.Hour)
	insert := func(agent string, score int, status string, ts time.Time, lastSeen *time.Time) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO sigma_alerts(agent_id, risk_score, status, timestamp, last_seen_at) VALUES($1,$2,$3,$4,$5)`, agent, score, status, ts, lastSeen); err != nil {
			t.Fatal(err)
		}
	}
	live := "00000000-0000-4000-8000-000000000001"
	insert(live, 95, "open", recent, nil)                                   // counts: critical, open
	insert(live, 75, "investigating", recent, nil)                          // counts: high
	insert(live, 50, "acknowledged", recent, nil)                           // counts: medium
	insert(live, 99, "suppressed", recent, nil)                             // excluded: suppressed by exception
	insert(live, 99, "false_positive", recent, nil)                         // excluded
	insert(live, 99, "resolved", recent, nil)                               // excluded
	insert(live, 99, "open", stale, nil)                                    // excluded: idle beyond window
	insert(live, 60, "open", stale, &recent)                                // counts: recurring alert seen recently
	insert("00000000-0000-4000-8000-000000000002", 99, "open", recent, nil) // deleted agent
	insert("ffffffff-0000-4000-8000-000000000009", 99, "open", recent, nil) // unknown agent
	insert("old-agent-id", 80, "open", recent, nil)                         // re-enrolled agent

	repo := NewPostgresAlertRepository(pool)
	rows, err := repo.GetEndpointRiskSummary(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want live + re-enrolled endpoints only, got %d: %+v", len(rows), rows)
	}
	top := rows[0]
	if top.AgentID != live || top.Hostname != "live-host" || top.DeviceCriticality != "high" {
		t.Fatalf("unexpected top row %+v", top)
	}
	if top.TotalAlerts != 4 || top.PeakRiskScore != 95 || top.CriticalCount != 1 || top.HighCount != 1 || top.MediumCount != 2 || top.OpenCount != 2 {
		t.Fatalf("wrong counts %+v", top)
	}
	if want := (95.0 + 75 + 50 + 60) / 4; top.AvgRiskScore != want {
		t.Fatalf("avg %v want %v", top.AvgRiskScore, want)
	}
	if rows[1].AgentID != "00000000-0000-4000-8000-000000000003" || rows[1].PeakRiskScore != 80 || rows[1].AgentStatus != "offline" {
		t.Fatalf("re-enrolled endpoint not attributed: %+v", rows[1])
	}
	// Deleting the endpoint removes it from the board.
	if _, err := pool.Exec(ctx, `UPDATE agents SET status='deleted' WHERE id=$1`, live); err != nil {
		t.Fatal(err)
	}
	if rows, err = repo.GetEndpointRiskSummary(ctx, now.Add(-7*24*time.Hour)); err != nil || len(rows) != 1 {
		t.Fatalf("deleted endpoint still listed: %v %+v", err, rows)
	}
}
