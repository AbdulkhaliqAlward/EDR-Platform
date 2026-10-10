package repository

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresLocalDiscoverySeedPreservesOperatorChoices(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	apply := func(suffix string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("..", "database", "migrations", "063_local_discovery_investigation."+suffix+".sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			t.Fatal(err)
		}
	}
	apply("up")
	apply("up")
	const policy = "56956211-fd47-49a1-ad67-7d6586e7d61a"
	const playbook = "1e13819d-8d38-44e9-8f74-8ab945e85835"
	var count int
	var auto, enabled bool
	var cooldown int
	if err := pool.QueryRow(ctx, `SELECT auto_execute,enabled,cooldown_minutes,jsonb_array_length(trigger_conditions->'rule_ids') FROM automation_rules WHERE id=$1`, policy).Scan(&auto, &enabled, &cooldown, &count); err != nil {
		t.Fatal(err)
	}
	if !auto || !enabled || cooldown != 30 || count != 3 {
		t.Fatalf("incorrect default policy: %v %v %d %d", auto, enabled, cooldown, count)
	}
	var action, limit, lookback string
	if err := pool.QueryRow(ctx, `SELECT commands->0->>'type',commands->0->'params'->>'max_events',commands->0->'params'->>'time_range' FROM response_playbooks WHERE id=$1`, playbook).Scan(&action, &limit, &lookback); err != nil {
		t.Fatal(err)
	}
	if action != "collect_logs" || limit != "200" || lookback != "15m" {
		t.Fatalf("unexpected seeded command: %s %s %s", action, limit, lookback)
	}
	if _, err := pool.Exec(ctx, `UPDATE automation_rules SET auto_execute=false,enabled=false,cooldown_minutes=90 WHERE id=$1`, policy); err != nil {
		t.Fatal(err)
	}
	apply("up")
	if err := pool.QueryRow(ctx, `SELECT auto_execute,enabled,cooldown_minutes FROM automation_rules WHERE id=$1`, policy).Scan(&auto, &enabled, &cooldown); err != nil {
		t.Fatal(err)
	}
	if auto || enabled || cooldown != 90 {
		t.Fatal("seed overwrote operator choices")
	}
	apply("down")
	if err := pool.QueryRow(ctx, `SELECT enabled FROM response_playbooks WHERE id=$1`, playbook).Scan(&enabled); err != nil {
		t.Fatal("rollback must preserve referenced playbook:", err)
	}
	if enabled {
		t.Fatal("rollback must disable the built-in playbook")
	}
}
