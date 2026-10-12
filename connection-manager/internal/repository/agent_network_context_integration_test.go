package repository

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAgentNetworkContextRepository(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `ALTER TABLE agents ADD COLUMN hostname TEXT`); err != nil {
		t.Fatal(err)
	}
	ddl, err := os.ReadFile(filepath.Join("..", "database", "migrations", "071_agent_network_context.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // idempotent
		if _, err := pool.Exec(ctx, string(ddl)); err != nil {
			t.Fatal(err)
		}
	}
	agent := fixtureAgent(t, pool)
	if _, err := pool.Exec(ctx, `UPDATE agents SET hostname='WS-01' WHERE id=$1`, agent); err != nil {
		t.Fatal(err)
	}
	r := NewAgentNetworkContextRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	off := int64(-125000)
	if err := r.Upsert(ctx, &AgentNetworkContext{AgentID: agent, PublicIP: "198.51.100.23", NetworkScope: "public",
		CountryCode: "SA", Country: "Saudi Arabia", Region: "Riyadh Region", City: "Riyadh", GeoSource: "DB-IP",
		GeoResolvedAt: &now, ClockOffsetMs: &off, ClockMeasuredAt: &now}); err != nil {
		t.Fatal(err)
	}
	// A heartbeat without an agent timestamp keeps the last measured offset.
	if err := r.Upsert(ctx, &AgentNetworkContext{AgentID: agent, PublicIP: "198.51.100.24", NetworkScope: "public",
		CountryCode: "SA", Country: "Saudi Arabia", City: "Jeddah", GeoResolvedAt: &now}); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, agent)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.Hostname != "WS-01" || got.PublicIP != "198.51.100.24" || got.City != "Jeddah" || got.Region != "" ||
		got.ClockOffsetMs == nil || *got.ClockOffsetMs != off || got.ClockMeasuredAt == nil || !got.ClockMeasuredAt.Equal(now) {
		t.Fatalf("unexpected row: %+v", got)
	}

	// Unknown agents are ignored, not errors (FK would reject them).
	ghost := uuid.New()
	if err := r.Upsert(ctx, &AgentNetworkContext{AgentID: ghost, NetworkScope: "unknown"}); err != nil {
		t.Fatalf("unknown agent: %v", err)
	}
	if g, err := r.Get(ctx, ghost); err != nil || g != nil {
		t.Fatalf("ghost row stored: %v %v", g, err)
	}

	rows, err := r.GetMany(ctx, []uuid.UUID{agent, ghost})
	if err != nil || len(rows) != 1 || rows[0].AgentID != agent {
		t.Fatalf("GetMany: %+v %v", rows, err)
	}
	if rows, err := r.GetMany(ctx, nil); err != nil || len(rows) != 0 {
		t.Fatalf("empty GetMany: %v %v", rows, err)
	}

	// Deleting the agent removes its context.
	if _, err := pool.Exec(ctx, `DELETE FROM agents WHERE id=$1`, agent); err != nil {
		t.Fatal(err)
	}
	if g, _ := r.Get(ctx, agent); g != nil {
		t.Fatal("context survived agent deletion")
	}
}
