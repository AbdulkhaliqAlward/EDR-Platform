package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every test creates its own database on an explicitly isolated loopback
// cluster. It never migrates the application database named in configuration.
func responseTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("EDR_TEST_DB_ISOLATED") != "1" || os.Getenv("EDR_TEST_DB_URL") == "" {
		t.Skip("set EDR_TEST_DB_ISOLATED=1 and a disposable loopback EDR_TEST_DB_URL")
	}
	config, err := pgxpool.ParseConfig(os.Getenv("EDR_TEST_DB_URL"))
	if err != nil {
		t.Fatal("invalid isolated test DB configuration")
	}
	if config.ConnConfig.Host != "127.0.0.1" && config.ConnConfig.Host != "localhost" {
		t.Fatal("integration tests require a loopback DB")
	}
	ctx := context.Background()
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	name := "codex_edr_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config = config.Copy()
	config.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Error("isolated fixture cleanup failed:", err)
		}
		admin.Close()
	})
	// Only referenced ancestor tables are fixtures; the tested service tables,
	// constraints, indexes and triggers come from the repository's migrations.
	if _, err := pool.Exec(ctx, `CREATE TABLE agents(id uuid PRIMARY KEY); CREATE TABLE users(id uuid PRIMARY KEY);
		CREATE TABLE alerts(id uuid PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range []string{"009_create_commands", "020_create_events", "030_add_automation_infrastructure", "059_response_engine", "060_response_coordination", "061_response_activity_indexes"} {
		sql, err := os.ReadFile(filepath.Join("..", "database", "migrations", migration+".up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("migration %s: %v", migration, err)
		}
	}
	return pool
}

func fixtureAgent(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(), "INSERT INTO agents(id) VALUES($1)", id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPostgresCommandStatusCannotRegressAfterResult(t *testing.T) {
	pool := responseTestDB(t)
	r := NewPostgresCommandRepository(pool)
	ctx := context.Background()
	c := &models.Command{AgentID: fixtureAgent(t, pool), CommandType: "collect_logs", Status: models.CommandStatusPending, Priority: 5, TimeoutSeconds: 10, ExpiresAt: time.Now().Add(time.Minute)}
	expiry := c.ExpiresAt
	if err := r.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	if !c.ExpiresAt.Equal(expiry) {
		t.Fatal("explicit delivery expiry was overwritten")
	}
	if _, err := r.GetByID(ctx, c.ID); err != nil {
		t.Fatal("pending command must decode nullable DB fields:", err)
	}
	if err := r.UpdateStatus(ctx, c.ID, models.CommandStatusCompleted, map[string]any{"output": "synthetic success"}, ""); err != nil {
		t.Fatal(err)
	}
	// Simulate a late dispatch/ACK update racing a fast endpoint's result.
	for _, status := range []models.CommandStatus{models.CommandStatusSent, models.CommandStatusAcknowledged, models.CommandStatusExecuting} {
		if err := r.UpdateStatus(ctx, c.ID, status, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	got, err := r.GetByID(ctx, c.ID)
	if err != nil || got.Status != models.CommandStatusCompleted || got.Result["output"] != "synthetic success" {
		t.Fatalf("terminal result regressed: %+v, %v", got, err)
	}
}

func TestPostgresActivityKeysetsDrainTiedAndDelayedRows(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	agent := fixtureAgent(t, pool)
	var pb uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO response_playbooks(name, category) VALUES('fixture', 'investigation') RETURNING id`).Scan(&pb); err != nil {
		t.Fatal(err)
	}
	r := NewResponseEngineRepository(pool)
	for i := 0; i < 650; i++ {
		if err := r.CreateExecution(ctx, &ExecutionRecord{AgentID: agent, PlaybookID: pb, Status: "pending", TriggerSource: "automation"}); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `UPDATE playbook_executions SET updated_at=$1`, at); err != nil {
		t.Fatal(err)
	}
	from, through := at.Add(-time.Minute), at.Add(time.Minute)
	f := ExecutionListFilter{UpdatedSince: &from, UpdatedUntil: &through, Trigger: "automation", Limit: 200}
	seen := map[uuid.UUID]bool{}
	for {
		rows, err := r.ListExecutions(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if seen[row.ID] {
				t.Fatal("duplicate tied execution")
			}
			seen[row.ID] = true
		}
		if len(rows) < 200 {
			break
		}
		last := rows[len(rows)-1]
		f.AfterUpdatedAt, f.AfterID = &last.UpdatedAt, &last.ID
	}
	if len(seen) != 650 {
		t.Fatal("saturated execution feed lost rows", len(seen))
	}
	events := NewPostgresEventRepository(pool)
	var inserts []EventInsert
	for i := 0; i < 450; i++ {
		inserts = append(inserts, EventInsert{ID: uuid.New(), AgentID: agent, EventType: "process", Severity: "high", Timestamp: at.Add(-7 * 24 * time.Hour), Raw: json.RawMessage(`{"data":{"autonomous":true,"action":"auto_terminated"}}`)})
	}
	if err := events.InsertMany(ctx, inserts); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE events SET created_at=$1`, at); err != nil {
		t.Fatal(err)
	}
	ef := PreventionActivityFilter{From: from, Through: through, Limit: 200}
	seen = map[uuid.UUID]bool{}
	for {
		rows, err := events.ListPreventionActivity(ctx, ef)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if seen[row.ID] {
				t.Fatal("duplicate tied prevention event")
			}
			seen[row.ID] = true
			if !row.Timestamp.Before(from) {
				t.Fatal("fixture should be delayed")
			}
		}
		if len(rows) < 200 {
			break
		}
		last := rows[len(rows)-1]
		ef.AfterAt, ef.AfterID = &last.IngestedAt, &last.ID
	}
	if len(seen) != 450 {
		t.Fatal("delayed/saturated prevention feed lost rows", len(seen))
	}
}

func TestPostgresResponseStateAndExceptionCRUD(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	sql, err := os.ReadFile(filepath.Join("..", "..", "..", "sigma_engine_go", "internal", "infrastructure", "database", "migrations", "018_detection_exceptions.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	s := NewResponseEngineRepository(pool)
	if got, err := s.GetOrInitState(ctx, "switch", "off"); err != nil || got != "off" {
		t.Fatal(got, err)
	}
	if err := s.SetState(ctx, "switch", "on"); err != nil {
		t.Fatal(err)
	}
	if got, _, found, err := s.GetState(ctx, "switch"); err != nil || !found || got != "on" {
		t.Fatal(got, found, err)
	}
	alert := uuid.New()
	if ok, err := s.ClaimSigmaAlert(ctx, alert); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := s.ClaimSigmaAlert(ctx, alert); err != nil || ok {
		t.Fatal("duplicate alert claim", ok, err)
	}
	r := NewDetectionExceptionRepository(pool)
	ex := &DetectionException{Name: "fixture", Reason: "synthetic benign sample", Enabled: true, Conditions: []ExceptionCondition{{Field: "Image", Op: "equals", Value: `C:\fixture\app.exe`}}}
	if err := r.Create(ctx, ex); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Get(ctx, ex.ID); err != nil || len(got.Conditions) != 1 || got.RuleID != "" {
		t.Fatal(got, err)
	}
	ex.Enabled = false
	if err := r.Update(ctx, ex); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Get(ctx, ex.ID); err != nil || got.Enabled {
		t.Fatal(got, err)
	}
	if err := r.Delete(ctx, ex.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, ex.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestPostgresResponseReadsAggregatedSigmaIdentities(t *testing.T) {
	pool := responseTestDB(t)
	ctx := context.Background()
	for _, name := range []string{"001_create_sigma_alerts", "014_add_risk_scoring"} {
		sql, err := os.ReadFile(filepath.Join("..", "..", "..", "sigma_engine_go", "internal", "infrastructure", "database", "migrations", name+".up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	sql, err := os.ReadFile(filepath.Join("..", "database", "migrations", "062_alert_rule_identities.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	ids := []string{"primary", "related-exact"}
	if _, err := pool.Exec(ctx, `INSERT INTO sigma_alerts(id,timestamp,agent_id,rule_id,severity,related_rule_ids) VALUES($1,now(),'synthetic','primary','medium',$2)`, id, ids); err != nil {
		t.Fatal(err)
	}
	alert, err := NewResponseEngineRepository(pool).GetSigmaAlert(ctx, id)
	if err != nil || len(alert.RelatedRuleIDs) != 2 || alert.RelatedRuleIDs[1] != "related-exact" {
		t.Fatalf("identity contract failed: %+v %v", alert, err)
	}
}
