package database_test

import (
	"context"
	"github.com/edr-platform/sigma-engine/internal/application/baselines"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/application/rulesync"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"os"
	"strings"
	"testing"
	"time"
)

func isolatedDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("EDR_TEST_DB_ISOLATED") != "1" || os.Getenv("EDR_TEST_DB_URL") == "" {
		t.Skip("requires explicitly disposable loopback DB")
	}
	cfg, err := pgxpool.ParseConfig(os.Getenv("EDR_TEST_DB_URL"))
	require.NoError(t, err)
	require.Contains(t, []string{"127.0.0.1", "localhost"}, cfg.ConnConfig.Host)
	ctx := context.Background()
	admin, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	name := "codex_edr_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	_, err = admin.Exec(ctx, "CREATE DATABASE "+quoted)
	require.NoError(t, err)
	cfg = cfg.Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, "DROP DATABASE "+quoted+" WITH (FORCE)")
		if err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	require.NoError(t, database.RunMigrations(ctx, pool))
	return pool
}
func TestPostgresAlertIdentityRoundtripAndDedup(t *testing.T) {
	pool := isolatedDB(t)
	repo := database.NewPostgresAlertRepository(pool)
	ctx := context.Background()
	confidence := 0.9
	a := &database.Alert{ID: uuid.NewString(), Timestamp: time.Now(), AgentID: "synthetic", RuleID: "primary", RuleTitle: "Fixture", Severity: "high", Status: "open", EventCount: 1, EventIDs: []string{"event1"}, Confidence: &confidence, RelatedRuleIDs: []string{"primary", "second"}}
	saved, fresh, err := repo.UpsertWithDedup(ctx, a, time.Minute)
	require.NoError(t, err)
	require.True(t, fresh)
	got, err := repo.GetByID(ctx, saved.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, a.RelatedRuleIDs, got.RelatedRuleIDs)
	next := *a
	next.ID = uuid.NewString()
	next.EventIDs = []string{"event2"}
	next.RelatedRuleIDs = []string{"third"}
	merged, fresh, err := repo.UpsertWithDedup(ctx, &next, time.Minute)
	require.NoError(t, err)
	require.False(t, fresh)
	require.Equal(t, saved.ID, merged.ID)
	require.ElementsMatch(t, []string{"primary", "second", "third"}, merged.RelatedRuleIDs)
	manual := *a
	manual.RuleID = "manual"
	manual.ID = ""
	created, err := repo.Create(ctx, &manual)
	require.NoError(t, err)
	got, err = repo.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, a.RelatedRuleIDs, got.RelatedRuleIDs)
	_, _, err = repo.List(ctx, database.AlertFilters{Limit: 100})
	require.NoError(t, err)
}

const content = `title: Database runtime fixture
id: 11111111-1111-4111-8111-111111111111
status: stable
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\fixture.exe'
  condition: selection
`

func TestPostgresRuleEditsActivateInDetector(t *testing.T) {
	pool := isolatedDB(t)
	ctx := context.Background()
	repo := database.NewPostgresRuleRepository(pool)
	row, err := repo.Create(ctx, &database.Rule{ID: "11111111-1111-4111-8111-111111111111", Title: "Fixture", Content: content, Enabled: true, Severity: "high", Status: "stable", Product: "windows", Category: "process_creation", Source: "custom", Version: 1})
	require.NoError(t, err)
	engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(nil), detection.NewModifierRegistry(nil), nil, detection.QualityConfig{MinConfidence: 0.01})
	runtime := rulesync.New(repo, engine, nil, nil)
	event, err := domain.NewLogEvent(map[string]interface{}{"event_type": "process", "data": map[string]interface{}{"executable": `C:\fixture.exe`}})
	require.NoError(t, err)
	require.NoError(t, runtime.Refresh(ctx))
	require.Len(t, engine.Detect(event), 1)
	require.NoError(t, repo.Disable(ctx, row.ID))
	require.NoError(t, runtime.Refresh(ctx))
	require.Empty(t, engine.Detect(event))
	require.NoError(t, repo.Enable(ctx, row.ID))
	require.NoError(t, runtime.Refresh(ctx))
	require.Len(t, engine.Detect(event), 1)
	row.Content = strings.Replace(content, "fixture.exe", "different.exe", 1)
	_, err = repo.Update(ctx, row.ID, row)
	require.NoError(t, err)
	require.NoError(t, runtime.Refresh(ctx))
	require.Empty(t, engine.Detect(event))
	require.NoError(t, repo.Delete(ctx, row.ID))
	require.NoError(t, runtime.Refresh(ctx))
	require.Equal(t, 0, engine.RuleCount())
}

func TestPostgresLegacyRuleRecoveryPreservesOperatorEdits(t *testing.T) {
	pool := isolatedDB(t)
	ctx := context.Background()
	repo := database.NewPostgresRuleRepository(pool)
	parsed, err := rules.NewRuleParser(true).ParseContent(content)
	require.NoError(t, err)
	legacy, err := yaml.Marshal(parsed)
	require.NoError(t, err)
	row, err := repo.Create(ctx, &database.Rule{ID: parsed.ID, Title: "Analyst title", Content: string(legacy), Enabled: true, Severity: "medium", Status: "stable", Product: "windows", Category: "process_creation", Source: "official", Version: 3})
	require.NoError(t, err)
	engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(nil), detection.NewModifierRegistry(nil), nil, detection.QualityConfig{MinConfidence: 0.01})
	runtime := rulesync.New(repo, engine, nil, nil)
	event, err := domain.NewLogEvent(map[string]interface{}{"event_type": "process", "data": map[string]interface{}{"executable": `C:\fixture.exe`}})
	require.NoError(t, err)
	require.NoError(t, runtime.Refresh(ctx))
	require.Len(t, engine.Detect(event), 1)
	stored, err := repo.GetByID(ctx, row.ID)
	require.NoError(t, err)
	require.Equal(t, string(legacy), stored.Content, "recovery must not overwrite stored content")
	require.Equal(t, "Analyst title", stored.Title)
	require.Equal(t, "medium", stored.Severity)
	require.Equal(t, 3, stored.Version)
	require.NoError(t, repo.Disable(ctx, row.ID))
	require.NoError(t, runtime.Refresh(ctx))
	require.Empty(t, engine.Detect(event))
}
func TestPostgresBaselineBatchRetryAndRestart(t *testing.T) {
	pool := isolatedDB(t)
	repo := baselines.NewPostgresBaselineRepository(pool)
	ctx := context.Background()
	id := uuid.NewString()
	counts := []baselines.HourlyCount{{AgentID: "fixture", ProcessName: "fixture.exe", Hour: time.Now().UTC().Truncate(time.Hour), Count: 5}}
	require.NoError(t, repo.AddBatchCounts(ctx, id, counts))
	require.NoError(t, repo.AddBatchCounts(ctx, id, counts))
	restored := baselines.NewBaselineAggregator(repo, 0, 0)
	restored.Start(ctx)
	defer restored.Stop()
	require.Equal(t, 5, restored.CurrentCount("fixture", "fixture.exe", time.Now()))
	restored.Record(baselines.AggregationInput{AgentID: "fixture", ProcessName: "fixture.exe", ObservedAt: time.Now()})
	restored.Flush(ctx)
	rows, err := repo.RecentCounts(ctx, counts[0].Hour.Add(-time.Hour), counts[0].Hour.Add(time.Hour), 10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, 6, rows[0].Count)
}
func TestPostgresExceptionHitBatchRollsBackOnFailure(t *testing.T) {
	pool := isolatedDB(t)
	ctx := context.Background()
	valid := uuid.NewString()
	_, err := pool.Exec(ctx, `INSERT INTO detection_exceptions(id,name,reason,conditions) VALUES($1,'Fixture','Synthetic test','[]')`, valid)
	require.NoError(t, err)
	repo := database.NewExceptionRepository(pool)
	require.Error(t, repo.RecordExceptionHits(ctx, map[string]int64{valid: 2, "zz-invalid-uuid": 3}))
	var n int64
	require.NoError(t, pool.QueryRow(ctx, "SELECT hit_count FROM detection_exceptions WHERE id=$1", valid).Scan(&n))
	require.Equal(t, int64(0), n)
	require.NoError(t, repo.RecordExceptionHits(ctx, map[string]int64{valid: 2}))
	require.NoError(t, pool.QueryRow(ctx, "SELECT hit_count FROM detection_exceptions WHERE id=$1", valid).Scan(&n))
	require.Equal(t, int64(2), n)
	token := uuid.NewString()
	require.NoError(t, repo.RecordExceptionHitBatch(ctx, token, map[string]int64{valid: 3}))
	require.NoError(t, repo.RecordExceptionHitBatch(ctx, token, map[string]int64{valid: 3}))
	require.NoError(t, pool.QueryRow(ctx, "SELECT hit_count FROM detection_exceptions WHERE id=$1", valid).Scan(&n))
	require.Equal(t, int64(5), n)

}
