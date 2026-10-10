package database_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/edr-platform/sigma-engine/internal/application/alert"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/mapping"
	"github.com/edr-platform/sigma-engine/internal/application/rules"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPostgresAlertOptionalRelatedIDs(t *testing.T) {
	pool := isolatedDB(t)
	repo := database.NewPostgresAlertRepository(pool)
	ctx := context.Background()
	for _, mode := range []string{"create", "upsert"} {
		for _, tc := range []struct {
			name string
			ids  []string
		}{
			{"nil", nil}, {"empty", []string{}}, {"additional", []string{"secondary-rule"}},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				a := &database.Alert{ID: uuid.NewString(), Timestamp: time.Now(), AgentID: "isolated-fixture", RuleID: mode + "-" + tc.name, RuleTitle: "Fixture", Severity: "medium", Status: "open", EventCount: 1, EventIDs: []string{"event-1"}, RelatedRuleIDs: tc.ids}
				var saved *database.Alert
				var err error
				if mode == "create" {
					saved, err = repo.Create(ctx, a)
				} else {
					var fresh bool
					saved, fresh, err = repo.UpsertWithDedup(ctx, a, time.Minute)
					require.True(t, fresh)
				}
				require.NoError(t, err)
				stored, err := repo.GetByID(ctx, saved.ID)
				require.NoError(t, err)
				require.NotNil(t, stored.RelatedRuleIDs)
				require.ElementsMatch(t, tc.ids, stored.RelatedRuleIDs)
				require.NotNil(t, saved.RelatedRuleIDs, "returned record must agree with database")
				if mode == "upsert" {
					a.ID = uuid.NewString()
					a.RelatedRuleIDs = nil
					a.EventIDs = []string{"event-2"}
					merged, fresh, err := repo.UpsertWithDedup(ctx, a, time.Minute)
					require.NoError(t, err)
					require.False(t, fresh)
					require.Equal(t, stored.ID, merged.ID)
					require.ElementsMatch(t, tc.ids, merged.RelatedRuleIDs, "nil incoming IDs must not erase prior matches")
				}
			})
		}
	}
}

func TestSingleRuleDetectionPersistsAndNotifiesAfterCommit(t *testing.T) {
	pool := isolatedDB(t)
	repo := database.NewPostgresAlertRepository(pool)
	ctx := context.Background()
	rule, err := rules.NewRuleParser(true).ParseFile(filepath.Join("../../../sigma_rules/rules/edr_custom", "mitras_proc_local_account_discovery.yml"))
	require.NoError(t, err)
	engine := detection.NewSigmaDetectionEngine(mapping.NewFieldMapper(nil), detection.NewModifierRegistry(nil), nil, detection.QualityConfig{MinConfidence: 0.01})
	require.NoError(t, engine.LoadRules([]*domain.SigmaRule{rule}))
	event, err := domain.NewLogEvent(map[string]interface{}{"event_type": "process", "agent_id": "isolated-fixture", "data": map[string]interface{}{"executable": `C:\Windows\System32\net.exe`, "command_line": "net user"}})
	require.NoError(t, err)
	writer := database.NewAlertWriter(repo, database.DefaultAlertWriterConfig())
	var notified []string
	writer.SetOnAlertPersisted(func(a *database.Alert) {
		// Same callback used for dashboard fan-out, checked against a separate DB
		// query to prove that the notification follows the committed transaction.
		stored, err := repo.GetByID(ctx, a.ID)
		require.NoError(t, err)
		require.Equal(t, rule.ID, stored.RuleID)
		require.Empty(t, stored.RelatedRuleIDs, "a single match has no secondary rules")
		notified = append(notified, a.ID)
	})
	for attempt := 0; attempt < 2; attempt++ {
		matches := engine.DetectAggregated(event)
		require.Equal(t, 1, matches.MatchCount())
		a := alert.NewAlertGenerator().GenerateAggregatedAlert(matches)
		require.NotNil(t, a)
		require.Nil(t, a.RelatedRuleIDs, "reproduce the actual single-match generator output")
		id, fresh, err := writer.Persist(ctx, a)
		require.NoError(t, err)
		require.Equal(t, attempt == 0, fresh)
		require.Equal(t, id, a.ID)
		require.Len(t, notified, attempt+1)
		require.Equal(t, notified[0], id, "merged and new notifications share canonical identity")
	}
	require.Zero(t, writer.Metrics().WriteErrors)
}
