package database_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/edr-platform/shared/pagination"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/stretchr/testify/require"
)

func TestRulePagesPostgres(t *testing.T) {
	pool := isolatedDB(t)
	ctx := context.Background()
	repo := database.NewPostgresRuleRepository(pool)
	for n := 0; n < 63; n++ {
		_, err := repo.Create(ctx, &database.Rule{ID: fmt.Sprintf("page-rule-%03d", n), Title: "Identical title", Description: "page-fixture", Content: "full YAML evidence", Source: "custom", Enabled: true, Status: "stable", Severity: "high", CustomMetadata: map[string]interface{}{"evidence": "detail-only"}})
		require.NoError(t, err)
	}
	enabled := true
	for _, sort := range []string{"title", "created_at", "severity"} {
		t.Run(sort, func(t *testing.T) {
			q := url.Values{"limit": {"25"}, "sort": {sort}, "order": {"asc"}, "search": {"page-fixture"}}
			load := func() pagination.Page[*database.Rule] {
				p, err := pagination.Parse(q, pagination.Options{Scope: "rule-test", Offset: true, DefaultSort: "title", Sorts: database.RuleSortColumns})
				require.NoError(t, err)
				rows, total, err := repo.List(ctx, database.RuleFilters{Page: &p, Enabled: &enabled, Search: "page-fixture", SortBy: p.Sort, SortOrder: p.Order})
				require.NoError(t, err)
				require.Zero(t, total)
				for _, row := range rows {
					require.Empty(t, row.Content)
					require.Empty(t, row.CustomMetadata)
				}
				return pagination.BuildOffset(rows, p)
			}
			first := load()
			require.Len(t, first.Data, 25)
			page := first
			seen := map[string]bool{}
			for {
				for _, row := range page.Data {
					require.False(t, seen[row.ID], "duplicate %s", row.ID)
					seen[row.ID] = true
				}
				if !page.PageInfo.HasNext {
					break
				}
				q.Set("cursor", *page.PageInfo.NextCursor)
				page = load()
			}
			require.Len(t, seen, 63)
			for page.PageInfo.HasPrev {
				q.Set("cursor", *page.PageInfo.PrevCursor)
				page = load()
			}
			require.Equal(t, first.Data, page.Data)
			full, err := repo.GetByID(ctx, first.Data[0].ID)
			require.NoError(t, err)
			require.Equal(t, "full YAML evidence", full.Content)
			require.Equal(t, "detail-only", full.CustomMetadata["evidence"])
		})
	}
	all, err := repo.LoadAll(ctx)
	require.NoError(t, err)
	require.Len(t, all, 63)
	require.NotEmpty(t, all[0].Content, "internal rule loading must remain complete")
}

func TestAlertPagesPostgres(t *testing.T) {
	pool := isolatedDB(t)
	ctx := context.Background()
	repo := database.NewPostgresAlertRepository(pool)
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond).Add(123 * time.Microsecond)
	_, err := pool.Exec(ctx, `INSERT INTO sigma_alerts(id,timestamp,created_at,rule_id,severity,context_data)
 SELECT md5(n::text)::uuid,$1::timestamptz,CASE WHEN n=1 THEN NULL ELSE $1::timestamptz END,'page-fixture','high',jsonb_build_object('payload',repeat('heavy',10000)) FROM generate_series(1,63) n`, stamp)
	require.NoError(t, err)
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			q := url.Values{"limit": {"25"}, "order": {order}}
			opt := pagination.Options{Scope: "alerts-test", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}}
			load := func() pagination.Page[*database.Alert] {
				p, err := pagination.Parse(q, opt)
				require.NoError(t, err)
				rows, total, err := repo.List(ctx, database.AlertFilters{Page: &p, Severity: []string{"high"}})
				require.NoError(t, err)
				require.Zero(t, total)
				for _, row := range rows {
					// The list carries only the small values the table renders.
					require.NotContains(t, row.ContextData, "payload")
					require.Equal(t, []string{"source"}, keys(row.ContextData))
					require.False(t, row.CreatedAt.IsZero())
				}
				return pagination.Build(rows, p, func(a *database.Alert) pagination.Key { return pagination.TimeKey(a.CreatedAt, a.ID) })
			}
			first := load()
			require.Len(t, first.Data, 25)
			_, err := pool.Exec(ctx, `INSERT INTO sigma_alerts(timestamp,created_at,rule_id,severity) VALUES($1,now()+interval '1 hour','page-fixture','high')`, stamp)
			require.NoError(t, err)
			seen := map[string]bool{}
			page := first
			for {
				for _, row := range page.Data {
					require.False(t, seen[row.ID], "duplicate row")
					seen[row.ID] = true
				}
				if !page.PageInfo.HasNext {
					break
				}
				q.Set("cursor", *page.PageInfo.NextCursor)
				page = load()
			}
			require.Len(t, seen, 63)
			for page.PageInfo.HasPrev {
				q.Set("cursor", *page.PageInfo.PrevCursor)
				page = load()
			}
			require.Equal(t, first.Data, page.Data)
			full, err := repo.GetByID(ctx, first.Data[0].ID)
			require.NoError(t, err)
			require.NotEmpty(t, full.ContextData["payload"])
		})
	}
}

func keys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Risk-score browsing: many alerts share each score, so the id tiebreaker
// must keep a walk free of duplicates and gaps in both directions.
func TestAlertRiskPagesPostgres(t *testing.T) {
	pool := isolatedDB(t)
	ctx := context.Background()
	repo := database.NewPostgresAlertRepository(pool)
	stamp := time.Now().UTC().Add(-time.Hour)
	_, err := pool.Exec(ctx, `INSERT INTO sigma_alerts(id,timestamp,created_at,rule_id,severity,risk_score,context_data)
 SELECT md5('risk'||n)::uuid,$1::timestamptz,$1::timestamptz,'risk-fixture','high',(n%3)*40,jsonb_build_object('source',jsonb_build_object('hostname','host-'||n),'payload',repeat('x',1000)) FROM generate_series(1,63) n`, stamp)
	require.NoError(t, err)
	opt := pagination.Options{Scope: "alerts-risk-test", DefaultSort: "created_at", Sorts: database.AlertSortColumns}
	for _, order := range []string{"asc", "desc"} {
		t.Run(order, func(t *testing.T) {
			q := url.Values{"limit": {"10"}, "sort": {"risk_score"}, "order": {order}}
			load := func() pagination.Page[*database.Alert] {
				p, err := pagination.Parse(q, opt)
				require.NoError(t, err)
				rows, _, err := repo.List(ctx, database.AlertFilters{Page: &p, RuleID: "risk-fixture"})
				require.NoError(t, err)
				return pagination.Build(rows, p, func(a *database.Alert) pagination.Key { return pagination.IntKey(int64(a.RiskScore), a.ID) })
			}
			first := load()
			require.Len(t, first.Data, 10)
			require.Equal(t, "high", first.Data[0].Severity)
			require.NotEmpty(t, first.Data[0].ContextData["source"].(map[string]interface{})["hostname"])
			seen := map[string]bool{}
			last := -1
			page := first
			for {
				for _, row := range page.Data {
					require.False(t, seen[row.ID], "duplicate row")
					seen[row.ID] = true
					if last >= 0 {
						if order == "desc" {
							require.LessOrEqual(t, row.RiskScore, last)
						} else {
							require.GreaterOrEqual(t, row.RiskScore, last)
						}
					}
					last = row.RiskScore
				}
				if !page.PageInfo.HasNext {
					break
				}
				q.Set("cursor", *page.PageInfo.NextCursor)
				page = load()
			}
			require.Len(t, seen, 63)
			for page.PageInfo.HasPrev {
				q.Set("cursor", *page.PageInfo.PrevCursor)
				page = load()
			}
			require.Equal(t, first.Data, page.Data)
		})
	}
}
