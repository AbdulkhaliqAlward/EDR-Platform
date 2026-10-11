package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edr-platform/shared/pagination"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
)

type pageAlertRepo struct {
	database.AlertRepository
	called  bool
	filters database.AlertFilters
}

func (m *pageAlertRepo) List(_ context.Context, f database.AlertFilters) ([]*database.Alert, int64, error) {
	m.called = true
	m.filters = f
	rows := make([]*database.Alert, f.Limit+1)
	for i := range rows {
		rows[i] = &database.Alert{ID: time.Unix(int64(i), 0).Format(time.RFC3339), CreatedAt: time.Now(), Severity: "high", Status: "open"}
	}
	return rows, 0, nil
}
func TestAlertPaginationValidation(t *testing.T) {
	for _, query := range []string{"limit=-1", "limit=abc", "cursor=invalid", "offset=25", "sort=severity", "sort=context_data", "order=sideways", "date_from=broken", "severity=unknown", "status=unknown"} {
		t.Run(query, func(t *testing.T) {
			repo := &pageAlertRepo{}
			h := &AlertHandler{repo: repo}
			w := httptest.NewRecorder()
			h.QueryAlerts(w, httptest.NewRequest("GET", "/sigma/alerts?"+query, nil))
			if w.Code != 400 || repo.called {
				t.Fatalf("status=%d called=%v", w.Code, repo.called)
			}
		})
	}
	for _, query := range []string{"", "limit=9999"} {
		repo := &pageAlertRepo{}
		h := &AlertHandler{repo: repo}
		w := httptest.NewRecorder()
		h.QueryAlerts(w, httptest.NewRequest("GET", "/sigma/alerts?"+query, nil))
		var page pagination.Page[*AlertResponse]
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		want := 25
		if query != "" {
			want = 100
		}
		if w.Code != 200 || len(page.Data) != want || !page.PageInfo.HasNext || page.Total != nil {
			t.Fatalf("invalid page: %s", w.Body.String())
		}
	}
}

// risk_score is a supported keyset sort; its cursor must carry an integer key.
func TestAlertRiskSortCursor(t *testing.T) {
	repo := &pageAlertRepo{}
	h := &AlertHandler{repo: repo}
	w := httptest.NewRecorder()
	h.QueryAlerts(w, httptest.NewRequest("GET", "/sigma/alerts?sort=risk_score&order=desc", nil))
	var page pagination.Page[*AlertResponse]
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || page.PageInfo.NextCursor == nil {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if repo.filters.Page == nil || repo.filters.Page.Sort != "risk_score" {
		t.Fatalf("sort not passed to repository: %+v", repo.filters.Page)
	}
	repo2 := &pageAlertRepo{}
	h2 := &AlertHandler{repo: repo2}
	w = httptest.NewRecorder()
	h2.QueryAlerts(w, httptest.NewRequest("GET", "/sigma/alerts?sort=risk_score&order=desc&cursor="+*page.PageInfo.NextCursor, nil))
	if w.Code != 200 || !repo2.called || repo2.filters.Page.Key.Value != "0" {
		t.Fatalf("follow-up page status=%d key=%+v", w.Code, repo2.filters.Page)
	}
	// The same cursor is rejected when the sort changes.
	w = httptest.NewRecorder()
	h2.QueryAlerts(w, httptest.NewRequest("GET", "/sigma/alerts?sort=created_at&order=desc&cursor="+*page.PageInfo.NextCursor, nil))
	if w.Code != 400 {
		t.Fatalf("cursor accepted for another sort: %d", w.Code)
	}
}

type pageRuleRepo struct {
	database.RuleRepository
	called  bool
	filters database.RuleFilters
}

func (m *pageRuleRepo) List(_ context.Context, f database.RuleFilters) ([]*database.Rule, int64, error) {
	m.called = true
	m.filters = f
	return []*database.Rule{}, 0, nil
}
func TestRulePaginationValidation(t *testing.T) {
	for _, query := range []string{"cursor=bad", "limit=-1", "sort=content", "order=sideways", "enabled=maybe"} {
		repo := &pageRuleRepo{}
		h := &RuleHandler{repo: repo}
		w := httptest.NewRecorder()
		h.ListRules(w, httptest.NewRequest("GET", "/sigma/rules?"+query, nil))
		if w.Code != 400 || repo.called {
			t.Fatalf("%s status=%d", query, w.Code)
		}
	}
	repo := &pageRuleRepo{}
	h := &RuleHandler{repo: repo}
	w := httptest.NewRecorder()
	h.ListRules(w, httptest.NewRequest("GET", "/sigma/rules?limit=9999&search=test&enabled=false", nil))
	if w.Code != 200 || repo.filters.Limit != 100 || repo.filters.Search != "test" || *repo.filters.Enabled {
		t.Fatalf("bad bounded filters: %+v", repo.filters)
	}
}
