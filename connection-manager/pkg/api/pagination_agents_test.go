package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type pageAgentService struct {
	service.AgentService
	called   bool
	filter   repository.AgentFilter
	countErr error
}

func (s *pageAgentService) ListAgents(_ context.Context, f repository.AgentFilter) ([]*models.Agent, error) {
	s.called, s.filter = true, f
	rows := make([]*models.Agent, f.Page.Limit+1)
	for i := range rows {
		rows[i] = &models.Agent{Hostname: "fixture"}
	}
	return rows, nil
}
func (s *pageAgentService) CountAgents(_ context.Context, _ repository.AgentFilter) (int64, error) {
	return 150, s.countErr
}

func TestAgentPagination(t *testing.T) {
	for _, q := range []string{"cursor=bad", "limit=0", "offset=-1", "sort=metadata", "sort=hostname&sort_by=status", "order=asc&sort_order=desc"} {
		s := &pageAgentService{}
		h := &Handlers{agentSvc: s, logger: logrus.New()}
		w := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("GET", "/agents?"+q, nil), w)
		if err := h.ListAgents(c); err != nil {
			t.Fatal(err)
		}
		if w.Code != 400 || s.called {
			t.Fatalf("%s: status %d, called %v", q, w.Code, s.called)
		}
	}
	for _, q := range []string{"", "limit=9999", "sort_by=hostname&sort_order=asc&os_type=windows&search=host"} {
		s := &pageAgentService{}
		h := &Handlers{agentSvc: s, logger: logrus.New()}
		w := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("GET", "/agents?"+q, nil), w)
		if err := h.ListAgents(c); err != nil {
			t.Fatal(err)
		}
		var got AgentListResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		want := 25
		if q == "limit=9999" {
			want = 100
		}
		if w.Code != 200 || len(got.Data) != want || !got.PageInfo.HasNext || got.PageInfo.NextCursor == nil || got.Pagination.Total != 150 {
			t.Fatalf("%s: %s", q, w.Body.String())
		}
		if q != "" && q != "limit=9999" && (s.filter.SortBy != "hostname" || s.filter.SortOrder != "asc" || *s.filter.OSType != "windows" || *s.filter.Search != "host") {
			t.Fatal("lost legacy sort/filter")
		}
	}
	s := &pageAgentService{countErr: errors.New("database failure")}
	h := &Handlers{agentSvc: s, logger: logrus.New()}
	w := httptest.NewRecorder()
	if err := h.ListAgents(echo.New().NewContext(httptest.NewRequest("GET", "/agents", nil), w)); err != nil {
		t.Fatal(err)
	}
	if w.Code != 500 {
		t.Fatal("count failure was presented as a successful page")
	}
}
