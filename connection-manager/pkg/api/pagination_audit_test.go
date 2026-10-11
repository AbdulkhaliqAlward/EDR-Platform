package api

import (
	"context"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"net/http/httptest"
	"testing"
)

type pageAuditRepo struct {
	repository.AuditLogRepository
	called, counted bool
	filter          repository.AuditLogFilter
}

func (m *pageAuditRepo) List(_ context.Context, f repository.AuditLogFilter) ([]*models.AuditLog, error) {
	m.called = true
	m.filter = f
	return nil, nil
}
func (m *pageAuditRepo) Count(_ context.Context, f repository.AuditLogFilter) (int64, error) {
	m.counted = true
	return 0, nil
}
func TestAuditPaginationValidation(t *testing.T) {
	for _, query := range []string{"cursor=invalid", "sort=old_value", "offset=10", "limit=0", "user_id=bad", "from=bad", "from=2026-10-11T00:00:00Z&to=2026-10-10T00:00:00Z"} {
		repo := &pageAuditRepo{}
		h := &Handlers{auditRepo: repo, logger: logrus.New()}
		w := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("GET", "/audit/logs?"+query, nil), w)
		if err := h.ListAuditLogs(c); err != nil {
			t.Fatal(err)
		}
		if w.Code != 400 || repo.called {
			t.Fatalf("%s: status=%d called=%v", query, w.Code, repo.called)
		}
	}
	for _, query := range []string{"", "limit=9999", "include_total=true"} {
		repo := &pageAuditRepo{}
		h := &Handlers{auditRepo: repo, logger: logrus.New()}
		w := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("GET", "/audit/logs?"+query, nil), w)
		if err := h.ListAuditLogs(c); err != nil {
			t.Fatal(err)
		}
		want := 25
		if query == "limit=9999" {
			want = 100
		}
		if w.Code != 200 || repo.filter.Page.Limit != want || repo.counted != (query == "include_total=true") {
			t.Fatalf("%s: %s", query, w.Body.String())
		}
	}
}
