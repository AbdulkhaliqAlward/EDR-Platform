package api

import (
	"context"
	"encoding/json"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/shared/pagination"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"net/http/httptest"
	"testing"
)

type pageCommandRepo struct {
	repository.CommandRepository
	called bool
	filter repository.CommandListFilter
}

func (r *pageCommandRepo) ListAll(_ context.Context, f repository.CommandListFilter) ([]repository.CommandListItem, int64, error) {
	r.called = true
	r.filter = f
	return nil, 10001, nil
}
func TestCommandPageValidation(t *testing.T) {
	for _, q := range []string{"cursor=bad", "limit=-1", "offset=25", "sort=status", "agent_id=bad", "status=bad", "from=bad", "from=2099-01-01T00:00:00Z", "sort=issued_at&sort_by=status"} {
		repo := &pageCommandRepo{}
		h := &Handlers{commandRepo: repo, logger: logrus.New()}
		w := httptest.NewRecorder()
		err := h.ListCommands(echo.New().NewContext(httptest.NewRequest("GET", "/commands?"+q, nil), w))
		if err != nil || w.Code != 400 || repo.called {
			t.Fatalf("%s: status %d err %v called %v", q, w.Code, err, repo.called)
		}
	}
	for _, q := range []string{"", "limit=500", "include_total=true", "sort_by=issued_at&sort_order=asc"} {
		repo := &pageCommandRepo{}
		h := &Handlers{commandRepo: repo, logger: logrus.New()}
		w := httptest.NewRecorder()
		err := h.ListCommands(echo.New().NewContext(httptest.NewRequest("GET", "/commands?"+q, nil), w))
		if err != nil || w.Code != 200 {
			t.Fatalf("%s: %s %v", q, w.Body.String(), err)
		}
		var page pagination.Page[repository.CommandListItem]
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		want := 25
		if q == "limit=500" {
			want = 100
		}
		if page.PageInfo.Limit != want || (page.Total != nil) != (q == "include_total=true") {
			t.Fatal("incorrect cap/count", w.Body.String())
		}
		if page.Total != nil && (!page.Total.Capped || page.Total.Value != 10000) {
			t.Fatal("incorrect capped total")
		}
	}
}
