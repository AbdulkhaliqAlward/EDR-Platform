package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/shared/pagination"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

type pageEventRepo struct {
	repository.EventRepository
	called bool
}

func (m *pageEventRepo) Search(_ context.Context, r repository.EventSearchRequest) ([]repository.EventRow, int, error) {
	m.called = true
	rows := make([]repository.EventRow, r.Page.Limit+1)
	for i := range rows {
		rows[i] = repository.EventRow{ID: uuid.New(), CreatedAt: time.Now()}
	}
	return rows, 0, nil
}
func TestEventPaginationValidation(t *testing.T) {
	for _, body := range []string{`{"limit":-1}`, `{"cursor":"bad"}`, `{"offset":25}`, `{"sort":"raw"}`, `{"logic":"not"}`, `{"filters":[{"field":"severity","operator":"equals","value":{}}]}`, `{"filters":[{"field":"data.name","operator":"in","value":[{}]}]}`, `{"filters":[{"field":"agent_id","operator":"equals","value":"bad"}]}`} {
		repo := &pageEventRepo{}
		h := &Handlers{eventRepo: repo, logger: logrus.New()}
		e := echo.New()
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/events/search", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if err := h.SearchEvents(e.NewContext(r, w)); err != nil {
			t.Fatal(err)
		}
		if w.Code != 400 || repo.called {
			t.Fatalf("%s status=%d called=%v", body, w.Code, repo.called)
		}
	}
	for _, limit := range []int{0, 9999} {
		repo := &pageEventRepo{}
		h := &Handlers{eventRepo: repo, logger: logrus.New()}
		w := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest("POST", "/events/search", nil), w)
		if err := h.eventPage(c, EventSearchRequest{Limit: limit}); err != nil {
			t.Fatal(err)
		}
		var page pagination.Page[EventSummary]
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		want := 25
		if limit > 0 {
			want = 100
		}
		if w.Code != 200 || len(page.Data) != want || !page.PageInfo.HasNext || page.Total != nil {
			t.Fatalf("invalid page: %s", w.Body.String())
		}
	}
}
