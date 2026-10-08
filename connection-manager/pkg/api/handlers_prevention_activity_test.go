package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type preventionActivityStore struct {
	repository.EventRepository
	filter repository.PreventionActivityFilter
	rows   []repository.PreventionActivity
}

func (s *preventionActivityStore) ListPreventionActivity(_ context.Context, f repository.PreventionActivityFilter) ([]repository.PreventionActivity, error) {
	s.filter = f
	return s.rows, nil
}

func TestPreventionActivityRetainsEventAndIngestionTimes(t *testing.T) {
	now := time.Now().UTC()
	s := &preventionActivityStore{rows: []repository.PreventionActivity{{
		EventRow:   repository.EventRow{ID: uuid.New(), AgentID: uuid.New(), Timestamp: now.Add(-7 * 24 * time.Hour), Raw: json.RawMessage(`{"data":{"autonomous":true,"response_action":"terminate","name":"sample.exe","command_line":"large evidence omitted"}}`)},
		IngestedAt: now,
	}}}
	h := &Handlers{eventRepo: s}
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/events/prevention-activity", nil), rec)
	if err := h.ListPreventionActivity(c); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Data []preventionActivityResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || !body.Data[0].IngestedAt.Equal(now) || !body.Data[0].Timestamp.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("delayed event lost timing: %+v", body)
	}
	if body.Data[0].Data["response_action"] != "terminate" || body.Data[0].Data["command_line"] != nil {
		t.Fatal("activity summary fields incorrect")
	}
}

func TestPreventionActivityRejectsIncompleteCursor(t *testing.T) {
	h := &Handlers{eventRepo: &preventionActivityStore{}}
	for _, query := range []string{"?cursor_id=" + uuid.NewString(), "?cursor_ingested_at=invalid", "?limit=0", "?limit=201"} {
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/events/prevention-activity"+query, nil), rec)
		if err := h.ListPreventionActivity(c); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatal("invalid cursor/limit accepted", query, rec.Code)
		}
	}
}
