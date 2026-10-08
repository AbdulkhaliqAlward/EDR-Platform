package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type preventionActivityResponse struct {
	EventSummary
	IngestedAt time.Time `json:"ingested_at"`
}

func (h *Handlers) ListPreventionActivity(c echo.Context) error {
	source, ok := h.eventRepo.(repository.PreventionActivityRepository)
	if !ok {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Prevention activity repository is unavailable")
	}
	now := time.Now().UTC()
	f := repository.PreventionActivityFilter{From: now.Add(-24 * time.Hour), Through: now, Limit: 200}
	for name, target := range map[string]*time.Time{"from": &f.From, "through": &f.Through} {
		if value := c.QueryParam(name); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return errorResponse(c, http.StatusBadRequest, "INVALID_RANGE", name+" must be an RFC3339 timestamp")
			}
			*target = parsed
		}
	}
	if f.Through.Before(f.From) {
		return errorResponse(c, http.StatusBadRequest, "INVALID_RANGE", "through must be at or after from")
	}
	if value := c.QueryParam("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || limit < 1 || limit > 200 {
			return errorResponse(c, http.StatusBadRequest, "INVALID_LIMIT", "limit must be 1 to 200")
		}
		f.Limit = limit
	}
	afterAt, afterID := c.QueryParam("cursor_ingested_at"), c.QueryParam("cursor_id")
	if afterAt != "" || afterID != "" {
		at, timeErr := time.Parse(time.RFC3339Nano, afterAt)
		id, idErr := uuid.Parse(afterID)
		if timeErr != nil || idErr != nil {
			return errorResponse(c, http.StatusBadRequest, "INVALID_CURSOR", "cursor requires both ingestion timestamp and event UUID")
		}
		f.AfterAt, f.AfterID = &at, &id
	}
	rows, err := source.ListPreventionActivity(c.Request().Context(), f)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Could not load prevention activity")
	}
	out := make([]preventionActivityResponse, 0, len(rows))
	for _, row := range rows {
		item := preventionActivityResponse{EventSummary: EventSummary{ID: row.ID, AgentID: row.AgentID,
			EventType: row.EventType, Severity: row.Severity, Timestamp: row.Timestamp, Summary: row.Summary}, IngestedAt: row.IngestedAt}
		var data map[string]interface{}
		if json.Unmarshal(row.Raw, &data) == nil {
			if nested, ok := data["data"].(map[string]interface{}); ok {
				data = nested
			}
			item.Data = map[string]interface{}{}
			for _, key := range []string{"autonomous", "action", "response_action", "name", "process_name", "path", "matched_rule_id", "matched_rule_title", "threat_name"} {
				if value, ok := data[key]; ok {
					item.Data[key] = value
				}
			}
		}
		out = append(out, item)
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"data": out})
}
