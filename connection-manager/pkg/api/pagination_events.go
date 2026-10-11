package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/shared/pagination"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func (h *Handlers) eventPage(c echo.Context, req EventSearchRequest) error {
	bad := func(message string) error {
		return errorResponse(c, http.StatusBadRequest, "INVALID_PAGINATION", message)
	}
	q := url.Values{}
	for k, v := range c.QueryParams() {
		q[k] = v
	}
	if req.Limit != 0 {
		q.Set("limit", fmt.Sprint(req.Limit))
	}
	if req.Offset != 0 {
		q.Set("offset", fmt.Sprint(req.Offset))
	}
	if req.Cursor != "" {
		q.Set("cursor", req.Cursor)
	}
	if req.Sort != "" {
		q.Set("sort", req.Sort)
	}
	if req.Order != "" {
		q.Set("order", req.Order)
	}
	if req.IncludeTotal {
		q.Set("include_total", "true")
	}
	if req.Logic == "" {
		req.Logic = "AND"
	}
	if req.Logic != "AND" && req.Logic != "OR" {
		return bad("logic must be AND or OR")
	}
	if len(req.Filters) > 20 {
		return bad("too many filters")
	}
	fields := map[string]bool{"agent_id": true, "event_type": true, "severity": true, "data.autonomous": true, "data.action": true, "data.name": true, "data.matched_rule_id": true, "data.matched_rule_title": true, "data.response_action": true, "data.decision_mode": true, "data.pid": true, "data.user_name": true}
	filters := make([]repository.EventSearchFilter, 0, len(req.Filters))
	for _, f := range req.Filters {
		if !fields[f.Field] {
			return bad("unsupported event filter")
		}
		validOp := f.Operator == "equals" || f.Operator == "contains" || (!strings.HasPrefix(f.Field, "data.") && f.Operator == "regex") || (strings.HasPrefix(f.Field, "data.") && f.Operator == "in")
		if !validOp {
			return bad("unsupported event filter operator")
		}
		if f.Field == "agent_id" {
			if f.Operator != "equals" {
				return bad("agent_id requires equals")
			}
			if _, err := uuid.Parse(fmt.Sprint(f.Value)); err != nil {
				return bad("invalid agent_id")
			}
		}
		if len(fmt.Sprint(f.Value)) > 1024 {
			return bad("filter value is too long")
		}
		if f.Operator == "regex" {
			if _, err := regexp.Compile(fmt.Sprint(f.Value)); err != nil {
				return bad("invalid regular expression")
			}
		}
		if f.Operator == "in" {
			v, ok := f.Value.([]interface{})
			if !ok || len(v) == 0 || len(v) > 100 {
				return bad("in requires 1 to 100 values")
			}
			for _, item := range v {
				if _, ok := item.(string); !ok {
					return bad("in requires string values")
				}
			}
		} else {
			switch f.Value.(type) {
			case string:
			case bool:
				if f.Field != "data.autonomous" || f.Operator != "equals" {
					return bad("this filter requires a string value")
				}
			case float64:
				if f.Field != "data.pid" || f.Operator != "equals" {
					return bad("this filter requires a string value")
				}
			default:
				return bad("filter value must be a scalar")
			}
		}
		filters = append(filters, repository.EventSearchFilter{Field: f.Field, Operator: f.Operator, Value: f.Value})
	}
	binding, _ := json.Marshal(struct {
		Filters   []EventFilter
		Logic     string
		TimeRange TimeRange
	}{req.Filters, req.Logic, req.TimeRange})
	q.Set("filter", string(binding))
	p, err := pagination.Parse(q, pagination.Options{Scope: "events", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at", "timestamp": "created_at"}})
	if err != nil {
		return bad(err.Error())
	}
	if req.TimeRange.From.IsZero() {
		req.TimeRange.From = p.From
	}
	if req.TimeRange.To.IsZero() {
		req.TimeRange.To = p.Until
	}
	if req.TimeRange.From.After(req.TimeRange.To) {
		return bad("from must precede to")
	}
	args := []any{}
	if _, _, err := p.Keyset("created_at", "id", &args); err != nil {
		return bad(err.Error())
	}
	if h.eventRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Event storage is unavailable")
	}
	rows, total, err := h.eventRepo.Search(c.Request().Context(), repository.EventSearchRequest{Filters: filters, Logic: req.Logic, TimeFrom: req.TimeRange.From, TimeTo: req.TimeRange.To, Page: &p, Limit: p.Limit})
	if err != nil {
		h.logger.WithError(err).Error("Event page query failed")
		return errorResponse(c, http.StatusInternalServerError, "SEARCH_FAILED", "Unable to load events; retry with a narrower time range")
	}
	out := make([]EventSummary, 0, len(rows))
	for _, r := range rows {
		e := EventSummary{ID: r.ID, AgentID: r.AgentID, EventType: r.EventType, Severity: r.Severity, Timestamp: r.Timestamp, CreatedAt: r.CreatedAt, Summary: r.Summary}
		if len(r.Raw) > 0 {
			_ = json.Unmarshal(r.Raw, &e.Data)
		}
		out = append(out, e)
	}
	page := pagination.Build(out, p, func(e EventSummary) pagination.Key { return pagination.TimeKey(e.CreatedAt, e.ID.String()) })
	if p.IncludeTotal {
		page.Total = pagination.CappedTotal(total)
	}
	return c.JSON(http.StatusOK, page)
}
