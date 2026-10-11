// handlers_security_events.go — GET /api/v1/security/events and /summary.
package api

import (
	"errors"
	"github.com/edr-platform/shared/pagination"
	"github.com/jackc/pgx/v5"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/pkg/audit"
)

// ListSecurityEvents handles GET /api/v1/security/events
// Query params: event_type, severity, actor_id, since (RFC3339), until (RFC3339), limit, offset
func (h *Handlers) ListSecurityEvents(c echo.Context) error {
	bad := func(message string) error { return errorResponse(c, 400, "INVALID_PAGINATION", message) }
	q := c.QueryParams()
	for _, pair := range [][2]string{{"since", "from"}, {"until", "to"}} {
		if v := q.Get(pair[0]); v != "" {
			if q.Get(pair[1]) != "" && q.Get(pair[1]) != v {
				return bad("conflicting date filters")
			}
			q.Set(pair[1], v)
			q.Del(pair[0])
		}
	}
	p, err := pagination.Parse(q, pagination.Options{Scope: "security/events", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}})
	if err != nil {
		return bad(err.Error())
	}
	for _, key := range []string{"from", "to"} {
		if v := q.Get(key); v != "" {
			stamp, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return bad("invalid " + key)
			}
			if key == "from" {
				p.From = stamp
			} else if stamp.Before(p.Until) {
				p.Until = stamp
			}
		}
	}
	if p.From.After(p.Until) {
		return bad("from must precede to")
	}
	f := audit.SecurityEventFilter{Page: &p, EventType: q.Get("event_type"), Severity: q.Get("severity")}
	if len(f.EventType) > 128 {
		return bad("event_type exceeds 128 characters")
	}
	if f.Severity != "" && f.Severity != "info" && f.Severity != "warning" && f.Severity != "critical" {
		return bad("invalid severity")
	}
	if v := q.Get("actor_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return bad("invalid actor_id")
		}
		f.ActorID = &id
	}
	args := []any{}
	if _, _, err := p.Keyset("created_at", "id", &args); err != nil {
		return bad(err.Error())
	}
	if h.securityEventRepo == nil {
		return errorResponse(c, 503, "DB_UNAVAILABLE", "Security event store not available")
	}
	events, err := h.securityEventRepo.List(c.Request().Context(), f)
	if err != nil {
		h.logger.WithError(err).Warn("Security event page failed")
		return errorResponse(c, 500, "DB_ERROR", "Failed to retrieve security events")
	}
	return c.JSON(200, pagination.Build(events, p, func(event audit.Event) pagination.Key { return pagination.TimeKey(event.CreatedAt, event.ID.String()) }))
}

func (h *Handlers) GetSecurityEvent(c echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, 400, "INVALID_ID", "Invalid security event ID")
	}
	if h.securityEventRepo == nil {
		return errorResponse(c, 503, "DB_UNAVAILABLE", "Security event store not available")
	}
	event, err := h.securityEventRepo.GetByID(c.Request().Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errorResponse(c, 404, "NOT_FOUND", "Security event not found")
	}
	if err != nil {
		return errorResponse(c, 500, "DB_ERROR", "Unable to load security event")
	}
	return c.JSON(200, map[string]any{"data": event})
}

// GetSecurityEventsSummary handles GET /api/v1/security/events/summary
// Returns counts grouped by event_type and severity for the last 24h.
func (h *Handlers) GetSecurityEventsSummary(c echo.Context) error {
	if h.securityEventRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Security event store not available")
	}

	rows, err := h.securityEventRepo.Summary(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get security events summary")
		return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Failed to retrieve security summary")
	}
	if rows == nil {
		rows = []audit.SeveritySummaryRow{}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": rows,
		"meta": map[string]interface{}{
			"window": "24h",
		},
	})
}
