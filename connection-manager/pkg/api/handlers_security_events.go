// handlers_security_events.go — GET /api/v1/security/events and /summary.
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/pkg/audit"
)

// ListSecurityEvents handles GET /api/v1/security/events
// Query params: event_type, severity, actor_id, since (RFC3339), until (RFC3339), limit, offset
func (h *Handlers) ListSecurityEvents(c echo.Context) error {
	if h.securityEventRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Security event store not available")
	}

	f := audit.SecurityEventFilter{}

	if v := c.QueryParam("event_type"); v != "" {
		f.EventType = v
	}
	if v := c.QueryParam("severity"); v != "" {
		f.Severity = v
	}
	if v := c.QueryParam("actor_id"); v != "" {
		if uid, err := uuid.Parse(v); err == nil {
			f.ActorID = &uid
		}
	}
	if v := c.QueryParam("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Since = &t
		}
	}
	if v := c.QueryParam("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.Until = &t
		}
	}
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := c.QueryParam("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}

	events, err := h.securityEventRepo.List(c.Request().Context(), f)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list security events")
		return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Failed to retrieve security events")
	}
	if events == nil {
		events = []audit.Event{}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": events,
		"meta": map[string]interface{}{
			"limit":  f.Limit,
			"offset": f.Offset,
			"count":  len(events),
		},
	})
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
