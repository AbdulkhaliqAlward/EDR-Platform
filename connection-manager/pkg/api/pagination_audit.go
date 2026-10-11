package api

import (
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/shared/pagination"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"net/http"
	"time"
)

func (h *Handlers) ListAuditLogs(c echo.Context) error {
	bad := func(message string) error {
		return errorResponse(c, http.StatusBadRequest, "INVALID_PAGINATION", message)
	}
	p, err := pagination.Parse(c.QueryParams(), pagination.Options{Scope: "audit/logs", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}})
	if err != nil {
		return bad(err.Error())
	}
	f := repository.AuditLogFilter{Page: &p, StartTime: &p.From, EndTime: &p.Until, Text: map[string]string{}}
	for _, key := range []string{"from", "to"} {
		if v := c.QueryParam(key); v != "" {
			t, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return bad("invalid " + key)
			}
			if key == "from" {
				f.StartTime = &t
			} else if t.Before(p.Until) {
				f.EndTime = &t
			}
		}
	}
	if f.StartTime.After(*f.EndTime) {
		return bad("from must precede to")
	}
	if v := c.QueryParam("user_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return bad("invalid user_id")
		}
		f.UserID = &id
	}
	if v := c.QueryParam("action"); v != "" {
		if group, ok := actionGroupToDB[v]; ok {
			f.Actions = group
		} else {
			f.Action = &v
		}
	}
	if v := c.QueryParam("resource_type"); v != "" {
		f.ResourceType = &v
	}
	if v := c.QueryParam("result"); v != "" {
		f.Result = &v
	}
	for _, key := range []string{"staff", "affected", "oldVal", "newVal", "extra", "session", "search"} {
		v := c.QueryParam(key)
		if len(v) > 512 {
			return bad("filter exceeds 512 characters")
		}
		f.Text[key] = v
	}
	args := []any{}
	if _, _, err = p.Keyset("created_at", "id", &args); err != nil {
		return bad(err.Error())
	}
	if h.auditRepo == nil {
		return errorResponse(c, 503, "DB_UNAVAILABLE", "Audit storage is unavailable")
	}
	rows, err := h.auditRepo.List(c.Request().Context(), f)
	if err != nil {
		h.logger.WithError(err).Warn("Audit page failed")
		return errorResponse(c, 500, "QUERY_FAILED", "Unable to load audit logs; retry with a narrower time range")
	}
	page := pagination.Build(rows, p, func(row *models.AuditLog) pagination.Key { return pagination.TimeKey(row.Timestamp, row.ID.String()) })
	if p.IncludeTotal {
		n, err := h.auditRepo.Count(c.Request().Context(), f)
		if err != nil {
			return errorResponse(c, 500, "QUERY_FAILED", "Unable to count audit logs")
		}
		page.Total = pagination.CappedTotal(int(n))
	}
	return c.JSON(200, page)
}
