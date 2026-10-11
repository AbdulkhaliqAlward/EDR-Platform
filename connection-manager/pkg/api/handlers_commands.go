// Package api provides command handler implementations for the Action Center.
package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/edr-platform/shared/pagination"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
)

// ListCommands returns paginated list of commands for the Action Center.
func (h *Handlers) ListCommands(c echo.Context) error { return h.commandPage(c, nil) }

func (h *Handlers) commandPage(c echo.Context, agentID *uuid.UUID) error {
	bad := func(message string) error { return errorResponse(c, 400, "INVALID_PAGINATION", message) }
	q := c.QueryParams()
	for _, pair := range [][2]string{{"sort_by", "sort"}, {"sort_order", "order"}} {
		if v := q.Get(pair[0]); v != "" {
			if q.Get(pair[1]) != "" && q.Get(pair[1]) != v {
				return bad("conflicting sort parameters")
			}
			q.Set(pair[1], v)
			q.Del(pair[0])
		}
	}
	if agentID != nil {
		if q.Get("agent_id") != "" && q.Get("agent_id") != agentID.String() {
			return bad("conflicting agent scope")
		}
		q.Set("agent_id", agentID.String())
	}
	p, err := pagination.Parse(q, pagination.Options{Scope: "commands", DefaultSort: "issued_at", Sorts: repository.CommandSortColumns})
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
	f := repository.CommandListFilter{Page: &p}
	if v := q.Get("agent_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return bad("invalid agent_id")
		}
		f.AgentID = &id
	}
	if v := q.Get("status"); v != "" {
		switch v {
		case "pending", "sent", "acknowledged", "executing", "completed", "failed", "timeout", "cancelled":
		default:
			return bad("invalid status")
		}
		f.Status = &v
	}
	if v := q.Get("command_type"); v != "" {
		if len(v) > 128 {
			return bad("command_type exceeds 128 characters")
		}
		f.CommandType = &v
	}
	args := []any{}
	if _, _, err := p.Keyset("c.issued_at", "c.id", &args); err != nil {
		return bad(err.Error())
	}
	if h.commandRepo == nil {
		return errorResponse(c, 503, "DB_UNAVAILABLE", "Command storage is unavailable")
	}
	items, total, err := h.commandRepo.ListAll(c.Request().Context(), f)
	if err != nil {
		h.logger.WithError(err).Warn("Command page failed")
		return errorResponse(c, 500, "QUERY_FAILED", "Unable to load command history")
	}
	page := pagination.Build(items, p, func(item repository.CommandListItem) pagination.Key {
		return pagination.TimeKey(item.IssuedAt, item.ID.String())
	})
	if p.IncludeTotal {
		page.Total = pagination.CappedTotal(int(total))
	}
	return c.JSON(200, page)
}

// GetCommandStats returns aggregate command statistics for Action Center KPIs.
func (h *Handlers) GetCommandStats(c echo.Context) error {
	if h.commandRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Command repository is not available")
	}

	stats, err := h.commandRepo.GetStats(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to get command stats")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve command statistics")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": stats,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// GetCommand returns one command by ID (same row shape as Action Center / agents/:id/commands).
func (h *Handlers) GetCommand(c echo.Context) error {
	if h.commandRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Command repository is not available")
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid command ID format")
	}

	cmd, err := h.commandRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Command not found")
		}
		h.logger.WithError(err).Error("GetCommand failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve command")
	}

	hostname := ""
	if h.agentSvc != nil {
		if a, err := h.agentSvc.GetByID(c.Request().Context(), cmd.AgentID); err == nil && a != nil {
			hostname = a.Hostname
		}
	}

	issuedByUser := ""
	if cmd.Metadata != nil {
		if u, ok := cmd.Metadata["issued_by_username"].(string); ok {
			issuedByUser = u
		}
	}

	item := repository.CommandListItem{
		Command:       *cmd,
		AgentHostname: hostname,
		IssuedByUser:  issuedByUser,
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": item,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}
