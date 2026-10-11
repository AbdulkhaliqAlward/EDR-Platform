package api

import (
	"net/http"
	"strconv"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/shared/pagination"
	"github.com/labstack/echo/v4"
)

// smallListCap bounds endpoints that return a whole configuration table
// (roles, permissions, scripts, connectors, enrollment tokens, context
// policies, detection exceptions, automation rules, per-endpoint quarantine).
// These tables hold tens of rows and their screens need every row, so they keep
// the legacy full-list shape; the cap only guarantees a bounded response. When
// it trips, X-Result-Truncated tells the client the list is incomplete.
const smallListCap = 1000

func capList[T any](c echo.Context, rows []T) []T {
	if len(rows) <= smallListCap {
		return rows
	}
	c.Response().Header().Set("X-Result-Truncated", "true")
	return rows[:smallListCap]
}

// ListSignatureCatalog pages the signature catalog newest-first with keyset
// pagination on (version, id). GET /api/v1/signatures/catalog
// Params: limit (10–100 in the UI, ≤100 server), cursor, search (exact
// SHA-256 or name/family substring), source.
func (h *Handlers) ListSignatureCatalog(c echo.Context) error {
	if h.malwareHashRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Signature store not available")
	}
	p, err := pagination.Parse(c.QueryParams(), pagination.Options{Scope: "signatures/catalog", DefaultSort: "version", Sorts: map[string]string{"version": "version"}})
	if err != nil || p.Order != "desc" {
		return errorResponse(c, http.StatusBadRequest, "INVALID_PAGINATION", "invalid pagination parameters")
	}
	f := repository.SignatureCatalogFilter{Search: c.QueryParam("search"), Source: c.QueryParam("source"), Limit: p.Limit + 1, Before: p.Before}
	if len(f.Search) > 128 || len(f.Source) > 64 {
		return errorResponse(c, http.StatusBadRequest, "INVALID_FILTER", "filter is too long")
	}
	if p.Cursor != "" {
		version, verr := strconv.ParseInt(p.Key.Value, 10, 64)
		id, ierr := strconv.ParseInt(p.Key.ID, 10, 64)
		if verr != nil || ierr != nil {
			return errorResponse(c, http.StatusBadRequest, "INVALID_PAGINATION", pagination.ErrCursor.Error())
		}
		f.HasCursor, f.AfterVersion, f.AfterID = true, version, id
	}
	rows, err := h.malwareHashRepo.ListCatalog(c.Request().Context(), f)
	if err != nil {
		h.logger.WithError(err).Error("[signatures] catalog page failed")
		return errorResponse(c, http.StatusInternalServerError, "QUERY_FAILED", "Unable to load signatures; narrow the search")
	}
	page := pagination.Build(rows, p, func(m *models.MalwareHash) pagination.Key {
		return pagination.IntKey(m.Version, strconv.FormatInt(m.ID, 10))
	})
	if p.IncludeTotal && f.Search == "" && f.Source == "" {
		if n, err := h.malwareHashRepo.Count(c.Request().Context()); err == nil {
			page.Total = &pagination.Total{Value: int(n)}
		}
	}
	return c.JSON(http.StatusOK, page)
}
