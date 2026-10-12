package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/geoip"
	"github.com/edr-platform/shared/tzdetect"
)

const maxNetworkContextIDs = 200

// SetAgentNetworkContext wires agent geolocation/clock data (both optional).
func (h *Handlers) SetAgentNetworkContext(repo *repository.AgentNetworkContextRepository, geo *geoip.Resolver) {
	h.networkContextRepo = repo
	h.geo = geo
}

// displayZone is the platform display time zone, detected automatically from
// the server host (see shared/tzdetect). Display only: the process time zone
// is not changed, storage and processing stay in UTC.
func (h *Handlers) displayZone() tzdetect.Zone {
	if h.tz != nil {
		return h.tz.Current()
	}
	return tzdetect.Current()
}

// GetSystemTime handles GET /api/v1/system/time: the server clock and display
// timezone, so every dashboard renders times on one time base regardless of
// the viewer's own clock and region.
func (h *Handlers) GetSystemTime(c echo.Context) error {
	now := time.Now()
	zone := h.displayZone()
	abbr, offset := now.In(zone.Location).Zone()
	return c.JSON(http.StatusOK, map[string]interface{}{
		"server_time":        now.UTC().Format(time.RFC3339Nano),
		"timezone":           zone.Name, // "" = offset only (unnamed host zone)
		"timezone_abbr":      abbr,
		"timezone_source":    zone.Source,
		"utc_offset_seconds": offset,
		"geoip": map[string]interface{}{
			"enabled":         h.geo.Enabled(),
			"source":          h.geo.Source(),
			"attribution_url": h.geo.AttributionURL(),
		},
		"meta": responseMeta(c),
	})
}

// ListAgentNetworkContext handles GET /api/v1/agents/network-context?ids=a,b:
// where each agent connects from (geolocated server-side from the address
// the server sees) and its measured clock offset.
func (h *Handlers) ListAgentNetworkContext(c echo.Context) error {
	if h.networkContextRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}
	var ids []uuid.UUID
	seen := map[uuid.UUID]bool{}
	for _, part := range strings.Split(c.QueryParam("ids"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := uuid.Parse(part)
		if err != nil {
			return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "ids must be agent UUIDs")
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return errorResponse(c, http.StatusBadRequest, "MISSING_IDS", "ids is required")
	}
	if len(ids) > maxNetworkContextIDs {
		return errorResponse(c, http.StatusBadRequest, "TOO_MANY_IDS", "at most 200 ids per request")
	}
	rows, err := h.networkContextRepo.GetMany(c.Request().Context(), ids)
	if err != nil {
		h.logger.WithError(err).Error("Failed to load agent network context")
		return errorResponse(c, http.StatusInternalServerError, "QUERY_FAILED", "Failed to load agent network context")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"data": rows, "meta": responseMeta(c)})
}
