package api

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/geoip"
)

const maxNetworkContextIDs = 200

// SetAgentNetworkContext wires agent geolocation/clock data (both optional).
func (h *Handlers) SetAgentNetworkContext(repo *repository.AgentNetworkContextRepository, geo *geoip.Resolver) {
	h.networkContextRepo = repo
	h.geo = geo
}

// serverTimezone is the platform display timezone: EDR_TIMEZONE (IANA name,
// e.g. "Asia/Riyadh"), else the server's TZ, else the server's local zone
// (UTC in the container; an empty name means "offset only"). Display only:
// the process time zone is not changed, storage and processing stay in UTC.
func serverTimezone(now time.Time) (name string, loc *time.Location) {
	for _, env := range []string{"EDR_TIMEZONE", "TZ"} {
		if tz := strings.TrimPrefix(strings.TrimSpace(os.Getenv(env)), ":"); tz != "" {
			if l, err := time.LoadLocation(tz); err == nil {
				return l.String(), l
			}
		}
	}
	if n := time.Local.String(); n != "" && n != "Local" {
		return n, time.Local
	}
	if _, off := now.In(time.Local).Zone(); off == 0 {
		return "UTC", time.UTC
	}
	return "", time.Local // offset-only (no IANA name available)
}

// GetSystemTime handles GET /api/v1/system/time: the server clock and display
// timezone, so every dashboard renders times on one time base regardless of
// the viewer's own clock and region.
func (h *Handlers) GetSystemTime(c echo.Context) error {
	now := time.Now()
	name, loc := serverTimezone(now)
	abbr, offset := now.In(loc).Zone()
	return c.JSON(http.StatusOK, map[string]interface{}{
		"server_time":        now.UTC().Format(time.RFC3339Nano),
		"timezone":           name,
		"timezone_abbr":      abbr,
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
