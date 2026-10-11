package api

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
)

type siemConnectorCreateRequest struct {
	Name          string `json:"name"`
	ConnectorType string `json:"connector_type"`
	EndpointURL   string `json:"endpoint_url"`
	Enabled       bool   `json:"enabled"`
	Notes         string `json:"notes"`
}

type siemConnectorPatchRequest struct {
	Name          *string `json:"name,omitempty"`
	ConnectorType *string `json:"connector_type,omitempty"`
	EndpointURL   *string `json:"endpoint_url,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
	Notes         *string `json:"notes,omitempty"`
	Status        *string `json:"status,omitempty"`
}

// ListSiemConnectors returns configured SIEM / webhook destinations.
// GET /api/v1/siem/connectors
func (h *Handlers) ListSiemConnectors(c echo.Context) error {
	if h.siemRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "SIEM connector store is not available")
	}
	rows, err := h.siemRepo.List(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to list SIEM connectors")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list SIEM connectors")
	}
	rows = capList(c, rows)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": rows,
		"meta": responseMeta(c),
	})
}

// CreateSiemConnector adds a destination.
// POST /api/v1/siem/connectors
func (h *Handlers) CreateSiemConnector(c echo.Context) error {
	if h.siemRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "SIEM connector store is not available")
	}
	var req siemConnectorCreateRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_BODY", "Invalid JSON body")
	}
	if strings.TrimSpace(req.Name) == "" {
		return errorResponse(c, http.StatusBadRequest, "INVALID_NAME", "name is required")
	}
	if !repository.ValidSiemConnectorType(req.ConnectorType) {
		return errorResponse(c, http.StatusBadRequest, "INVALID_TYPE", "connector_type must be splunk_hec, azure_sentinel, elastic_webhook, generic_webhook, or syslog_tls")
	}
	u := strings.TrimSpace(req.EndpointURL)
	if u == "" {
		return errorResponse(c, http.StatusBadRequest, "INVALID_URL", "endpoint_url is required")
	}
	if !strings.HasPrefix(strings.ToLower(u), "http://") && !strings.HasPrefix(strings.ToLower(u), "https://") {
		return errorResponse(c, http.StatusBadRequest, "INVALID_URL", "endpoint_url must start with http:// or https://")
	}
	status := "never_tested"
	if !req.Enabled {
		status = "disabled"
	}
	row := &repository.SiemConnectorRow{
		Name:          strings.TrimSpace(req.Name),
		ConnectorType: strings.TrimSpace(req.ConnectorType),
		EndpointURL:   u,
		Enabled:       req.Enabled,
		Status:        status,
		Notes:         strings.TrimSpace(req.Notes),
		Metadata:      []byte(`{}`),
	}
	if err := h.siemRepo.Create(c.Request().Context(), row); err != nil {
		h.logger.WithError(err).Error("Failed to create SIEM connector")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create SIEM connector")
	}
	return c.JSON(http.StatusCreated, map[string]interface{}{
		"data": row,
		"meta": responseMeta(c),
	})
}

// PatchSiemConnector updates a connector.
// PATCH /api/v1/siem/connectors/:id
func (h *Handlers) PatchSiemConnector(c echo.Context) error {
	if h.siemRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "SIEM connector store is not available")
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid connector id")
	}
	row, err := h.siemRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		if err == repository.ErrNotFound {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Connector not found")
		}
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load connector")
	}
	var req siemConnectorPatchRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_BODY", "Invalid JSON body")
	}
	if req.Name != nil {
		row.Name = strings.TrimSpace(*req.Name)
	}
	if req.ConnectorType != nil {
		if !repository.ValidSiemConnectorType(*req.ConnectorType) {
			return errorResponse(c, http.StatusBadRequest, "INVALID_TYPE", "invalid connector_type")
		}
		row.ConnectorType = strings.TrimSpace(*req.ConnectorType)
	}
	if req.EndpointURL != nil {
		u := strings.TrimSpace(*req.EndpointURL)
		if u != "" && !strings.HasPrefix(strings.ToLower(u), "http://") && !strings.HasPrefix(strings.ToLower(u), "https://") {
			return errorResponse(c, http.StatusBadRequest, "INVALID_URL", "endpoint_url must start with http:// or https://")
		}
		if u != "" {
			row.EndpointURL = u
		}
	}
	if req.Enabled != nil {
		row.Enabled = *req.Enabled
		if !row.Enabled {
			row.Status = "disabled"
		} else if row.Status == "disabled" {
			row.Status = "never_tested"
		}
	}
	if req.Notes != nil {
		row.Notes = strings.TrimSpace(*req.Notes)
	}
	if req.Status != nil {
		s := strings.TrimSpace(*req.Status)
		switch s {
		case "never_tested", "ok", "degraded", "error", "disabled":
			row.Status = s
		default:
			return errorResponse(c, http.StatusBadRequest, "INVALID_STATUS", "invalid status")
		}
	}
	if err := h.siemRepo.Update(c.Request().Context(), row); err != nil {
		if err == repository.ErrNotFound {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Connector not found")
		}
		h.logger.WithError(err).Error("Failed to update SIEM connector")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update SIEM connector")
	}
	updated, _ := h.siemRepo.GetByID(c.Request().Context(), id)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": updated,
		"meta": responseMeta(c),
	})
}

// DeleteSiemConnector removes a connector.
// DELETE /api/v1/siem/connectors/:id
func (h *Handlers) DeleteSiemConnector(c echo.Context) error {
	if h.siemRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "SIEM connector store is not available")
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid connector id")
	}
	if err := h.siemRepo.Delete(c.Request().Context(), id); err != nil {
		if err == repository.ErrNotFound {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Connector not found")
		}
		h.logger.WithError(err).Error("Failed to delete SIEM connector")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete SIEM connector")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": map[string]bool{"deleted": true},
		"meta": responseMeta(c),
	})
}
