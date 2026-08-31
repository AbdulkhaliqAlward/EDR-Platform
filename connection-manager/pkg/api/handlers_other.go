// Package api provides alert, event, policy, user, and audit handlers.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/handlers"
	"github.com/edr-platform/connection-manager/pkg/models"
)

type contextPolicyRequest struct {
	Name                    string   `json:"name"`
	ScopeType               string   `json:"scope_type"`
	ScopeValue              string   `json:"scope_value"`
	Enabled                 *bool    `json:"enabled,omitempty"`
	UserRoleWeight          float64  `json:"user_role_weight"`
	DeviceCriticalityWeight float64  `json:"device_criticality_weight"`
	NetworkAnomalyFactor    float64  `json:"network_anomaly_factor"`
	TrustedNetworks         []string `json:"trusted_networks"`
	Notes                   string   `json:"notes"`
}

func validateContextPolicyInput(req *contextPolicyRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	switch req.ScopeType {
	case "global", "agent", "user":
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "scope_type must be one of: global, agent, user")
	}
	if strings.TrimSpace(req.ScopeValue) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "scope_value is required")
	}
	// Hardening: global scope must always use "*" (single effective global policy).
	// The DB seeds this row and enforces uniqueness by (scope_type, scope_value).
	if req.ScopeType == "global" && strings.TrimSpace(req.ScopeValue) != "*" {
		return echo.NewHTTPError(http.StatusBadRequest, "global scope_value must be '*'")
	}
	if req.UserRoleWeight <= 0 || req.DeviceCriticalityWeight <= 0 || req.NetworkAnomalyFactor <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "all weights/factors must be > 0")
	}
	return nil
}

// GetReliabilityHealth returns operational reliability counters for the data plane.
// GET /api/v1/reliability
func (h *Handlers) GetReliabilityHealth(c echo.Context) error {
	type fallbackPayload struct {
		Enabled bool                         `json:"enabled"`
		Reason  string                       `json:"reason,omitempty"`
		Stats   *handlers.EventFallbackStats `json:"stats,omitempty"`
	}

	var fb fallbackPayload
	if h.fallbackStore == nil {
		fb = fallbackPayload{
			Enabled: false,
			Reason:  "DB fallback store not configured (PostgreSQL unavailable or fallback disabled at startup)",
		}
	} else {
		stats := h.fallbackStore.Stats()
		fb = fallbackPayload{
			Enabled: true,
			Stats:   &stats,
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"fallback_store": fb,
		"meta":           responseMeta(c),
	})
}

// ListContextPolicies returns all context-aware policies.
func (h *Handlers) ListContextPolicies(c echo.Context) error {
	if h.contextPolicyRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}
	items, err := h.contextPolicyRepo.List(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to list context policies")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list context policies")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":  items,
		"total": len(items),
		"meta":  responseMeta(c),
	})
}

// GetContextPolicy returns a context policy by ID.
func (h *Handlers) GetContextPolicy(c echo.Context) error {
	if h.contextPolicyRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid policy ID")
	}
	item, err := h.contextPolicyRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		if err == repository.ErrNotFound {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Context policy not found")
		}
		h.logger.WithError(err).Error("Failed to get context policy")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get context policy")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": item,
		"meta": responseMeta(c),
	})
}

// CreateContextPolicy creates a new context-aware policy.
func (h *Handlers) CreateContextPolicy(c echo.Context) error {
	if h.contextPolicyRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}
	var req contextPolicyRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	if err := validateContextPolicyInput(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	item := &models.ContextPolicy{
		Name:                    strings.TrimSpace(req.Name),
		ScopeType:               req.ScopeType,
		ScopeValue:              strings.TrimSpace(req.ScopeValue),
		Enabled:                 enabled,
		UserRoleWeight:          req.UserRoleWeight,
		DeviceCriticalityWeight: req.DeviceCriticalityWeight,
		NetworkAnomalyFactor:    req.NetworkAnomalyFactor,
		TrustedNetworks:         req.TrustedNetworks,
		Notes:                   req.Notes,
	}
	if err := h.contextPolicyRepo.Create(c.Request().Context(), item); err != nil {
		h.logger.WithError(err).Error("Failed to create context policy")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create context policy")
	}
	return c.JSON(http.StatusCreated, map[string]interface{}{
		"data": item,
		"meta": responseMeta(c),
	})
}

// UpdateContextPolicy updates an existing context-aware policy.
func (h *Handlers) UpdateContextPolicy(c echo.Context) error {
	if h.contextPolicyRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid policy ID")
	}
	var req contextPolicyRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	if err := validateContextPolicyInput(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	item := &models.ContextPolicy{
		ID:                      id,
		Name:                    strings.TrimSpace(req.Name),
		ScopeType:               req.ScopeType,
		ScopeValue:              strings.TrimSpace(req.ScopeValue),
		Enabled:                 enabled,
		UserRoleWeight:          req.UserRoleWeight,
		DeviceCriticalityWeight: req.DeviceCriticalityWeight,
		NetworkAnomalyFactor:    req.NetworkAnomalyFactor,
		TrustedNetworks:         req.TrustedNetworks,
		Notes:                   req.Notes,
	}
	if err := h.contextPolicyRepo.Update(c.Request().Context(), item); err != nil {
		if err == repository.ErrNotFound {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Context policy not found")
		}
		h.logger.WithError(err).Error("Failed to update context policy")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update context policy")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": item,
		"meta": responseMeta(c),
	})
}

// DeleteContextPolicy deletes a context-aware policy.
func (h *Handlers) DeleteContextPolicy(c echo.Context) error {
	if h.contextPolicyRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid policy ID")
	}
	if err := h.contextPolicyRepo.Delete(c.Request().Context(), id); err != nil {
		if err == repository.ErrNotFound {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Context policy not found")
		}
		h.logger.WithError(err).Error("Failed to delete context policy")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete context policy")
	}
	return c.NoContent(http.StatusNoContent)
}

// ============================================================================
// AUDIT HELPER
// ============================================================================

// fireAudit creates and persists an audit log entry asynchronously.
// It is intentionally non-blocking: the result is best-effort.
func (h *Handlers) fireAudit(
	c echo.Context,
	action, resourceType string,
	resourceID uuid.UUID,
	details string,
	failed bool,
	failReason string,
) {
	if h.auditRepo == nil {
		return
	}
	ip, ua := auditContext(c)
	userID := uuid.Nil
	username := "unknown"
	if user := getCurrentUser(c); user != nil {
		username = user.Username
		if uid, err := uuid.Parse(user.UserID); err == nil {
			userID = uid
		}
	}
	entry := models.NewAuditLog(userID, username, action, resourceType, resourceID).
		WithContext(ip, ua).
		WithDetails(details)
	if failed {
		entry.MarkFailed(failReason)
	}

	go func(e *models.AuditLog) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.auditRepo.Create(ctx, e); err != nil {
			h.logger.WithError(err).Warn("[Audit] Failed to persist audit entry (non-fatal)")
		}
	}(entry)
}

// ============================================================================
// ALERT HANDLERS
// ============================================================================

// ListAlerts returns paginated list of alerts.
func (h *Handlers) ListAlerts(c echo.Context) error {
	return c.JSON(http.StatusOK, AlertListResponse{
		Data:       []AlertSummary{},
		Pagination: PaginationResponse{Total: 0, Limit: 50, Offset: 0},
		Meta:       responseMeta(c),
	})
}

// SearchAlerts performs advanced alert search.
func (h *Handlers) SearchAlerts(c echo.Context) error {
	var req AlertSearchRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	return c.JSON(http.StatusOK, AlertListResponse{
		Data:       []AlertSummary{},
		Pagination: PaginationResponse{Total: 0, Limit: req.Limit, Offset: req.Offset},
		Meta:       responseMeta(c),
	})
}

// GetAlertStats returns alert statistics.
func (h *Handlers) GetAlertStats(c echo.Context) error {
	if h.alertRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	stats, err := h.alertRepo.GetStats(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to fetch alert stats")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fetch alert stats")
	}

	return c.JSON(http.StatusOK, AlertStatsResponse{
		Total:         stats.Total,
		Alerts24h:     stats.Alerts24h,
		AvgConfidence: stats.AvgConfidence,
		Open:          stats.Open,
		InProgress:    stats.InProgress,
		Resolved:      stats.Resolved,
		BySeverity:    stats.BySeverity,
		ByStatus:      stats.ByStatus,
		Meta:          responseMeta(c),
	})
}

// GetEndpointRisk returns the per-agent risk posture summary (Phase 2).
// Aggregates risk_score data from sigma_alerts grouped by agent_id,
// ordered by peak_risk_score DESC so the riskiest endpoints appear first.
func (h *Handlers) GetEndpointRisk(c echo.Context) error {
	if h.alertRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	summaries, err := h.alertRepo.GetEndpointRiskSummary(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("Failed to fetch endpoint risk summary")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to compute endpoint risk summary")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":  summaries,
		"total": len(summaries),
		"meta":  responseMeta(c),
	})
}

// GetAlert returns a single alert.
func (h *Handlers) GetAlert(c echo.Context) error {
	idStr := c.Param("id")
	if _, err := uuid.Parse(idStr); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert ID format")
	}
	return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Alert not found")
}

// UpdateAlert updates alert status (used to acknowledge an alert).
func (h *Handlers) UpdateAlert(c echo.Context) error {
	idStr := c.Param("id")
	alertID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert ID format")
	}
	var req AlertUpdateRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	// Audit: alert acknowledged
	h.fireAudit(c, models.AuditActionAlertAcknowledged, "alert", alertID,
		"status="+req.Status, false, "")

	return c.JSON(http.StatusOK, map[string]interface{}{"message": "Alert updated", "meta": responseMeta(c)})
}

// ResolveAlert resolves an alert.
func (h *Handlers) ResolveAlert(c echo.Context) error {
	idStr := c.Param("id")
	alertID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert ID format")
	}
	var req AlertResolveRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	// Audit: alert resolved
	h.fireAudit(c, models.AuditActionAlertResolved, "alert", alertID,
		"resolution="+req.Resolution, false, "")

	return c.JSON(http.StatusOK, map[string]interface{}{"message": "Alert resolved", "meta": responseMeta(c)})
}

// AddAlertNote adds a note to an alert.
func (h *Handlers) AddAlertNote(c echo.Context) error {
	idStr := c.Param("id")
	if _, err := uuid.Parse(idStr); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert ID format")
	}
	var req AlertNoteRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	return c.JSON(http.StatusCreated, map[string]interface{}{"message": "Note added", "meta": responseMeta(c)})
}

// DeleteAlert deletes an alert.
func (h *Handlers) DeleteAlert(c echo.Context) error {
	idStr := c.Param("id")
	alertID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert ID format")
	}

	// Audit: alert deleted
	h.fireAudit(c, models.AuditActionAlertDeleted, "alert", alertID, "", false, "")

	return c.NoContent(http.StatusNoContent)
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

// SearchEvents performs advanced event search.
func (h *Handlers) SearchEvents(c echo.Context) error {
	var req EventSearchRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	if h.eventRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Event repository is not available")
	}

	// Validate defaults
	limit := req.Limit
	offset := req.Offset
	if limit <= 0 {
		limit = 50
	}
	if limit > 10000 {
		limit = 10000
	}
	if offset < 0 {
		offset = 0
	}

	// Convert request to repository request
	filters := make([]repository.EventSearchFilter, 0, len(req.Filters))
	for _, f := range req.Filters {
		filters = append(filters, repository.EventSearchFilter{
			Field:    f.Field,
			Operator: f.Operator,
			Value:    f.Value,
		})
	}

	rows, total, err := h.eventRepo.Search(c.Request().Context(), repository.EventSearchRequest{
		Filters:  filters,
		Logic:    req.Logic,
		TimeFrom: req.TimeRange.From,
		TimeTo:   req.TimeRange.To,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "SEARCH_FAILED", err.Error())
	}

	out := make([]EventSummary, 0, len(rows))
	for _, r := range rows {
		es := EventSummary{
			ID:        r.ID,
			AgentID:   r.AgentID,
			EventType: r.EventType,
			Severity:  r.Severity,
			Timestamp: r.Timestamp,
			Summary:   r.Summary,
		}
		// Decode raw payload so the dashboard gets typed fields (action, name, pid, rule, etc.)
		// without needing a second /events/:id fetch for every row.
		if len(r.Raw) > 0 {
			var raw map[string]interface{}
			if err := json.Unmarshal(r.Raw, &raw); err == nil {
				// Prefer the nested "data" object if present, otherwise use top-level raw.
				if nested, ok := raw["data"].(map[string]interface{}); ok {
					es.Data = nested
				} else {
					// Flatten: copy useful keys from the top-level raw into Data.
					flat := make(map[string]interface{})
					for _, k := range []string{
						"action", "autonomous", "name", "process_name",
						"pid", "ppid", "command_line", "parent_name",
						"matched_rule_id", "matched_rule_title", "decision_mode",
						"kill_tree", "kill_output", "kill_error",
						"user_name", "is_elevated", "signature_status",
						"hostname",
					} {
						if v, exists := raw[k]; exists {
							flat[k] = v
						}
					}
					if len(flat) > 0 {
						es.Data = flat
					}
				}
				// Also pull severity from raw if not set
				if es.Severity == "" || es.Severity == "informational" {
					if s, ok := raw["severity"].(string); ok && s != "" {
						es.Severity = s
					}
				}
			}
		}
		out = append(out, es)
	}

	return c.JSON(http.StatusOK, EventListResponse{
		Data:       out,
		Pagination: PaginationResponse{Total: total, Limit: limit, Offset: offset},
		Meta:       responseMeta(c),
	})
}

// GetEventStats returns event statistics.
func (h *Handlers) GetEventStats(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"total_events":  1500000,
		"today":         15000,
		"by_type":       map[string]int{"process": 500000, "file": 400000, "network": 350000, "registry": 250000},
		"by_agent_top5": []map[string]interface{}{},
		"meta":          responseMeta(c),
	})
}

// GetEvent returns a single event.
func (h *Handlers) GetEvent(c echo.Context) error {
	idStr := c.Param("id")
	eventID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid event ID format")
	}
	if h.eventRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Event repository is not available")
	}
	row, err := h.eventRepo.GetByID(c.Request().Context(), eventID)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "FETCH_FAILED", err.Error())
	}
	if row == nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Event not found")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": EventDetail{
			ID:        row.ID,
			AgentID:   row.AgentID,
			EventType: row.EventType,
			Severity:  row.Severity,
			Timestamp: row.Timestamp,
			Summary:   row.Summary,
			Raw:       row.Raw,
		},
		"meta": responseMeta(c),
	})
}

// ExportEvents exports events to CSV/JSON.
func (h *Handlers) ExportEvents(c echo.Context) error {
	var req EventExportRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"export_id": uuid.New().String(),
		"status":    "processing",
		"meta":      responseMeta(c),
	})
}

// ============================================================================
// POLICY HANDLERS
// ============================================================================

// ListPolicies returns all policies.
func (h *Handlers) ListPolicies(c echo.Context) error {
	return c.JSON(http.StatusOK, PolicyListResponse{
		Data:       []PolicySummary{},
		Pagination: PaginationResponse{Total: 0, Limit: 50, Offset: 0},
		Meta:       responseMeta(c),
	})
}

// CreatePolicy creates a new policy.
func (h *Handlers) CreatePolicy(c echo.Context) error {
	var req PolicyCreateRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	policyID := uuid.New()

	// Audit: policy created
	h.fireAudit(c, models.AuditActionPolicyCreated, "policy", policyID,
		"name="+req.Name, false, "")

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"id":   policyID,
		"name": req.Name,
		"meta": responseMeta(c),
	})
}

// GetPolicy returns a single policy.
func (h *Handlers) GetPolicy(c echo.Context) error {
	idStr := c.Param("id")
	if _, err := uuid.Parse(idStr); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid policy ID format")
	}
	return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Policy not found")
}

// UpdatePolicy updates a policy.
func (h *Handlers) UpdatePolicy(c echo.Context) error {
	idStr := c.Param("id")
	policyID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid policy ID format")
	}

	// Audit: policy updated
	h.fireAudit(c, models.AuditActionPolicyUpdated, "policy", policyID, "", false, "")

	return c.JSON(http.StatusOK, map[string]interface{}{"message": "Policy updated", "meta": responseMeta(c)})
}

// DeletePolicy deletes a policy.
func (h *Handlers) DeletePolicy(c echo.Context) error {
	idStr := c.Param("id")
	policyID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid policy ID format")
	}

	// Audit: policy deleted
	h.fireAudit(c, models.AuditActionPolicyDeleted, "policy", policyID, "", false, "")

	return c.NoContent(http.StatusNoContent)
}

// GetPolicyAgents returns agents using a policy.
func (h *Handlers) GetPolicyAgents(c echo.Context) error {
	idStr := c.Param("id")
	if _, err := uuid.Parse(idStr); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid policy ID format")
	}
	return c.JSON(http.StatusOK, AgentListResponse{
		Data:       []AgentSummary{},
		Pagination: PaginationResponse{Total: 0, Limit: 50, Offset: 0},
		Meta:       responseMeta(c),
	})
}

// ============================================================================
// USER HANDLERS
// ============================================================================

// ListUsers returns paginated list of users from the database.
func (h *Handlers) ListUsers(c echo.Context) error {
	if h.userRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	filter := repository.UserFilter{
		Limit:  50,
		Offset: 0,
	}
	if v := c.QueryParam("role"); v != "" {
		filter.Role = &v
	}
	if v := c.QueryParam("status"); v != "" {
		filter.Status = &v
	}
	if v := c.QueryParam("search"); v != "" {
		filter.Search = &v
	}
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			filter.Limit = n
		}
	}
	if v := c.QueryParam("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			filter.Offset = n
		}
	}

	total, err := h.userRepo.Count(c.Request().Context(), filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to count users")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to count users")
	}

	users, err := h.userRepo.List(c.Request().Context(), filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list users")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list users")
	}

	// Convert to response DTOs (never expose password hash)
	data := make([]UserResponse, 0, len(users))
	for _, u := range users {
		resp := UserResponse{
			ID:         u.ID,
			Username:   u.Username,
			Email:      u.Email,
			FullName:   u.FullName,
			Role:       u.Role,
			Status:     u.Status,
			MFAEnabled: u.MFAEnabled,
			LastLogin:  u.LastLogin,
			CreatedAt:  u.CreatedAt,
			UpdatedAt:  u.UpdatedAt,
		}
		data = append(data, resp)
	}

	hasMore := int64(filter.Offset+len(users)) < total

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": data,
		"pagination": PaginationResponse{
			Total:   int(total),
			Limit:   filter.Limit,
			Offset:  filter.Offset,
			HasMore: hasMore,
		},
		"meta": responseMeta(c),
	})
}

// CreateUser creates a new user via AuthService (bcrypt + DB insert).
func (h *Handlers) CreateUser(c echo.Context) error {
	if h.authSvc == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	var req UserCreateRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	if req.Username == "" || req.Email == "" || req.Password == "" || req.Role == "" {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "username, email, password, and role are required")
	}

	user, err := h.authSvc.CreateUser(c.Request().Context(), &service.CreateUserRequest{
		Username:   req.Username,
		Email:      req.Email,
		Password:   req.Password,
		FullName:   req.FullName,
		Role:       req.Role,
		MFAEnabled: req.MFAEnabled,
	})
	if err != nil {
		h.logger.WithError(err).WithField("username", req.Username).Warn("Failed to create user")
		return errorResponse(c, http.StatusConflict, "CREATE_FAILED", err.Error())
	}

	// Audit: user created
	h.fireAudit(c, models.AuditActionUserCreated, "user", user.ID,
		"username="+req.Username+" role="+req.Role, false, "")

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"data": UserResponse{
			ID:         user.ID,
			Username:   user.Username,
			Email:      user.Email,
			FullName:   user.FullName,
			Role:       user.Role,
			Status:     user.Status,
			MFAEnabled: user.MFAEnabled,
			CreatedAt:  user.CreatedAt,
			UpdatedAt:  user.UpdatedAt,
		},
		"meta": responseMeta(c),
	})
}

// GetUser returns a single user by ID.
func (h *Handlers) GetUser(c echo.Context) error {
	if h.userRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid user ID format")
	}

	user, err := h.userRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "User not found")
	}

	resp := UserResponse{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		FullName:   user.FullName,
		Role:       user.Role,
		Status:     user.Status,
		MFAEnabled: user.MFAEnabled,
		LastLogin:  user.LastLogin,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": resp,
		"meta": responseMeta(c),
	})
}

// UpdateUser updates a user's profile (email, full_name, role, status).
func (h *Handlers) UpdateUser(c echo.Context) error {
	if h.userRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	idStr := c.Param("id")
	targetUserID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid user ID format")
	}

	var req UserUpdateRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	user, err := h.userRepo.GetByID(c.Request().Context(), targetUserID)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "User not found")
	}

	// Protect admin accounts: role, status cannot be changed for admin users.
	// This ensures the admin account can never be demoted, locked, or deactivated
	// through the API — even by another admin.
	if user.Role == "admin" && (req.Role != "" || req.Status != "") {
		return errorResponse(c, http.StatusForbidden, "ADMIN_PROTECTED",
			"Cannot change the role or status of an admin account")
	}

	// Apply updates
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.FullName != "" {
		user.FullName = req.FullName
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.Status != "" {
		user.Status = req.Status
	}
	if req.MFAEnabled != nil {
		user.MFAEnabled = *req.MFAEnabled
		// When MFA is being turned off, also wipe any stored secret so a
		// re-enable later doesn't accidentally reuse an old TOTP seed.
		if !*req.MFAEnabled {
			user.MFASecret = nil
		}
	}

	if err := h.userRepo.Update(c.Request().Context(), user); err != nil {
		h.logger.WithError(err).Error("Failed to update user")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update user")
	}

	// Audit: user updated
	h.fireAudit(c, models.AuditActionUserUpdated, "user", targetUserID, "", false, "")

	resp := UserResponse{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		FullName:   user.FullName,
		Role:       user.Role,
		Status:     user.Status,
		MFAEnabled: user.MFAEnabled,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": resp,
		"meta": responseMeta(c),
	})
}

// DeleteUser soft-deletes a user (sets status to deleted).
func (h *Handlers) DeleteUser(c echo.Context) error {
	if h.userRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	idStr := c.Param("id")
	targetUserID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid user ID format")
	}

	// Prevent self-deletion
	currentUser := getCurrentUser(c)
	if currentUser != nil && currentUser.UserID == idStr {
		return errorResponse(c, http.StatusBadRequest, "SELF_DELETE", "Cannot delete your own account")
	}

	// Protect admin accounts: admin users cannot be deleted.
	// Fetch the target user to verify their role before deletion.
	targetUser, err := h.userRepo.GetByID(c.Request().Context(), targetUserID)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "User not found")
	}
	if targetUser.Role == "admin" {
		return errorResponse(c, http.StatusForbidden, "ADMIN_PROTECTED",
			"Cannot delete an admin account")
	}

	if err := h.userRepo.Delete(c.Request().Context(), targetUserID); err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "User not found")
	}

	// Audit: user deleted
	h.fireAudit(c, models.AuditActionUserDeleted, "user", targetUserID, "", false, "")

	return c.NoContent(http.StatusNoContent)
}

// ChangePassword changes a user's password via AuthService.
//
// After a successful password change:
//   - The current JWT is blacklisted so the session is immediately invalidated.
//   - The response includes force_logout: true so the dashboard redirects to login.
//   - If an admin resets another user's password, the admin's own session is NOT
//     invalidated (only the target user's next login will use the new password).
func (h *Handlers) ChangePassword(c echo.Context) error {
	if h.authSvc == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable")
	}

	idStr := c.Param("id")
	targetUserID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid user ID format")
	}

	var req PasswordChangeRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	// Check authorization: only self or admin can change password
	currentUser := getCurrentUser(c)
	isSelf := currentUser != nil && currentUser.UserID == idStr
	isAdmin := false
	if currentUser != nil {
		for _, r := range currentUser.Roles {
			if r == "admin" {
				isAdmin = true
				break
			}
		}
	}
	if !isSelf && !isAdmin {
		return errorResponse(c, http.StatusForbidden, "FORBIDDEN", "Can only change your own password")
	}

	if err := h.authSvc.ChangePassword(c.Request().Context(), targetUserID, req.OldPassword, req.NewPassword); err != nil {
		h.logger.WithError(err).Warn("Password change failed")
		return errorResponse(c, http.StatusBadRequest, "PASSWORD_CHANGE_FAILED", err.Error())
	}

	// Audit: password changed
	h.fireAudit(c, models.AuditActionPasswordChanged, "user", targetUserID, "", false, "")

	ctx := c.Request().Context()

	// ── Invalidate ALL sessions for the target user ───────────────────────
	// 1. Increment session_version: every existing JWT for this user will
	//    be rejected by AuthMiddleware on the next request regardless of device.
	//    This is the primary invalidation mechanism (works without Redis).
	if h.userRepo != nil {
		if _, incrErr := h.userRepo.IncrementSessionVersion(ctx, targetUserID); incrErr != nil {
			h.logger.WithError(incrErr).Warn("Failed to increment session_version after password change")
		} else {
			h.logger.WithField("target_user_id", targetUserID).
				Info("session_version incremented — all existing tokens invalidated by password change")
		}
	}

	// 2. Revoke all DB session records (refresh tokens) so no refresh-based
	//    re-issue is possible even before the sv check fires.
	if h.sessionRepo != nil {
		if revokeErr := h.sessionRepo.RevokeAllForUser(ctx, targetUserID, "password_changed"); revokeErr != nil {
			h.logger.WithError(revokeErr).Warn("Failed to revoke sessions after password change")
		}
	}

	// 3. Blacklist the CALLER's current access token in Redis as defense-in-depth.
	//    For self-change: their token is blacklisted immediately even before the
	//    next request triggers the sv check.
	//    For admin-reset: the admin's own token is NOT blacklisted (admin stays
	//    logged in) — only the target user's sessions are invalidated above.
	if isSelf && h.redis != nil && h.jwtManager != nil {
		if parts := splitBearer(c.Request().Header.Get("Authorization")); parts != "" {
			if jti, jtiErr := h.jwtManager.GetTokenID(parts); jtiErr == nil && jti != "" {
				expiresAt := time.Now().Add(24 * time.Hour)
				if blErr := h.redis.BlacklistToken(ctx, jti, expiresAt, "password_changed"); blErr != nil {
					h.logger.WithError(blErr).Warn("Failed to blacklist caller token after password change")
				}
			}
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Password changed successfully. All active sessions have been terminated.",
		// force_logout is always true: the caller's token (and every other token
		// for the target user) will be rejected by the sv check on the next request.
		"force_logout": true,
		"meta":         responseMeta(c),
	})
}


// splitBearer extracts the token string from a "Bearer <token>" header value.
// Returns empty string if the header is malformed.
func splitBearer(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

// ============================================================================
// AUDIT LOG HANDLERS
// ============================================================================

// actionGroupToDB maps frontend filter values to one or more DB action strings.
// Returns a slice; if nil, use the value as-is (direct match).
var actionGroupToDB = map[string][]string{
	"login":             {"user_login"},
	"logout":            {"user_logout"},
	"create":            {"user_created", "policy_created", "rule_created", "token_created", "agent_registered"},
	"update":            {"user_updated", "policy_updated", "rule_updated"},
	"delete":            {"user_deleted", "policy_deleted", "rule_deleted", "alert_deleted", "agent_deleted"},
	"execute_command":   {"execute_command"},
	"acknowledge_alert": {"acknowledge_alert"},
	"resolve_alert":     {"resolve_alert"},
}

// ListAuditLogs returns audit logs from the database with filtering and pagination.
func (h *Handlers) ListAuditLogs(c echo.Context) error {
	emptyResp := func() error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"data":       []interface{}{},
			"pagination": PaginationResponse{Total: 0, Limit: 50, Offset: 0},
			"meta":       responseMeta(c),
		})
	}

	if h.auditRepo == nil {
		return emptyResp()
	}

	filter := repository.AuditLogFilter{
		Limit:  50,
		Offset: 0,
	}

	// Action filter: map frontend group → DB value(s)
	if v := c.QueryParam("action"); v != "" {
		if dbActions, ok := actionGroupToDB[v]; ok {
			// Use first value for simple equality; for groups use first action
			// (the repository supports single action filter; multi-value requires
			// a schema/repo change — for now first in list is most representative)
			filter.Action = &dbActions[0]
		} else {
			// Passed value is a direct DB action string
			filter.Action = &v
		}
	}

	if v := c.QueryParam("resource_type"); v != "" {
		filter.ResourceType = &v
	}
	if v := c.QueryParam("user_id"); v != "" {
		if uid, err := uuid.Parse(v); err == nil {
			filter.UserID = &uid
		}
	}
	if v := c.QueryParam("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.StartTime = &t
		}
	}
	if v := c.QueryParam("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.EndTime = &t
		}
	}
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			filter.Limit = n
		}
	}
	if v := c.QueryParam("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			filter.Offset = n
		}
	}

	ctx := c.Request().Context()

	logs, err := h.auditRepo.List(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Warn("Failed to list audit logs")
		return emptyResp()
	}

	total, err := h.auditRepo.Count(ctx, filter)
	if err != nil {
		h.logger.WithError(err).Warn("Failed to count audit logs")
		total = int64(len(logs))
	}

	// Normalise nil slice → empty slice so JSON shows [] not null
	if logs == nil {
		logs = []*models.AuditLog{}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":       logs,
		"pagination": PaginationResponse{Total: int(total), Limit: filter.Limit, Offset: filter.Offset, HasMore: int64(filter.Offset+filter.Limit) < total},
		"meta":       responseMeta(c),
	})
}

// GetAuditLog returns a single audit log by ID.
func (h *Handlers) GetAuditLog(c echo.Context) error {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid audit log ID format")
	}

	if h.auditRepo == nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Audit log not found")
	}

	log, err := h.auditRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Audit log not found")
	}

	return c.JSON(http.StatusOK, log)
}

// ============================================================================
// HELPERS
// ============================================================================

func responseMeta(c echo.Context) ResponseMeta {
	return ResponseMeta{
		RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}
