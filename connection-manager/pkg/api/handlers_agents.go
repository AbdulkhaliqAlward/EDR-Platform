// Package api provides agent handler implementations.
package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// ListAgents returns paginated list of agents from the database.
func (h *Handlers) ListAgents(c echo.Context) error {
	if h.agentSvc == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Agent service is not available")
	}

	var req AgentListRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid query parameters")
	}

	// Set defaults
	if req.Limit == 0 {
		req.Limit = 50
	}

	// Build repository filter
	filter := repository.AgentFilter{
		Limit:     req.Limit,
		Offset:    req.Offset,
		SortBy:    req.SortBy,
		SortOrder: req.SortOrder,
	}
	if req.Status != "" {
		filter.Status = &req.Status
	}
	if req.OSType != "" {
		filter.OSType = &req.OSType
	}
	if req.Search != "" {
		filter.Search = &req.Search
	}

	// Query agents from database
	agents, err := h.agentSvc.ListAgents(c.Request().Context(), filter)
	if err != nil {
		h.logger.WithError(err).Error("Failed to list agents")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve agents")
	}

	// Get total count for pagination
	total, err := h.agentSvc.CountAgents(c.Request().Context(), filter)
	if err != nil {
		h.logger.WithError(err).Warn("Failed to count agents")
		total = int64(len(agents))
	}

	// Map to API response models — populate ALL fields for InlineAgentDetail panel
	summaries := make([]AgentSummary, 0, len(agents))
	for _, a := range agents {
		summary := AgentSummary{
			ID:              a.ID,
			Hostname:        a.Hostname,
			Status:          a.Status,
			OSType:          a.OSType,
			OSVersion:       a.OSVersion,
			AgentVersion:    a.AgentVersion,
			LastSeen:        a.LastSeen,
			HealthScore:     a.HealthScore,
			EventsDelivered: a.EventsDelivered,
			CPUCount:        a.CPUCount,
			MemoryMB:        a.MemoryMB,
			IPAddresses:     a.IPAddresses,
			IsIsolated:      a.IsIsolated,
			EventsCollected: a.EventsCollected,
			EventsDropped:   a.EventsDropped,
			CPUUsage:        a.CPUUsage,
			MemoryUsedMB:    a.MemoryUsedMB,
			QueueDepth:      a.QueueDepth,
			CurrentCertID:   a.CurrentCertID,
			InstalledDate:   a.InstalledDate,
			CreatedAt:       a.CreatedAt,
			UpdatedAt:       a.UpdatedAt,
			Tags:            a.Tags,
			Metadata:        a.Metadata,
		}
		if a.CertExpiresAt != nil && !a.CertExpiresAt.IsZero() {
			summary.CertExpiresAt = a.CertExpiresAt
		}
		summary.SysmonInstalled = a.SysmonInstalled
		summary.SysmonRunning = a.SysmonRunning
		summary.Criticality = a.Criticality
		summary.BusinessUnit = a.BusinessUnit
		summary.Environment = a.Environment
		summaries = append(summaries, summary)
	}

	return c.JSON(http.StatusOK, AgentListResponse{
		Data: summaries,
		Pagination: PaginationResponse{
			Total:   int(total),
			Limit:   req.Limit,
			Offset:  req.Offset,
			HasMore: int64(req.Offset+req.Limit) < total,
		},
		Meta: ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// GetAgent returns a single agent by ID from the database.
func (h *Handlers) GetAgent(c echo.Context) error {
	if h.agentSvc == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Agent service is not available")
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}

	a, err := h.agentSvc.GetByID(c.Request().Context(), id)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Agent not found")
	}

	// Use the actual IPAddresses field from the DB (not metadata)
	ipAddresses := a.IPAddresses

	detail := AgentDetail{
		AgentSummary: AgentSummary{
			ID:              a.ID,
			Hostname:        a.Hostname,
			Status:          a.Status,
			OSType:          a.OSType,
			OSVersion:       a.OSVersion,
			AgentVersion:    a.AgentVersion,
			LastSeen:        a.LastSeen,
			HealthScore:     a.HealthScore,
			EventsDelivered: a.EventsDelivered,
			IsIsolated:      a.IsIsolated,
			SysmonInstalled: a.SysmonInstalled,
			SysmonRunning:   a.SysmonRunning,
			Criticality:     a.Criticality,
			BusinessUnit:    a.BusinessUnit,
			Environment:     a.Environment,
		},
		IPAddresses:     ipAddresses,
		CPUCount:        a.CPUCount,
		MemoryMB:        a.MemoryMB,
		Tags:            a.Tags,
		EventsGenerated: a.EventsCollected,
		EventsSent:      a.EventsDelivered,
		CPUUsage:        a.CPUUsage,
		MemoryUsedMB:    a.MemoryUsedMB,
		QueueDepth:      a.QueueDepth,
		SysmonInstalled: a.SysmonInstalled,
		SysmonRunning:   a.SysmonRunning,
	}
	if a.InstalledDate != nil {
		detail.InstalledDate = *a.InstalledDate
	}
	if a.CertExpiresAt != nil && !a.CertExpiresAt.IsZero() {
		detail.CertExpiresAt = a.CertExpiresAt
	}
	if a.CurrentCertID != nil {
		detail.CurrentCertID = a.CurrentCertID
	}

	return c.JSON(http.StatusOK, AgentDetailResponse{
		Data: detail,
		Meta: ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// UpdateAgent updates agent metadata.
func (h *Handlers) UpdateAgent(c echo.Context) error {
	idStr := c.Param("id")
	_, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}

	var req AgentUpdateRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	// TODO: Update in AgentRepository

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Agent updated successfully",
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// agentBusinessContextRequest is the body for PATCH /api/v1/agents/:id/business-context
// All fields are optional; only provided ones are updated.
type agentBusinessContextRequest struct {
	Criticality  *string `json:"criticality,omitempty"`   // low | medium | high | critical
	BusinessUnit *string `json:"business_unit,omitempty"` // free-form
	Environment  *string `json:"environment,omitempty"`   // production | staging | development | ''
	// Tag-based fields — written into agents.tags JSONB
	Profile      *string `json:"profile,omitempty"`        // e.g. Server, Workstation, Laptop
	Customer     *string `json:"customer,omitempty"`       // e.g. ACME Corp
	LoggedInUser *string `json:"logged_in_user,omitempty"` // last known user
}

// PatchAgentBusinessContext updates an agent's asset-context fields.
// A DB trigger on `criticality` automatically recomputes priority_score for the
// agent's vulnerability findings (Phase 3 — Risk-Adjusted Scoring).
//
// PATCH /api/v1/agents/:id/business-context
func (h *Handlers) PatchAgentBusinessContext(c echo.Context) error {
	if h.agentSvc == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Agent service is not available")
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}

	var body agentBusinessContextRequest
	if err := c.Bind(&body); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_BODY", "Invalid JSON body")
	}
	if body.Criticality == nil && body.BusinessUnit == nil && body.Environment == nil &&
		body.Profile == nil && body.Customer == nil && body.LoggedInUser == nil {
		return errorResponse(c, http.StatusBadRequest, "EMPTY_PATCH", "Provide at least one field to update")
	}

	if body.Criticality != nil {
		switch strings.ToLower(strings.TrimSpace(*body.Criticality)) {
		case "low", "medium", "high", "critical":
			normalized := strings.ToLower(strings.TrimSpace(*body.Criticality))
			body.Criticality = &normalized
		default:
			return errorResponse(c, http.StatusBadRequest, "INVALID_CRITICALITY", "criticality must be one of: low, medium, high, critical")
		}
	}

	err = h.agentSvc.UpdateBusinessContext(c.Request().Context(), id, repository.AgentBusinessContext{
		Criticality:  body.Criticality,
		BusinessUnit: body.BusinessUnit,
		Environment:  body.Environment,
		Profile:      body.Profile,
		Customer:     body.Customer,
		LoggedInUser: body.LoggedInUser,
	})
	if err != nil {
		if err == repository.ErrNotFound {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Agent not found")
		}
		h.logger.WithError(err).Error("Failed to update agent business context")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
	}

	// Return the refreshed agent so the dashboard can reflect the change immediately.
	updated, err := h.agentSvc.GetByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]string{"id": id.String()}, "meta": responseMeta(c)})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": updated,
		"meta": responseMeta(c),
	})
}

// DeleteAgent removes an agent.
//
// Removes the device from the dashboard (soft delete): the agent row and all
// of its history (alerts, events, commands, findings) are kept for audit, but
// the device disappears from the device list and counts, and any later
// connection from that agent is rejected. Reinstalling the same machine
// re-enrolls it and brings it back with its history.
//
// A device whose agent is connected right now is refused (409): uninstall it
// first, so no running agent is left without a dashboard entry.
func (h *Handlers) DeleteAgent(c echo.Context) error {
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}
	if h.agentSvc == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Agent service is not available")
	}

	ctx := c.Request().Context()
	agent, err := h.agentSvc.GetByID(ctx, agentID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return errorResponse(c, http.StatusNotFound, "AGENT_NOT_FOUND", "Agent not found")
		}
		h.logger.WithError(err).WithField("agent_id", agentID).Error("DeleteAgent: lookup failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up agent")
	}
	if agent.Status == models.AgentStatusDeleted {
		return c.NoContent(http.StatusNoContent) // already removed — idempotent
	}

	if h.registry != nil && h.registry.IsOnline(agentID.String()) {
		return errorResponse(c, http.StatusConflict, "AGENT_ONLINE",
			"This device's agent is currently connected. Uninstall the agent first, then remove the device from the dashboard.")
	}

	if err := h.agentSvc.Delete(ctx, agentID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return errorResponse(c, http.StatusNotFound, "AGENT_NOT_FOUND", "Agent not found")
		}
		h.logger.WithError(err).WithField("agent_id", agentID).Error("DeleteAgent: soft delete failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to remove agent")
	}

	h.logger.WithFields(logrus.Fields{
		"agent_id":        agentID,
		"hostname":        agent.Hostname,
		"previous_status": agent.Status,
	}).Info("Device removed from dashboard (soft delete, history retained)")
	h.fireAudit(c, "agent.delete", "agent", agentID,
		"Device "+agent.Hostname+" removed from dashboard (previous status="+agent.Status+"); history retained",
		false, "")

	return c.NoContent(http.StatusNoContent)
}

// GetAgentStats returns agent statistics from the database.
func (h *Handlers) GetAgentStats(c echo.Context) error {
	if h.agentSvc == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Agent service is not available")
	}

	ctx := c.Request().Context()

	// Query counts per status
	statusKeys := []string{"online", "offline", "degraded", "pending", "suspended"}
	counts := make(map[string]int)
	var totalCount int64

	for _, s := range statusKeys {
		status := s
		cnt, err := h.agentSvc.CountAgents(ctx, repository.AgentFilter{Status: &status})
		if err != nil {
			h.logger.WithError(err).Warnf("Failed to count %s agents", s)
			continue
		}
		counts[s] = int(cnt)
		totalCount += cnt
	}

	// Calculate average health from online agents
	var avgHealth float64
	onlineAgents, err := h.agentSvc.GetOnlineAgents(ctx)
	if err == nil && len(onlineAgents) > 0 {
		var totalHealth float64
		for _, a := range onlineAgents {
			totalHealth += a.HealthScore
		}
		avgHealth = totalHealth / float64(len(onlineAgents))
	}

	// Build OS type and version breakdown from all agents
	allAgents, err := h.agentSvc.ListAgents(ctx, repository.AgentFilter{Limit: 10000})
	byOS := make(map[string]int)
	byVersion := make(map[string]int)
	if err == nil {
		for _, a := range allAgents {
			byOS[a.OSType]++
			byVersion[a.AgentVersion]++
		}
	}

	return c.JSON(http.StatusOK, AgentStatsResponse{
		Total:     int(totalCount),
		Online:    counts["online"],
		Offline:   counts["offline"],
		Degraded:  counts["degraded"],
		Pending:   counts["pending"],
		Suspended: counts["suspended"],
		ByOSType:  byOS,
		ByVersion: byVersion,
		AvgHealth: avgHealth,
		Meta: ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// GetAgentEvents returns events for an agent.
func (h *Handlers) GetAgentEvents(c echo.Context) error {
	idStr := c.Param("id")
	agentID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}

	if h.eventRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Event repository is not available")
	}

	limit, offset := 50, 0
	_ = echo.QueryParamsBinder(c).Int("limit", &limit).Int("offset", &offset)
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	rows, total, err := h.eventRepo.ListByAgent(c.Request().Context(), agentID, limit, offset)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "QUERY_FAILED", err.Error())
	}

	out := make([]EventSummary, 0, len(rows))
	for _, r := range rows {
		out = append(out, EventSummary{
			ID:        r.ID,
			AgentID:   r.AgentID,
			EventType: r.EventType,
			Timestamp: r.Timestamp,
			Summary:   r.Summary,
		})
	}

	return c.JSON(http.StatusOK, EventListResponse{
		Data:       out,
		Pagination: PaginationResponse{Total: total, Limit: limit, Offset: offset},
		Meta: ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// GetAgentCommands returns command history for an agent (same row shape as Action Center list).
func (h *Handlers) GetAgentCommands(c echo.Context) error {
	idStr := c.Param("id")
	agentID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}

	if h.commandRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Command repository is not available")
	}

	limit, offset := 50, 0
	_ = echo.QueryParamsBinder(c).Int("limit", &limit).Int("offset", &offset)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	filter := repository.CommandListFilter{
		AgentID:   &agentID,
		Limit:     limit,
		Offset:    offset,
		SortBy:    "issued_at",
		SortOrder: "desc",
	}

	items, total, err := h.commandRepo.ListAll(c.Request().Context(), filter)
	if err != nil {
		h.logger.WithError(err).Error("GetAgentCommands: ListAll failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve commands")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": items,
		"pagination": PaginationResponse{
			Total:   int(total),
			Limit:   limit,
			Offset:  offset,
			HasMore: int64(offset+limit) < total,
		},
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// ExecuteAgentCommand pushes a command to a live agent via the AgentRegistry.
// Dual-write strategy:
//  1. Persist command to DB with status=pending (durable record created first)
//  2. Push to agent's live gRPC stream — update DB to sent or failed accordingly
//
// This eliminates the race condition where a command is lost if the stream
// disconnects between the Send() call and the actual delivery.
func (h *Handlers) ExecuteAgentCommand(c echo.Context) error {
	h.logger.Info("[C2] ExecuteAgentCommand called")

	idStr := c.Param("id")
	agentID, err := uuid.Parse(idStr)
	if err != nil {
		h.logger.Warnf("[C2] Invalid agent ID: %s", idStr)
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}

	var req CommandRequest
	if err := c.Bind(&req); err != nil {
		h.logger.Warnf("[C2] Bind failed: %v", err)
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	req.CommandType = normalizeCommandType(req.CommandType)
	h.logger.Infof("[C2] Request bound: agent=%s type=%s timeout=%d", agentID, req.CommandType, req.Timeout)

	// ── Out-of-band approval gate ────────────────────────────────────────
	// Every manual command issued through this HTTP endpoint must carry a
	// single-use approval token (OTP-derived, sent to EC2_EMAIL_VERIFY).
	// Internal automated paths (Sigma → response engine → AgentRegistry)
	// bypass this entirely because they do not pass through HTTP. When the
	// approval service is not configured the gate is a no-op so behaviour
	// is unchanged for environments without SMTP.
	//
	// NOTE: consumeApprovalIfRequired writes the HTTP error response itself
	// and returns void. We check c.Response().Committed to know if the gate
	// blocked the request — this avoids returning a non-nil error which
	// would cause Echo's Timeout middleware to discard the buffered response.
	h.consumeApprovalIfRequired(c, req.ApprovalToken)
	if c.Response().Committed {
		return nil // gate wrote the 403 — stop here
	}

	// Reject unknown types here (API allowlist). Agent still enforces its own rules
	// (e.g. run_cmd executable whitelist) after delivery.
	if mapCommandType(req.CommandType) == edrv1.CommandType_COMMAND_TYPE_UNSPECIFIED {
		h.logger.Warnf("[C2] Unsupported command_type: %q", req.CommandType)
		return errorResponse(c, http.StatusBadRequest, "UNSUPPORTED_COMMAND",
			"Unknown or unsupported command_type — see API documentation for allowed values")
	}

	// ── Command authorization tier (server-authoritative) ────────────────────
	// The arbitrary "custom" tier can be granted ONLY by the server, below.
	// Strip any client-supplied authz_tier so a caller can never self-grant it.
	//
	// NOTE: the legacy "from_playbook" marker (curated playbookAllowedCommands
	// set) is intentionally left intact — it only unlocks a fixed set of safe
	// operational commands for callers who already hold responses:execute, and
	// the manual playbook UI relies on it. It does NOT grant the custom tier.
	delete(req.Parameters, "authz_tier")

	if req.CommandType == "custom" {
		// Admin-authored custom command: strongest controls. OTP (when the
		// approval service is configured) was already enforced above.
		if !h.allowCustomCommands {
			return errorResponse(c, http.StatusForbidden, "CUSTOM_COMMANDS_DISABLED",
				"Custom commands are disabled on this server. An administrator must enable them (EDR_ALLOW_CUSTOM_COMMANDS=true).")
		}
		user := getCurrentUser(c)
		if user == nil || !userHasRole(user, "admin") {
			return errorResponse(c, http.StatusForbidden, "CUSTOM_REQUIRES_ADMIN",
				"Custom commands require an administrator account.")
		}
		if strings.TrimSpace(req.Reason) == "" {
			return errorResponse(c, http.StatusBadRequest, "REASON_REQUIRED",
				"A reason is required for a custom command (recorded in the audit log).")
		}
		if req.Parameters == nil {
			req.Parameters = map[string]string{}
		}
		if strings.TrimSpace(req.Parameters["cmd"]) == "" {
			return errorResponse(c, http.StatusBadRequest, "CMD_REQUIRED",
				"The 'cmd' parameter is required for a custom command.")
		}
		req.Parameters["authz_tier"] = "custom"
		h.logger.Warnf("[C2] CUSTOM command authorized by admin %q on agent %s: %q (reason: %s)",
			user.Username, agentID, req.Parameters["cmd"], req.Reason)
	}

	// Validate registry is available
	if h.registry == nil {
		h.logger.Warn("[C2] Registry is nil")
		return errorResponse(c, http.StatusServiceUnavailable, "C2_UNAVAILABLE", "Command routing is not available")
	}

	// Special case: start_agent works even when agent is offline.
	// The command is stored in DB (status=pending). When the agent reconnects
	// it auto-starts because: (1) Windows service recovery restarts it, or
	// (2) the redeliverPendingCommands goroutine pushes it on next connect.
	if req.CommandType == "start_agent" {
		// Inject mode so agent's restartService handler knows to only start, not stop
		if req.Parameters == nil {
			req.Parameters = map[string]string{}
		}
		req.Parameters["mode"] = "start"
	}

	// Check if agent is online.
	//
	// Some commands must remain dispatchable even when the agent is offline.
	// Most notably: restore_network (unisolate). If the agent was isolated
	// incorrectly (e.g. allowlist misconfig) it may appear offline; returning a
	// hard 404 here creates a dead-end in the UI. Instead we persist the command
	// as pending so it can be delivered on next reconnect.
	offlineSafe := req.CommandType == "start_agent" ||
		req.CommandType == "restore_network" ||
		req.CommandType == "unisolate_network" ||
		req.CommandType == "unisolate"

	online := h.registry.IsOnline(agentID.String())
	if !online && !offlineSafe {
		h.logger.Warnf("[C2] Agent %s is not online", agentID)
		return errorResponse(c, http.StatusNotFound, "AGENT_OFFLINE", "Agent is not online — command cannot be delivered")
	}

	// Block any new commands when the agent has already confirmed uninstall.
	// `uninstall_agent` itself is allowed so operators can retry a stuck uninstall.
	if h.agentSvc != nil && req.CommandType != "uninstall_agent" {
		if current, err := h.agentSvc.GetByID(c.Request().Context(), agentID); err == nil && current != nil {
			if current.Status == models.AgentStatusUninstalled {
				h.logger.Warnf("[C2] Agent %s is uninstalled — refusing new command %s", agentID, req.CommandType)
				return errorResponse(c, http.StatusGone, "AGENT_UNINSTALLED", "Agent has been uninstalled; no further commands will be dispatched")
			}
		}
	}

	execTimeoutSec := req.Timeout
	if req.TimeoutSeconds > 0 {
		execTimeoutSec = req.TimeoutSeconds
	}
	if execTimeoutSec <= 0 {
		execTimeoutSec = 300
	}

	// ── Step 1: Persist to DB FIRST (status=pending) ──────────────────────────
	// Always create a durable record before attempting delivery so commands are
	// never lost if the gRPC stream disconnects during the Send() call.
	// NOTE: issued_by is intentionally left nil (NULL). The JWT UserID is a
	// claims string that may not match the UUID in the users table, causing FK
	// violations. The issuer username is stored in Metadata for audit purposes.
	commandID := uuid.New()
	if h.commandRepo != nil {
		params := make(map[string]any, len(req.Parameters))
		for k, v := range req.Parameters {
			params[k] = v
		}
		// Build metadata with issuer info for audit (avoids FK constraint on issued_by)
		meta := map[string]any{}
		if user := getCurrentUser(c); user != nil {
			meta["issued_by_username"] = user.Username
			if len(user.Roles) > 0 {
				meta["issued_by_role"] = user.Roles[0]
			}
		}
		dbCmd := &models.Command{
			ID:             commandID,
			AgentID:        agentID,
			CommandType:    models.CommandType(req.CommandType),
			Parameters:     params,
			Priority:       5,
			Status:         models.CommandStatusPending,
			TimeoutSeconds: execTimeoutSec,
			IssuedBy:       nil, // always nil to avoid FK violation
			Metadata:       meta,
		}
		if err := h.commandRepo.Create(c.Request().Context(), dbCmd); err != nil {
			h.logger.WithError(err).Error("[C2] Failed to persist command to DB before dispatch — aborting")
			return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Failed to persist command")
		}
		h.logger.Infof("[C2] Command %s persisted to DB (status=pending)", commandID)
	}

	// Offline-safe commands stop here: they are queued for delivery on reconnect.
	if !online && offlineSafe {
		h.logger.Infof("[C2] Agent %s offline — queued offline-safe command %s as pending", agentID, req.CommandType)
		return c.JSON(http.StatusAccepted, CommandResponse{
			CommandID: commandID.String(),
			Status:    "pending",
			IssuedAt:  time.Now(),
		})
	}

	// ── Step 1b: Inject mode parameter for agent service control commands ───────
	// The agent's restartService handler checks Parameters["mode"] to decide
	// whether to stop+start (restart), stop only, or start only.
	switch req.CommandType {
	case "stop_agent", "stop_service":
		if req.Parameters == nil {
			req.Parameters = map[string]string{}
		}
		req.Parameters["mode"] = "stop" // agent: sc stop EDRAgent only
	case "restart_agent", "restart_service":
		if req.Parameters == nil {
			req.Parameters = map[string]string{}
		}
		req.Parameters["mode"] = "restart" // agent: sc stop → sc start
		// start_agent mode already injected in the offline-safe block above
	case "enable_sysmon":
		if req.Parameters == nil {
			req.Parameters = map[string]string{}
		}
		req.Parameters["mode"] = "enable_sysmon"
	case "disable_sysmon":
		if req.Parameters == nil {
			req.Parameters = map[string]string{}
		}
		req.Parameters["mode"] = "disable_sysmon"
	case "isolate", "isolate_network", "unisolate", "unisolate_network", "restore_network":
		// Auto-inject the C2 server address so the agent builds correct ALLOW
		// firewall rules. The agent falls back to config.server.address when
		// server_address is not provided, but explicit injection is more reliable.
		if h.grpcAddress != "" {
			if req.Parameters == nil {
				req.Parameters = map[string]string{}
			}
			if req.Parameters["server_address"] == "" {
				req.Parameters["server_address"] = h.grpcAddress
			}
		}
	}

	// ── Step 2: Map REST command_type to proto and push to gRPC stream ─────────
	cmdType := mapCommandType(req.CommandType)
	cmd := &edrv1.Command{
		CommandId:  commandID.String(),
		Timestamp:  timestamppb.Now(),
		Type:       cmdType,
		Parameters: req.Parameters,
		Priority:   5,
		ExpiresAt:  timestamppb.New(time.Now().Add(time.Duration(execTimeoutSec) * time.Second)),
	}

	if err := h.registry.Send(agentID.String(), cmd); err != nil {
		h.logger.WithError(err).WithField("agent_id", agentID).Warn("[C2] Failed to push command to agent — marking as FAILED in DB")
		// R1 FIX: Explicitly update DB to 'failed' and CHECK the error.
		// If this update also fails, the command stays at 'pending' forever
		// (phantom pending) — log it as CRITICAL so it's never missed.
		if h.commandRepo != nil {
			if uErr := h.commandRepo.UpdateStatus(c.Request().Context(), commandID, models.CommandStatusFailed, nil, err.Error()); uErr != nil {
				h.logger.WithError(uErr).Errorf("[C2] CRITICAL: Failed to update command %s to FAILED in DB — phantom pending command!", commandID)
			} else {
				h.logger.Infof("[C2] Command %s marked FAILED in DB (channel full or agent offline)", commandID)
			}
		}
		return errorResponse(c, http.StatusConflict, "SEND_FAILED", err.Error())
	}

	// ── Step 3: Update DB to 'sent' ────────────────────────────────────────────
	if h.commandRepo != nil {
		if err := h.commandRepo.UpdateStatus(c.Request().Context(), commandID, models.CommandStatusSent, nil, ""); err != nil {
			h.logger.WithError(err).Warn("[C2] Failed to update command status to sent (non-fatal)")
		}
	}

	// ── Step 3b: Proactively update isolation state ──────────────────────────
	// Set is_isolated in the DB immediately at dispatch rather than waiting
	// for the agent's asynchronous SendCommandResult ACK. This eliminates the
	// race between the dashboard's next query and the async result, ensuring
	// the UI shows "Restore Network" (or "Isolate Network") right away.
	if h.agentSvc != nil {
		switch req.CommandType {
		case "isolate_network", "isolate":
			if err := h.agentSvc.SetIsolation(c.Request().Context(), agentID, true); err != nil {
				h.logger.WithError(err).Warn("[Isolation] Failed to proactively set is_isolated=true")
			} else {
				h.logger.Infof("[Isolation] Agent %s proactively marked ISOLATED at dispatch", agentID)
			}
		case "restore_network", "unisolate_network", "unisolate":
			if err := h.agentSvc.SetIsolation(c.Request().Context(), agentID, false); err != nil {
				h.logger.WithError(err).Warn("[Isolation] Failed to proactively set is_isolated=false")
			} else {
				h.logger.Infof("[Isolation] Agent %s proactively marked UN-ISOLATED at dispatch", agentID)
			}
		case "uninstall_agent":
			// Mark pending_uninstall right when the uninstall order is dispatched.
			// A successful SendCommandResult from the agent promotes this to 'uninstalled';
			// otherwise the UI can surface the pending state plus missed-heartbeat signal.
			if err := h.agentSvc.UpdateStatus(c.Request().Context(), agentID, models.AgentStatusPendingUninstall, nil); err != nil {
				h.logger.WithError(err).Warn("[Uninstall] Failed to set agent status=pending_uninstall")
			} else {
				h.logger.Infof("[Uninstall] Agent %s marked PENDING_UNINSTALL at dispatch", agentID)
			}
		}
	}

	h.logger.WithFields(logrus.Fields{
		"agent_id":     agentID,
		"command_id":   commandID,
		"command_type": req.CommandType,
		"proto_type":   cmdType.String(),
	}).Info("[C2] Command dispatched to agent via live stream")

	// ── Step 4: Write audit log entry (non-blocking) ────────────────────────
	if h.auditRepo != nil {
		ip, ua := auditContext(c)
		username := "unknown"
		userID := uuid.Nil
		if user := getCurrentUser(c); user != nil {
			username = user.Username
			if uid, parseErr := uuid.Parse(user.UserID); parseErr == nil {
				userID = uid
			}
		}
		auditAction := models.AuditActionCommandExecuted
		if req.CommandType == "isolate" || req.CommandType == "isolate_network" {
			auditAction = models.AuditActionIsolate
		} else if req.CommandType == "unisolate" || req.CommandType == "unisolate_network" || req.CommandType == "restore_network" {
			auditAction = models.AuditActionUnisolate
		} else if req.CommandType == "update_filter_policy" {
			auditAction = models.AuditActionDeployPolicy
		}

		details := "agent=" + agentID.String() + " type=" + req.CommandType
		if req.CommandType == "custom" {
			details += " cmd=" + req.Parameters["cmd"] + " reason=" + req.Reason
		}
		auditEntry := models.NewAuditLog(userID, username, auditAction, "command", commandID).
			WithContext(ip, ua).
			WithDetails(details)
		go func(entry *models.AuditLog) {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.auditRepo.Create(auditCtx, entry); err != nil {
				h.logger.WithError(err).Warn("[C2] Failed to write audit log entry (non-fatal)")
			}
		}(auditEntry)
	}

	return c.JSON(http.StatusAccepted, CommandResponse{
		CommandID: commandID.String(),
		Status:    "sent",
		IssuedAt:  time.Now(),
	})
}

// AddProcessException pushes a live allow-exception for process auto-response.
// It uses UPDATE_CONFIG sparse override (exclude_process=<name>) so the agent
// hot-reloads immediately and preserves existing exclusions.
func (h *Handlers) AddProcessException(c echo.Context) error {
	idStr := c.Param("id")
	agentID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}
	var req ProcessExceptionRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	procName := strings.TrimSpace(req.ProcessName)
	if procName == "" {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "process_name is required")
	}
	if h.registry == nil || h.commandRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "C2_UNAVAILABLE", "Command routing is not available")
	}
	if !h.registry.IsOnline(agentID.String()) {
		return errorResponse(c, http.StatusNotFound, "AGENT_OFFLINE", "Agent is not online — exception cannot be delivered")
	}

	commandID := uuid.New()
	meta := map[string]any{
		"exception_type": "process_allow",
		"process_name":   procName,
		"reason":         strings.TrimSpace(req.Reason),
	}
	if user := getCurrentUser(c); user != nil {
		meta["issued_by_username"] = user.Username
	}
	dbCmd := &models.Command{
		ID:          commandID,
		AgentID:     agentID,
		CommandType: models.CommandType("update_config"),
		Parameters: map[string]any{
			"exclude_process": procName,
		},
		Priority:       5,
		Status:         models.CommandStatusPending,
		TimeoutSeconds: 120,
		IssuedBy:       nil,
		Metadata:       meta,
	}
	if err := h.commandRepo.Create(c.Request().Context(), dbCmd); err != nil {
		h.logger.WithError(err).Error("[C2] Failed to persist process exception command")
		return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Failed to persist exception command")
	}

	cmd := &edrv1.Command{
		CommandId: commandID.String(),
		Timestamp: timestamppb.Now(),
		Type:      edrv1.CommandType_COMMAND_TYPE_UPDATE_CONFIG,
		Parameters: map[string]string{
			"exclude_process": procName,
		},
		Priority: 5,
	}
	if err := h.registry.Send(agentID.String(), cmd); err != nil {
		_ = h.commandRepo.UpdateStatus(c.Request().Context(), commandID, models.CommandStatusFailed, nil, err.Error())
		return errorResponse(c, http.StatusConflict, "SEND_FAILED", err.Error())
	}
	if err := h.commandRepo.UpdateStatus(c.Request().Context(), commandID, models.CommandStatusSent, nil, ""); err != nil {
		h.logger.WithError(err).Warn("[C2] Failed to update process exception command status to sent")
	}

	h.logger.WithFields(logrus.Fields{
		"agent_id":   agentID,
		"command_id": commandID,
		"process":    procName,
	}).Info("[C2] Process allow-exception dispatched")

	if h.auditRepo != nil {
		ip, ua := auditContext(c)
		username := "unknown"
		userID := uuid.Nil
		if user := getCurrentUser(c); user != nil {
			username = user.Username
			if uid, parseErr := uuid.Parse(user.UserID); parseErr == nil {
				userID = uid
			}
		}
		entry := models.NewAuditLog(userID, username, models.AuditActionDeployPolicy, "agent", agentID).
			WithContext(ip, ua).
			WithDetails("process_exception=" + procName)
		go func() {
			auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = h.auditRepo.Create(auditCtx, entry)
		}()
	}

	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"command_id":   commandID.String(),
		"status":       "sent",
		"agent_id":     agentID.String(),
		"process_name": procName,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// mapCommandType maps REST API command type strings to proto CommandType.
// Every command type exposed in the dashboard must have a case here;
// missing entries would cause the agent to receive COMMAND_TYPE_UNSPECIFIED
// and log "unknown command type", silently dropping the command.
func mapCommandType(cmdType string) edrv1.CommandType {
	switch normalizeCommandType(cmdType) {
	case "kill_process", "terminate_process":
		return edrv1.CommandType_COMMAND_TYPE_TERMINATE_PROCESS
	case "collect_logs", "collect_forensics":
		return edrv1.CommandType_COMMAND_TYPE_COLLECT_FORENSICS
	case "quarantine_file":
		return edrv1.CommandType(13) // COMMAND_TYPE_QUARANTINE_FILE
	case "block_ip":
		return edrv1.CommandType(14)
	case "unblock_ip":
		return edrv1.CommandType(15)
	case "block_domain":
		return edrv1.CommandType(16)
	case "unblock_domain":
		return edrv1.CommandType(17)
	case "update_signatures":
		return edrv1.CommandType(18)
	case "restore_quarantine_file":
		return edrv1.CommandType(19) // COMMAND_TYPE_RESTORE_QUARANTINE_FILE
	case "delete_quarantine_file":
		return edrv1.CommandType(20) // COMMAND_TYPE_DELETE_QUARANTINE_FILE
	case "scan_file", "scan_memory":
		// Map to COLLECT_FORENSICS so the agent receives it; params carry sub-type.
		return edrv1.CommandType_COMMAND_TYPE_COLLECT_FORENSICS
	case "isolate", "isolate_network":
		return edrv1.CommandType_COMMAND_TYPE_ISOLATE
	case "unisolate", "unisolate_network", "restore_network":
		return edrv1.CommandType_COMMAND_TYPE_UNISOLATE
	case "restart_agent", "restart_service":
		return edrv1.CommandType_COMMAND_TYPE_RESTART_SERVICE
	case "stop_agent", "stop_service":
		// Stop only — agent checks Parameters["mode"] == "stop"
		return edrv1.CommandType_COMMAND_TYPE_RESTART_SERVICE
	case "start_agent", "start_service":
		// Start only — agent checks Parameters["mode"] == "start"
		return edrv1.CommandType_COMMAND_TYPE_RESTART_SERVICE
	case "restart", "restart_machine":
		return edrv1.CommandType(10)
	case "shutdown", "shutdown_machine":
		return edrv1.CommandType(11)
	case "update_agent":
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_AGENT
	case "uninstall_agent":
		// Proto enum value 21 — server is the sole authority for agent uninstall.
		// Using a numeric literal avoids forcing a pb.go regeneration pass; the agent
		// decodes the same integer and routes it through the uninstall command path.
		return edrv1.CommandType(21)
	case "update_config", "update_policy", "update_vuln_config":
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_CONFIG
	case "enable_sysmon", "disable_sysmon":
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_CONFIG
	case "update_filter_policy":
		return edrv1.CommandType(12) // COMMAND_TYPE_UPDATE_FILTER_POLICY
	case "adjust_rate":
		return edrv1.CommandType_COMMAND_TYPE_ADJUST_RATE
	case "run_cmd", "custom":
		return edrv1.CommandType(9) // COMMAND_TYPE_RUN_CMD
	case "post_isolation_triage":
		return edrv1.CommandType_COMMAND_TYPE_POST_ISOLATION_TRIAGE
	case "process_tree_snapshot":
		return edrv1.CommandType_COMMAND_TYPE_PROCESS_TREE_SNAPSHOT
	case "persistence_scan":
		return edrv1.CommandType_COMMAND_TYPE_PERSISTENCE_SCAN
	case "lsass_access_audit":
		return edrv1.CommandType_COMMAND_TYPE_LSASS_ACCESS_AUDIT
	case "filesystem_timeline":
		return edrv1.CommandType_COMMAND_TYPE_FILESYSTEM_TIMELINE
	case "network_last_seen":
		return edrv1.CommandType_COMMAND_TYPE_NETWORK_LAST_SEEN
	case "agent_integrity_check":
		return edrv1.CommandType_COMMAND_TYPE_AGENT_INTEGRITY_CHECK
	case "memory_dump":
		return edrv1.CommandType_COMMAND_TYPE_MEMORY_DUMP
	default:
		return edrv1.CommandType_COMMAND_TYPE_UNSPECIFIED
	}
}

func normalizeCommandType(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
