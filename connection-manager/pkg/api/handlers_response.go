package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/response"
)

// ─────────────────────────────────────────────────────────────────────────────
// Server-side response engine API (under /api/v1/automation, which the
// dashboard gateway routes to the Connection Manager).
//
//   GET  /automation/catalog                     approved actions + library scripts
//   GET  /automation/alerts/:id/suggestions      ranked playbooks for an alert
//   GET  /automation/playbooks/:id/preview       bound parameters for an alert/endpoint
//   POST /automation/playbooks/:id/run           start a tracked run (202)
//   GET  /automation/executions                  run history (filters)
//   GET  /automation/executions/:id              run status with per-step results
// ─────────────────────────────────────────────────────────────────────────────

// responseEngineDeps groups what the response API needs.
type responseEngineDeps struct {
	engine    *response.Engine
	store     *repository.ResponseEngineRepository
	playbooks repository.ResponsePlaybookRepository
	rules     repository.AutomationRuleRepository
}

// SetResponseEngine wires the response engine API.
func (h *Handlers) SetResponseEngine(engine *response.Engine, store *repository.ResponseEngineRepository,
	playbooks repository.ResponsePlaybookRepository, rules repository.AutomationRuleRepository) {
	h.respEngine = &responseEngineDeps{engine: engine, store: store, playbooks: playbooks, rules: rules}
}

func (h *Handlers) responseUnavailable(c echo.Context) bool {
	if h.respEngine == nil || h.respEngine.engine == nil {
		_ = errorResponse(c, http.StatusServiceUnavailable, "RESPONSE_ENGINE_UNAVAILABLE", "Response engine is not available (database not connected)")
		return true
	}
	return false
}

// engineError maps engine errors to HTTP responses.
func (h *Handlers) engineError(c echo.Context, err error, plan *response.Plan) error {
	var nr *response.NotReadyError
	switch {
	case errors.As(err, &nr):
		return c.JSON(http.StatusUnprocessableEntity, map[string]any{
			"error_code": "PLAYBOOK_NOT_READY", "message": err.Error(), "plan": nr.Plan,
		})
	case errors.Is(err, response.ErrPlaybookNotFound):
		return errorResponse(c, http.StatusNotFound, "PLAYBOOK_NOT_FOUND", err.Error())
	case errors.Is(err, response.ErrAlertNotFound):
		return errorResponse(c, http.StatusNotFound, "ALERT_NOT_FOUND", err.Error())
	case errors.Is(err, response.ErrPlaybookDisabled), errors.Is(err, response.ErrAgentUnavailable):
		return errorResponse(c, http.StatusConflict, "PLAYBOOK_NOT_RUNNABLE", err.Error())
	case errors.Is(err, response.ErrAgentOffline):
		return c.JSON(http.StatusConflict, map[string]any{"error_code": "AGENT_OFFLINE", "message": err.Error(), "plan": plan})
	case errors.Is(err, response.ErrNoTarget), errors.Is(err, response.ErrAgentMismatch):
		return errorResponse(c, http.StatusBadRequest, "INVALID_TARGET", err.Error())
	default:
		h.logger.WithError(err).Error("Response engine request failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Response engine error")
	}
}

func optionalUUID(s string) (*uuid.UUID, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// GetResponseCatalog returns the approved playbook actions, the enabled
// library scripts and the alert variables usable in templates.
func (h *Handlers) GetResponseCatalog(c echo.Context) error {
	type scriptItem struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Timeout     int    `json:"timeout_seconds"`
	}
	scripts := []scriptItem{}
	if h.responseScriptRepo != nil {
		list, err := h.responseScriptRepo.List(c.Request().Context())
		if err != nil {
			h.logger.WithError(err).Warn("Catalog: could not list scripts")
		}
		for _, s := range list {
			if s.Enabled {
				scripts = append(scripts, scriptItem{ID: s.ID.String(), Name: s.Name, Description: s.Description, Timeout: s.TimeoutSeconds})
			}
		}
	}
	return c.JSON(http.StatusOK, map[string]any{
		"actions":   response.Actions,
		"scripts":   scripts,
		"variables": response.VariableNames,
	})
}

// GetAlertSuggestions ranks enabled playbooks for a Sigma alert.
func (h *Handlers) GetAlertSuggestions(c echo.Context) error {
	if h.responseUnavailable(c) {
		return nil
	}
	alertID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert ID")
	}
	ctx := c.Request().Context()
	alert, err := h.respEngine.store.GetSigmaAlert(ctx, alertID)
	if errors.Is(err, repository.ErrNotFound) {
		return errorResponse(c, http.StatusNotFound, "ALERT_NOT_FOUND", "Alert not found")
	}
	if err != nil {
		return h.engineError(c, err, nil)
	}
	playbooks, err := h.respEngine.playbooks.List(ctx, repository.PlaybookFilter{Limit: 500})
	if err != nil {
		return h.engineError(c, err, nil)
	}
	rules, err := h.respEngine.rules.List(ctx)
	if err != nil {
		return h.engineError(c, err, nil)
	}
	suggestions := response.Suggest(alert, playbooks, rules, 5)
	suggested := ""
	if len(suggestions) > 0 {
		suggested = suggestions[0].PlaybookID
	}
	return c.JSON(http.StatusOK, map[string]any{
		"alert_id":              alert.ID,
		"suggested_playbook_id": suggested,
		"suggestions":           suggestions,
	})
}

// PreviewPlaybookRun binds a playbook to an alert/endpoint without running it.
func (h *Handlers) PreviewPlaybookRun(c echo.Context) error {
	if h.responseUnavailable(c) {
		return nil
	}
	pbID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid playbook ID")
	}
	alertID, err := optionalUUID(c.QueryParam("alert_id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert_id")
	}
	plan, err := h.respEngine.engine.Prepare(c.Request().Context(), response.RunRequest{
		PlaybookID: pbID, AlertID: alertID, AgentID: c.QueryParam("agent_id"),
	})
	if err != nil {
		return h.engineError(c, err, nil)
	}
	return c.JSON(http.StatusOK, plan)
}

// RunPlaybookRequest is the body of POST /automation/playbooks/:id/run.
type RunPlaybookRequest struct {
	AlertID       string                    `json:"alert_id"`
	AgentID       string                    `json:"agent_id"`
	Overrides     map[int]map[string]string `json:"overrides"` // step index → params
	Reason        string                    `json:"reason"`
	ApprovalToken string                    `json:"approval_token,omitempty"`
}

// RunPlaybook starts a tracked, server-side playbook run.
func (h *Handlers) RunPlaybook(c echo.Context) error {
	if h.responseUnavailable(c) {
		return nil
	}
	pbID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid playbook ID")
	}
	var req RunPlaybookRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	alertID, err := optionalUUID(req.AlertID)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert_id")
	}
	for idx, params := range req.Overrides {
		if idx < 0 || len(params) > 20 {
			return errorResponse(c, http.StatusBadRequest, "INVALID_OVERRIDES", "Invalid step overrides")
		}
		for k, v := range params {
			if len(k) > 64 || len(v) > 1024 {
				return errorResponse(c, http.StatusBadRequest, "INVALID_OVERRIDES", "Override value too long")
			}
		}
	}

	ctx := c.Request().Context()
	runReq := response.RunRequest{
		PlaybookID: pbID, AlertID: alertID, AgentID: req.AgentID,
		Trigger: "manual", Username: currentUsername(c), Overrides: req.Overrides,
	}
	// Validate before consuming a single-use approval token.
	if _, err := h.respEngine.engine.Prepare(ctx, runReq); err != nil {
		return h.engineError(c, err, nil)
	}

	// Same out-of-band approval gate as manual commands (no-op when off).
	h.consumeApprovalIfRequired(c, req.ApprovalToken)
	if c.Response().Committed {
		return nil
	}

	rec, plan, err := h.respEngine.engine.Start(context.WithoutCancel(ctx), runReq)
	if err != nil {
		return h.engineError(c, err, plan)
	}
	alertRef := ""
	if alertID != nil {
		alertRef = " alert=" + alertID.String()
	}
	h.fireAudit(c, "playbook.run", "playbook_execution", rec.ID,
		fmt.Sprintf("playbook=%q agent=%s%s steps=%d reason=%q", plan.PlaybookName, plan.AgentID, alertRef, len(plan.Steps), strings.TrimSpace(req.Reason)),
		false, "")
	return c.JSON(http.StatusAccepted, map[string]any{"execution_id": rec.ID, "execution": rec, "plan": plan})
}

// ListPlaybookExecutions returns recent runs (optionally filtered).
func (h *Handlers) ListPlaybookExecutions(c echo.Context) error {
	if h.responseUnavailable(c) {
		return nil
	}
	var f repository.ExecutionListFilter
	var err error
	if f.AlertID, err = optionalUUID(c.QueryParam("alert_id")); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert_id")
	}
	if f.PlaybookID, err = optionalUUID(c.QueryParam("playbook_id")); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid playbook_id")
	}
	if f.AgentID, err = optionalUUID(c.QueryParam("agent_id")); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent_id")
	}
	if n, perr := strconv.Atoi(c.QueryParam("limit")); perr == nil {
		f.Limit = n
	}
	list, err := h.respEngine.store.ListExecutions(c.Request().Context(), f)
	if err != nil {
		return h.engineError(c, err, nil)
	}
	return c.JSON(http.StatusOK, map[string]any{"data": list, "total": len(list)})
}

// GetPlaybookExecution returns one run with its per-step results.
func (h *Handlers) GetPlaybookExecution(c echo.Context) error {
	if h.responseUnavailable(c) {
		return nil
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid execution ID")
	}
	rec, err := h.respEngine.store.GetExecution(c.Request().Context(), id)
	if errors.Is(err, repository.ErrNotFound) {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Execution not found")
	}
	if err != nil {
		return h.engineError(c, err, nil)
	}
	return c.JSON(http.StatusOK, map[string]any{"data": rec})
}
