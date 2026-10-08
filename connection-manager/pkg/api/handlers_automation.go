package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/response"
	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/models"
)

// AutomationHandlers handles automation-related API endpoints
type AutomationHandlers struct {
	logger            *logrus.Logger
	automationService *service.AutomationService
	metricsService    *service.MetricsService

	// Optional response-engine sources (set when the database is available).
	scripts response.ScriptStore
	alerts  sigmaAlertSource
}

// sigmaAlertSource loads Sigma alerts (the alerts the dashboard shows).
type sigmaAlertSource interface {
	GetSigmaAlert(ctx context.Context, id uuid.UUID) (*repository.SigmaAlertRecord, error)
}

// SetResponseSources wires the script library (step validation) and the
// Sigma alert source (rule matching previews).
func (h *AutomationHandlers) SetResponseSources(scripts response.ScriptStore, alerts sigmaAlertSource) {
	h.scripts = scripts
	h.alerts = alerts
}

// NewAutomationHandlers creates new automation handlers
func NewAutomationHandlers(
	logger *logrus.Logger,
	automationService *service.AutomationService,
	metricsService *service.MetricsService,
) *AutomationHandlers {
	return &AutomationHandlers{
		logger:            logger,
		automationService: automationService,
		metricsService:    metricsService,
	}
}

// CreatePlaybookRequest represents a request to create or update a playbook
type CreatePlaybookRequest struct {
	Name            string                   `json:"name" validate:"required"`
	Description     string                   `json:"description,omitempty"`
	Category        string                   `json:"category" validate:"required"`
	Commands        []models.PlaybookCommand `json:"commands" validate:"required"`
	Enabled         *bool                    `json:"enabled,omitempty"`
	SeverityFilter  []string                 `json:"severity_filter,omitempty"`
	RulePattern     string                   `json:"rule_pattern,omitempty"`
	MitreTechniques []string                 `json:"mitre_techniques,omitempty"`
}

// PlaybookListResponse represents a response with playbook list
type PlaybookListResponse struct {
	Data  []*models.ResponsePlaybook `json:"data"`
	Total int                        `json:"total"`
	Meta  ResponseMeta               `json:"meta"`
}

// AutomationRuleListResponse represents a response with automation rule list
type AutomationRuleListResponse struct {
	Data  []*models.AutomationRule `json:"data"`
	Total int                      `json:"total"`
	Meta  ResponseMeta             `json:"meta"`
}

// CreatePlaybook creates a new response playbook
func (h *AutomationHandlers) CreatePlaybook(c echo.Context) error {
	var req CreatePlaybookRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	steps, err := h.validatePlaybookRequest(c, &req)
	if err != nil {
		return h.playbookValidationError(c, err)
	}

	// Enabled defaults to true (the column default); the zero value of the
	// Go struct used to store every API-created playbook as disabled.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	playbook := &models.ResponsePlaybook{
		Name:           req.Name,
		Description:    req.Description,
		Category:       req.Category,
		Commands:       marshalCommands(steps),
		Enabled:        enabled,
		SeverityFilter: req.SeverityFilter,
		RulePattern:    req.RulePattern,
		MITRETechiques: req.MitreTechniques,
		CreatedBy:      getCurrentUserID(c),
	}

	if err := h.automationService.CreatePlaybook(c.Request().Context(), playbook); err != nil {
		h.logger.WithError(err).Error("CreatePlaybook failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create playbook")
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message": "Playbook created successfully",
		"data":    playbook,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// UpdatePlaybook replaces an existing playbook definition (steps, order,
// parameters, failure policy, enabled state and matching metadata).
func (h *AutomationHandlers) UpdatePlaybook(c echo.Context) error {
	playbookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid playbook ID")
	}
	var req CreatePlaybookRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	ctx := c.Request().Context()
	existing, err := h.automationService.GetPlaybookByID(ctx, playbookID)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Playbook not found")
	}
	steps, err := h.validatePlaybookRequest(c, &req)
	if err != nil {
		return h.playbookValidationError(c, err)
	}

	existing.Name = req.Name
	existing.Description = req.Description
	existing.Category = req.Category
	existing.Commands = marshalCommands(steps)
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.SeverityFilter = req.SeverityFilter
	existing.RulePattern = req.RulePattern
	existing.MITRETechiques = req.MitreTechniques

	if err := h.automationService.UpdatePlaybook(ctx, existing); err != nil {
		h.logger.WithError(err).Error("UpdatePlaybook failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update playbook")
	}
	updated, err := h.automationService.GetPlaybookByID(ctx, playbookID)
	if err != nil {
		updated = existing
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Playbook updated successfully",
		"data":    updated,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

func (h *AutomationHandlers) playbookValidationError(c echo.Context, err error) error {
	if errors.Is(err, response.ErrFreeTextCommandNotAllowed) {
		return errorResponse(c, http.StatusForbidden, "FREE_TEXT_COMMAND_REQUIRES_ADMIN", err.Error())
	}
	return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
}

// DeletePlaybook deletes a playbook
func (h *AutomationHandlers) DeletePlaybook(c echo.Context) error {
	playbookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid playbook ID")
	}

	if err := h.automationService.DeletePlaybook(c.Request().Context(), playbookID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete playbook")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Playbook deleted successfully",
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// ListPlaybooks retrieves all response playbooks with optional filtering
func (h *AutomationHandlers) ListPlaybooks(c echo.Context) error {
	ctx := c.Request().Context()

	// Extract query parameters
	category := c.QueryParam("category")
	enabled := c.QueryParam("enabled")
	alertID := c.QueryParam("alert_id")

	var playbooks []*models.ResponsePlaybook
	var err error

	if alertID != "" {
		// Playbooks recommended for a Sigma alert, best first.
		alertUUID, perr := uuid.Parse(alertID)
		if perr != nil {
			return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert ID")
		}
		if h.alerts == nil {
			return errorResponse(c, http.StatusServiceUnavailable, "UNAVAILABLE", "Alert source unavailable")
		}
		alert, aerr := h.alerts.GetSigmaAlert(ctx, alertUUID)
		if aerr != nil {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Alert not found")
		}
		all, lerr := h.automationService.ListPlaybooks(ctx, repository.PlaybookFilter{Limit: 500})
		if lerr != nil {
			return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fetch playbooks")
		}
		rules, _ := h.automationService.ListRules(ctx)
		byID := make(map[string]*models.ResponsePlaybook, len(all))
		for _, p := range all {
			byID[p.ID.String()] = p
		}
		for _, sg := range response.Suggest(alert, all, rules, 10) {
			if p := byID[sg.PlaybookID]; p != nil {
				playbooks = append(playbooks, p)
			}
		}
	} else {
		// Get all playbooks with filtering
		filter := repository.PlaybookFilter{
			Category: &category,
			Enabled:  &enabled,
		}
		playbooks, err = h.automationService.ListPlaybooks(ctx, filter)
	}

	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fetch playbooks")
	}

	return c.JSON(http.StatusOK, PlaybookListResponse{
		Data:  playbooks,
		Total: len(playbooks),
		Meta: ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// GetPlaybook retrieves a specific playbook by ID
func (h *AutomationHandlers) GetPlaybook(c echo.Context) error {
	playbookID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid playbook ID")
	}

	playbook, err := h.automationService.GetPlaybookByID(c.Request().Context(), playbookID)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Playbook not found")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": playbook,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// ListAutomationRules retrieves all automation rules with optional filtering for alert
func (h *AutomationHandlers) ListAutomationRules(c echo.Context) error {
	ctx := c.Request().Context()
	alertIDStr := c.QueryParam("alert_id")

	var rules []*models.AutomationRule
	var err error

	rules, err = h.automationService.ListRules(ctx)
	if err == nil && alertIDStr != "" {
		// Only the enabled rules whose conditions match this Sigma alert.
		alertID, perr := uuid.Parse(alertIDStr)
		if perr != nil {
			return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid alert ID")
		}
		if h.alerts == nil {
			return errorResponse(c, http.StatusServiceUnavailable, "UNAVAILABLE", "Alert source unavailable")
		}
		alert, aerr := h.alerts.GetSigmaAlert(ctx, alertID)
		if aerr != nil {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Alert not found")
		}
		matching := make([]*models.AutomationRule, 0, len(rules))
		for _, r := range rules {
			if cond, ok := response.ParseConditions(r.TriggerConditions); ok && r.Enabled && cond.Matches(alert) {
				r.MatchesCurrentAlert = true
				matching = append(matching, r)
			}
		}
		rules = matching
	}

	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fetch rules")
	}

	return c.JSON(http.StatusOK, AutomationRuleListResponse{
		Data:  rules,
		Total: len(rules),
		Meta: ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// AutomationRuleRequest is the body for creating/updating an automation rule.
type AutomationRuleRequest struct {
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	TriggerConditions json.RawMessage `json:"trigger_conditions"`
	PlaybookID        uuid.UUID       `json:"playbook_id"`
	Priority          *int            `json:"priority"`
	AutoExecute       *bool           `json:"auto_execute"`
	CooldownMinutes   *int            `json:"cooldown_minutes"`
	Enabled           *bool           `json:"enabled"`
}

const (
	defaultRuleCooldown = 30
	maxRuleCooldown     = 1440
)

// validateRuleRequest checks a rule's fields; partial=true for updates.
func (h *AutomationHandlers) validateRuleRequest(ctx context.Context, req *AutomationRuleRequest, partial bool) error {
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if !partial || req.Name != "" {
		if req.Name == "" || len(req.Name) > 255 {
			return errors.New("rule name is required (max 255 characters)")
		}
	}
	if !partial || len(req.TriggerConditions) > 0 {
		if _, ok := response.ParseConditions(req.TriggerConditions); !ok {
			return errors.New("trigger conditions must set at least one of severity, rule_patterns or min_risk_score")
		}
	}
	if !partial || req.PlaybookID != uuid.Nil {
		if req.PlaybookID == uuid.Nil {
			return errors.New("a target playbook is required")
		}
		if _, err := h.automationService.GetPlaybookByID(ctx, req.PlaybookID); err != nil {
			return errors.New("target playbook not found")
		}
	}
	if req.Priority != nil && (*req.Priority < 1 || *req.Priority > 100) {
		return errors.New("priority must be between 1 and 100")
	}
	if req.CooldownMinutes != nil && (*req.CooldownMinutes < 0 || *req.CooldownMinutes > maxRuleCooldown) {
		return fmt.Errorf("cooldown must be between 0 and %d minutes", maxRuleCooldown)
	}
	return nil
}

// CreateAutomationRule creates a new automation rule.
func (h *AutomationHandlers) CreateAutomationRule(c echo.Context) error {
	var req AutomationRuleRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	ctx := c.Request().Context()
	if err := h.validateRuleRequest(ctx, &req, false); err != nil {
		return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
	}
	cond, _ := response.ParseConditions(req.TriggerConditions)
	condJSON, _ := json.Marshal(cond)
	rule := models.AutomationRule{
		Name:              req.Name,
		Description:       req.Description,
		TriggerConditions: condJSON,
		PlaybookID:        req.PlaybookID,
		Priority:          5,
		CooldownMinutes:   defaultRuleCooldown,
		Enabled:           true,
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.CooldownMinutes != nil {
		rule.CooldownMinutes = *req.CooldownMinutes
	}
	if req.AutoExecute != nil {
		rule.AutoExecute = *req.AutoExecute
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}

	if err := h.automationService.CreateRule(ctx, &rule); err != nil {
		h.logger.WithError(err).Error("CreateAutomationRule failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create rule")
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message": "Automation rule created successfully",
		"data":    rule,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// UpdateAutomationRule updates an existing automation rule
func (h *AutomationHandlers) UpdateAutomationRule(c echo.Context) error {
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid rule ID")
	}

	var req AutomationRuleRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	ctx := c.Request().Context()
	if err := h.validateRuleRequest(ctx, &req, true); err != nil {
		return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
	}
	rule, err := h.automationService.GetRuleByID(ctx, ruleID)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Rule not found")
	}

	// Only fields present in the request change.
	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Description != "" {
		rule.Description = req.Description
	}
	if len(req.TriggerConditions) > 0 {
		cond, _ := response.ParseConditions(req.TriggerConditions)
		rule.TriggerConditions, _ = json.Marshal(cond)
	}
	if req.PlaybookID != uuid.Nil {
		rule.PlaybookID = req.PlaybookID
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if req.AutoExecute != nil {
		rule.AutoExecute = *req.AutoExecute
	}
	if req.CooldownMinutes != nil {
		rule.CooldownMinutes = *req.CooldownMinutes
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}

	if err := h.automationService.UpdateRule(ctx, rule); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update rule")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Automation rule updated successfully",
		"data":    rule,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// DeleteAutomationRule deletes an automation rule
func (h *AutomationHandlers) DeleteAutomationRule(c echo.Context) error {
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid rule ID")
	}

	if err := h.automationService.DeleteRule(c.Request().Context(), ruleID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete rule")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Automation rule deleted successfully",
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// ToggleAutomationRule toggles the enabled state of an automation rule
func (h *AutomationHandlers) ToggleAutomationRule(c echo.Context) error {
	ruleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid rule ID")
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	ctx := c.Request().Context()
	rule, err := h.automationService.GetRuleByID(ctx, ruleID)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Rule not found")
	}

	// Only the enabled flag changes. (auto_execute used to mirror it, so
	// enabling a manual-only rule silently made it auto-executing.)
	rule.Enabled = req.Enabled

	if err := h.automationService.UpdateRule(ctx, rule); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update rule")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Rule state updated successfully",
		"data":    rule,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// GetAutomationMetrics retrieves automation metrics
func (h *AutomationHandlers) GetAutomationMetrics(c echo.Context) error {
	timeRange := c.QueryParam("time_range")
	if timeRange == "" {
		timeRange = "7d" // Default to 7 days
	}

	metrics, err := h.metricsService.GetMetrics(c.Request().Context(), timeRange)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fetch metrics")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": metrics,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// GetAutomationOptimizations retrieves ML-based optimization suggestions
func (h *AutomationHandlers) GetAutomationOptimizations(c echo.Context) error {
	optimizations, err := h.automationService.GetRuleOptimizations(c.Request().Context())
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get optimizations")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": optimizations,
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}

var validPlaybookCategories = map[string]bool{
	"containment": true, "investigation": true, "remediation": true, "validation": true,
}

var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "informational": true,
}

var mitreTechniqueRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// validatePlaybookRequest validates and normalises a create/update request.
func (h *AutomationHandlers) validatePlaybookRequest(c echo.Context, req *CreatePlaybookRequest) ([]models.PlaybookCommand, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	req.Category = strings.ToLower(strings.TrimSpace(req.Category))
	req.RulePattern = strings.TrimSpace(req.RulePattern)
	if req.Name == "" || len(req.Name) > 255 {
		return nil, errors.New("playbook name is required (max 255 characters)")
	}
	if !validPlaybookCategories[req.Category] {
		return nil, errors.New("category must be containment, investigation, remediation or validation")
	}
	sev := make([]string, 0, len(req.SeverityFilter))
	for _, v := range req.SeverityFilter {
		v = strings.ToLower(strings.TrimSpace(v))
		if !validSeverities[v] {
			return nil, fmt.Errorf("invalid severity %q", v)
		}
		sev = append(sev, v)
	}
	req.SeverityFilter = sev
	if len(req.RulePattern) > 500 {
		return nil, errors.New("rule pattern is too long")
	}
	if req.RulePattern != "" {
		if _, err := regexp.Compile("(?i)" + req.RulePattern); err != nil {
			return nil, fmt.Errorf("rule pattern is not a valid regular expression: %v", err)
		}
	}
	techs := make([]string, 0, len(req.MitreTechniques))
	for _, t := range req.MitreTechniques {
		t = strings.ToUpper(strings.TrimSpace(t))
		if !mitreTechniqueRe.MatchString(t) {
			return nil, fmt.Errorf("invalid MITRE technique %q (expected e.g. T1059 or T1059.001)", t)
		}
		techs = append(techs, t)
	}
	req.MitreTechniques = techs

	user := getCurrentUser(c)
	isAdmin := user != nil && userHasRole(user, "admin")
	return response.ValidateDefinition(c.Request().Context(), req.Commands, h.scripts, isAdmin)
}

// marshalCommands converts playbook commands to JSON
func marshalCommands(commands []models.PlaybookCommand) json.RawMessage {
	data, _ := json.Marshal(commands)
	return data
}

// getCurrentUserID gets the current user ID from context
func getCurrentUserID(c echo.Context) uuid.UUID {
	if userID, ok := c.Get("user_id").(uuid.UUID); ok {
		return userID
	}
	return uuid.New() // Fallback - should be properly implemented
}
