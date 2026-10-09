package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/commandtypes"
)

// ─────────────────────────────────────────────────────────────────────────────
// Detection exceptions (false-positive suppression)  /api/v1/detection-exceptions
//
// An exception hides matches of one Sigma rule (or, narrowly, of every rule)
// for events whose fields satisfy ALL conditions, optionally on one endpoint.
// The sigma engine applies them; every suppressed match is counted.
// ─────────────────────────────────────────────────────────────────────────────

// exceptionFields are the Sigma fields an exception may test.
var exceptionFields = map[string]bool{
	"Image": true, "ParentImage": true, "CommandLine": true, "ParentCommandLine": true,
	"OriginalFileName": true, "Hashes": true, "User": true, "IntegrityLevel": true,
	"Company": true, "Product": true, "Description": true, "CurrentDirectory": true,
	"TargetFilename": true, "ImageLoaded": true, "TargetObject": true, "Details": true,
	"DestinationIp": true, "DestinationHostname": true, "DestinationPort": true, "QueryName": true,
	"PipeName": true, "SourceImage": true, "TargetImage": true, "ScriptBlockText": true, "Path": true,
}

// anchorFields identify a binary precisely; an all-rules exception must pin
// one of them with "equals".
var anchorFields = map[string]bool{"Image": true, "Hashes": true}

const (
	maxExceptionConditions = 10
	minPartialValueLen     = 4
	maxExceptionLifetime   = 365 * 24 * time.Hour
)

// SetDetectionExceptionRepo wires the detection exception API.
func (h *Handlers) SetDetectionExceptionRepo(r *repository.DetectionExceptionRepository) {
	h.detectionExceptionRepo = r
}

func (h *Handlers) exceptionsUnavailable(c echo.Context) bool {
	if h.detectionExceptionRepo == nil {
		_ = errorResponse(c, http.StatusServiceUnavailable, "EXCEPTIONS_UNAVAILABLE", "Detection exceptions are not available (database not connected)")
		return true
	}
	return false
}

// requireExceptionManager: suppressing detections is restricted to the
// admin and security roles (in addition to the route permission).
func (h *Handlers) requireExceptionManager(c echo.Context) bool {
	user := getCurrentUser(c)
	if user == nil || !(userHasRole(user, "admin") || userHasRole(user, "security")) {
		_ = errorResponse(c, http.StatusForbidden, "EXCEPTIONS_REQUIRE_SECURITY_ROLE",
			"Managing detection exceptions requires an administrator or security role.")
		return false
	}
	return true
}

// CreateDetectionExceptionRequest is the body of POST /detection-exceptions.
type CreateDetectionExceptionRequest struct {
	Name          string                          `json:"name"`
	RuleID        string                          `json:"rule_id"`
	RuleTitle     string                          `json:"rule_title"`
	AgentID       string                          `json:"agent_id"`
	Conditions    []repository.ExceptionCondition `json:"conditions"`
	Reason        string                          `json:"reason"`
	ExpiresAt     *time.Time                      `json:"expires_at"`
	SourceAlertID string                          `json:"source_alert_id"`
	ApprovalToken string                          `json:"approval_token,omitempty"`
}

// validateExceptionConditions normalises and checks conditions.
func validateExceptionConditions(conds []repository.ExceptionCondition, global bool) ([]repository.ExceptionCondition, error) {
	if len(conds) == 0 {
		return nil, errors.New("at least one condition is required")
	}
	if len(conds) > maxExceptionConditions {
		return nil, fmt.Errorf("at most %d conditions are allowed", maxExceptionConditions)
	}
	out := make([]repository.ExceptionCondition, 0, len(conds))
	anchored := false
	for i, c := range conds {
		c.Field = strings.TrimSpace(c.Field)
		c.Op = strings.ToLower(strings.TrimSpace(c.Op))
		c.Value = strings.TrimSpace(c.Value)
		n := i + 1
		if !exceptionFields[c.Field] {
			return nil, fmt.Errorf("condition %d: field %q cannot be used in exceptions", n, c.Field)
		}
		switch c.Op {
		case "equals", "startswith", "endswith", "contains":
		default:
			return nil, fmt.Errorf("condition %d: operator must be equals, startswith, endswith or contains", n)
		}
		if c.Value == "" || len(c.Value) > 1024 || commandtypes.HasControlChars(c.Value) {
			return nil, fmt.Errorf("condition %d: value is empty, too long or contains control characters", n)
		}
		if strings.ContainsAny(c.Value, "*?") {
			return nil, fmt.Errorf("condition %d: wildcards are not supported — use startswith/endswith/contains", n)
		}
		if c.Op != "equals" && len(c.Value) < minPartialValueLen {
			return nil, fmt.Errorf("condition %d: partial matches need at least %d characters", n, minPartialValueLen)
		}
		if c.Op == "equals" && anchorFields[c.Field] {
			anchored = true
		}
		out = append(out, c)
	}
	if global && !anchored {
		return nil, errors.New("an exception for every rule must pin the exact Image path or file hash (equals); otherwise scope it to one rule")
	}
	return out, nil
}

// ListDetectionExceptions returns all exceptions with their hit counters.
func (h *Handlers) ListDetectionExceptions(c echo.Context) error {
	if h.exceptionsUnavailable(c) {
		return nil
	}
	list, err := h.detectionExceptionRepo.List(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("ListDetectionExceptions failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list detection exceptions")
	}
	return c.JSON(http.StatusOK, map[string]any{"data": list, "total": len(list)})
}

// CreateDetectionException adds an exception (approval gate + audit).
func (h *Handlers) CreateDetectionException(c echo.Context) error {
	if h.exceptionsUnavailable(c) || !h.requireExceptionManager(c) {
		return nil
	}
	var req CreateDetectionExceptionRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Reason = strings.TrimSpace(req.Reason)
	req.RuleID = strings.TrimSpace(req.RuleID)
	if req.Name == "" || len(req.Name) > 255 {
		return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Name is required (max 255 characters)")
	}
	if req.Reason == "" || len(req.Reason) > 1000 {
		return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "A justification (reason) is required (max 1000 characters)")
	}
	if len(req.RuleID) > 255 || len(req.RuleTitle) > 500 {
		return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Rule ID or title is too long")
	}
	conds, err := validateExceptionConditions(req.Conditions, req.RuleID == "")
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
	}
	if req.ExpiresAt != nil {
		if !req.ExpiresAt.After(time.Now()) || req.ExpiresAt.After(time.Now().Add(maxExceptionLifetime)) {
			return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Expiry must be in the future and within one year")
		}
	}

	ctx := c.Request().Context()
	ex := &repository.DetectionException{
		Name: req.Name, RuleID: req.RuleID, RuleTitle: strings.TrimSpace(req.RuleTitle),
		Conditions: conds, Reason: req.Reason, Enabled: true, ExpiresAt: req.ExpiresAt,
		CreatedBy: currentUsername(c),
	}
	if a := strings.TrimSpace(req.AgentID); a != "" {
		id, perr := uuid.Parse(strings.TrimPrefix(strings.ToLower(a), "agent-"))
		if perr != nil {
			return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid agent_id")
		}
		ex.AgentID = id.String()
		if h.agentSvc == nil {
			return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Endpoint lookup is not available")
		}
		ag, gerr := h.agentSvc.GetByID(ctx, id)
		if errors.Is(gerr, repository.ErrNotFound) || (gerr == nil && ag == nil) {
			return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Selected endpoint no longer exists")
		}
		if gerr != nil {
			h.logger.WithError(gerr).Error("Detection exception endpoint lookup failed")
			return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Could not verify the selected endpoint")
		}
		ex.Hostname = ag.Hostname
	}
	if s := strings.TrimSpace(req.SourceAlertID); s != "" {
		id, perr := uuid.Parse(s)
		if perr != nil {
			return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid source_alert_id")
		}
		ex.SourceAlertID = &id
	}

	h.consumeApprovalIfRequired(c, req.ApprovalToken)
	if c.Response().Committed {
		return nil
	}
	if err := h.detectionExceptionRepo.Create(ctx, ex); err != nil {
		h.logger.WithError(err).Error("CreateDetectionException failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create detection exception")
	}
	scope := "rule=" + ex.RuleID
	if ex.RuleID == "" {
		scope = "rule=ALL"
	}
	if ex.AgentID != "" {
		scope += " agent=" + ex.AgentID
	}
	h.fireAudit(c, "detection_exception.created", "detection_exception", ex.ID,
		fmt.Sprintf("name=%q %s conditions=%d reason=%q", ex.Name, scope, len(ex.Conditions), ex.Reason), false, "")
	return c.JSON(http.StatusCreated, map[string]any{"data": ex})
}

// UpdateDetectionExceptionRequest is the body of PATCH /detection-exceptions/:id.
type UpdateDetectionExceptionRequest struct {
	Enabled       *bool      `json:"enabled"`
	ExpiresAt     *time.Time `json:"expires_at"`
	ClearExpiry   bool       `json:"clear_expiry"`
	Reason        string     `json:"reason"`
	ApprovalToken string     `json:"approval_token,omitempty"`
}

// UpdateDetectionException enables/disables an exception or changes expiry.
func (h *Handlers) UpdateDetectionException(c echo.Context) error {
	if h.exceptionsUnavailable(c) || !h.requireExceptionManager(c) {
		return nil
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid exception ID")
	}
	var req UpdateDetectionExceptionRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	ctx := c.Request().Context()
	ex, err := h.detectionExceptionRepo.Get(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Exception not found")
	}
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load exception")
	}
	enabling := req.Enabled != nil && *req.Enabled && !ex.Enabled
	if req.Enabled != nil {
		ex.Enabled = *req.Enabled
	}
	if req.ClearExpiry {
		ex.ExpiresAt = nil
	} else if req.ExpiresAt != nil {
		if !req.ExpiresAt.After(time.Now()) || req.ExpiresAt.After(time.Now().Add(maxExceptionLifetime)) {
			return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Expiry must be in the future and within one year")
		}
		ex.ExpiresAt = req.ExpiresAt
	}
	if r := strings.TrimSpace(req.Reason); r != "" {
		if len(r) > 1000 {
			return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Reason is too long")
		}
		ex.Reason = r
	}
	// Re-enabling hides detections again: same approval as creating one.
	if enabling {
		h.consumeApprovalIfRequired(c, req.ApprovalToken)
		if c.Response().Committed {
			return nil
		}
	}
	if err := h.detectionExceptionRepo.Update(ctx, ex); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update exception")
	}
	h.fireAudit(c, "detection_exception.updated", "detection_exception", ex.ID,
		fmt.Sprintf("name=%q enabled=%v expires_at=%v", ex.Name, ex.Enabled, ex.ExpiresAt), false, "")
	return c.JSON(http.StatusOK, map[string]any{"data": ex})
}

// DeleteDetectionException removes an exception (detections resume).
func (h *Handlers) DeleteDetectionException(c echo.Context) error {
	if h.exceptionsUnavailable(c) || !h.requireExceptionManager(c) {
		return nil
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid exception ID")
	}
	ctx := c.Request().Context()
	ex, err := h.detectionExceptionRepo.Get(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Exception not found")
	}
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load exception")
	}
	if err := h.detectionExceptionRepo.Delete(ctx, id); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete exception")
	}
	h.fireAudit(c, "detection_exception.deleted", "detection_exception", id,
		fmt.Sprintf("name=%q rule=%q hits=%d", ex.Name, ex.RuleID, ex.HitCount), false, "")
	return c.JSON(http.StatusOK, map[string]any{"message": "Detection exception deleted"})
}
