package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/commandtypes"
)

// ─────────────────────────────────────────────────────────────────────────────
// Response script library (Stage 2)
//
// Scripts are stored run_cmd command lines that the server dispatches at the
// agent's "library" authorization tier. Authoring a script defines code that
// runs as SYSTEM on endpoints, so create/update/delete require the admin role
// (plus responses:execute on the route), the out-of-band approval gate when it
// is configured for create/update, and every change is audited. Running a
// script goes through ExecuteAgentCommand with script_id, so it inherits every
// control a manual command has.
// ─────────────────────────────────────────────────────────────────────────────

const (
	maxScriptCmdLen         = commandtypes.MaxLibraryCommandLen
	maxScriptNameLen        = 128
	maxScriptDescriptionLen = 1000
	minScriptTimeoutSeconds = 30
	maxScriptTimeoutSeconds = 3600
	defaultScriptTimeout    = 300

	// ejectUSBToken is the agent's native USB-eject action (see agent runCommand).
	ejectUSBToken = commandtypes.EjectUSBToken
)

// The library-command rules live in pkg/commandtypes so the script library
// and the playbook response engine enforce exactly the same constraints.
var libraryExecutables = commandtypes.LibraryExecutables

func libraryExecutableNames() []string          { return commandtypes.LibraryExecutableNames() }
func parseAgentCommandLine(cmd string) []string { return commandtypes.ParseAgentCommandLine(cmd) }
func hasControlChars(s string) bool             { return commandtypes.HasControlChars(s) }
func validateScriptCmd(cmd string) error        { return commandtypes.ValidateLibraryCommand(cmd) }

// ResponseScriptRequest is the body for creating or updating a script.
type ResponseScriptRequest struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	Cmd            string `json:"cmd"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Enabled        *bool  `json:"enabled"`
	ApprovalToken  string `json:"approval_token,omitempty"`
}

// normalize trims fields, applies defaults and validates the request.
func (r *ResponseScriptRequest) normalize() error {
	r.Name = strings.TrimSpace(r.Name)
	r.Description = strings.TrimSpace(r.Description)
	r.Cmd = strings.TrimSpace(r.Cmd)
	if r.Name == "" {
		return errors.New("name is required")
	}
	if utf8.RuneCountInString(r.Name) > maxScriptNameLen {
		return fmt.Errorf("name is too long (max %d characters)", maxScriptNameLen)
	}
	if hasControlChars(r.Name) {
		return errors.New("name must not contain control characters")
	}
	if utf8.RuneCountInString(r.Description) > maxScriptDescriptionLen {
		return fmt.Errorf("description is too long (max %d characters)", maxScriptDescriptionLen)
	}
	if r.TimeoutSeconds == 0 {
		r.TimeoutSeconds = defaultScriptTimeout
	}
	if r.TimeoutSeconds < minScriptTimeoutSeconds || r.TimeoutSeconds > maxScriptTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must be between %d and %d", minScriptTimeoutSeconds, maxScriptTimeoutSeconds)
	}
	return validateScriptCmd(r.Cmd)
}

// SetResponseScriptRepo wires the script library repository.
func (h *Handlers) SetResponseScriptRepo(repo repository.ResponseScriptRepository) {
	h.responseScriptRepo = repo
}

// requireScriptAdmin enforces the admin role for script authoring. It writes
// the error response itself and returns false when the caller is not allowed.
func (h *Handlers) requireScriptAdmin(c echo.Context) bool {
	if h.responseScriptRepo == nil {
		_ = errorResponse(c, http.StatusServiceUnavailable, "SCRIPTS_UNAVAILABLE", "Script library is not available (database not connected)")
		return false
	}
	if user := getCurrentUser(c); user == nil || !userHasRole(user, "admin") {
		_ = errorResponse(c, http.StatusForbidden, "SCRIPTS_REQUIRE_ADMIN", "Managing the script library requires an administrator account.")
		return false
	}
	return true
}

func currentUsername(c echo.Context) string {
	if user := getCurrentUser(c); user != nil {
		return user.Username
	}
	return "unknown"
}

// ListResponseScripts returns all scripts.
// GET /api/v1/response-scripts
func (h *Handlers) ListResponseScripts(c echo.Context) error {
	if h.responseScriptRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "SCRIPTS_UNAVAILABLE", "Script library is not available (database not connected)")
	}
	scripts, err := h.responseScriptRepo.List(c.Request().Context())
	if err != nil {
		h.logger.WithError(err).Error("ListResponseScripts failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list scripts")
	}
	return c.JSON(http.StatusOK, map[string]any{"data": scripts, "total": len(scripts)})
}

// CreateResponseScript adds a script to the library (admin + approval + audit).
// POST /api/v1/response-scripts
func (h *Handlers) CreateResponseScript(c echo.Context) error {
	if !h.requireScriptAdmin(c) {
		return nil
	}
	var req ResponseScriptRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	if err := req.normalize(); err != nil {
		return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
	}
	h.consumeApprovalIfRequired(c, req.ApprovalToken)
	if c.Response().Committed {
		return nil // gate wrote the 403
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	username := currentUsername(c)
	script := &repository.ResponseScript{
		Name:           req.Name,
		Description:    req.Description,
		Cmd:            req.Cmd,
		TimeoutSeconds: req.TimeoutSeconds,
		Enabled:        enabled,
		CreatedBy:      username,
		UpdatedBy:      username,
	}
	if err := h.responseScriptRepo.Create(c.Request().Context(), script); err != nil {
		if errors.Is(err, repository.ErrScriptNameExists) {
			return errorResponse(c, http.StatusConflict, "SCRIPT_NAME_EXISTS", err.Error())
		}
		h.logger.WithError(err).Error("CreateResponseScript failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create script")
	}
	h.fireAudit(c, "response_script.create", "response_script", script.ID,
		fmt.Sprintf("name=%q enabled=%t timeout=%ds cmd=%q", script.Name, script.Enabled, script.TimeoutSeconds, script.Cmd), false, "")
	return c.JSON(http.StatusCreated, map[string]any{"data": script})
}

// UpdateResponseScript replaces a script's fields (admin + approval + audit).
// PUT /api/v1/response-scripts/:id
func (h *Handlers) UpdateResponseScript(c echo.Context) error {
	if !h.requireScriptAdmin(c) {
		return nil
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid script ID")
	}
	var req ResponseScriptRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	if err := req.normalize(); err != nil {
		return errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
	}

	ctx := c.Request().Context()
	existing, err := h.responseScriptRepo.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Script not found")
	}
	if err != nil {
		h.logger.WithError(err).Error("UpdateResponseScript: lookup failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load script")
	}

	h.consumeApprovalIfRequired(c, req.ApprovalToken)
	if c.Response().Committed {
		return nil // gate wrote the 403
	}

	prevCmd := existing.Cmd
	existing.Name = req.Name
	existing.Description = req.Description
	existing.Cmd = req.Cmd
	existing.TimeoutSeconds = req.TimeoutSeconds
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	existing.UpdatedBy = currentUsername(c)
	if err := h.responseScriptRepo.Update(ctx, existing); err != nil {
		if errors.Is(err, repository.ErrScriptNameExists) {
			return errorResponse(c, http.StatusConflict, "SCRIPT_NAME_EXISTS", err.Error())
		}
		if errors.Is(err, repository.ErrNotFound) {
			return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Script not found")
		}
		h.logger.WithError(err).Error("UpdateResponseScript failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update script")
	}
	details := fmt.Sprintf("name=%q enabled=%t timeout=%ds", existing.Name, existing.Enabled, existing.TimeoutSeconds)
	if prevCmd != existing.Cmd {
		details += fmt.Sprintf(" cmd_changed old=%q new=%q", prevCmd, existing.Cmd)
	}
	h.fireAudit(c, "response_script.update", "response_script", existing.ID, details, false, "")
	return c.JSON(http.StatusOK, map[string]any{"data": existing})
}

// DeleteResponseScript removes a script (admin + audit).
// DELETE /api/v1/response-scripts/:id
func (h *Handlers) DeleteResponseScript(c echo.Context) error {
	if !h.requireScriptAdmin(c) {
		return nil
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid script ID")
	}
	ctx := c.Request().Context()
	existing, err := h.responseScriptRepo.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Script not found")
	}
	if err != nil {
		h.logger.WithError(err).Error("DeleteResponseScript: lookup failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load script")
	}
	if err := h.responseScriptRepo.Delete(ctx, id); err != nil && !errors.Is(err, repository.ErrNotFound) {
		h.logger.WithError(err).Error("DeleteResponseScript failed")
		return errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete script")
	}
	h.fireAudit(c, "response_script.delete", "response_script", id,
		fmt.Sprintf("name=%q cmd=%q", existing.Name, existing.Cmd), false, "")
	return c.JSON(http.StatusOK, map[string]any{"message": "Script deleted"})
}

// loadRunnableScript resolves a script_id for ExecuteAgentCommand. On failure
// it returns a nil script plus the HTTP status, error code and message.
func (h *Handlers) loadRunnableScript(ctx context.Context, scriptID string) (*repository.ResponseScript, int, string, string) {
	if h.responseScriptRepo == nil {
		return nil, http.StatusServiceUnavailable, "SCRIPTS_UNAVAILABLE", "Script library is not available (database not connected)"
	}
	id, err := uuid.Parse(strings.TrimSpace(scriptID))
	if err != nil {
		return nil, http.StatusBadRequest, "INVALID_SCRIPT_ID", "Invalid script_id"
	}
	script, err := h.responseScriptRepo.GetByID(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, http.StatusNotFound, "SCRIPT_NOT_FOUND", "Script not found"
	}
	if err != nil {
		h.logger.WithError(err).Error("loadRunnableScript: lookup failed")
		return nil, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load script"
	}
	if !script.Enabled {
		return nil, http.StatusConflict, "SCRIPT_DISABLED", "This script is disabled"
	}
	// Re-validate at run time in case the row was changed outside the API.
	if err := validateScriptCmd(script.Cmd); err != nil {
		return nil, http.StatusConflict, "SCRIPT_INVALID", "Stored script failed validation: " + err.Error()
	}
	return script, 0, "", ""
}
