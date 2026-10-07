package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
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
	maxScriptCmdLen         = 4096
	maxScriptNameLen        = 128
	maxScriptDescriptionLen = 1000
	minScriptTimeoutSeconds = 30
	maxScriptTimeoutSeconds = 3600
	defaultScriptTimeout    = 300

	// ejectUSBToken is the agent's native USB-eject action (see agent runCommand).
	ejectUSBToken = "__EJECT_USB__"
)

// libraryExecutables mirrors the agent's playbookAllowedCommands
// (win_edrAgent/internal/command/handler.go). The agent remains the authority;
// this copy only lets the server reject a script at save time instead of the
// script failing on every endpoint. Keep the two lists in sync.
var libraryExecutables = map[string]bool{
	"ping": true, "tracert": true, "pathping": true, "netstat": true, "ipconfig": true,
	"nslookup": true, "whoami": true, "hostname": true, "systeminfo": true, "tasklist": true,
	"arp": true, "route": true,
	"powershell": true, "cmd": true, "sc": true, "net": true, "reg": true, "wmic": true,
	"attrib": true, "wevtutil": true, "icacls": true, "mountvol": true,
}

// libraryExecutableNames returns the allowed executables, sorted.
func libraryExecutableNames() []string {
	names := make([]string, 0, len(libraryExecutables))
	for k := range libraryExecutables {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// parseAgentCommandLine tokenizes exactly like the agent's parseCommandLine:
// split on spaces outside double quotes; quote characters are dropped.
func parseAgentCommandLine(cmd string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ' ' && !inQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// hasControlChars reports whether s contains ASCII control characters
// (newlines and tabs included) or invalid UTF-8.
func hasControlChars(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validateScriptCmd checks a script command line against the agent's
// library-tier rules, plus stricter server-side rules for stored scripts.
func validateScriptCmd(cmd string) error {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return errors.New("command is required")
	}
	if len(cmd) > maxScriptCmdLen {
		return fmt.Errorf("command is too long (max %d characters)", maxScriptCmdLen)
	}
	if hasControlChars(cmd) {
		return errors.New("command must be a single line without tabs or control characters")
	}
	if strings.EqualFold(cmd, ejectUSBToken) {
		return nil
	}
	if strings.Count(cmd, `"`)%2 != 0 {
		return errors.New("command has unbalanced double quotes")
	}
	parts := parseAgentCommandLine(cmd)
	if len(parts) == 0 {
		return errors.New("command is empty after parsing")
	}
	exe := parts[0]
	// Require a bare executable name. The agent resolves names via PATH; a path
	// (e.g. C:\Users\Public\powershell.exe) would run whatever file is there.
	if strings.ContainsAny(exe, `\/:`) {
		return fmt.Errorf("use the bare executable name (e.g. %q), not a path", "powershell")
	}
	name := strings.TrimSuffix(strings.ToLower(exe), ".exe")
	if !libraryExecutables[name] {
		return fmt.Errorf("%q is not an allowed executable. Allowed: %s", exe, strings.Join(libraryExecutableNames(), ", "))
	}
	if name == "powershell" {
		for _, arg := range parts[1:] {
			argL := strings.ToLower(strings.TrimLeft(arg, "-/"))
			if argL == "file" || argL == "f" {
				return errors.New("powershell -File is not permitted; use -Command with an inline script")
			}
			if argL == "encodedcommand" || argL == "ec" || argL == "en" || argL == "enc" {
				return errors.New("powershell -EncodedCommand is not permitted")
			}
		}
	}
	return nil
}

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
