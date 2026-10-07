package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/connection-manager/pkg/security"
)

// defaultUninstallTokenTTL is used when none is configured.
const defaultUninstallTokenTTL = 30 * time.Minute

// SetAllowCustomCommands sets the master switch for admin-authored custom
// run_cmd commands. Default is false (feature off).
func (h *Handlers) SetAllowCustomCommands(enabled bool) {
	h.allowCustomCommands = enabled
}

// GetCommandCapabilities reports which command features are enabled, so the
// dashboard can show or hide the custom-command UI. The actual authorization
// is always enforced server-side in ExecuteAgentCommand regardless of this.
func (h *Handlers) GetCommandCapabilities(c echo.Context) error {
	user := getCurrentUser(c)
	return c.JSON(http.StatusOK, map[string]any{
		// Custom commands are usable only when the master switch is on AND the
		// caller is an admin.
		"custom_commands_enabled": h.allowCustomCommands && userHasRole(user, "admin"),
		// Whether the feature is switched on at all (for an explanatory message).
		"custom_commands_available": h.allowCustomCommands,
		// Response script library: whether it is available, whether the caller
		// may manage it (admin), and which executables a script may start.
		"script_library_available":   h.responseScriptRepo != nil,
		"script_library_manage":      h.responseScriptRepo != nil && userHasRole(user, "admin"),
		"script_library_executables": libraryExecutableNames(),
		// Whether manual commands currently require an out-of-band OTP
		// (COMMAND_APPROVAL_ENABLED + SMTP + EC2_EMAIL_VERIFY all configured).
		"command_approval_enabled": h.approvalGateActive(),
	})
}

// SetUninstallSigner wires the Ed25519 key used to sign offline uninstall
// tokens. ttl <= 0 selects defaultUninstallTokenTTL. When priv is nil the
// mint endpoint reports the feature as unavailable.
func (h *Handlers) SetUninstallSigner(priv ed25519.PrivateKey, ttl time.Duration) {
	h.uninstallSigner = priv
	if ttl <= 0 {
		ttl = defaultUninstallTokenTTL
	}
	h.uninstallTokenTTL = ttl
}

// uninstallPubKeyB64 returns the standard-base64 raw Ed25519 public key that
// matches the configured signing key, for embedding into agent builds. Returns
// "" when no signing key is configured.
func (h *Handlers) uninstallPubKeyB64() string {
	if len(h.uninstallSigner) != ed25519.PrivateKeySize {
		return ""
	}
	pub, ok := h.uninstallSigner.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// UninstallTokenResponse is returned by GenerateUninstallToken.
type UninstallTokenResponse struct {
	Token     string    `json:"token"`      // the signed, agent-bound uninstall token (shown once)
	AgentID   string    `json:"agent_id"`   // target agent
	ExpiresAt time.Time `json:"expires_at"` // absolute expiry
	TTLSecond int       `json:"ttl_seconds"`
}

// GenerateUninstallToken mints a signed, agent-bound, short-lived offline
// uninstall token for the target agent.
//
// POST /api/v1/agents/:id/uninstall-token
//
// Authorization mirrors the remote uninstall command: it is reached through
// the protected router (JWT), gated by RequirePermission("responses","execute")
// on the route, by the out-of-band approval gate (when configured), and every
// issuance is written to the audit log. The token lets an operator remove the
// agent locally even while it is offline; it is bound to this agent_id and
// expires within minutes.
func (h *Handlers) GenerateUninstallToken(c echo.Context) error {
	idStr := c.Param("id")
	agentID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid agent ID format")
	}

	if len(h.uninstallSigner) != ed25519.PrivateKeySize {
		return errorResponse(c, http.StatusServiceUnavailable, "UNINSTALL_TOKEN_UNAVAILABLE",
			"Offline uninstall token signing is not configured on this server")
	}

	// Out-of-band approval gate (same control as manual commands). Accepts the
	// token via X-Approval-Token header or the approval_token body field.
	var body struct {
		ApprovalToken string `json:"approval_token"`
		Reason        string `json:"reason"`
	}
	_ = c.Bind(&body) // body is optional; bind errors fall through to the gate
	h.consumeApprovalIfRequired(c, body.ApprovalToken)
	if c.Response().Committed {
		return nil // gate wrote the 403 — stop here
	}

	// Confirm the agent exists and is not already uninstalled.
	if h.agentSvc != nil {
		agent, gErr := h.agentSvc.GetByID(c.Request().Context(), agentID)
		if gErr != nil {
			return errorResponse(c, http.StatusNotFound, "AGENT_NOT_FOUND", "Agent not found")
		}
		if agent.Status == models.AgentStatusUninstalled {
			return errorResponse(c, http.StatusGone, "AGENT_UNINSTALLED", "Agent has already been uninstalled")
		}
	}

	token, err := security.SignUninstallToken(h.uninstallSigner, agentID.String(), h.uninstallTokenTTL)
	if err != nil {
		h.logger.WithError(err).Error("GenerateUninstallToken: signing failed")
		return errorResponse(c, http.StatusInternalServerError, "TOKEN_SIGN_ERROR", "Failed to sign uninstall token")
	}
	expiresAt := time.Now().Add(h.uninstallTokenTTL)

	reason := strings.TrimSpace(body.Reason)
	h.fireAudit(c, "agent.uninstall_token.issue", "agent", agentID,
		"Offline uninstall token issued (ttl="+h.uninstallTokenTTL.String()+", reason="+reason+")", false, "")

	return c.JSON(http.StatusOK, UninstallTokenResponse{
		Token:     token,
		AgentID:   agentID.String(),
		ExpiresAt: expiresAt,
		TTLSecond: int(h.uninstallTokenTTL.Seconds()),
	})
}
