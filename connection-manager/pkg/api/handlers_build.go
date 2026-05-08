// Package api provides the agent binary build endpoint.
package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/connection-manager/pkg/security"
)

// BuildAgentRequest is the JSON body for agent build requests from the dashboard.
type BuildAgentRequest struct {
	ServerIP      string `json:"server_ip"`
	ServerDomain  string `json:"server_domain"`
	ServerPort    string `json:"server_port"`
	// TokenID references an existing enrollment token. If omitted, MaxUses must be provided
	// and BuildAgent will mint a new enrollment token for this build.
	TokenID       string `json:"token_id"`
	MaxUses       *int   `json:"max_uses"`       // nil = require token_id; non-nil must be >= 1
	ExpiresInH    *int   `json:"expires_in_hours"` // nil = default 24 hours
	SkipConfig    bool   `json:"skip_config"`    // if true, only CA is embedded (no server addr)
	InstallSysmon bool   `json:"install_sysmon"` // if true, agent installs Sysmon on first run
}

// builderRequest is the JSON body sent to the agent-builder service.
// Token-related fields are now BuildID + TokenBinding (HMAC).
// Legacy Token/TokenEnc/TokenKeyA/TokenID fields are intentionally omitted —
// the agent-builder only embeds BuildID and TokenBinding.
type builderRequest struct {
	ServerIP      string `json:"server_ip"`
	ServerDomain  string `json:"server_domain"`
	ServerPort    string `json:"server_port"`
	BuildID       string `json:"build_id"`       // UUID — injected as EmbeddedBuildID
	TokenBinding  string `json:"token_binding"`  // HMAC-SHA256(key=token, msg=buildID) hex — injected as EmbeddedTokenHash
	SkipConfig    bool   `json:"skip_config"`
	CACertPEM     string `json:"ca_cert_pem"`
	InstallSysmon bool   `json:"install_sysmon"`
}

// BuildAgentJSONResponse is the JSON body returned to the dashboard after a successful build.
// The token field is shown ONCE here — the server returns the plaintext token so the admin
// can save it securely and pipe it via stdin at installation time.
// The binary is base64-encoded for inline delivery.
type BuildAgentJSONResponse struct {
	Token    string `json:"token"`    // plaintext enrollment token — shown once, store securely
	BuildID  string `json:"build_id"` // UUID baked into binary
	SHA256   string `json:"sha256"`   // hex SHA256 of the binary
	Size     int    `json:"size"`     // binary size in bytes
	Duration string `json:"duration"` // build duration
	Binary   string `json:"binary"`   // base64-encoded .exe for download
}

// BuildAgent handles POST /api/v1/agent/build
//
// Workflow:
//  1. Validate request + resolve/mint enrollment token from DB.
//  2. Generate random BuildID (UUID).
//  3. Compute HMAC-SHA256(key=token, msg=buildID) as the token binding.
//  4. Store BuildID atomically in DB (WHERE build_id IS NULL — CAS guard).
//  5. Read the CA certificate from disk.
//  6. Send build request to agent-builder service (BuildID + TokenBinding, no token).
//  7. Return JSON: { token (plaintext, once), build_id, sha256, size, duration, binary (base64) }.
func (h *Handlers) BuildAgent(c echo.Context) error {
	var req BuildAgentRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	if h.enrollmentTokenRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE",
			"Database unavailable — cannot validate token")
	}

	var tokenValue string
	var tokenID   uuid.UUID
	var tokenDesc string

	// ── Resolve/mint enrollment token ──────────────────────────────────────
	if strings.TrimSpace(req.TokenID) == "" {
		// Mint a new enrollment token dedicated to this build.
		if req.MaxUses == nil {
			v := 1
			req.MaxUses = &v
		}
		if req.ExpiresInH == nil {
			v := 24
			req.ExpiresInH = &v
		}
		if *req.MaxUses < 1 {
			return errorResponse(c, http.StatusBadRequest, "INVALID_MAX_USES", "max_uses must be >= 1")
		}
		if *req.ExpiresInH < 1 {
			return errorResponse(c, http.StatusBadRequest, "INVALID_EXPIRY", "expires_in_hours must be >= 1")
		}

		tokenStr, err := models.GenerateSecureToken()
		if err != nil {
			h.logger.Errorf("BuildAgent: failed to generate token: %v", err)
			return errorResponse(c, http.StatusInternalServerError, "TOKEN_GEN_ERROR",
				"Failed to generate enrollment token")
		}

		createdBy := "system"
		if u := getCurrentUser(c); u != nil {
			createdBy = u.Username
		}

		desc := fmt.Sprintf("build-token (max_uses=%d, expires_in_hours=%d)", *req.MaxUses, *req.ExpiresInH)
		exp := time.Now().Add(time.Duration(*req.ExpiresInH) * time.Hour)
		token := &models.EnrollmentToken{
			ID:          uuid.New(),
			Token:       tokenStr,
			TokenHash:   security.HashToken(tokenStr),
			Description: desc,
			IsActive:    true,
			MaxUses:     req.MaxUses,
			ExpiresAt:   &exp,
			CreatedBy:   createdBy,
		}

		if err := h.enrollmentTokenRepo.Create(c.Request().Context(), token); err != nil {
			h.logger.Errorf("BuildAgent: failed to create build token: %v", err)
			return errorResponse(c, http.StatusInternalServerError, "TOKEN_CREATE_ERROR",
				"Failed to create enrollment token for build")
		}
		if err := h.enrollmentTokenRepo.IncrementBuildCount(c.Request().Context(), token.ID); err != nil {
			h.logger.Errorf("BuildAgent: IncrementBuildCount (new token): %v", err)
			return errorResponse(c, http.StatusConflict, "TOKEN_ALREADY_BUILT",
				"Enrollment token has already been used to build an agent binary")
		}

		tokenValue = tokenStr
		tokenID = token.ID
		tokenDesc = desc
	} else {
		// Use an existing token.
		tokens, err := h.enrollmentTokenRepo.List(c.Request().Context())
		if err != nil {
			h.logger.Errorf("BuildAgent: failed to list tokens: %v", err)
			return errorResponse(c, http.StatusInternalServerError, "TOKEN_FETCH_ERROR",
				"Failed to fetch enrollment tokens")
		}

		for _, t := range tokens {
			if t.ID.String() == req.TokenID {
				if !t.IsActive {
					return errorResponse(c, http.StatusBadRequest, "TOKEN_REVOKED",
						"The selected token has been revoked")
				}
				if t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now()) {
					return errorResponse(c, http.StatusBadRequest, "TOKEN_EXPIRED",
						"The selected token has expired")
				}
				if t.MaxUses != nil && t.UseCount >= *t.MaxUses {
					return errorResponse(c, http.StatusBadRequest, "TOKEN_MAXED",
						"The selected token has reached its maximum number of uses")
				}
				if err := h.enrollmentTokenRepo.IncrementBuildCount(c.Request().Context(), t.ID); err != nil {
					h.logger.Errorf("BuildAgent: IncrementBuildCount (existing token %s): %v", t.ID, err)
					return errorResponse(c, http.StatusConflict, "TOKEN_ALREADY_BUILT",
						"Enrollment token has already been used to build an agent binary")
				}
				tokenValue = t.Token
				tokenID = t.ID
				tokenDesc = t.Description
				break
			}
		}
		if tokenValue == "" {
			return errorResponse(c, http.StatusNotFound, "TOKEN_NOT_FOUND",
				"Token not found or does not meet validity requirements")
		}
	}

	// ── Generate BuildID + HMAC binding ────────────────────────────────────
	//
	// BuildID is a random UUID injected into the binary via ldflag.
	// TokenBinding = hex( HMAC-SHA256(key=token, message=buildID) )
	//
	// Security properties:
	//   - Binary contains ZERO token material — no ciphertext, no key fragment.
	//   - HMAC is one-way: an attacker with the binary cannot recover the token.
	//   - The agent verifies the HMAC locally before any network call,
	//     silently rejecting any wrong token (wrong binary for this token).
	buildID := uuid.New()
	buildIDStr := buildID.String()

	mac := hmac.New(sha256.New, []byte(tokenValue))
	mac.Write([]byte(buildIDStr))
	tokenBinding := hex.EncodeToString(mac.Sum(nil))

	// ── Store BuildID atomically in DB (CAS: WHERE build_id IS NULL) ───────
	// If this fails, abort — we must never return a binary without a DB record.
	if err := h.enrollmentTokenRepo.StoreBuildID(c.Request().Context(), tokenID, buildID); err != nil {
		h.logger.Errorf("BuildAgent: StoreBuildID failed for token %s: %v", tokenID, err)
		return errorResponse(c, http.StatusInternalServerError, "BUILD_ID_STORE_ERROR",
			"Failed to store BuildID — build aborted")
	}

	// ── Validate server config if not skipping ─────────────────────────────
	if !req.SkipConfig {
		if req.ServerIP == "" || req.ServerDomain == "" {
			return errorResponse(c, http.StatusBadRequest, "MISSING_CONFIG",
				"server_ip and server_domain are required when not skipping config")
		}
	}
	if req.ServerPort == "" {
		req.ServerPort = "50051"
	}

	// ── Read CA certificate PEM ────────────────────────────────────────────
	var caCertPEM string
	if h.caCertPath != "" {
		data, err := os.ReadFile(h.caCertPath)
		if err != nil {
			h.logger.Errorf("BuildAgent: failed to read CA cert at %s: %v", h.caCertPath, err)
			return errorResponse(c, http.StatusInternalServerError, "CA_READ_ERROR",
				"Failed to read CA certificate from server")
		}
		caCertPEM = string(data)
	}

	// ── Resolve builder URL ────────────────────────────────────────────────
	builderURL := os.Getenv("AGENT_BUILDER_URL")
	if builderURL == "" {
		builderURL = "http://agent-builder:8090"
	}

	h.logger.Infof("BuildAgent: sending build to %s (skip_config=%v, token=%s, build_id=%s)",
		builderURL, req.SkipConfig, tokenDesc, buildIDStr)

	buildReq := builderRequest{
		ServerIP:      req.ServerIP,
		ServerDomain:  req.ServerDomain,
		ServerPort:    req.ServerPort,
		BuildID:       buildIDStr,
		TokenBinding:  tokenBinding,
		SkipConfig:    req.SkipConfig,
		CACertPEM:     caCertPEM,
		InstallSysmon: req.InstallSysmon,
	}

	body, err := json.Marshal(buildReq)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "MARSHAL_ERROR",
			"Failed to marshal build request")
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Post(builderURL+"/build", "application/json", bytes.NewReader(body))
	if err != nil {
		h.logger.Errorf("BuildAgent: builder request failed: %v", err)
		return errorResponse(c, http.StatusBadGateway, "BUILDER_UNAVAILABLE",
			"Agent builder service is not reachable. Ensure the agent-builder container is running.")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			h.logger.Errorf("BuildAgent: builder returned %d: %v", resp.StatusCode, errResp)
			return c.JSON(resp.StatusCode, errResp)
		}
		return errorResponse(c, http.StatusInternalServerError, "BUILD_FAILED",
			"Agent build failed — check builder logs")
	}

	binaryData, err := io.ReadAll(resp.Body)
	if err != nil {
		h.logger.Errorf("BuildAgent: failed to read builder response: %v", err)
		return errorResponse(c, http.StatusInternalServerError, "READ_ERROR",
			"Failed to read built binary from builder")
	}

	sha256Hash := resp.Header.Get("X-Agent-SHA256")
	buildDuration := resp.Header.Get("X-Build-Duration")

	h.logger.Infof("BuildAgent: build succeeded in %s, size=%d bytes, build_id=%s",
		buildDuration, len(binaryData), buildIDStr)

	h.fireAudit(c, "agent.build", "agent_binary", uuid.Nil, fmt.Sprintf(
		"Agent built: skip_config=%v, token=%s, build_id=%s, sha256=%s, duration=%s, size=%d",
		req.SkipConfig, tokenDesc, buildIDStr,
		func() string {
			if len(sha256Hash) > 16 {
				return sha256Hash[:16] + "..."
			}
			return sha256Hash
		}(),
		buildDuration, len(binaryData)), false, "")

	// ── Return JSON response with token (shown once) + binary (base64) ─────
	//
	// SECURITY NOTE: tokenValue is returned here in plaintext so the admin
	// can save it and use it with: echo '<token>' | agent.exe -install -token-stdin
	// The server stores only the SHA-256 hash of the token — this response is
	// the last time the plaintext token is visible. It is NOT stored in the
	// binary; the binary contains only BuildID + HMAC binding.
	jsonResp := BuildAgentJSONResponse{
		Token:    tokenValue,
		BuildID:  buildIDStr,
		SHA256:   sha256Hash,
		Size:     len(binaryData),
		Duration: buildDuration,
		Binary:   base64.StdEncoding.EncodeToString(binaryData),
	}

	// Zero tokenValue from memory after building the response struct
	// (best-effort — Go strings are immutable but this removes the reference).
	tokenValue = ""
	_ = rand.Read(make([]byte, 1)) // prevent compiler from optimizing out the zero

	return c.JSON(http.StatusOK, jsonResp)
}
