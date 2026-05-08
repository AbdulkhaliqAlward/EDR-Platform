// Package api provides the agent binary build endpoint.
package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	ServerIP     string `json:"server_ip"`
	ServerDomain string `json:"server_domain"`
	ServerPort   string `json:"server_port"`
	// TokenID references an existing enrollment token. If omitted, MaxUses must be provided
	// and BuildAgent will mint a new enrollment token for this build.
	TokenID      string `json:"token_id"`
	MaxUses      *int   `json:"max_uses"` // nil = require token_id; non-nil must be >= 1
	ExpiresInH   *int   `json:"expires_in_hours"` // nil = default 24 hours
	SkipConfig   bool   `json:"skip_config"` // if true, only token + CA are embedded
	InstallSysmon bool  `json:"install_sysmon"` // if true, agent will install + enable Sysmon on first run

	// internal: populated by splitKeyForBuild, never from JSON
	tokenEnc  string
	tokenKeyA string
}

// builderRequest is the JSON body sent to the agent-builder service.
// For split-key builds (TokenEnc + TokenKeyA + TokenID set), the agent-builder
// injects the pre-computed ciphertext and key_a directly — no token in plaintext.
// Token field kept for backward compatibility with old agent-builder images.
type builderRequest struct {
	ServerIP      string `json:"server_ip"`
	ServerDomain  string `json:"server_domain"`
	ServerPort    string `json:"server_port"`
	Token         string `json:"token"`          // deprecated: only for legacy builder
	TokenEnc      string `json:"token_enc"`      // hex(nonce||ciphertext||tag) — split-key
	TokenKeyA     string `json:"token_key_a"`    // hex(16-byte key_a) — baked into binary
	TokenID       string `json:"token_id"`       // UUID — baked into binary for /key-half fetch
	SkipConfig    bool   `json:"skip_config"`
	CACertPEM     string `json:"ca_cert_pem"`
	InstallSysmon bool   `json:"install_sysmon"`
}

// BuildAgent handles POST /api/v1/agent/build
//
// Workflow:
//  1. Validate request + fetch token from DB.
//  2. Read the CA certificate from disk.
//  3. Send build request to the dedicated agent-builder service.
//  4. Stream the resulting binary back to the dashboard as a download.
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
	var tokenDesc string

	// ── Resolve/mint enrollment token ──────────────────────────────────────
	// Backwards compatible: if token_id provided, use it. If omitted, require max_uses
	// and create a token dedicated to this build.
	if strings.TrimSpace(req.TokenID) == "" {
		// Defaults: single device + 24 hours validity.
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

		// Gap 2: extract operator identity from JWT claims.
		createdBy := "system"
		if u := getCurrentUser(c); u != nil {
			createdBy = u.Username
		}

		desc := fmt.Sprintf("build-token (max_uses=%d, expires_in_hours=%d)", *req.MaxUses, *req.ExpiresInH)
		exp := time.Now().Add(time.Duration(*req.ExpiresInH) * time.Hour)
		token := &models.EnrollmentToken{
			ID:          uuid.New(),
			Token:       tokenStr,
			// Gap 1: store SHA-256 hash for DB lookups; agent binary receives raw tokenStr.
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

		// Atomically consume this token for a binary build (build_count 0→1).
		// A newly-created token always has build_count=0, so this is a
		// formality here — but it keeps the code path identical to the
		// existing-token path and future-proofs against concurrent requests.
		if err := h.enrollmentTokenRepo.IncrementBuildCount(c.Request().Context(), token.ID); err != nil {
			h.logger.Errorf("BuildAgent: IncrementBuildCount (new token): %v", err)
			return errorResponse(c, http.StatusConflict, "TOKEN_ALREADY_BUILT",
				"Enrollment token has already been used to build an agent binary")
		}

		// SPLIT-KEY: generate key_a (binary) + key_b (DB) from a 32-byte master key.
		// fullKey is zeroed immediately after use — it never leaves this scope.
		if err := splitKeyForBuild(c, h, token.ID, req.TokenID, token.Token, &req); err != nil {
			return err // response already written by splitKeyForBuild
		}

		req.TokenID = token.ID.String()
		tokenValue = token.Token
		tokenDesc = token.Description
	} else {
		// Fetch all tokens and find the requested one that is valid
		tokens, err := h.enrollmentTokenRepo.List(c.Request().Context())
		if err != nil {
			h.logger.Errorf("BuildAgent: failed to list tokens: %v", err)
			return errorResponse(c, http.StatusInternalServerError, "TOKEN_FETCH_ERROR",
				"Failed to fetch enrollment tokens")
		}

		for _, t := range tokens {
			if t.ID.String() == req.TokenID {
				// Validate the token is usable
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
				// Atomically consume this token for a binary build.
				// WHERE build_count = 0 prevents a token being used for two builds.
				if err := h.enrollmentTokenRepo.IncrementBuildCount(c.Request().Context(), t.ID); err != nil {
					h.logger.Errorf("BuildAgent: IncrementBuildCount (existing token %s): %v", t.ID, err)
					return errorResponse(c, http.StatusConflict, "TOKEN_ALREADY_BUILT",
						"Enrollment token has already been used to build an agent binary")
				}
				// SPLIT-KEY: generate key_a (binary) + key_b (DB).
				if err := splitKeyForBuild(c, h, t.ID, req.TokenID, t.Token, &req); err != nil {
					return err // response already written
				}
				tokenValue = t.Token
				tokenDesc = t.Description
				break
			}
		}
		if tokenValue == "" {
			return errorResponse(c, http.StatusNotFound, "TOKEN_NOT_FOUND",
				"Token not found or does not meet validity requirements")
		}
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

	// ── Send build request to agent-builder service ────────────────────────
	h.logger.Infof("BuildAgent: sending build to %s (skip_config=%v, token=%s)",
		builderURL, req.SkipConfig, tokenDesc)

	buildReq := builderRequest{
		ServerIP:      req.ServerIP,
		ServerDomain:  req.ServerDomain,
		ServerPort:    req.ServerPort,
		SkipConfig:    req.SkipConfig,
		CACertPEM:     caCertPEM,
		InstallSysmon: req.InstallSysmon,
		// Split-key fields (set by splitKeyForBuild above).
		// Token field intentionally left empty: the agent uses the split-key path.
		TokenEnc:  req.tokenEnc,
		TokenKeyA: req.tokenKeyA,
		TokenID:   req.TokenID,
	}

	body, err := json.Marshal(buildReq)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "MARSHAL_ERROR",
			"Failed to marshal build request")
	}

	client := &http.Client{Timeout: 10 * time.Minute} // generous timeout for cross-compilation (first build can take 3-5 min)
	resp, err := client.Post(builderURL+"/build", "application/json", bytes.NewReader(body))
	if err != nil {
		h.logger.Errorf("BuildAgent: builder request failed: %v", err)
		return errorResponse(c, http.StatusBadGateway, "BUILDER_UNAVAILABLE",
			"Agent builder service is not reachable. Ensure the agent-builder container is running.")
	}
	defer resp.Body.Close()

	// ── Handle builder error ───────────────────────────────────────────────
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			h.logger.Errorf("BuildAgent: builder returned %d: %v", resp.StatusCode, errResp)
			return c.JSON(resp.StatusCode, errResp)
		}
		return errorResponse(c, http.StatusInternalServerError, "BUILD_FAILED",
			"Agent build failed — check builder logs")
	}

	// ── Read full binary from builder ─────────────────────────────────────
	binaryData, err := io.ReadAll(resp.Body)
	if err != nil {
		h.logger.Errorf("BuildAgent: failed to read builder response: %v", err)
		return errorResponse(c, http.StatusInternalServerError, "READ_ERROR",
			"Failed to read built binary from builder")
	}

	sha256Hash := resp.Header.Get("X-Agent-SHA256")
	buildDuration := resp.Header.Get("X-Build-Duration")

	h.logger.Infof("BuildAgent: build succeeded in %s, size=%d bytes (sha256=%s)",
		buildDuration, len(binaryData), sha256Hash[:16]+"...")

	// Audit log
	h.fireAudit(c, "agent.build", "agent_binary", uuid.Nil, fmt.Sprintf(
		"Agent built: skip_config=%v, token=%s, sha256=%s, duration=%s, size=%d",
		req.SkipConfig, tokenDesc, sha256Hash[:16]+"...", buildDuration, len(binaryData)), false, "")

	// Set download headers
	c.Response().Header().Set("Content-Disposition", `attachment; filename="edr-agent.exe"`)
	c.Response().Header().Set("X-Agent-SHA256", sha256Hash)
	c.Response().Header().Set("X-Agent-Token-Id", req.TokenID)
	c.Response().Header().Set("X-Agent-Token-Description", tokenDesc)
	c.Response().Header().Set("X-Build-Duration", buildDuration)
	if !req.SkipConfig {
		c.Response().Header().Set("X-Agent-Server",
			fmt.Sprintf("%s:%s", req.ServerDomain, req.ServerPort))
	}
	c.Response().Header().Set("X-Agent-CA-Embedded", fmt.Sprintf("%v", caCertPEM != ""))

	return c.Blob(http.StatusOK, "application/octet-stream", binaryData)
}

// splitKeyForBuild generates the AES-256 split-key for a new agent binary build.
//
// Security contract:
//  1. Generates 32 cryptographically random bytes as fullKey.
//  2. Splits: keyA = fullKey[:16] (baked into binary), keyB = fullKey[16:] (stored in DB).
//  3. Encrypts token with fullKey using AES-256-GCM.
//  4. Stores keyB in the DB via StoreKeyB BEFORE returning.
//     If StoreKeyB fails, the function returns an error and the build is aborted.
//     A binary where keyB was not stored would be permanently undeployable.
//  5. Zeros fullKey and keyB slices from memory before returning.
//  6. Populates req.tokenEnc and req.tokenKeyA for injection into builderRequest.
func splitKeyForBuild(
	c echo.Context,
	h *Handlers,
	tokenUUID uuid.UUID,
	_ string, // tokenIDStr (unused — tokenUUID is authoritative)
	tokenPlaintext string,
	req *BuildAgentRequest,
) error {
	// Step 1: Generate 32 cryptographically random bytes.
	fullKey := make([]byte, 32)
	if _, err := rand.Read(fullKey); err != nil {
		h.logger.Errorf("[SPLITKEY] rand.Read failed: %v", err)
		return errorResponse(c, http.StatusInternalServerError, "KEY_GEN_ERROR",
			"Failed to generate split key material")
	}
	// Step 5: Zero fullKey from memory before returning — runs after step 4.
	defer func() {
		for i := range fullKey {
			fullKey[i] = 0
		}
	}()

	// Step 2: Split.
	keyA := make([]byte, 16)
	keyB := make([]byte, 16)
	copy(keyA, fullKey[:16])
	copy(keyB, fullKey[16:])
	defer func() {
		for i := range keyB {
			keyB[i] = 0
		}
	}()

	// Step 3: Encrypt token with fullKey using AES-256-GCM.
	block, err := aes.NewCipher(fullKey)
	if err != nil {
		h.logger.Errorf("[SPLITKEY] AES NewCipher: %v", err)
		return errorResponse(c, http.StatusInternalServerError, "CIPHER_ERROR",
			"Failed to initialize AES cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		h.logger.Errorf("[SPLITKEY] GCM init: %v", err)
		return errorResponse(c, http.StatusInternalServerError, "GCM_ERROR",
			"Failed to initialize GCM")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		h.logger.Errorf("[SPLITKEY] nonce rand.Read: %v", err)
		return errorResponse(c, http.StatusInternalServerError, "NONCE_ERROR",
			"Failed to generate nonce")
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(tokenPlaintext), nil)
	tokenEnc := hex.EncodeToString(ciphertext)
	keyAHex := hex.EncodeToString(keyA)
	keyBHex := hex.EncodeToString(keyB)

	// Step 4: Store keyB in DB BEFORE build proceeds.
	// If this fails, abort immediately — do not return a binary with no server key.
	if err := h.enrollmentTokenRepo.StoreKeyB(c.Request().Context(), tokenUUID, keyBHex); err != nil {
		h.logger.Errorf("[SPLITKEY] StoreKeyB failed for token %s: %v", tokenUUID, err)
		return errorResponse(c, http.StatusInternalServerError, "KEY_STORE_ERROR",
			"Failed to store key material — build aborted")
	}

	req.tokenEnc = tokenEnc
	req.tokenKeyA = keyAHex
	req.TokenID = tokenUUID.String()
	return nil
}
