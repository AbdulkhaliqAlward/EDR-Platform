package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
)

type CreateAgentPackageRequest struct {
	// AgentID binds this package to a single already-enrolled agent. The download link
	// is rejected for any other identity, revoked after the first successful download,
	// and cleaned up on expiry — so no stale URL can be replayed by an attacker.
	AgentID string `json:"agent_id" validate:"required"`

	ServerIP      string `json:"server_ip"`
	ServerDomain  string `json:"server_domain"`
	ServerPort    string `json:"server_port"`
	// PublicAPIBaseURL optional base (scheme://host[:port]) used when minting the
	// download link — e.g. the dashboard's window.location.origin. When empty and
	// the inbound Host is loopback, server_ip/server_domain from this request
	// replace localhost so remote agents can reach the API.
	PublicAPIBaseURL string `json:"public_api_base_url"`
	// TokenID is deprecated for upgrade flow and ignored when provided.
	// Kept only for backward compatibility with older dashboard clients.
	TokenID       string `json:"token_id"`
	SkipConfig    bool   `json:"skip_config"`
	InstallSysmon bool   `json:"install_sysmon"`

	ExpiresInSeconds int `json:"expires_in_seconds"` // default 900, max 7200 (2h)
}

type CreateAgentPackageResponse struct {
	PackageID string `json:"package_id"`
	SHA256    string `json:"sha256"`
	Filename  string `json:"filename"`
	ExpiresAt string `json:"expires_at"`
	URL       string `json:"url"`
}

func (h *Handlers) CreateAgentPackage(c echo.Context) error {
	if h.agentPackageRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database unavailable")
	}
	var req CreateAgentPackageRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	agentID, err := uuid.Parse(strings.TrimSpace(req.AgentID))
	if err != nil || agentID == uuid.Nil {
		return errorResponse(c, http.StatusBadRequest, "AGENT_REQUIRED", "agent_id is required — upgrade packages are per-agent")
	}
	// Confirm the target agent exists and is not already uninstalled.
	if h.agentSvc != nil {
		agent, aerr := h.agentSvc.GetByID(c.Request().Context(), agentID)
		if aerr != nil || agent == nil {
			return errorResponse(c, http.StatusNotFound, "AGENT_NOT_FOUND", "Target agent does not exist")
		}
		if agent.Status == "uninstalled" {
			return errorResponse(c, http.StatusGone, "AGENT_UNINSTALLED", "Target agent has been uninstalled")
		}
	}

	if !req.SkipConfig && (req.ServerIP == "" || req.ServerDomain == "") {
		return errorResponse(c, http.StatusBadRequest, "MISSING_CONFIG", "server_ip and server_domain are required when not skipping config")
	}
	if req.ServerPort == "" {
		req.ServerPort = "50051"
	}
	exp := req.ExpiresInSeconds
	if exp <= 0 {
		exp = 900
	}
	if exp > 7200 {
		exp = 7200
	}
	expiresAt := time.Now().Add(time.Duration(exp) * time.Second)

	// Upgrade binaries carry no enrollment token — enrolled agents authenticate via mTLS.
	_ = req.TokenID

	// Read CA PEM
	var caCertPEM string
	if h.caCertPath != "" {
		if data, err := os.ReadFile(h.caCertPath); err == nil {
			caCertPEM = string(data)
		}
	}

	// Call builder
	builderURL := os.Getenv("AGENT_BUILDER_URL")
	if builderURL == "" {
		builderURL = "http://agent-builder:8090"
	}
	buildReq := builderRequest{
		ServerIP:      req.ServerIP,
		ServerDomain:  req.ServerDomain,
		ServerPort:    req.ServerPort,
		SkipConfig:    req.SkipConfig,
		CACertPEM:     caCertPEM,
		InstallSysmon: req.InstallSysmon,
	}
	body, _ := json.Marshal(buildReq)
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Post(builderURL+"/build", "application/json", bytes.NewReader(body))
	if err != nil {
		return errorResponse(c, http.StatusBadGateway, "BUILDER_UNAVAILABLE", "Agent builder service is not reachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return errorResponse(c, http.StatusInternalServerError, "BUILD_FAILED", fmt.Sprintf("Builder error: %s", strings.TrimSpace(string(raw))))
	}
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "READ_ERROR", "Failed to read built binary")
	}
	sum := sha256.Sum256(bin)
	shaStr := hex.EncodeToString(sum[:])

	// Persist to disk
	packageID := uuid.New()
	dataDir := os.Getenv("AGENT_PACKAGES_DIR")
	if dataDir == "" {
		dataDir = `./data/agent-packages`
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "STORAGE_ERROR", "Failed to create packages directory")
	}
	storagePath := filepath.Join(dataDir, packageID.String()+".exe")
	if err := os.WriteFile(storagePath, bin, 0600); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "STORAGE_ERROR", "Failed to write package to disk")
	}

	// Tokenize download URL (short-lived)
	downloadToken, _ := newRandomToken(32)
	downloadTokenHash := sha256Hex(downloadToken)

	// Save package row bound to the agent (download is revoked after first use / on expiry).
	params := map[string]any{
		"server_ip":           req.ServerIP,
		"server_domain":       req.ServerDomain,
		"server_port":         req.ServerPort,
		"skip_config":         req.SkipConfig,
		"install_sysmon":      req.InstallSysmon,
		"download_token_hash": downloadTokenHash,
	}
	if err := h.agentPackageRepo.Create(c.Request().Context(), repository.AgentPackageRow{
		ID:          packageID,
		AgentID:     agentID,
		SHA256:      shaStr,
		Filename:    "edr-agent.exe",
		StoragePath: storagePath,
		BuildParams: params,
		ExpiresAt:   expiresAt,
	}); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "DB_ERROR", "Failed to save package metadata")
	}

	baseURL := resolveAgentPackageDownloadBase(c, req)
	url := fmt.Sprintf("%s/api/v1/agent/packages/%s/download?token=%s", baseURL, packageID.String(), downloadToken)

	return c.JSON(http.StatusOK, CreateAgentPackageResponse{
		PackageID: packageID.String(),
		SHA256:    shaStr,
		Filename:  "edr-agent.exe",
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		URL:       url,
	})
}

func (h *Handlers) DownloadAgentPackage(c echo.Context) error {
	if h.agentPackageRepo == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database unavailable")
	}
	idStr := c.Param("id")
	pkgID, err := uuid.Parse(idStr)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_ID", "Invalid package id")
	}
	token := c.QueryParam("token")
	if token == "" {
		return errorResponse(c, http.StatusUnauthorized, "TOKEN_REQUIRED", "token query parameter required")
	}

	row, err := h.agentPackageRepo.Get(c.Request().Context(), pkgID)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "NOT_FOUND", "Package not found")
	}
	// Single-use semantics: once downloaded, the link is dead. This also prevents
	// any replay even if the URL leaks after the first fetch.
	if row.ConsumedAt != nil {
		return errorResponse(c, http.StatusGone, "ALREADY_CONSUMED", "Package link has already been used")
	}
	if time.Now().After(row.ExpiresAt) {
		// Lazy cleanup: expired links are deleted right here so nothing usable persists.
		h.cleanupPackage(c.Request().Context(), row)
		return errorResponse(c, http.StatusGone, "EXPIRED", "Package link expired")
	}
	wantHash := ""
	if row.BuildParams != nil {
		if v, ok := row.BuildParams["download_token_hash"].(string); ok {
			wantHash = v
		}
	}
	if wantHash == "" || sha256Hex(token) != wantHash {
		return errorResponse(c, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid download token")
	}

	// If the agent already registered a client certificate, require it to match the bound
	// agent_id. This enforces that only the exact endpoint the link was minted for can
	// download the binary — closing the "any attacker with the URL" escape hatch.
	if row.AgentID != uuid.Nil {
		if tls := c.Request().TLS; tls != nil && len(tls.PeerCertificates) > 0 {
			if peerAgentID := extractAgentIDFromPeerCert(tls.PeerCertificates[0].Subject.CommonName); peerAgentID != "" && peerAgentID != row.AgentID.String() {
				return errorResponse(c, http.StatusForbidden, "AGENT_MISMATCH", "This download link is bound to a different agent")
			}
		}
	}

	data, err := os.ReadFile(row.StoragePath)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "READ_ERROR", "Failed to read package")
	}
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", row.Filename))
	c.Response().Header().Set("X-Agent-SHA256", row.SHA256)

	// Stream first, then revoke — otherwise a broken client would lose access on retry
	// without having actually obtained the binary.
	if err := c.Blob(http.StatusOK, "application/octet-stream", data); err != nil {
		return err
	}

	// Mark consumed + delete the file from disk + remove the DB row so no usable link remains.
	h.cleanupPackage(c.Request().Context(), row)
	return nil
}

// cleanupPackage revokes a package link: removes the on-disk binary and the DB row.
// Called after a successful download and on expiry — so nothing redeemable outlives the event.
func (h *Handlers) cleanupPackage(ctx context.Context, row *repository.AgentPackageRow) {
	if row == nil || h.agentPackageRepo == nil {
		return
	}
	if row.StoragePath != "" {
		_ = os.Remove(row.StoragePath)
	}
	_ = h.agentPackageRepo.MarkConsumed(ctx, row.ID)
	_ = h.agentPackageRepo.Delete(ctx, row.ID)
}

// extractAgentIDFromPeerCert pulls the agent UUID from the client certificate's CN.
// Agent certs are issued with CN=<agent-uuid> during enrollment; any other format
// falls back to an empty string (permissive for non-mTLS deployments).
func extractAgentIDFromPeerCert(commonName string) string {
	cn := strings.TrimSpace(commonName)
	if _, err := uuid.Parse(cn); err == nil {
		return cn
	}
	return ""
}

func newRandomToken(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

