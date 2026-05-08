// Package api provides zero-touch provisioning endpoints.
package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
)

// ServeCA serves the public CA certificate so agents can auto-bootstrap TLS
// trust without manual file distribution. The CA certificate is public data
// (only the public key) — serving it over plain HTTP is standard practice
// (identical to CRL / AIA distribution).
func (h *Handlers) ServeCA(c echo.Context) error {
	if h.caCertPath == "" {
		h.logger.Error("ServeCA: caCertPath not configured")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "CA certificate path not configured on server",
		})
	}

	pemData, err := os.ReadFile(h.caCertPath)
	if err != nil {
		h.logger.Errorf("ServeCA: failed to read CA certificate at %s: %v", h.caCertPath, err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to read CA certificate",
		})
	}

	return c.Blob(http.StatusOK, "application/x-pem-file", pemData)
}

// ============================================================================
// IP-based rate limiter for /api/v1/agent/key-half
// ============================================================================
//
// Simple token-bucket: max 5 requests per minute per IP.
// Standard library only — no external packages.
// Entries older than 5 minutes are evicted on each access to prevent unbounded
// map growth (a single goroutine cleanup would need a ticker; this is simpler
// and sufficient for the low-traffic /key-half endpoint).
//
// Thread safety: all access is serialised through keyHalfRL.mu.

type keyHalfBucket struct {
	tokens    int       // remaining tokens in this window
	windowEnd time.Time // when the current 1-minute window expires
	lastSeen  time.Time // for eviction of stale entries
}

type keyHalfRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*keyHalfBucket
}

var keyHalfRL = &keyHalfRateLimiter{
	buckets: make(map[string]*keyHalfBucket),
}

const (
	keyHalfMaxPerWindow = 5
	keyHalfWindowLen    = time.Minute
	keyHalfEvictAfter   = 5 * time.Minute
)

// allow returns true if the IP is within its rate limit, false if exceeded.
// It also evicts stale entries older than keyHalfEvictAfter.
func (rl *keyHalfRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Evict stale entries (O(n) but n is tiny for this endpoint).
	for k, b := range rl.buckets {
		if now.Sub(b.lastSeen) > keyHalfEvictAfter {
			delete(rl.buckets, k)
		}
	}

	b, ok := rl.buckets[ip]
	if !ok || now.After(b.windowEnd) {
		// New entry or expired window — reset bucket.
		rl.buckets[ip] = &keyHalfBucket{
			tokens:    keyHalfMaxPerWindow - 1, // consume one for this request
			windowEnd: now.Add(keyHalfWindowLen),
			lastSeen:  now,
		}
		return true
	}

	b.lastSeen = now
	if b.tokens <= 0 {
		return false // rate limited
	}
	b.tokens--
	return true
}

// ============================================================================
// ServeKeyHalf — POST /api/v1/agent/key-half
// ============================================================================
//
// This is the split-key distribution endpoint.  It serves key_b (the second
// 16-byte half of the AES-256 decryption key) exactly once, then permanently
// NULLs it in the database.  After this call:
//
//   - DB row: key_b = NULL, key_b_served = TRUE (permanent)
//   - DB dump: no useful key material remains
//   - Binary alone: has key_a but not key_b → cannot decrypt token
//   - This endpoint: returns 410 Gone on any subsequent request
//
// Security properties guaranteed by ServeKeyB CTE (single atomic statement):
//   - No TOCTOU race — SELECT + UPDATE happen in one server-side transaction
//   - Concurrent requests from two machines with the same token: one wins
//     (gets key_b), the other gets ErrKeyBAlreadyServed → 410

type keyHalfRequest struct {
	TokenID            string `json:"token_id"`
	MachineFingerprint string `json:"machine_fingerprint"`
}

type keyHalfResponse struct {
	KeyB string `json:"key_b"`
}

func (h *Handlers) ServeKeyHalf(c echo.Context) error {
	// ── Rate limiting ────────────────────────────────────────────────────────
	requesterIP := realIP(c)
	if !keyHalfRL.allow(requesterIP) {
		h.logger.WithField("ip", requesterIP).Warn("[KEYHALF] rate limit exceeded")
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "rate limit exceeded",
		})
	}

	// ── Parse and validate request ───────────────────────────────────────────
	var req keyHalfRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
	}

	tokenID, err := uuid.Parse(strings.TrimSpace(req.TokenID))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "token_id must be a valid UUID",
		})
	}

	fp := strings.TrimSpace(req.MachineFingerprint)
	if !isValidHex64(fp) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "machine_fingerprint must be a 64-character lowercase hex string",
		})
	}

	// ── Dependency check ────────────────────────────────────────────────────
	if h.enrollmentTokenRepo == nil {
		h.logger.Error("[KEYHALF] enrollmentTokenRepo is nil")
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "service unavailable",
		})
	}

	// ── Atomic key-half serve ───────────────────────────────────────────────
	keyB, err := h.enrollmentTokenRepo.ServeKeyB(c.Request().Context(), tokenID)
	if err != nil {
		if err == repository.ErrKeyBAlreadyServed {
			h.auditKeyHalf(requesterIP, tokenID.String(), fp, "key_b_already_served")
			return c.JSON(http.StatusGone, map[string]string{
				"error": "key already served — token has been consumed",
			})
		}
		h.logger.WithError(err).Error("[KEYHALF] ServeKeyB failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "internal server error",
		})
	}

	// ── Structured forensic audit log ────────────────────────────────────────
	h.auditKeyHalf(requesterIP, tokenID.String(), fp, "key_b_served")

	return c.JSON(http.StatusOK, keyHalfResponse{KeyB: keyB})
}

// auditKeyHalf writes a structured audit log entry for forensic investigation.
// Fields: token_id, machine_fingerprint, requester_ip, timestamp, action.
func (h *Handlers) auditKeyHalf(ip, tokenID, machineFingerprint, action string) {
	entry := map[string]string{
		"event":               "key_half_serve",
		"action":              action,
		"token_id":            tokenID,
		"machine_fingerprint": machineFingerprint,
		"requester_ip":        ip,
		"timestamp":           time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(entry)
	h.logger.WithField("audit", string(data)).Info("[KEYHALF] audit")
}

// isValidHex64 returns true if s is exactly 64 lowercase hex characters.
// SHA-256 output is always 32 bytes = 64 hex characters.
func isValidHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// realIP extracts the real client IP, honouring X-Forwarded-For and X-Real-IP.
// Falls back to the remote address from the request.
func realIP(c echo.Context) string {
	if xff := c.Request().Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may be a comma-separated list; use the first entry.
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	if xri := c.Request().Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(strings.TrimSpace(xri)) != nil {
			return strings.TrimSpace(xri)
		}
	}
	host, _, err := net.SplitHostPort(c.Request().RemoteAddr)
	if err != nil {
		return c.Request().RemoteAddr
	}
	return host
}

// Ensure fmt is used (imported for potential future use in audit formatting).
var _ = fmt.Sprintf
