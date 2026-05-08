// Package api provides enrollment token management REST handlers.
package api

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/connection-manager/pkg/security"
)

// --------------------------------------------------------------------------
// Request / Response types
// --------------------------------------------------------------------------

// CreateEnrollmentTokenRequest is the JSON body for token generation.
type CreateEnrollmentTokenRequest struct {
	Description string `json:"description"`
	ExpiresInH  *int   `json:"expires_in_hours"` // nil = default 24 hours
	MaxUses     *int   `json:"max_uses"`         // nil = default 1
}

// EnrollmentTokenResponse is the JSON representation returned to the dashboard.
type EnrollmentTokenResponse struct {
	ID          string     `json:"id"`
	Token       string     `json:"token"`
	Description string     `json:"description"`
	IsActive    bool       `json:"is_active"`
	ExpiresAt   *time.Time `json:"expires_at"`
	UseCount    int        `json:"use_count"`
	MaxUses     *int       `json:"max_uses"`
	// BuildCount is 0 (not yet built into a binary) or 1 (binary already produced).
	BuildCount  int        `json:"build_count"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

func enrollmentTokenToResponse(t *models.EnrollmentToken) EnrollmentTokenResponse {
	return EnrollmentTokenResponse{
		ID:          t.ID.String(),
		Token:       t.Token,
		Description: t.Description,
		IsActive:    t.IsActive,
		ExpiresAt:   t.ExpiresAt,
		UseCount:    t.UseCount,
		MaxUses:     t.MaxUses,
		BuildCount:  t.BuildCount,
		CreatedBy:   t.CreatedBy,
		CreatedAt:   t.CreatedAt,
		RevokedAt:   t.RevokedAt,
	}
}

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

// ListEnrollmentTokens returns all enrollment tokens.
func (h *Handlers) ListEnrollmentTokens(c echo.Context) error {
	if h.enrollmentTokenRepo == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
	}

	tokens, err := h.enrollmentTokenRepo.List(c.Request().Context())
	if err != nil {
		h.logger.Errorf("ListEnrollmentTokens: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list tokens"})
	}

	// Never return nil list to frontend
	resp := make([]EnrollmentTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		resp = append(resp, enrollmentTokenToResponse(t))
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": resp,
	})
}

// GenerateEnrollmentToken creates a new enrollment token.
func (h *Handlers) GenerateEnrollmentToken(c echo.Context) error {
	if h.enrollmentTokenRepo == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
	}

	var req CreateEnrollmentTokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Defaults: 1 use + 24 hours unless specified.
	if req.MaxUses == nil {
		v := 1
		req.MaxUses = &v
	}
	if req.ExpiresInH == nil {
		v := 24
		req.ExpiresInH = &v
	}
	if req.MaxUses != nil && *req.MaxUses < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "max_uses must be >= 1"})
	}
	if req.ExpiresInH != nil && *req.ExpiresInH < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "expires_in_hours must be >= 1"})
	}

	tokenStr, err := models.GenerateSecureToken()
	if err != nil {
		h.logger.Errorf("GenerateEnrollmentToken: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
	}

	// Gap 2: extract operator identity from JWT claims instead of hardcoding.
	createdBy := "system"
	if u := getCurrentUser(c); u != nil {
		createdBy = u.Username
	}

	token := &models.EnrollmentToken{
		ID:          uuid.New(),
		Token:       tokenStr,
		// Gap 1: store SHA-256 hash for DB lookups; raw value stays in Token
		// for the API response (enrollmentTokenToResponse reads token.Token).
		TokenHash:   security.HashToken(tokenStr),
		Description: req.Description,
		IsActive:    true,
		MaxUses:     req.MaxUses,
		CreatedBy:   createdBy,
	}

	if req.ExpiresInH != nil && *req.ExpiresInH > 0 {
		exp := time.Now().Add(time.Duration(*req.ExpiresInH) * time.Hour)
		token.ExpiresAt = &exp
	}

	if err := h.enrollmentTokenRepo.Create(c.Request().Context(), token); err != nil {
		h.logger.Errorf("GenerateEnrollmentToken: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create token"})
	}

	// token.Token still holds the raw value — enrollmentTokenToResponse returns
	// it as-is so the dashboard can display and copy the token once on creation.
	return c.JSON(http.StatusCreated, enrollmentTokenToResponse(token))
}

// RevokeEnrollmentToken deactivates an enrollment token.
func (h *Handlers) RevokeEnrollmentToken(c echo.Context) error {
	if h.enrollmentTokenRepo == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid token ID"})
	}

	if err := h.enrollmentTokenRepo.Revoke(c.Request().Context(), id); err != nil {
		if err == repository.ErrNotFound {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
		}
		h.logger.Errorf("RevokeEnrollmentToken: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to revoke token"})
	}

	// Audit: token revoked
	h.fireAudit(c, models.AuditActionTokenRevoked, "token", id, "", false, "")

	return c.JSON(http.StatusOK, map[string]string{"status": "revoked"})
}

// DeleteEnrollmentToken permanently deletes an enrollment token.
func (h *Handlers) DeleteEnrollmentToken(c echo.Context) error {
	if h.enrollmentTokenRepo == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid token ID"})
	}

	if err := h.enrollmentTokenRepo.Delete(c.Request().Context(), id); err != nil {
		if err == repository.ErrNotFound {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
		}
		h.logger.Errorf("DeleteEnrollmentToken: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete token"})
	}

	// Audit: token deleted
	h.fireAudit(c, "TOKEN_DELETED", "token", id, "", false, "")

	return c.JSON(http.StatusOK, map[string]string{"status": "deleted"})
}
