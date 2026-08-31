// Package api provides auth handler implementations.
package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/connection-manager/pkg/security"
)

// Login handles user login — authenticates against the database and issues
// a JWT access token + opaque refresh token with server-side session tracking.
func (h *Handlers) Login(c echo.Context) error {
	if h.authSvc == nil {
		if h.jwtManager == nil {
			return errorResponse(c, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE", "Authentication service is not configured")
		}
		return errorResponse(c, http.StatusServiceUnavailable, "DB_UNAVAILABLE", "Database is unavailable — cannot authenticate")
	}

	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	ip, ua := auditContext(c)

	// Authenticate via AuthService (bcrypt password check, DB user lookup)
	loginResp, err := h.authSvc.Login(c.Request().Context(), req.Username, req.Password)
	if err != nil {
		h.logger.WithField("username", req.Username).WithError(err).Warn("Login failed")

		// Audit: login failure
		if h.auditRepo != nil {
			audit := models.NewAuditLog(uuid.Nil, req.Username, models.AuditActionLoginFailed, "user", uuid.Nil).
				WithContext(ip, ua).
				MarkFailed(err.Error())
			go h.auditRepo.Create(c.Request().Context(), audit) //nolint:errcheck
		}
		h.auditLogger.LoginFailed(req.Username, ip, ua, err.Error())

		return errorResponse(c, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid username or password")
	}

	// ── MFA challenge branch ─────────────────────────────────────────────
	// AuthService returned a challenge rather than tokens. We intentionally
	// do NOT emit a login-success audit event here — the user is not yet
	// authenticated; the success event fires after VerifyMFA.
	if loginResp.MFAChallenge != nil {
		return c.JSON(http.StatusOK, LoginResponse{
			MFARequired: true,
			MFAChallenge: &MFAChallengeSummary{
				ID:          loginResp.MFAChallenge.ID,
				MaskedEmail: loginResp.MFAChallenge.MaskedEmail,
				ExpiresAt:   loginResp.MFAChallenge.ExpiresAt,
			},
			User: UserResponse{
				ID:         loginResp.User.ID,
				Username:   loginResp.User.Username,
				FullName:   loginResp.User.FullName,
				MFAEnabled: true,
			},
		})
	}

	// ── Session-based token issuance ─────────────────────────────────────
	return h.issueSessionTokens(c, loginResp, ip, ua)
}

// VerifyMFA completes a login started by Login() when the user has MFA
// enabled. Accepts {challenge_id, code}; on success returns the same shape
// as a successful Login (tokens + user).
func (h *Handlers) VerifyMFA(c echo.Context) error {
	if h.authSvc == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE", "Authentication service is not configured")
	}

	var req MFAVerifyRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}
	if req.ChallengeID == "" || req.Code == "" {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "challenge_id and code are required")
	}

	ip, ua := auditContext(c)

	loginResp, err := h.authSvc.VerifyMFA(c.Request().Context(), req.ChallengeID, req.Code)
	if err != nil {
		h.logger.WithError(err).Warn("MFA verification failed")
		switch {
		case errors.Is(err, service.ErrMFAChallengeNotFound):
			return errorResponse(c, http.StatusUnauthorized, "MFA_EXPIRED", "Verification code expired — please log in again")
		case errors.Is(err, service.ErrMFAAttemptsExceeded):
			return errorResponse(c, http.StatusUnauthorized, "MFA_LOCKED", "Too many incorrect attempts — please log in again")
		case errors.Is(err, service.ErrMFACodeInvalid):
			return errorResponse(c, http.StatusUnauthorized, "MFA_INVALID", "Invalid verification code")
		case errors.Is(err, service.ErrMFAUnavailable):
			return errorResponse(c, http.StatusServiceUnavailable, "MFA_UNAVAILABLE", "MFA service unavailable")
		}
		return errorResponse(c, http.StatusUnauthorized, "MFA_FAILED", "MFA verification failed")
	}

	return h.issueSessionTokens(c, loginResp, ip, ua)
}

// issueSessionTokens is the common path for Login and VerifyMFA after
// successful credential verification. It creates the session record,
// enforces single active session, and returns the token response.
func (h *Handlers) issueSessionTokens(c echo.Context, loginResp *service.LoginResponse, ip, ua string) error {
	ctx := c.Request().Context()

	// ── Increment session_version BEFORE generating the access token ──────
	// This invalidates all previously issued tokens for this user immediately.
	// The new token will carry the incremented version as the sv claim.
	var sessionVersion int
	if h.userRepo != nil {
		newVersion, incrErr := h.userRepo.IncrementSessionVersion(ctx, loginResp.User.ID)
		if incrErr != nil {
			// Non-fatal: log and fall back to version 0 (disables sv enforcement for this token)
			h.logger.WithError(incrErr).Warn("Failed to increment session_version — sv enforcement skipped for this token")
		} else {
			sessionVersion = newVersion
		}
	}

	// Generate access token (JWT) with current session version embedded as sv claim
	accessToken, accessJTI, accessExp, err := h.jwtManager.GenerateAccessTokenOnly(
		loginResp.User.ID.String(), loginResp.User.Username, []string{loginResp.User.Role}, sessionVersion,
	)
	if err != nil {
		h.logger.WithError(err).Error("Failed to generate access token")
		return errorResponse(c, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to generate tokens")
	}

	// Generate opaque refresh token
	rawRefresh, refreshHash, err := security.GenerateOpaqueToken()
	if err != nil {
		h.logger.WithError(err).Error("Failed to generate refresh token")
		return errorResponse(c, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to generate tokens")
	}

	// ── Single Active Session enforcement ────────────────────────────────
	// Revoke any existing active sessions for this user before creating a new one.
	// Also blacklist their access JTIs in Redis so the old browser gets an
	// immediate 401 instead of silently working until the JWT expires.
	if h.sessionRepo != nil {
		oldSessions, listErr := h.sessionRepo.GetActiveForUser(ctx, loginResp.User.ID)
		if listErr != nil {
			h.logger.WithError(listErr).Warn("Failed to list previous sessions")
		}
		if len(oldSessions) > 0 {
			h.auditLogger.SessionSuperseded(loginResp.User.ID, loginResp.User.Username, ip, ua)
		}
		for _, old := range oldSessions {
			if h.redis != nil && old.AccessJTI != "" {
				if blErr := h.redis.BlacklistToken(ctx, old.AccessJTI, time.Now().Add(1*time.Hour), "superseded"); blErr != nil {
					h.logger.WithError(blErr).Warn("Failed to blacklist superseded access JTI")
				}
			}
		}
		if err := h.sessionRepo.RevokeAllForUser(ctx, loginResp.User.ID, "superseded"); err != nil {
			h.logger.WithError(err).Warn("Failed to revoke previous sessions")
			// Non-fatal: continue with login
		}

		// Create new session record
		now := time.Now()
		session := &models.Session{
			ID:               uuid.New(),
			UserID:           loginResp.User.ID,
			RefreshTokenHash: refreshHash,
			AccessJTI:        accessJTI,
			IPAddress:        ip,
			UserAgent:        ua,
			CreatedAt:        now,
			LastActiveAt:     now,
			ExpiresAt:        now.Add(h.jwtManager.RefreshTTL()),
		}
		if err := h.sessionRepo.Create(ctx, session); err != nil {
			h.logger.WithError(err).Error("Failed to create session")
			return errorResponse(c, http.StatusInternalServerError, "SESSION_ERROR", "Failed to create session")
		}
	}

	// Audit: login success
	if h.auditRepo != nil {
		audit := models.NewAuditLog(loginResp.User.ID, loginResp.User.Username, models.AuditActionLoginSuccess, "user", loginResp.User.ID).
			WithContext(ip, ua)
		go h.auditRepo.Create(ctx, audit) //nolint:errcheck
	}
	h.auditLogger.LoginSuccess(loginResp.User.ID, loginResp.User.Username, ip, ua)

	return c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int64(time.Until(accessExp).Seconds()),
		TokenType:    "Bearer",
		User: UserResponse{
			ID:         loginResp.User.ID,
			Username:   loginResp.User.Username,
			Email:      loginResp.User.Email,
			FullName:   loginResp.User.FullName,
			Role:       loginResp.User.Role,
			Status:     loginResp.User.Status,
			MFAEnabled: loginResp.User.MFAEnabled,
		},
	})
}

// RefreshToken handles token refresh with rotation and reuse detection.
//
// Flow:
//  1. Hash the incoming opaque refresh token
//  2. Look up session by hash in the DB
//  3. If NOT found or revoked → reuse detection: revoke ALL user sessions
//  4. If found and active → rotate: new access token + new refresh token,
//     update session, blacklist old access JTI
func (h *Handlers) RefreshToken(c echo.Context) error {
	if h.jwtManager == nil {
		return errorResponse(c, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE", "JWT authentication is not configured")
	}

	var req RefreshTokenRequest
	if err := c.Bind(&req); err != nil {
		return errorResponse(c, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
	}

	// ── Session-based rotation (primary path) ────────────────────────────
	if h.sessionRepo != nil {
		return h.refreshWithSession(c, req.RefreshToken)
	}

	// ── Legacy fallback (no session repo — should not happen in prod) ────
	accessToken, expiresAt, err := h.jwtManager.RefreshAccessToken(req.RefreshToken)
	if err != nil {
		return errorResponse(c, http.StatusUnauthorized, "INVALID_REFRESH_TOKEN", "Invalid or expired refresh token")
	}
	return c.JSON(http.StatusOK, RefreshTokenResponse{
		AccessToken: accessToken,
		ExpiresIn:   int64(time.Until(expiresAt).Seconds()),
	})
}

// refreshWithSession performs the session-based refresh token rotation.
func (h *Handlers) refreshWithSession(c echo.Context, rawRefreshToken string) error {
	ctx := c.Request().Context()
	tokenHash := security.HashToken(rawRefreshToken)

	session, err := h.sessionRepo.FindByRefreshTokenHash(ctx, tokenHash)
	if err != nil {
		h.logger.WithError(err).Error("Session lookup failed")
		return errorResponse(c, http.StatusInternalServerError, "SESSION_ERROR", "Session lookup failed")
	}

	// ── Reuse Detection ──────────────────────────────────────────────────
	// Token not found OR session already revoked → possible theft.
	// Revoke ALL sessions for the user as a security measure.
	if session == nil || !session.IsActive() {
		h.logger.Warn("Refresh token reuse detected — revoking all sessions for user")
		if session != nil {
			// We know the user — revoke everything.
			if revokeErr := h.sessionRepo.RevokeAllForUser(ctx, session.UserID, "security"); revokeErr != nil {
				h.logger.WithError(revokeErr).Error("Failed to revoke sessions on reuse detection")
			}
			ip, ua := auditContext(c)
			h.auditLogger.TokenReuseDetected(&session.UserID, session.UserID.String(), ip, ua)
		} else {
			ip, ua := auditContext(c)
			h.auditLogger.TokenReuseDetected(nil, "unknown", ip, ua)
		}
		return errorResponse(c, http.StatusUnauthorized, "INVALID_REFRESH_TOKEN", "Invalid or expired refresh token")
	}

	// ── Generate new tokens ──────────────────────────────────────────────
	// Look up the user to get current username and role.
	userID := session.UserID.String()
	username := ""
	var roles []string

	// Extract username/roles from the old access token (best-effort).
	if session.AccessJTI != "" && h.jwtManager != nil {
		// We can't look up by JTI alone; use session.UserID instead.
		// The username is embedded in the JWT claims of the access token.
		// Since we don't store it in the session, we'll query the user repo.
	}

	// Query user from DB for fresh role/username.
	if h.userRepo != nil {
		user, userErr := h.userRepo.GetByID(ctx, session.UserID)
		if userErr != nil || user == nil {
			h.logger.WithError(userErr).Error("Failed to lookup user for session refresh")
			return errorResponse(c, http.StatusUnauthorized, "INVALID_REFRESH_TOKEN", "Session user not found")
		}
		username = user.Username
		roles = []string{user.Role}
	}

	newRawRefresh, newRefreshHash, rotateErr := security.GenerateOpaqueToken()
	if rotateErr != nil {
		h.logger.WithError(rotateErr).Error("Failed to generate new refresh token")
		return errorResponse(c, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to rotate tokens")
	}

	// Embed the current session_version in the new access token (same version as last login —
	// no increment on refresh, only on login/logout).
	var newSV int
	if h.userRepo != nil {
		if sv, svErr := h.userRepo.GetSessionVersion(ctx, session.UserID); svErr == nil {
			newSV = sv
		}
	}

	newAccessToken, newAccessJTI, newAccessExp, err := h.jwtManager.GenerateAccessTokenOnly(
		userID, username, roles, newSV,
	)
	if err != nil {
		h.logger.WithError(err).Error("Failed to generate new access token")
		return errorResponse(c, http.StatusInternalServerError, "TOKEN_ERROR", "Failed to generate access token")
	}


	// ── Blacklist old access token JTI (Redis — existing mechanism) ──────
	if h.redis != nil && session.AccessJTI != "" {
		blacklistExp := time.Now().Add(24 * time.Hour)
		if blErr := h.redis.BlacklistToken(ctx, session.AccessJTI, blacklistExp, "rotation"); blErr != nil {
			h.logger.WithError(blErr).Warn("Failed to blacklist old access token JTI")
		}
	}

	// ── Rotate session in DB (atomic update) ─────────────────────────────
	// Keep original expires_at — no sliding window.
	if err := h.sessionRepo.RotateSession(ctx, session.ID, newRefreshHash, newAccessJTI); err != nil {
		h.logger.WithError(err).Error("Failed to rotate session")
		return errorResponse(c, http.StatusInternalServerError, "SESSION_ERROR", "Failed to rotate session")
	}
	{
		ip, ua := auditContext(c)
		h.auditLogger.TokenRefreshed(session.UserID, username, ip, ua)
	}

	return c.JSON(http.StatusOK, RefreshTokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRawRefresh,
		ExpiresIn:    int64(time.Until(newAccessExp).Seconds()),
	})
}

// Logout handles user logout.
func (h *Handlers) Logout(c echo.Context) error {
	ip, ua := auditContext(c)
	ctx := c.Request().Context()

	// ── Terminate ALL sessions for this user on logout ───────────────────
	// Three complementary layers ensure complete invalidation across all devices:
	//
	//  1. IncrementSessionVersion  — any existing JWT (all browsers/devices) will
	//     be rejected by AuthMiddleware on the very next request, without waiting
	//     for JWT expiry. This is the primary, DB-level kill-switch.
	//
	//  2. RevokeAllForUser         — invalidates every refresh token in the DB, so
	//     no device can silently obtain a new access token via /auth/refresh.
	//
	//  3. Redis BlacklistToken     — blacklists the caller's current access token
	//     immediately, so even the in-flight request after logout is rejected.

	currentUser := getCurrentUser(c)
	if currentUser != nil && currentUser.UserID != "" {
		if uid, parseErr := uuid.Parse(currentUser.UserID); parseErr == nil {

			// Layer 1: increment session_version → all JWTs instantly stale
			if h.userRepo != nil {
				if _, incrErr := h.userRepo.IncrementSessionVersion(ctx, uid); incrErr != nil {
					h.logger.WithError(incrErr).Warn("Failed to increment session_version on logout")
				} else {
					h.logger.WithField("user_id", uid).Info("session_version incremented — all tokens invalidated on logout")
				}
			}

			// Layer 2: revoke ALL DB session records (refresh tokens) for this user
			if h.sessionRepo != nil {
				if revokeErr := h.sessionRepo.RevokeAllForUser(ctx, uid, "logout"); revokeErr != nil {
					h.logger.WithError(revokeErr).Warn("Failed to revoke all sessions on logout")
				} else {
					h.logger.WithField("user_id", uid).Info("All sessions revoked on logout")
				}
			}
		}
	}

	// Layer 3: blacklist the caller's current access token in Redis (fast path)
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && h.redis != nil && h.jwtManager != nil {
			token := parts[1]
			if jti, err := h.jwtManager.GetTokenID(token); err == nil && jti != "" {
				expiresAt := time.Now().Add(24 * time.Hour)
				if err := h.redis.BlacklistToken(ctx, jti, expiresAt, "logout"); err != nil {
					h.logger.WithError(err).Warn("Failed to blacklist token on logout")
				}
			}
		}
	}

	// Audit: logout
	{
		user := getCurrentUser(c)
		userID := uuid.Nil
		username := "unknown"
		if user != nil {
			username = user.Username
			if uid, err := uuid.Parse(user.UserID); err == nil {
				userID = uid
			}
		}
		if h.auditRepo != nil {
			audit := models.NewAuditLog(userID, username, models.AuditActionUserLogout, "user", userID).
				WithContext(ip, ua)
			go h.auditRepo.Create(ctx, audit) //nolint:errcheck
		}
		h.auditLogger.Logout(userID, username, ip, ua)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// GetCurrentUser returns the current authenticated user (full profile when DB is available).
func (h *Handlers) GetCurrentUser(c echo.Context) error {
	user := getCurrentUser(c)
	if user == nil {
		return errorResponse(c, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required")
	}

	if h.userRepo != nil && user.UserID != "" {
		if uid, err := uuid.Parse(user.UserID); err == nil {
			dbUser, err := h.userRepo.GetByID(c.Request().Context(), uid)
			if err == nil && dbUser != nil {
				return c.JSON(http.StatusOK, map[string]interface{}{
					"data": UserResponse{
						ID:         dbUser.ID,
						Username:   dbUser.Username,
						Email:      dbUser.Email,
						FullName:   dbUser.FullName,
						Role:       dbUser.Role,
						Status:     dbUser.Status,
						MFAEnabled: dbUser.MFAEnabled,
						LastLogin:  dbUser.LastLogin,
						CreatedAt:  dbUser.CreatedAt,
						UpdatedAt:  dbUser.UpdatedAt,
					},
					"meta": ResponseMeta{
						RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
						Timestamp: time.Now().UTC().Format(time.RFC3339),
					},
				})
			}
		}
	}

	role := ""
	if len(user.Roles) > 0 {
		role = user.Roles[0]
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": UserResponse{
			Username: user.Username,
			Role:     role,
		},
		"meta": ResponseMeta{
			RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	})
}
