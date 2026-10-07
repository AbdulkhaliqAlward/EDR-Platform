// Package service provides the business logic layer.
package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/connection-manager/pkg/security"
)

// AuthService provides authentication and authorization services.
type AuthService interface {
	// Login authenticates a user. If the user has MFA enabled and the MFA
	// service is available, the response will carry MFAChallenge instead of
	// tokens; the caller MUST then drive the second step via VerifyMFA.
	Login(ctx context.Context, username, password string) (*LoginResponse, error)

	// VerifyMFA consumes a challenge issued by Login and returns the final
	// token pair. Fails if the code is wrong, expired, or rate-limited.
	VerifyMFA(ctx context.Context, challengeID, code string) (*LoginResponse, error)

	// ValidateToken validates a JWT token.
	ValidateToken(ctx context.Context, tokenString string) (*security.Claims, error)

	// RefreshToken refreshes an access token using a refresh token.
	RefreshToken(ctx context.Context, refreshToken string) (string, time.Time, error)

	// Logout invalidates tokens.
	Logout(ctx context.Context, accessToken, refreshToken string) error

	// CreateUser creates a new user.
	CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error)

	// ChangePassword changes a user's password.
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error
}

// LoginResponse contains authentication tokens — OR an MFA challenge that
// must be solved before tokens are issued. Exactly one of (AccessToken,
// MFAChallenge) is populated:
//
//   - MFAChallenge != nil  → caller must POST {challenge_id, code} to
//     VerifyMFA. AccessToken/RefreshToken are empty.
//   - MFAChallenge == nil  → tokens are valid; the user is signed in.
type LoginResponse struct {
	AccessToken  string
	RefreshToken string
	AccessExp    time.Time
	RefreshExp   time.Time
	User         *models.User

	MFAChallenge *MFAChallenge
}

// CreateUserRequest contains user creation data.
type CreateUserRequest struct {
	Username   string
	Email      string
	Password   string
	FullName   string
	Role       string
	MFAEnabled bool
}

// authServiceImpl implements AuthService.
type authServiceImpl struct {
	userRepo   repository.UserRepository
	auditRepo  repository.AuditLogRepository
	jwtManager *security.JWTManager
	redis      *cache.RedisClient
	logger     *logrus.Logger
	mfa        MFAService // optional — nil disables MFA entirely

	// mfaPolicyDisabled is the platform-wide switch (MFA_ENABLED=false).
	// When true, login never asks for a second factor, even for users with
	// mfa_enabled=true. Default false keeps per-user MFA (fail-safe) behavior.
	mfaPolicyDisabled bool

	maxLoginAttempts int
	lockDuration     time.Duration
}

// NewAuthService creates a new AuthService.
func NewAuthService(
	userRepo repository.UserRepository,
	auditRepo repository.AuditLogRepository,
	jwtManager *security.JWTManager,
	redis *cache.RedisClient,
	logger *logrus.Logger,
) AuthService {
	return &authServiceImpl{
		userRepo:         userRepo,
		auditRepo:        auditRepo,
		jwtManager:       jwtManager,
		redis:            redis,
		logger:           logger,
		maxLoginAttempts: 5,
		lockDuration:     15 * time.Minute,
	}
}

// SetMFAService installs (or removes) the MFA challenge service. Wired by
// cmd/server/main.go after both AuthService and MFAService have been built.
// Passing nil disables MFA so users with mfa_enabled=true can still log in
// during outages — see the fail-safe note inside Login.
func (s *authServiceImpl) SetMFAService(m MFAService) {
	if s == nil {
		return
	}
	s.mfa = m
}

// SetMFAPolicyEnabled sets the platform-wide MFA switch (MFA_ENABLED).
// enabled=false: no second factor is requested at login for anyone.
// enabled=true: users with mfa_enabled=true must pass email OTP, and login is
// refused if the MFA service is unavailable (fail-safe).
func (s *authServiceImpl) SetMFAPolicyEnabled(enabled bool) {
	if s == nil {
		return
	}
	s.mfaPolicyDisabled = !enabled
}

// AuthServiceWithMFA is implemented by authServiceImpl and lets the wiring
// code attach an MFAService without exposing the concrete struct. This
// keeps the cmd/server/main.go dependency on the interface, not on impl.
type AuthServiceWithMFA interface {
	AuthService
	SetMFAService(m MFAService)
	SetMFAPolicyEnabled(enabled bool)
}

// Login authenticates a user.
func (s *authServiceImpl) Login(ctx context.Context, username, password string) (*LoginResponse, error) {
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		s.logger.WithField("username", username).Warn("Login attempt for unknown user")
		return nil, ErrInvalidPassword
	}

	// Check if account is locked
	if user.IsLocked() {
		s.logger.WithField("username", username).Warn("Login attempt on locked account")
		return nil, ErrAccountLocked
	}

	// Check if account is active
	if !user.IsActive() {
		return nil, ErrAccountLocked
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Record failed attempt
		user.RecordFailedLogin(s.maxLoginAttempts, s.lockDuration)
		s.userRepo.Update(ctx, user)

		// Audit log
		audit := models.NewAuditLog(user.ID, username, models.AuditActionLoginFailed, "user", user.ID)
		audit.MarkFailed("invalid password")
		s.auditRepo.Create(ctx, audit)

		return nil, ErrInvalidPassword
	}

	// ── MFA gate ──────────────────────────────────────────────────────────
	// If the user opted in to MFA AND the MFA service is available, do not
	// issue tokens yet. Issue an email OTP challenge and let the caller
	// drive VerifyMFA.
	//
	// Fail-safe semantics: if mfa_enabled=true but MFAService is unavailable
	// (e.g. SMTP outage) we REFUSE login rather than silently bypass MFA.
	// This is the secure default for a security product.
	//
	// When MFA is switched off platform-wide (MFA_ENABLED=false) the gate is
	// skipped for everyone — an explicit administrator decision.
	if user.MFAEnabled && !s.mfaPolicyDisabled {
		if s.mfa == nil || !s.mfa.Available() {
			s.logger.WithField("username", username).
				Error("MFA required but service unavailable — refusing login")
			return nil, ErrMFAUnavailable
		}
		challenge, err := s.mfa.IssueChallenge(ctx, user)
		if err != nil {
			s.logger.WithError(err).WithField("username", username).
				Error("Failed to issue MFA challenge")
			return nil, err
		}
		return &LoginResponse{
			User:         user,
			MFAChallenge: challenge,
		}, nil
	}

	return s.completeLogin(ctx, user)
}

// completeLogin generates tokens, persists last_login, audits, and returns
// the final LoginResponse. Shared between password-only login and the
// post-MFA verification path.
func (s *authServiceImpl) completeLogin(ctx context.Context, user *models.User) (*LoginResponse, error) {
	tokenPair, err := s.jwtManager.GenerateTokenPair(user.ID.String(), user.Username, []string{user.Role})
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate tokens")
		return nil, ErrInternal
	}

	user.RecordSuccessfulLogin()
	s.userRepo.Update(ctx, user)

	audit := models.NewAuditLog(user.ID, user.Username, models.AuditActionLoginSuccess, "user", user.ID)
	s.auditRepo.Create(ctx, audit)

	s.logger.WithField("username", user.Username).Info("User logged in successfully")

	return &LoginResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		AccessExp:    tokenPair.AccessExp,
		RefreshExp:   tokenPair.RefreshExp,
		User:         user,
	}, nil
}

// VerifyMFA consumes a challenge issued during Login and finalises the sign-in.
func (s *authServiceImpl) VerifyMFA(ctx context.Context, challengeID, code string) (*LoginResponse, error) {
	if s.mfa == nil || !s.mfa.Available() {
		return nil, ErrMFAUnavailable
	}
	userID, err := s.mfa.VerifyChallenge(ctx, challengeID, code)
	if err != nil {
		return nil, err
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	// Re-validate state in case the account was disabled between the two
	// requests (defence in depth).
	if user.IsLocked() || !user.IsActive() {
		return nil, ErrAccountLocked
	}
	return s.completeLogin(ctx, user)
}

// ValidateToken validates a JWT token.
func (s *authServiceImpl) ValidateToken(ctx context.Context, tokenString string) (*security.Claims, error) {
	// Check if token is blacklisted (skip when Redis unavailable)
	if s.redis != nil {
		jti, err := s.jwtManager.GetTokenID(tokenString)
		if err == nil {
			blacklisted, err := s.redis.IsTokenBlacklisted(ctx, jti)
			if err == nil && blacklisted {
				return nil, ErrInvalidToken
			}
		}
	}

	return s.jwtManager.ValidateToken(tokenString)
}

// RefreshToken refreshes an access token.
func (s *authServiceImpl) RefreshToken(ctx context.Context, refreshToken string) (string, time.Time, error) {
	return s.jwtManager.RefreshAccessToken(refreshToken)
}

// Logout invalidates tokens.
func (s *authServiceImpl) Logout(ctx context.Context, accessToken, refreshToken string) error {
	if s.redis == nil {
		return nil
	}
	// Blacklist access token
	if accessToken != "" {
		claims, err := s.jwtManager.ValidateToken(accessToken)
		if err == nil {
			s.redis.BlacklistToken(ctx, claims.ID, claims.ExpiresAt.Time, "logout")
		}
	}

	// Blacklist refresh token
	if refreshToken != "" {
		claims, err := s.jwtManager.ValidateToken(refreshToken)
		if err == nil {
			s.redis.BlacklistToken(ctx, claims.ID, claims.ExpiresAt.Time, "logout")
		}
	}

	return nil
}

// CreateUser creates a new user.
func (s *authServiceImpl) CreateUser(ctx context.Context, req *CreateUserRequest) (*models.User, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, ErrInternal
	}

	user := &models.User{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FullName:     req.FullName,
		Role:         req.Role,
		Status:       models.UserStatusActive,
		MFAEnabled:   req.MFAEnabled,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// Audit log
	audit := models.NewAuditLog(uuid.Nil, "system", models.AuditActionUserCreated, "user", user.ID)
	audit.WithDetail("username", user.Username)
	s.auditRepo.Create(ctx, audit)

	return user, nil
}

// ChangePassword changes a user's password.
func (s *authServiceImpl) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return ErrInvalidPassword
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return ErrInternal
	}

	if err := s.userRepo.UpdatePassword(ctx, userID, string(hashedPassword)); err != nil {
		return err
	}

	// Audit log
	audit := models.NewAuditLog(userID, user.Username, models.AuditActionPasswordChanged, "user", userID)
	s.auditRepo.Create(ctx, audit)

	return nil
}
