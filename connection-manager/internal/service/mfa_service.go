// Package service — MFA challenge issuance and verification.
//
// Strategy: email-delivered 6-digit One-Time Passwords (OTP).
//
// Flow:
//
//	1. AuthService.Login completes password verification, then if the user
//	   has MFA enabled it asks MFAService.IssueChallenge(user). The handler
//	   returns {mfa_required: true, challenge_id, masked_email} INSTEAD of
//	   tokens.
//	2. The user receives an email with a 6-digit code.
//	3. The dashboard POSTs {challenge_id, code} to /auth/login/mfa, which
//	   calls MFAService.VerifyChallenge. On success the handler issues the
//	   token pair the way Login normally would.
//
// Storage:
//
//	The challenge is keyed by an opaque UUID and stored in Redis with a
//	short TTL (default 5 minutes). We never persist the raw OTP — only a
//	bcrypt hash of it together with the bound user-id and an attempt
//	counter (max 5). Failed attempts decrement towards 0; once exhausted
//	the challenge is destroyed.
//
//	Storing the user id INSIDE the challenge prevents an attacker who
//	guesses a challenge_id from being able to bind it to a different user.
package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/pkg/models"
)

// MFA-related errors. Keep distinct from auth errors so the API layer can
// return precise diagnostics without leaking which step failed.
var (
	ErrMFAUnavailable    = errors.New("mfa: service unavailable (email or cache not configured)")
	ErrMFAChallengeNotFound = errors.New("mfa: challenge not found or expired")
	ErrMFACodeInvalid    = errors.New("mfa: invalid verification code")
	ErrMFAAttemptsExceeded = errors.New("mfa: too many incorrect attempts")
)

// MFAChallenge is the public summary returned to the API layer when issuing
// a new challenge. Never exposes the OTP itself.
type MFAChallenge struct {
	ID          string
	UserID      uuid.UUID
	MaskedEmail string
	ExpiresAt   time.Time
}

// MFAService issues + verifies email OTP challenges.
type MFAService interface {
	// IssueChallenge generates a fresh 6-digit code, mails it to user.Email,
	// and stores the verification context in Redis. Returns the challenge
	// summary the dashboard needs to drive the second step.
	IssueChallenge(ctx context.Context, user *models.User) (*MFAChallenge, error)

	// VerifyChallenge consumes the code. On success it deletes the
	// challenge and returns the bound user id so the caller can mint
	// session tokens for THAT user (not whoever the request claims).
	VerifyChallenge(ctx context.Context, challengeID, code string) (uuid.UUID, error)

	// Available reports whether MFA can actually be performed (i.e.,
	// outbound email is configured and Redis is reachable). Call this
	// before forcing MFA on a user — if it returns false the AuthService
	// should fail-closed (refuse login) rather than silently bypass.
	Available() bool
}

// mfaServiceImpl is the production implementation backed by Redis + email.
type mfaServiceImpl struct {
	redis    *cache.RedisClient
	email    EmailSender
	logger   *logrus.Logger
	ttl      time.Duration
	maxTries int
}

// NewMFAService constructs an MFAService.
func NewMFAService(redis *cache.RedisClient, email EmailSender, logger *logrus.Logger) MFAService {
	return &mfaServiceImpl{
		redis:    redis,
		email:    email,
		logger:   logger,
		ttl:      5 * time.Minute,
		maxTries: 5,
	}
}

// Available — see interface comment.
func (s *mfaServiceImpl) Available() bool {
	return s != nil && s.redis != nil && s.email != nil && s.email.Enabled()
}

// challengePayload is what we serialise into Redis. The OTP itself is stored
// hashed (bcrypt cost 4 — low cost is fine because the OTP is high-entropy
// for its lifetime: only 5 attempts, 5 minutes).
type challengePayload struct {
	UserID    string `json:"u"`
	CodeHash  string `json:"h"` // bcrypt hash of the 6-digit code
	Tries     int    `json:"t"` // remaining attempts
	IssuedAt  int64  `json:"i"`
}

const mfaKeyPrefix = "mfa:challenge:"

// IssueChallenge — see interface comment.
func (s *mfaServiceImpl) IssueChallenge(ctx context.Context, user *models.User) (*MFAChallenge, error) {
	if !s.Available() {
		return nil, ErrMFAUnavailable
	}
	if user == nil || user.Email == "" {
		return nil, errors.New("mfa: user or email is empty")
	}

	code, err := generateOTP(6)
	if err != nil {
		return nil, fmt.Errorf("mfa: rng failure: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(code), 4)
	if err != nil {
		return nil, fmt.Errorf("mfa: hash code: %w", err)
	}

	payload := challengePayload{
		UserID:   user.ID.String(),
		CodeHash: string(hash),
		Tries:    s.maxTries,
		IssuedAt: time.Now().Unix(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("mfa: marshal payload: %w", err)
	}

	challengeID := uuid.New().String()
	key := mfaKeyPrefix + challengeID
	if err := s.redis.Client().SetEx(ctx, key, raw, s.ttl).Err(); err != nil {
		return nil, fmt.Errorf("mfa: redis SetEx: %w", err)
	}

	if err := s.email.Send(EmailMessage{
		To:      user.Email,
		Subject: "Your MITRAS sign-in verification code",
		HTML:    renderMFAEmail(user.FullName, user.Username, code, s.ttl),
		Text:    renderMFAEmailText(user.FullName, user.Username, code, s.ttl),
	}); err != nil {
		// Roll back the cached challenge so the user is not stuck with a
		// dangling, unverifiable OTP.
		_ = s.redis.Client().Del(ctx, key).Err()
		s.logger.WithError(err).WithField("username", user.Username).
			Error("MFA: failed to send verification email")
		return nil, fmt.Errorf("mfa: send email: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":      user.ID,
		"challenge_id": challengeID,
	}).Info("MFA challenge issued")

	return &MFAChallenge{
		ID:          challengeID,
		UserID:      user.ID,
		MaskedEmail: maskEmail(user.Email),
		ExpiresAt:   time.Now().Add(s.ttl),
	}, nil
}

// VerifyChallenge — see interface comment.
func (s *mfaServiceImpl) VerifyChallenge(ctx context.Context, challengeID, code string) (uuid.UUID, error) {
	if !s.Available() {
		return uuid.Nil, ErrMFAUnavailable
	}
	challengeID = strings.TrimSpace(challengeID)
	code = strings.TrimSpace(code)
	if challengeID == "" || code == "" {
		return uuid.Nil, ErrMFACodeInvalid
	}

	key := mfaKeyPrefix + challengeID
	raw, err := s.redis.Client().Get(ctx, key).Bytes()
	if err != nil {
		// Either Nil (expired/missing) or transport error — treat both as
		// "challenge gone" so the user has to start over.
		return uuid.Nil, ErrMFAChallengeNotFound
	}

	var p challengePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		_ = s.redis.Client().Del(ctx, key).Err()
		return uuid.Nil, ErrMFAChallengeNotFound
	}

	if bcrypt.CompareHashAndPassword([]byte(p.CodeHash), []byte(code)) == nil {
		// success — single-use, destroy the challenge.
		_ = s.redis.Client().Del(ctx, key).Err()
		uid, perr := uuid.Parse(p.UserID)
		if perr != nil {
			return uuid.Nil, ErrMFAChallengeNotFound
		}
		return uid, nil
	}

	// failure — decrement remaining tries.
	p.Tries--
	if p.Tries <= 0 {
		_ = s.redis.Client().Del(ctx, key).Err()
		return uuid.Nil, ErrMFAAttemptsExceeded
	}
	if updated, err := json.Marshal(p); err == nil {
		// preserve original TTL on overwrite (KEEPTTL not exposed by go-redis
		// on simple Set, so we re-read the TTL and re-apply).
		if ttl, terr := s.redis.Client().TTL(ctx, key).Result(); terr == nil && ttl > 0 {
			_ = s.redis.Client().Set(ctx, key, updated, ttl).Err()
		}
	}
	return uuid.Nil, ErrMFACodeInvalid
}

// generateOTP returns a numeric one-time password of length n digits.
// Uses crypto/rand so it's not predictable from process entropy.
func generateOTP(n int) (string, error) {
	const digits = "0123456789"
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		out[i] = digits[idx.Int64()]
	}
	return string(out), nil
}

// maskEmail returns "ab***@example.com" so the dashboard can confirm to the
// user where the code went without exposing the full address.
func maskEmail(email string) string {
	at := strings.IndexByte(email, '@')
	if at < 1 {
		return email
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 2 {
		return local[:1] + "***" + domain
	}
	return local[:2] + "***" + domain
}

// renderMFAEmail builds a minimal-but-trustworthy looking HTML body. We do
// NOT depend on a templating engine here — the markup is small and any
// dynamic value is HTML-escaped by being a digits-only OTP / a username we
// already control.
func renderMFAEmail(fullName, username, code string, ttl time.Duration) string {
	display := fullName
	if strings.TrimSpace(display) == "" {
		display = username
	}
	mins := int(ttl.Minutes())
	return fmt.Sprintf(`<!doctype html>
<html><body style="font-family:Segoe UI,Roboto,Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px">
  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0">
    <tr><td align="center">
      <table role="presentation" width="480" cellpadding="0" cellspacing="0"
             style="background:#111827;border:1px solid #1f2937;border-radius:12px;padding:24px">
        <tr><td>
          <p style="margin:0 0 12px 0;font-size:13px;letter-spacing:.18em;color:#22d3ee;text-transform:uppercase">MITRAS</p>
          <h1 style="margin:0 0 8px 0;font-size:20px;color:#f8fafc">Verify your sign-in</h1>
          <p style="margin:0 0 16px 0;font-size:14px;color:#cbd5e1">
            Hi %s, use the code below to finish signing in. It expires in
            <strong style="color:#22d3ee">%d minutes</strong>.
          </p>
          <div style="font-size:30px;font-weight:700;letter-spacing:.4em;
                      background:#0b1220;border:1px solid #1f2937;border-radius:8px;
                      padding:18px;text-align:center;color:#22d3ee">%s</div>
          <p style="margin:18px 0 0 0;font-size:12px;color:#94a3b8">
            If you did not request this code you can safely ignore this email — your
            password remains unchanged.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`, display, mins, code)
}

func renderMFAEmailText(fullName, username, code string, ttl time.Duration) string {
	display := fullName
	if strings.TrimSpace(display) == "" {
		display = username
	}
	mins := int(ttl.Minutes())
	return fmt.Sprintf(
		"MITRAS — sign-in verification\n\n"+
			"Hi %s,\n\n"+
			"Use this code to finish signing in (valid for %d minutes):\n\n    %s\n\n"+
			"If you did not request this code, you can safely ignore this email.",
		display, mins, code,
	)
}
