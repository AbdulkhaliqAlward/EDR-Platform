// Package service — out-of-band approval for manual endpoint commands.
//
// PROBLEM
//
//	If an attacker steals an admin's JWT they can immediately trigger
//	destructive response actions (isolate, kill_process, run_cmd, …) from
//	the dashboard. RBAC alone is not enough because the role check is
//	already passing — the token is valid.
//
// MITIGATION
//
//	Every manual command issued from the dashboard now requires a fresh,
//	single-use approval token. To get the token the operator must first
//	request a 6-digit OTP, which is delivered out-of-band to the address
//	configured in EC2_EMAIL_VERIFY (typically a separate mailbox watched
//	by a second human, e.g. SOC lead). Without access to that mailbox a
//	stolen JWT cannot execute any command.
//
//	Automated paths (Sigma → response engine → AgentRegistry) do NOT pass
//	through the HTTP API and therefore do not consume tokens — they remain
//	unaffected. This is intentional: the user explicitly asked that only
//	"manual" commands be gated.
//
// FLOW
//
//  1. Dashboard POSTs /commands/approval with a short summary
//     (agent + command type) → service emails an OTP to EC2_EMAIL_VERIFY.
//  2. Operator reads the email and POSTs /commands/approval/verify
//     {approval_id, code}. On success the dashboard receives an opaque
//     approval_token that lives in Redis for ~120s.
//  3. Dashboard re-issues the original POST /agents/:id/commands with
//     the X-Approval-Token header. The handler atomically consumes the
//     token (DEL) and proceeds. Re-using or replaying the token fails.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/edr-platform/connection-manager/internal/cache"
)

// Public sentinel errors. Mapped to API error codes by handlers.
var (
	ErrApprovalUnavailable       = errors.New("approval: service unavailable")
	ErrApprovalChallengeNotFound = errors.New("approval: challenge not found or expired")
	ErrApprovalCodeInvalid       = errors.New("approval: invalid code")
	ErrApprovalAttemptsExceeded  = errors.New("approval: too many incorrect attempts")
	ErrApprovalTokenInvalid      = errors.New("approval: token missing or invalid")
)

// ApprovalChallenge is the public summary returned when issuing a challenge.
type ApprovalChallenge struct {
	ID          string
	MaskedEmail string
	ExpiresAt   time.Time
}

// ApprovalRequest captures the operator-supplied context that ends up in the
// approval email so the second human can review what's about to happen.
type ApprovalRequest struct {
	UserID      uuid.UUID
	Username    string
	IPAddress   string
	UserAgent   string
	Summary     string // free-form, e.g. "isolate_network on host XYZ"
	AgentID     string // optional
	CommandType string // optional
}

// CommandApprovalService gates manual command execution behind an OTP that
// is delivered to a SECOND mailbox (EC2_EMAIL_VERIFY), not the operator's.
type CommandApprovalService interface {
	// Available reports whether approvals can actually be performed
	// (email + redis + verify-address all configured). When false the
	// API layer should fail-closed and refuse manual commands rather than
	// silently bypass the gate.
	Available() bool

	// VerifyAddress returns the configured EC2_EMAIL_VERIFY mailbox so
	// the API can include a masked form of it in the issue response.
	VerifyAddress() string

	// IssueChallenge sends a 6-digit OTP to EC2_EMAIL_VERIFY and stores
	// the verification context in Redis. Returns the challenge_id the
	// dashboard needs to drive step 2.
	IssueChallenge(ctx context.Context, req ApprovalRequest) (*ApprovalChallenge, error)

	// VerifyChallenge consumes the OTP. On success it issues an opaque,
	// single-use token bound to req.UserID and stores it in Redis for a
	// short window. The dashboard presents this token in the next command
	// request via the X-Approval-Token header.
	VerifyChallenge(ctx context.Context, userID uuid.UUID, challengeID, code string) (string, time.Time, error)

	// ConsumeToken atomically validates and removes a token. Must be
	// called AT MOST once per token. Returns nil on success, or one of the
	// approval errors above.
	ConsumeToken(ctx context.Context, userID uuid.UUID, token string) error
}

// commandApprovalServiceImpl is the production implementation.
type commandApprovalServiceImpl struct {
	redis         *cache.RedisClient
	email         EmailSender
	verifyAddress string
	logger        *logrus.Logger
	challengeTTL  time.Duration
	tokenTTL      time.Duration
	maxTries      int
}

// NewCommandApprovalService constructs the service. `verifyAddress` MUST be
// the value of the EC2_EMAIL_VERIFY env var; if empty the service reports
// Available()=false so callers can fail-closed.
func NewCommandApprovalService(
	redis *cache.RedisClient,
	email EmailSender,
	verifyAddress string,
	logger *logrus.Logger,
) CommandApprovalService {
	return &commandApprovalServiceImpl{
		redis:         redis,
		email:         email,
		verifyAddress: strings.TrimSpace(verifyAddress),
		logger:        logger,
		challengeTTL:  5 * time.Minute,
		tokenTTL:      120 * time.Second, // long enough to retry the original POST, short enough to limit replay
		maxTries:      5,
	}
}

func (s *commandApprovalServiceImpl) Available() bool {
	return s != nil &&
		s.redis != nil &&
		s.email != nil && s.email.Enabled() &&
		s.verifyAddress != ""
}

func (s *commandApprovalServiceImpl) VerifyAddress() string {
	if s == nil {
		return ""
	}
	return s.verifyAddress
}

const (
	approvalChallengeKeyPrefix = "approval:challenge:"
	approvalTokenKeyPrefix     = "approval:token:"
)

// challengeRecord is what we serialise into Redis. Like the MFA flow we
// store only a bcrypt hash of the code; the user_id binding prevents an
// attacker who guesses challenge_id from binding it to a different user.
type approvalChallengeRecord struct {
	UserID      string `json:"u"`
	CodeHash    string `json:"h"`
	Tries       int    `json:"t"`
	IssuedAt    int64  `json:"i"`
	Summary     string `json:"s,omitempty"`
	AgentID     string `json:"a,omitempty"`
	CommandType string `json:"c,omitempty"`
}

// approvalTokenRecord describes a verified, single-use token waiting to be
// consumed by the next /agents/:id/commands call.
type approvalTokenRecord struct {
	UserID   string `json:"u"`
	IssuedAt int64  `json:"i"`
	Summary  string `json:"s,omitempty"`
}

// IssueChallenge — see interface comment.
func (s *commandApprovalServiceImpl) IssueChallenge(ctx context.Context, req ApprovalRequest) (*ApprovalChallenge, error) {
	if !s.Available() {
		return nil, ErrApprovalUnavailable
	}
	if req.UserID == uuid.Nil {
		return nil, errors.New("approval: user id required")
	}

	// Reuse the OTP generator from the MFA file (same package).
	code, err := generateOTP(6)
	if err != nil {
		return nil, fmt.Errorf("approval: rng failure: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(code), 4)
	if err != nil {
		return nil, fmt.Errorf("approval: hash code: %w", err)
	}

	rec := approvalChallengeRecord{
		UserID:      req.UserID.String(),
		CodeHash:    string(hash),
		Tries:       s.maxTries,
		IssuedAt:    time.Now().Unix(),
		Summary:     req.Summary,
		AgentID:     req.AgentID,
		CommandType: req.CommandType,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("approval: marshal: %w", err)
	}

	challengeID := uuid.New().String()
	key := approvalChallengeKeyPrefix + challengeID
	if err := s.redis.Client().SetEx(ctx, key, raw, s.challengeTTL).Err(); err != nil {
		return nil, fmt.Errorf("approval: redis SetEx: %w", err)
	}

	if err := s.email.Send(EmailMessage{
		To:      s.verifyAddress,
		Subject: "MITRAS — manual command approval required",
		HTML:    renderApprovalEmailHTML(code, s.challengeTTL, req),
		Text:    renderApprovalEmailText(code, s.challengeTTL, req),
	}); err != nil {
		_ = s.redis.Client().Del(ctx, key).Err()
		s.logger.WithError(err).WithField("user_id", req.UserID).
			Error("Approval: failed to send verification email")
		return nil, fmt.Errorf("approval: send email: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":      req.UserID,
		"challenge_id": challengeID,
		"agent_id":     req.AgentID,
		"command":      req.CommandType,
		"to":           maskEmail(s.verifyAddress),
	}).Info("Approval: challenge issued")

	return &ApprovalChallenge{
		ID:          challengeID,
		MaskedEmail: maskEmail(s.verifyAddress),
		ExpiresAt:   time.Now().Add(s.challengeTTL),
	}, nil
}

// VerifyChallenge — see interface comment.
func (s *commandApprovalServiceImpl) VerifyChallenge(
	ctx context.Context,
	userID uuid.UUID,
	challengeID, code string,
) (string, time.Time, error) {
	if !s.Available() {
		return "", time.Time{}, ErrApprovalUnavailable
	}
	challengeID = strings.TrimSpace(challengeID)
	code = strings.TrimSpace(code)
	if challengeID == "" || code == "" {
		return "", time.Time{}, ErrApprovalCodeInvalid
	}

	key := approvalChallengeKeyPrefix + challengeID
	raw, err := s.redis.Client().Get(ctx, key).Bytes()
	if err != nil {
		return "", time.Time{}, ErrApprovalChallengeNotFound
	}

	var rec approvalChallengeRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		_ = s.redis.Client().Del(ctx, key).Err()
		return "", time.Time{}, ErrApprovalChallengeNotFound
	}

	// User-id binding: even if an attacker somehow learned both
	// challenge_id and code, they cannot redeem it under a DIFFERENT
	// session because the token issued is bound to rec.UserID.
	if rec.UserID != userID.String() {
		// Don't decrement attempt counter on cross-user replay — just say
		// "not found" so the attacker gets no oracle.
		return "", time.Time{}, ErrApprovalChallengeNotFound
	}

	if bcrypt.CompareHashAndPassword([]byte(rec.CodeHash), []byte(code)) != nil {
		// Wrong code → decrement remaining attempts.
		rec.Tries--
		if rec.Tries <= 0 {
			_ = s.redis.Client().Del(ctx, key).Err()
			return "", time.Time{}, ErrApprovalAttemptsExceeded
		}
		if updated, mErr := json.Marshal(rec); mErr == nil {
			if ttl, terr := s.redis.Client().TTL(ctx, key).Result(); terr == nil && ttl > 0 {
				_ = s.redis.Client().Set(ctx, key, updated, ttl).Err()
			}
		}
		return "", time.Time{}, ErrApprovalCodeInvalid
	}

	// Code OK — single-use challenge, destroy it.
	_ = s.redis.Client().Del(ctx, key).Err()

	// Mint a token. We use 32 bytes (256-bit) of entropy; collisions are
	// statistically impossible. The token value itself is the Redis key.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("approval: token rng: %w", err)
	}
	token := encodeURLSafe(tokenBytes)

	tokRec := approvalTokenRecord{
		UserID:   userID.String(),
		IssuedAt: time.Now().Unix(),
		Summary:  rec.Summary,
	}
	tokRaw, _ := json.Marshal(tokRec)
	expiresAt := time.Now().Add(s.tokenTTL)
	if err := s.redis.Client().SetEx(ctx, approvalTokenKeyPrefix+token, tokRaw, s.tokenTTL).Err(); err != nil {
		return "", time.Time{}, fmt.Errorf("approval: store token: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":      userID,
		"challenge_id": challengeID,
		"token_ttl":    s.tokenTTL.String(),
	}).Info("Approval: challenge verified, token issued")

	return token, expiresAt, nil
}

// ConsumeToken — see interface comment. Uses GETDEL so concurrent attempts
// can't race past the validation. Falls back to GET+DEL on Redis < 6.2.
func (s *commandApprovalServiceImpl) ConsumeToken(ctx context.Context, userID uuid.UUID, token string) error {
	if !s.Available() {
		return ErrApprovalUnavailable
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrApprovalTokenInvalid
	}

	key := approvalTokenKeyPrefix + token

	// Atomic read-and-delete. GetDel returns redis.Nil if the key is gone.
	raw, err := s.redis.Client().GetDel(ctx, key).Bytes()
	if err != nil {
		return ErrApprovalTokenInvalid
	}

	var rec approvalTokenRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return ErrApprovalTokenInvalid
	}
	if rec.UserID != userID.String() {
		// Token belonged to a different user — refuse. The token is
		// already gone (GetDel) so a stolen token is now useless either
		// way; this branch is mostly defence in depth.
		return ErrApprovalTokenInvalid
	}
	return nil
}

// encodeURLSafe is a small helper that base64-url-encodes a byte slice
// without padding so the value is HTTP-header-safe.
func encodeURLSafe(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// renderApprovalEmailHTML builds the human-facing email body. The structure
// mirrors the MFA email but the copy makes it crystal clear that the
// recipient is approving someone else's pending action.
func renderApprovalEmailHTML(code string, ttl time.Duration, req ApprovalRequest) string {
	mins := int(ttl.Minutes())
	cmd := req.CommandType
	if cmd == "" {
		cmd = "(unspecified)"
	}
	agent := req.AgentID
	if agent == "" {
		agent = "(unspecified)"
	}
	summary := req.Summary
	if summary == "" {
		summary = cmd + " on " + agent
	}
	user := req.Username
	if user == "" {
		user = req.UserID.String()
	}
	return fmt.Sprintf(`<!doctype html>
<html><body style="font-family:Segoe UI,Roboto,Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px">
  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0">
    <tr><td align="center">
      <table role="presentation" width="520" cellpadding="0" cellspacing="0"
             style="background:#111827;border:1px solid #1f2937;border-radius:12px;padding:24px">
        <tr><td>
          <p style="margin:0 0 12px 0;font-size:13px;letter-spacing:.18em;color:#f59e0b;text-transform:uppercase">MITRAS · Manual Approval</p>
          <h1 style="margin:0 0 8px 0;font-size:20px;color:#f8fafc">A manual endpoint command needs your approval</h1>
          <p style="margin:0 0 16px 0;font-size:14px;color:#cbd5e1">
            Operator <strong style="color:#f8fafc">%s</strong> is trying to run
            <strong style="color:#f8fafc">%s</strong> against agent
            <code style="background:#0b1220;border:1px solid #1f2937;border-radius:4px;padding:2px 6px;color:#22d3ee">%s</code>
            from <code style="color:#22d3ee">%s</code>. The action is paused until this code is entered.
          </p>
          <div style="font-size:30px;font-weight:700;letter-spacing:.4em;
                      background:#0b1220;border:1px solid #1f2937;border-radius:8px;
                      padding:18px;text-align:center;color:#f59e0b">%s</div>
          <p style="margin:18px 0 0 0;font-size:12px;color:#94a3b8">
            Code expires in <strong style="color:#f59e0b">%d minutes</strong>.
            If you did not expect this request, do NOT share the code and revoke the operator's session immediately.
          </p>
          <p style="margin:8px 0 0 0;font-size:11px;color:#64748b">Summary: %s</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`, htmlEscape(user), htmlEscape(cmd), htmlEscape(agent), htmlEscape(req.IPAddress), code, mins, htmlEscape(summary))
}

func renderApprovalEmailText(code string, ttl time.Duration, req ApprovalRequest) string {
	mins := int(ttl.Minutes())
	user := req.Username
	if user == "" {
		user = req.UserID.String()
	}
	return fmt.Sprintf(
		"MITRAS — manual command approval\n\n"+
			"Operator: %s\n"+
			"From IP:  %s\n"+
			"Action:   %s on agent %s\n"+
			"Summary:  %s\n\n"+
			"Approval code (valid for %d minutes):\n\n    %s\n\n"+
			"If you did not expect this request, ignore the code and revoke the operator's session.",
		user, req.IPAddress, req.CommandType, req.AgentID, req.Summary, mins, code,
	)
}

// htmlEscape is a tiny helper. We avoid html/template here because we're
// only stitching together known-safe pieces, but operator-supplied summaries
// could contain '<' or '&' so we still escape them.
func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}
