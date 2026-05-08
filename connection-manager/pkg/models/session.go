package models

import (
	"time"

	"github.com/google/uuid"
)

// Session represents a server-side user session for refresh token rotation
// and single active session enforcement.
type Session struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	RefreshTokenHash string     `json:"refresh_token_hash"` // SHA-256 hex
	AccessJTI        string     `json:"access_jti"`
	IPAddress        string     `json:"ip_address"`
	UserAgent        string     `json:"user_agent"`
	CreatedAt        time.Time  `json:"created_at"`
	LastActiveAt     time.Time  `json:"last_active_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevokeReason     string     `json:"revoke_reason,omitempty"`
}

// IsActive returns true if the session has not been revoked and has not expired.
func (s *Session) IsActive() bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(time.Now())
}
