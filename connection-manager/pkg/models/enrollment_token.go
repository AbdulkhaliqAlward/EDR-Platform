package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EnrollmentToken represents a dynamic, reusable token for agent enrollment.
// Unlike InstallationToken (one-time-use), enrollment tokens can be used
// multiple times (optionally capped by MaxUses), have descriptions, and
// can be revoked via the Dashboard.
type EnrollmentToken struct {
	ID          uuid.UUID  `db:"id"          json:"id"`
	Token       string     `db:"token"       json:"token"`
	// TokenHash is the SHA-256 hex digest of the raw Token value.
	TokenHash   string     `db:"token_hash"  json:"-"`
	Description string     `db:"description" json:"description"`
	IsActive    bool       `db:"is_active"   json:"is_active"`
	ExpiresAt   *time.Time `db:"expires_at"  json:"expires_at"`
	UseCount    int        `db:"use_count"   json:"use_count"`
	MaxUses     *int       `db:"max_uses"    json:"max_uses"`
	BuildCount  int        `db:"build_count" json:"build_count"`
	// KeyB is the hex-encoded 16-byte second half of the AES-256 split key.
	// It is set by the agent-builder after generating the key split.
	// It is permanently NULLed after being served once — it cannot be replayed.
	KeyB        *string    `db:"key_b"       json:"-"` // never exposed in JSON
	// KeyBServed is a permanent audit flag — TRUE once key_b has been served.
	KeyBServed  bool       `db:"key_b_served" json:"key_b_served"`
	CreatedBy   string     `db:"created_by"  json:"created_by"`
	CreatedAt   time.Time  `db:"created_at"  json:"created_at"`
	RevokedAt   *time.Time `db:"revoked_at"  json:"revoked_at"`
	UpdatedAt   time.Time  `db:"updated_at"  json:"updated_at"`
}

// IsValid returns true if the token can be used for enrollment:
// - Must be active (not revoked)
// - Must not be expired
// - Must not have exceeded max uses
func (t *EnrollmentToken) IsValid() bool {
	if !t.IsActive {
		return false
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return false
	}
	if t.MaxUses != nil && t.UseCount >= *t.MaxUses {
		return false
	}
	return true
}

// GenerateSecureToken creates a cryptographically secure random token string.
// Returns a 64-character hex string (32 bytes of entropy).
func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}
