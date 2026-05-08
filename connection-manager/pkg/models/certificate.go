// Package models defines the domain models for the connection-manager.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// Certificate represents an agent's TLS certificate.
type Certificate struct {
	ID              uuid.UUID `db:"id" json:"id"`
	AgentID         uuid.UUID `db:"agent_id" json:"agent_id"`
	CertFingerprint string    `db:"cert_fingerprint" json:"cert_fingerprint"` // SHA256 of certificate
	PublicKey       []byte    `db:"public_key" json:"public_key"`             // PEM encoded
	SerialNumber    string    `db:"serial_number" json:"serial_number"`
	Status          string    `db:"status" json:"status"` // active, expired, revoked, superseded

	IssuedAt   time.Time  `db:"issued_at" json:"issued_at"`
	ExpiresAt  time.Time  `db:"expires_at" json:"expires_at"`
	LastSeenAt *time.Time `db:"last_seen_at" json:"last_seen_at,omitempty"`

	// Revocation info
	RevokedAt    time.Time `db:"revoked_at" json:"revoked_at"`
	RevokedBy    uuid.UUID `db:"revoked_by" json:"revoked_by"`
	RevokeReason string    `db:"revoke_reason" json:"revoke_reason"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// Certificate status constants
const (
	CertStatusActive     = "active"
	CertStatusExpired    = "expired"
	CertStatusRevoked    = "revoked"
	CertStatusSuperseded = "superseded"
)

// IsValid returns true if the certificate is active and not expired.
func (c *Certificate) IsValid() bool {
	if c.Status != CertStatusActive {
		return false
	}
	return time.Now().Before(c.ExpiresAt)
}

// IsExpiringSoon returns true if certificate expires within given duration.
func (c *Certificate) IsExpiringSoon(within time.Duration) bool {
	return time.Until(c.ExpiresAt) < within
}

// GenerateFingerprint calculates SHA256 fingerprint of the certificate.
func GenerateFingerprint(certBytes []byte) string {
	hash := sha256.Sum256(certBytes)
	return hex.EncodeToString(hash[:])
}

// CSR represents a Certificate Signing Request pending approval.
type CSR struct {
	ID      uuid.UUID `db:"id" json:"id"`
	AgentID uuid.UUID `db:"agent_id" json:"agent_id"`
	CSRData []byte    `db:"csr_data" json:"csr_data"` // PEM encoded CSR

	Approved   bool      `db:"approved" json:"approved"`
	ApprovedBy uuid.UUID `db:"approved_by" json:"approved_by"`
	ApprovedAt time.Time `db:"approved_at" json:"approved_at"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"` // CSR expires after 24h
}

// InstallationToken represents a one-time token for agent registration.
type InstallationToken struct {
	ID         uuid.UUID `db:"id" json:"id"`
	TokenValue string    `db:"token_value" json:"token_value"`
	AgentID    uuid.UUID `db:"agent_id" json:"agent_id"` // Set when used

	Used   bool      `db:"used" json:"used"`
	UsedAt time.Time `db:"used_at" json:"used_at"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"` // Token expires after 24h
}

// IsValid returns true if the token is not used and not expired.
func (t *InstallationToken) IsValid() bool {
	if t.Used {
		return false
	}
	return time.Now().Before(t.ExpiresAt)
}
