// Package models defines the domain models for the connection-manager.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a dashboard user account.
type User struct {
	ID           uuid.UUID `db:"id" json:"id"`
	Username     string    `db:"username" json:"username"`
	Email        string    `db:"email" json:"email"`
	PasswordHash string    `db:"password_hash" json:"-"` // Never expose in JSON

	FullName string `db:"full_name" json:"full_name"`
	Role     string `db:"role" json:"role"`     // admin, analyst, viewer
	Status   string `db:"status" json:"status"` // active, inactive, locked

	LastLogin     *time.Time `db:"last_login" json:"last_login"`
	LoginAttempts int        `db:"login_attempts" json:"login_attempts"`
	LockedUntil   *time.Time `db:"locked_until" json:"locked_until"`

	MFAEnabled bool    `db:"mfa_enabled" json:"mfa_enabled"`
	MFASecret  *string `db:"mfa_secret" json:"-"` // Never expose in JSON

	// SessionVersion is incremented on every login and logout.
	// It is embedded as the sv claim in JWT access tokens.
	// The auth middleware rejects tokens whose sv differs from the DB value,
	// invalidating all existing tokens instantly without waiting for JWT expiry.
	// Never exposed in API responses.
	SessionVersion int `db:"session_version" json:"-"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}


// User role constants — must match the roles table seed.
const (
	UserRoleAdmin      = "admin"
	UserRoleSecurity   = "security"
	UserRoleAnalyst    = "analyst"
	UserRoleOperations = "operations"
	UserRoleViewer     = "viewer"
)

// User status constants
const (
	UserStatusActive   = "active"
	UserStatusInactive = "inactive"
	UserStatusLocked   = "locked"
	UserStatusDeleted  = "deleted"
)

// IsActive returns true if the user account is active.
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

// IsLocked returns true if the user account is locked.
func (u *User) IsLocked() bool {
	if u.Status == UserStatusLocked {
		return true
	}
	// Check if temporarily locked due to failed attempts
	if u.LockedUntil != nil && !u.LockedUntil.IsZero() && time.Now().Before(*u.LockedUntil) {
		return true
	}
	return false
}

// HasRole checks if user has the specified role.
func (u *User) HasRole(role string) bool {
	return u.Role == role
}

// IsAdmin returns true if the user is an admin.
func (u *User) IsAdmin() bool {
	return u.Role == UserRoleAdmin
}

// RecordFailedLogin records a failed login attempt.
func (u *User) RecordFailedLogin(maxAttempts int, lockDuration time.Duration) {
	u.LoginAttempts++
	if u.LoginAttempts >= maxAttempts {
		t := time.Now().Add(lockDuration)
		u.LockedUntil = &t
	}
	u.UpdatedAt = time.Now()
}

// RecordSuccessfulLogin resets login attempts on successful login.
func (u *User) RecordSuccessfulLogin() {
	u.LoginAttempts = 0
	u.LockedUntil = nil
	now := time.Now()
	u.LastLogin = &now
	u.UpdatedAt = now
}
