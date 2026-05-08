package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/connection-manager/pkg/models"
)

// SessionRepository defines the interface for session persistence.
type SessionRepository interface {
	// Create inserts a new session record.
	Create(ctx context.Context, session *models.Session) error

	// FindByRefreshTokenHash retrieves a session by its refresh token SHA-256 hash.
	// Returns nil, nil if not found.
	FindByRefreshTokenHash(ctx context.Context, hash string) (*models.Session, error)

	// FindByAccessJTI retrieves the active session that holds the given access token JTI.
	// Returns nil, nil if not found.
	FindByAccessJTI(ctx context.Context, jti string) (*models.Session, error)

	// RotateSession atomically updates the refresh token hash, access JTI, and
	// last_active_at timestamp. Used during token refresh.
	RotateSession(ctx context.Context, sessionID uuid.UUID, newHash, newAccessJTI string) error

	// Revoke marks a single session as revoked with the given reason.
	Revoke(ctx context.Context, sessionID uuid.UUID, reason string) error

	// RevokeAllForUser revokes every active session for the given user.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID, reason string) error

	// GetActiveForUser returns all non-revoked, non-expired sessions for a user.
	GetActiveForUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)

	// DeleteExpired removes sessions whose expires_at is in the past.
	DeleteExpired(ctx context.Context) (int64, error)
}

// PostgresSessionRepository implements SessionRepository using pgxpool.
type PostgresSessionRepository struct {
	db *pgxpool.Pool
}

// NewPostgresSessionRepository creates a new session repository.
func NewPostgresSessionRepository(db *pgxpool.Pool) *PostgresSessionRepository {
	return &PostgresSessionRepository{db: db}
}

func (r *PostgresSessionRepository) Create(ctx context.Context, session *models.Session) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO sessions (id, user_id, refresh_token_hash, access_jti, ip_address, user_agent, created_at, last_active_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		session.ID, session.UserID, session.RefreshTokenHash, session.AccessJTI,
		session.IPAddress, session.UserAgent, session.CreatedAt, session.LastActiveAt, session.ExpiresAt,
	)
	return err
}

func (r *PostgresSessionRepository) FindByRefreshTokenHash(ctx context.Context, hash string) (*models.Session, error) {
	s := &models.Session{}
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, refresh_token_hash, access_jti, ip_address, user_agent,
		       created_at, last_active_at, expires_at, revoked_at, revoke_reason
		FROM sessions WHERE refresh_token_hash = $1`, hash,
	).Scan(
		&s.ID, &s.UserID, &s.RefreshTokenHash, &s.AccessJTI, &s.IPAddress, &s.UserAgent,
		&s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &s.RevokedAt, &s.RevokeReason,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return s, nil
}

func (r *PostgresSessionRepository) FindByAccessJTI(ctx context.Context, jti string) (*models.Session, error) {
	s := &models.Session{}
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, refresh_token_hash, access_jti, ip_address, user_agent,
		       created_at, last_active_at, expires_at, revoked_at, revoke_reason
		FROM sessions WHERE access_jti = $1 AND revoked_at IS NULL`, jti,
	).Scan(
		&s.ID, &s.UserID, &s.RefreshTokenHash, &s.AccessJTI, &s.IPAddress, &s.UserAgent,
		&s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &s.RevokedAt, &s.RevokeReason,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return s, nil
}

func (r *PostgresSessionRepository) RotateSession(ctx context.Context, sessionID uuid.UUID, newHash, newAccessJTI string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE sessions
		SET refresh_token_hash = $2, access_jti = $3, last_active_at = now()
		WHERE id = $1`,
		sessionID, newHash, newAccessJTI,
	)
	return err
}

func (r *PostgresSessionRepository) Revoke(ctx context.Context, sessionID uuid.UUID, reason string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE sessions SET revoked_at = now(), revoke_reason = $2
		WHERE id = $1 AND revoked_at IS NULL`,
		sessionID, reason,
	)
	return err
}

func (r *PostgresSessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID, reason string) error {
	_, err := r.db.Exec(ctx, `
		UPDATE sessions SET revoked_at = now(), revoke_reason = $2
		WHERE user_id = $1 AND revoked_at IS NULL`,
		userID, reason,
	)
	return err
}

func (r *PostgresSessionRepository) GetActiveForUser(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, refresh_token_hash, access_jti, ip_address, user_agent,
		       created_at, last_active_at, expires_at, revoked_at, revoke_reason
		FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*models.Session
	for rows.Next() {
		s := &models.Session{}
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.RefreshTokenHash, &s.AccessJTI, &s.IPAddress, &s.UserAgent,
			&s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &s.RevokedAt, &s.RevokeReason,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (r *PostgresSessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
