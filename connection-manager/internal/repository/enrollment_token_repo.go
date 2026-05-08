// Package repository provides PostgreSQL implementation for enrollment tokens.
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/connection-manager/pkg/models"
)

// PostgresEnrollmentTokenRepository implements EnrollmentTokenRepository using PostgreSQL.
type PostgresEnrollmentTokenRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresEnrollmentTokenRepository creates a new enrollment token repository.
func NewPostgresEnrollmentTokenRepository(pool *pgxpool.Pool) *PostgresEnrollmentTokenRepository {
	return &PostgresEnrollmentTokenRepository{pool: pool}
}

// Create inserts a new enrollment token. The token string must already be set (use models.GenerateSecureToken).
func (r *PostgresEnrollmentTokenRepository) Create(ctx context.Context, token *models.EnrollmentToken) error {
	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	now := time.Now()
	token.CreatedAt = now
	token.UpdatedAt = now

	query := `
		INSERT INTO enrollment_tokens (id, token, token_hash, description, is_active, expires_at, max_uses, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.pool.Exec(ctx, query,
		token.ID,
		token.Token,
		token.TokenHash,
		token.Description,
		token.IsActive,
		token.ExpiresAt,
		token.MaxUses,
		token.CreatedBy,
		token.CreatedAt,
		token.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create enrollment token: %w", err)
	}
	return nil
}

// GetByID retrieves an enrollment token by its UUID.
func (r *PostgresEnrollmentTokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.EnrollmentToken, error) {
	query := `
		SELECT id, token, token_hash, description, is_active, expires_at, use_count, max_uses, build_count, build_id, created_by, created_at, revoked_at, updated_at
		FROM enrollment_tokens
		WHERE id = $1`

	return r.scanOne(ctx, query, id)
}

// GetByToken retrieves an enrollment token by its raw token string.
// Deprecated for security-sensitive paths: prefer GetByTokenHash.
func (r *PostgresEnrollmentTokenRepository) GetByToken(ctx context.Context, token string) (*models.EnrollmentToken, error) {
	query := `
		SELECT id, token, token_hash, description, is_active, expires_at, use_count, max_uses, build_count, build_id, created_by, created_at, revoked_at, updated_at
		FROM enrollment_tokens
		WHERE token = $1`

	return r.scanOne(ctx, query, token)
}

// GetByTokenHash retrieves an enrollment token by its SHA-256 hex hash.
// Use this for all agent-registration lookups: the agent sends the raw token,
// the caller hashes it with security.HashToken(), then calls this method.
func (r *PostgresEnrollmentTokenRepository) GetByTokenHash(ctx context.Context, hash string) (*models.EnrollmentToken, error) {
	query := `
		SELECT id, token, token_hash, description, is_active, expires_at, use_count, max_uses, build_count, build_id, created_by, created_at, revoked_at, updated_at
		FROM enrollment_tokens
		WHERE token_hash = $1`

	return r.scanOne(ctx, query, hash)
}

// GetByBuildID retrieves an enrollment token by the BuildID assigned at agent build time.
// Used by RegisterAgent for the BuildID-path lookup (new binaries).
func (r *PostgresEnrollmentTokenRepository) GetByBuildID(ctx context.Context, buildID uuid.UUID) (*models.EnrollmentToken, error) {
	query := `
		SELECT id, token, token_hash, description, is_active, expires_at, use_count, max_uses, build_count, build_id, created_by, created_at, revoked_at, updated_at
		FROM enrollment_tokens
		WHERE build_id = $1`

	return r.scanOne(ctx, query, buildID)
}

// StoreBuildID atomically assigns a BuildID to a token using a CAS UPDATE:
//
//	WHERE build_id IS NULL — the first caller wins; concurrent calls fail fast.
//
// Returns ErrBuildIDAlreadySet if build_id was already assigned.
// Returns ErrNotFound if the tokenID does not exist.
func (r *PostgresEnrollmentTokenRepository) StoreBuildID(ctx context.Context, tokenID uuid.UUID, buildID uuid.UUID) error {
	query := `
		UPDATE enrollment_tokens
		SET    build_id   = $2,
		       updated_at = NOW()
		WHERE  id         = $1
		  AND  build_id   IS NULL`

	tag, err := r.pool.Exec(ctx, query, tokenID, buildID)
	if err != nil {
		return fmt.Errorf("StoreBuildID: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the token doesn't exist, or build_id was already set.
		// Disambiguate: check if the row exists.
		var exists bool
		chkErr := r.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM enrollment_tokens WHERE id = $1)`, tokenID,
		).Scan(&exists)
		if chkErr != nil || !exists {
			return ErrNotFound
		}
		return ErrBuildIDAlreadySet
	}
	return nil
}

// IncrementBuildCount atomically increments build_count from 0 to 1.
// Returns ErrTokenAlreadyBuilt when 0 rows are affected (already consumed).
func (r *PostgresEnrollmentTokenRepository) IncrementBuildCount(ctx context.Context, tokenID uuid.UUID) error {
	query := `
		UPDATE enrollment_tokens
		SET    build_count = build_count + 1,
		       updated_at  = NOW()
		WHERE  id          = $1
		  AND  build_count = 0`

	tag, err := r.pool.Exec(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("IncrementBuildCount: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTokenAlreadyBuilt
	}
	return nil
}

// List retrieves all enrollment tokens ordered by creation date (newest first).
func (r *PostgresEnrollmentTokenRepository) List(ctx context.Context) ([]*models.EnrollmentToken, error) {
	query := `
		SELECT id, token, token_hash, description, is_active, expires_at, use_count, max_uses, build_count, build_id, created_by, created_at, revoked_at, updated_at
		FROM enrollment_tokens
		ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list enrollment tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*models.EnrollmentToken
	for rows.Next() {
		t, err := r.scanRow(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// IncrementUsage atomically increments the use_count for a token.
func (r *PostgresEnrollmentTokenRepository) IncrementUsage(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE enrollment_tokens SET use_count = use_count + 1, updated_at = NOW() WHERE id = $1 AND is_active = TRUE`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment enrollment token usage: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Revoke sets an enrollment token as inactive (revoked).
func (r *PostgresEnrollmentTokenRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE enrollment_tokens SET is_active = FALSE, revoked_at = NOW(), updated_at = NOW() WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to revoke enrollment token: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete deletes an enrollment token from the database.
func (r *PostgresEnrollmentTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM enrollment_tokens WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete enrollment token: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *PostgresEnrollmentTokenRepository) HasConsumption(ctx context.Context, tokenID uuid.UUID, hardwareID string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM enrollment_token_consumptions
			WHERE token_id = $1 AND hardware_id = $2
		)`, tokenID, hardwareID,
	).Scan(&exists)
	if err != nil {
		// Backward compatibility: if the migrations creating enrollment_token_consumptions
		// were not applied yet, don't hard-fail enrollment.
		if strings.Contains(err.Error(), "enrollment_token_consumptions") && strings.Contains(err.Error(), "does not exist") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check token consumption: %w", err)
	}
	return exists, nil
}

func (r *PostgresEnrollmentTokenRepository) RecordConsumption(ctx context.Context, tokenID uuid.UUID, hardwareID string, agentID uuid.UUID) (bool, error) {
	query := `
		INSERT INTO enrollment_token_consumptions (token_id, hardware_id, agent_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (token_id, hardware_id) DO NOTHING`
	result, err := r.pool.Exec(ctx, query, tokenID, hardwareID, agentID)
	if err != nil {
		if strings.Contains(err.Error(), "enrollment_token_consumptions") && strings.Contains(err.Error(), "does not exist") {
			return true, nil
		}
		return false, fmt.Errorf("failed to record token consumption: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// scanOne executes query with a single arg and scans one row into EnrollmentToken.
func (r *PostgresEnrollmentTokenRepository) scanOne(ctx context.Context, query string, arg interface{}) (*models.EnrollmentToken, error) {
	var (
		t         models.EnrollmentToken
		expiresAt sql.NullTime
		maxUses   sql.NullInt32
		buildID   uuid.NullUUID
		revokedAt sql.NullTime
	)
	err := r.pool.QueryRow(ctx, query, arg).Scan(
		&t.ID, &t.Token, &t.TokenHash, &t.Description, &t.IsActive,
		&expiresAt, &t.UseCount, &maxUses, &t.BuildCount,
		&buildID,
		&t.CreatedBy, &t.CreatedAt, &revokedAt, &t.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan enrollment token: %w", err)
	}
	if expiresAt.Valid {
		t.ExpiresAt = &expiresAt.Time
	}
	if maxUses.Valid {
		v := int(maxUses.Int32)
		t.MaxUses = &v
	}
	if buildID.Valid {
		t.BuildID = &buildID.UUID
	}
	if revokedAt.Valid {
		t.RevokedAt = &revokedAt.Time
	}
	return &t, nil
}

// scanRow scans a single row from a multi-row result set.
func (r *PostgresEnrollmentTokenRepository) scanRow(rows pgx.Rows) (*models.EnrollmentToken, error) {
	var (
		t         models.EnrollmentToken
		expiresAt sql.NullTime
		maxUses   sql.NullInt32
		buildID   uuid.NullUUID
		revokedAt sql.NullTime
	)
	err := rows.Scan(
		&t.ID, &t.Token, &t.TokenHash, &t.Description, &t.IsActive,
		&expiresAt, &t.UseCount, &maxUses, &t.BuildCount,
		&buildID,
		&t.CreatedBy, &t.CreatedAt, &revokedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan enrollment token row: %w", err)
	}
	if expiresAt.Valid {
		t.ExpiresAt = &expiresAt.Time
	}
	if maxUses.Valid {
		v := int(maxUses.Int32)
		t.MaxUses = &v
	}
	if buildID.Valid {
		t.BuildID = &buildID.UUID
	}
	if revokedAt.Valid {
		t.RevokedAt = &revokedAt.Time
	}
	return &t, nil
}
