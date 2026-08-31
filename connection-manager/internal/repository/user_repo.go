// Package repository provides PostgreSQL implementations for repositories.
package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/connection-manager/pkg/models"
)

// PostgresUserRepository implements UserRepository using PostgreSQL.
type PostgresUserRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresUserRepository creates a new user repository.
func NewPostgresUserRepository(pool *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{pool: pool}
}

// Create creates a new user.
func (r *PostgresUserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (
			id, username, email, password_hash, full_name, role, status,
			mfa_enabled, mfa_secret, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.FullName,
		user.Role,
		user.Status,
		user.MFAEnabled,
		user.MFASecret,
		time.Now(),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by its ID.
func (r *PostgresUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, full_name, role, status,
			last_login, login_attempts, locked_until, mfa_enabled, mfa_secret,
			session_version, created_at, updated_at
		FROM users
		WHERE id = $1`

	user := &models.User{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.Role,
		&user.Status,
		&user.LastLogin,
		&user.LoginAttempts,
		&user.LockedUntil,
		&user.MFAEnabled,
		&user.MFASecret,
		&user.SessionVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// GetByUsername retrieves a user by username.
func (r *PostgresUserRepository) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, full_name, role, status,
			last_login, login_attempts, locked_until, mfa_enabled, mfa_secret,
			session_version, created_at, updated_at
		FROM users
		WHERE username = $1`

	user := &models.User{}
	err := r.pool.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.Role,
		&user.Status,
		&user.LastLogin,
		&user.LoginAttempts,
		&user.LockedUntil,
		&user.MFAEnabled,
		&user.MFASecret,
		&user.SessionVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by email.
func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, full_name, role, status,
			last_login, login_attempts, locked_until, mfa_enabled, mfa_secret,
			session_version, created_at, updated_at
		FROM users
		WHERE email = $1`

	user := &models.User{}
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.FullName,
		&user.Role,
		&user.Status,
		&user.LastLogin,
		&user.LoginAttempts,
		&user.LockedUntil,
		&user.MFAEnabled,
		&user.MFASecret,
		&user.SessionVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return user, nil
}

// Update updates an existing user.
func (r *PostgresUserRepository) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users SET
			username = $2, email = $3, full_name = $4, role = $5, status = $6,
			last_login = $7, login_attempts = $8, locked_until = $9,
			mfa_enabled = $10, mfa_secret = $11, updated_at = $12
		WHERE id = $1`

	result, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Username,
		user.Email,
		user.FullName,
		user.Role,
		user.Status,
		user.LastLogin,
		user.LoginAttempts,
		user.LockedUntil,
		user.MFAEnabled,
		user.MFASecret,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdatePassword updates the user's password hash.
func (r *PostgresUserRepository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	query := `UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id, passwordHash, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete soft-deletes a user.
func (r *PostgresUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET status = 'deleted', updated_at = $2 WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// List retrieves users with optional filters.
func (r *PostgresUserRepository) List(ctx context.Context, filter UserFilter) ([]*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, full_name, role, status,
			last_login, login_attempts, locked_until, mfa_enabled, mfa_secret,
			session_version, created_at, updated_at
		FROM users
		WHERE 1=1`

	args := []interface{}{}
	argNum := 1

	if filter.Role != nil {
		query += fmt.Sprintf(" AND role = $%d", argNum)
		args = append(args, *filter.Role)
		argNum++
	}

	if filter.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, *filter.Status)
		argNum++
	} else {
		// By default, do not return deleted users
		query += " AND status != 'deleted'"
	}

	if filter.Search != nil {
		query += fmt.Sprintf(" AND (username ILIKE $%d OR email ILIKE $%d OR full_name ILIKE $%d)", argNum, argNum, argNum)
		args = append(args, "%"+*filter.Search+"%")
		argNum++
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filter.Limit)
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Email,
			&user.PasswordHash,
			&user.FullName,
			&user.Role,
			&user.Status,
			&user.LastLogin,
			&user.LoginAttempts,
			&user.LockedUntil,
			&user.MFAEnabled,
			&user.MFASecret,
			&user.SessionVersion,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}
		users = append(users, user)
	}

	return users, nil
}

// Count returns how many users match the filter (same predicates as List; Limit/Offset ignored).
func (r *PostgresUserRepository) Count(ctx context.Context, filter UserFilter) (int64, error) {
	query := `
		SELECT COUNT(*)
		FROM users
		WHERE 1=1`

	args := []interface{}{}
	argNum := 1

	if filter.Role != nil {
		query += fmt.Sprintf(" AND role = $%d", argNum)
		args = append(args, *filter.Role)
		argNum++
	}

	if filter.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, *filter.Status)
		argNum++
	} else {
		query += " AND status != 'deleted'"
	}

	if filter.Search != nil {
		query += fmt.Sprintf(" AND (username ILIKE $%d OR email ILIKE $%d OR full_name ILIKE $%d)", argNum, argNum, argNum)
		args = append(args, "%"+*filter.Search+"%")
		argNum++
	}

	var n int64
	err := r.pool.QueryRow(ctx, query, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return n, nil
}

// IncrementSessionVersion atomically increments session_version and returns the new value.
// Called on login and logout so all existing JWTs with the old sv are immediately rejected.
func (r *PostgresUserRepository) IncrementSessionVersion(ctx context.Context, id uuid.UUID) (int, error) {
	var newVersion int
	err := r.pool.QueryRow(ctx,
		`UPDATE users SET session_version = session_version + 1, updated_at = NOW()
		 WHERE id = $1
		 RETURNING session_version`,
		id,
	).Scan(&newVersion)
	if err == pgx.ErrNoRows {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("increment session_version: %w", err)
	}
	return newVersion, nil
}

// GetSessionVersion returns the current session_version for a user.
// Used by AuthMiddleware to validate the sv claim in incoming JWT tokens.
func (r *PostgresUserRepository) GetSessionVersion(ctx context.Context, id uuid.UUID) (int, error) {
	var v int
	err := r.pool.QueryRow(ctx,
		`SELECT session_version FROM users WHERE id = $1`,
		id,
	).Scan(&v)
	if err == pgx.ErrNoRows {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("get session_version: %w", err)
	}
	return v, nil
}

// PostgresCSRRepository implements CSRRepository using PostgreSQL.
type PostgresCSRRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresCSRRepository creates a new CSR repository.
func NewPostgresCSRRepository(pool *pgxpool.Pool) *PostgresCSRRepository {
	return &PostgresCSRRepository{pool: pool}
}

// Create creates a new CSR record.
func (r *PostgresCSRRepository) Create(ctx context.Context, csr *models.CSR) error {
	query := `
		INSERT INTO csrs (id, agent_id, csr_data, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`

	_, err := r.pool.Exec(ctx, query,
		csr.ID,
		csr.AgentID,
		csr.CSRData,
		time.Now(),
		csr.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	return nil
}

// GetByID retrieves a CSR by its ID.
func (r *PostgresCSRRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.CSR, error) {
	query := `
		SELECT id, agent_id, csr_data, approved, approved_by, approved_at, created_at, expires_at
		FROM csrs
		WHERE id = $1`

	csr := &models.CSR{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&csr.ID,
		&csr.AgentID,
		&csr.CSRData,
		&csr.Approved,
		&csr.ApprovedBy,
		&csr.ApprovedAt,
		&csr.CreatedAt,
		&csr.ExpiresAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get CSR: %w", err)
	}

	return csr, nil
}

// GetByAgentID retrieves the pending CSR for an agent.
func (r *PostgresCSRRepository) GetByAgentID(ctx context.Context, agentID uuid.UUID) (*models.CSR, error) {
	query := `
		SELECT id, agent_id, csr_data, approved, approved_by, approved_at, created_at, expires_at
		FROM csrs
		WHERE agent_id = $1 AND approved = FALSE AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1`

	csr := &models.CSR{}
	err := r.pool.QueryRow(ctx, query, agentID).Scan(
		&csr.ID,
		&csr.AgentID,
		&csr.CSRData,
		&csr.Approved,
		&csr.ApprovedBy,
		&csr.ApprovedAt,
		&csr.CreatedAt,
		&csr.ExpiresAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get CSR by agent ID: %w", err)
	}

	return csr, nil
}

// Approve marks a CSR as approved.
func (r *PostgresCSRRepository) Approve(ctx context.Context, id uuid.UUID, approvedBy uuid.UUID) error {
	query := `
		UPDATE csrs SET approved = TRUE, approved_by = $2, approved_at = $3
		WHERE id = $1 AND approved = FALSE`

	result, err := r.pool.Exec(ctx, query, id, approvedBy, time.Now())
	if err != nil {
		return fmt.Errorf("failed to approve CSR: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete deletes a CSR.
func (r *PostgresCSRRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM csrs WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete CSR: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// GetPending retrieves all pending CSRs.
func (r *PostgresCSRRepository) GetPending(ctx context.Context) ([]*models.CSR, error) {
	query := `
		SELECT id, agent_id, csr_data, approved, approved_by, approved_at, created_at, expires_at
		FROM csrs
		WHERE approved = FALSE AND expires_at > NOW()
		ORDER BY created_at ASC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending CSRs: %w", err)
	}
	defer rows.Close()

	var csrs []*models.CSR
	for rows.Next() {
		csr := &models.CSR{}
		err := rows.Scan(
			&csr.ID,
			&csr.AgentID,
			&csr.CSRData,
			&csr.Approved,
			&csr.ApprovedBy,
			&csr.ApprovedAt,
			&csr.CreatedAt,
			&csr.ExpiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan CSR row: %w", err)
		}
		csrs = append(csrs, csr)
	}

	return csrs, nil
}

// DeleteExpired deletes CSRs that have expired.
func (r *PostgresCSRRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM csrs WHERE expires_at < NOW() AND approved = FALSE`

	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired CSRs: %w", err)
	}

	return result.RowsAffected(), nil
}
