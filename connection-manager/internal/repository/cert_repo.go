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

// PostgresCertificateRepository implements CertificateRepository using PostgreSQL.
type PostgresCertificateRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresCertificateRepository creates a new certificate repository.
func NewPostgresCertificateRepository(pool *pgxpool.Pool) *PostgresCertificateRepository {
	return &PostgresCertificateRepository{pool: pool}
}

// certColumns is the standard column list used in all certificate SELECT queries.
const certColumns = `id, agent_id, cert_fingerprint, public_key, serial_number,
	status, issued_at, expires_at, last_seen_at, revoked_at, revoked_by, revoke_reason,
	created_at`

// scanCert scans a single certificate row using the standard column order.
func scanCert(row pgx.Row) (*models.Certificate, error) {
	cert := &models.Certificate{}
	err := row.Scan(
		&cert.ID,
		&cert.AgentID,
		&cert.CertFingerprint,
		&cert.PublicKey,
		&cert.SerialNumber,
		&cert.Status,
		&cert.IssuedAt,
		&cert.ExpiresAt,
		&cert.LastSeenAt,
		&cert.RevokedAt,
		&cert.RevokedBy,
		&cert.RevokeReason,
		&cert.CreatedAt,
	)
	return cert, err
}

// Create creates a new certificate record.
func (r *PostgresCertificateRepository) Create(ctx context.Context, cert *models.Certificate) error {
	query := `
		INSERT INTO certificates (
			id, agent_id, cert_fingerprint, public_key, serial_number,
			status, issued_at, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.pool.Exec(ctx, query,
		cert.ID,
		cert.AgentID,
		cert.CertFingerprint,
		cert.PublicKey,
		cert.SerialNumber,
		cert.Status,
		cert.IssuedAt,
		cert.ExpiresAt,
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	return nil
}

// GetByID retrieves a certificate by its ID.
func (r *PostgresCertificateRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Certificate, error) {
	query := `SELECT ` + certColumns + ` FROM certificates WHERE id = $1`
	cert, err := scanCert(r.pool.QueryRow(ctx, query, id))
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}
	return cert, nil
}

// GetByFingerprint retrieves a certificate by its fingerprint.
func (r *PostgresCertificateRepository) GetByFingerprint(ctx context.Context, fingerprint string) (*models.Certificate, error) {
	query := `SELECT ` + certColumns + ` FROM certificates WHERE cert_fingerprint = $1`
	cert, err := scanCert(r.pool.QueryRow(ctx, query, fingerprint))
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate by fingerprint: %w", err)
	}
	return cert, nil
}

// GetActiveByAgentID retrieves the active certificate for an agent.
func (r *PostgresCertificateRepository) GetActiveByAgentID(ctx context.Context, agentID uuid.UUID) (*models.Certificate, error) {
	query := `SELECT ` + certColumns + `
		FROM certificates
		WHERE agent_id = $1 AND status = 'active'
		ORDER BY issued_at DESC
		LIMIT 1`
	cert, err := scanCert(r.pool.QueryRow(ctx, query, agentID))
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get active certificate: %w", err)
	}
	return cert, nil
}

// Update updates an existing certificate.
func (r *PostgresCertificateRepository) Update(ctx context.Context, cert *models.Certificate) error {
	query := `
		UPDATE certificates SET
			status = $2, revoked_at = $3, revoked_by = $4, revoke_reason = $5
		WHERE id = $1`

	result, err := r.pool.Exec(ctx, query,
		cert.ID,
		cert.Status,
		cert.RevokedAt,
		cert.RevokedBy,
		cert.RevokeReason,
	)

	if err != nil {
		return fmt.Errorf("failed to update certificate: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Revoke marks a certificate as revoked.
func (r *PostgresCertificateRepository) Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID, reason string) error {
	query := `
		UPDATE certificates SET
			status = 'revoked', revoked_at = $2, revoked_by = $3, revoke_reason = $4
		WHERE id = $1 AND status = 'active'`

	result, err := r.pool.Exec(ctx, query, id, time.Now(), revokedBy, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// MarkSuperseded marks a certificate as superseded by a new one.
func (r *PostgresCertificateRepository) MarkSuperseded(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE certificates SET status = 'superseded' WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to mark certificate as superseded: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// SupersedeAllForAgent marks all active certificates for an agent as "superseded".
func (r *PostgresCertificateRepository) SupersedeAllForAgent(ctx context.Context, agentID uuid.UUID) error {
	query := `UPDATE certificates SET status = 'superseded' WHERE agent_id = $1 AND status = 'active'`
	_, err := r.pool.Exec(ctx, query, agentID)
	if err != nil {
		return fmt.Errorf("failed to supersede certificates for agent: %w", err)
	}
	return nil
}

// GetExpiring retrieves certificates expiring within the given duration.
func (r *PostgresCertificateRepository) GetExpiring(ctx context.Context, within time.Duration) ([]*models.Certificate, error) {
	query := `SELECT ` + certColumns + `
		FROM certificates
		WHERE status = 'active' AND expires_at BETWEEN NOW() AND NOW() + $1`

	rows, err := r.pool.Query(ctx, query, within)
	if err != nil {
		return nil, fmt.Errorf("failed to get expiring certificates: %w", err)
	}
	defer rows.Close()

	return collectCerts(rows)
}

// List retrieves certificates with optional filters.
func (r *PostgresCertificateRepository) List(ctx context.Context, agentID uuid.UUID, status *string) ([]*models.Certificate, error) {
	query := `SELECT ` + certColumns + `
		FROM certificates
		WHERE agent_id = $1`

	args := []interface{}{agentID}

	if status != nil {
		query += " AND status = $2"
		args = append(args, *status)
	}

	query += " ORDER BY issued_at DESC"

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	defer rows.Close()

	return collectCerts(rows)
}

// UpdateLastSeen updates last_seen_at for a certificate identified by fingerprint.
func (r *PostgresCertificateRepository) UpdateLastSeen(ctx context.Context, fingerprint string) error {
	query := `UPDATE certificates SET last_seen_at = NOW() WHERE cert_fingerprint = $1 AND status = 'active'`
	_, err := r.pool.Exec(ctx, query, fingerprint)
	if err != nil {
		return fmt.Errorf("failed to update last_seen_at: %w", err)
	}
	return nil
}

// AddToCRL inserts a serial number into the certificate_revocation_list table.
func (r *PostgresCertificateRepository) AddToCRL(ctx context.Context, serialNumber, fingerprint, reason string) error {
	query := `INSERT INTO certificate_revocation_list (serial_number, fingerprint, revoked_at, reason)
		VALUES ($1, $2, NOW(), $3)
		ON CONFLICT (serial_number) DO NOTHING`
	_, err := r.pool.Exec(ctx, query, serialNumber, fingerprint, reason)
	if err != nil {
		return fmt.Errorf("failed to add to CRL: %w", err)
	}
	return nil
}

// GetCRLFingerprints returns all revoked fingerprints from the CRL table.
func (r *PostgresCertificateRepository) GetCRLFingerprints(ctx context.Context) ([]string, error) {
	query := `SELECT fingerprint FROM certificate_revocation_list WHERE fingerprint != ''`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get CRL fingerprints: %w", err)
	}
	defer rows.Close()

	var fingerprints []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("failed to scan CRL fingerprint: %w", err)
		}
		fingerprints = append(fingerprints, fp)
	}
	return fingerprints, rows.Err()
}

// GetStale returns active certs whose last_seen_at is older than the given duration.
func (r *PostgresCertificateRepository) GetStale(ctx context.Context, threshold time.Duration) ([]*models.Certificate, error) {
	query := `SELECT ` + certColumns + `
		FROM certificates
		WHERE status = 'active' AND last_seen_at IS NOT NULL AND last_seen_at < NOW() - $1`

	rows, err := r.pool.Query(ctx, query, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to get stale certificates: %w", err)
	}
	defer rows.Close()

	return collectCerts(rows)
}

// collectCerts scans all rows into a certificate slice.
func collectCerts(rows pgx.Rows) ([]*models.Certificate, error) {
	var certs []*models.Certificate
	for rows.Next() {
		cert := &models.Certificate{}
		err := rows.Scan(
			&cert.ID,
			&cert.AgentID,
			&cert.CertFingerprint,
			&cert.PublicKey,
			&cert.SerialNumber,
			&cert.Status,
			&cert.IssuedAt,
			&cert.ExpiresAt,
			&cert.LastSeenAt,
			&cert.RevokedAt,
			&cert.RevokedBy,
			&cert.RevokeReason,
			&cert.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate row: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
