// Package repository provides PostgreSQL implementations for repositories.
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/edr-platform/shared/pagination"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/connection-manager/pkg/models"
)

// PostgresAuditLogRepository implements AuditLogRepository using PostgreSQL.
type PostgresAuditLogRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuditLogRepository creates a new audit log repository.
func NewPostgresAuditLogRepository(pool *pgxpool.Pool) *PostgresAuditLogRepository {
	return &PostgresAuditLogRepository{pool: pool}
}

// Create creates a new audit log entry.
func (r *PostgresAuditLogRepository) Create(ctx context.Context, log *models.AuditLog) error {
	query := `
		INSERT INTO audit_logs (
			id, user_id, username, action, resource_type, resource_id,
			old_value, new_value, result, error_message,
			ip_address, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	_, err := r.pool.Exec(ctx, query,
		log.ID,
		log.UserID,
		log.Username,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		log.OldValue,
		log.NewValue,
		log.Result,
		log.ErrorMessage,
		log.IPAddress,
		log.UserAgent,
		log.Timestamp,
	)

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// GetByID retrieves an audit log by its ID.
func (r *PostgresAuditLogRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error) {
	query := `
		SELECT id, COALESCE(user_id,'00000000-0000-0000-0000-000000000000'::uuid), COALESCE(username,''), action, COALESCE(resource_type,''), COALESCE(resource_id,'00000000-0000-0000-0000-000000000000'::uuid),
			old_value, new_value, result, COALESCE(error_message,''),
			COALESCE(ip_address,''), COALESCE(user_agent,''), created_at
		FROM audit_logs
		WHERE id = $1`

	log := &models.AuditLog{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&log.ID,
		&log.UserID,
		&log.Username,
		&log.Action,
		&log.ResourceType,
		&log.ResourceID,
		&log.OldValue,
		&log.NewValue,
		&log.Result,
		&log.ErrorMessage,
		&log.IPAddress,
		&log.UserAgent,
		&log.Timestamp,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}

	return log, nil
}

// List retrieves audit logs with optional filters.
// auditWhere is shared by list and optional capped total so filters cannot diverge.
func auditWhere(filter AuditLogFilter) (string, []interface{}) {
	where := " WHERE 1=1"
	args := []interface{}{}
	argNum := 1

	if filter.UserID != nil {
		where += fmt.Sprintf(" AND user_id = $%d", argNum)
		args = append(args, *filter.UserID)
		argNum++
	}

	if filter.Action != nil {
		where += fmt.Sprintf(" AND action = $%d", argNum)
		args = append(args, *filter.Action)
		argNum++
	}

	if filter.ResourceType != nil {
		where += fmt.Sprintf(" AND resource_type = $%d", argNum)
		args = append(args, *filter.ResourceType)
		argNum++
	}

	if filter.ResourceID != nil {
		where += fmt.Sprintf(" AND resource_id = $%d", argNum)
		args = append(args, *filter.ResourceID)
		argNum++
	}

	if filter.Result != nil {
		where += fmt.Sprintf(" AND result = $%d", argNum)
		args = append(args, *filter.Result)
		argNum++
	}

	if filter.StartTime != nil {
		where += fmt.Sprintf(" AND created_at >= $%d", argNum)
		args = append(args, *filter.StartTime)
		argNum++
	}

	if filter.EndTime != nil {
		where += fmt.Sprintf(" AND created_at <= $%d", argNum)
		args = append(args, *filter.EndTime)
		argNum++
	}

	if len(filter.Actions) > 0 {
		where += fmt.Sprintf(" AND action=ANY($%d)", argNum)
		args = append(args, filter.Actions)
		argNum++
	}
	fields := map[string]string{"staff": "username", "affected": "concat_ws(' ',resource_type,resource_id::text)", "oldVal": "old_value::text", "newVal": "new_value::text", "extra": "error_message", "session": "id::text", "search": "concat_ws(' ',username,action,resource_type,resource_id::text,ip_address::text)"}
	for _, key := range []string{"staff", "affected", "oldVal", "newVal", "extra", "session", "search"} {
		if value := filter.Text[key]; value != "" {
			where += fmt.Sprintf(" AND %s ILIKE $%d", fields[key], argNum)
			args = append(args, "%"+value+"%")
			argNum++
		}
	}
	return where, args
}

func (r *PostgresAuditLogRepository) List(ctx context.Context, filter AuditLogFilter) ([]*models.AuditLog, error) {
	ctx, cancel := context.WithTimeout(ctx, pagination.QueryTimeout)
	defer cancel()
	p := filter.Page
	if p == nil {
		q := url.Values{}
		if filter.Limit > 0 {
			q.Set("limit", fmt.Sprint(filter.Limit))
		}
		if filter.Offset != 0 {
			return nil, fmt.Errorf("use cursor instead of offset")
		}
		parsed, err := pagination.Parse(q, pagination.Options{Scope: "audit", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}})
		if err != nil {
			return nil, err
		}
		p = &parsed
	}
	if filter.StartTime == nil {
		filter.StartTime = &p.From
	}
	if filter.EndTime == nil || filter.EndTime.After(p.Until) {
		filter.EndTime = &p.Until
	}
	where, args := auditWhere(filter)
	seek, order, err := p.Keyset("created_at", "id", &args)
	if err != nil {
		return nil, err
	}
	args = append(args, p.Limit+1)
	query := `SELECT id,COALESCE(user_id,'00000000-0000-0000-0000-000000000000'::uuid),COALESCE(username,''),action,COALESCE(resource_type,''),COALESCE(resource_id,'00000000-0000-0000-0000-000000000000'::uuid),
       to_jsonb(left(old_value::text,256)),to_jsonb(left(new_value::text,256)),result,COALESCE(left(error_message,256),''),
       COALESCE(ip_address,''),''::text,created_at FROM audit_logs` + where + seek + " ORDER BY " + order + fmt.Sprintf(" LIMIT $%d", len(args))

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.AuditLog
	for rows.Next() {
		log := &models.AuditLog{}
		err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.Username,
			&log.Action,
			&log.ResourceType,
			&log.ResourceID,
			&log.OldValue,
			&log.NewValue,
			&log.Result,
			&log.ErrorMessage,
			&log.IPAddress,
			&log.UserAgent,
			&log.Timestamp,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log row: %w", err)
		}
		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// Count returns the number of audit logs matching the filter.
func (r *PostgresAuditLogRepository) Count(ctx context.Context, filter AuditLogFilter) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, pagination.QueryTimeout)
	defer cancel()
	where, args := auditWhere(filter)
	var count int64
	err := r.pool.QueryRow(ctx, "SELECT count(*) FROM (SELECT 1 FROM audit_logs"+where+" LIMIT 10001) capped", args...).Scan(&count)
	return count, err
}

// PostgresInstallationTokenRepository implements InstallationTokenRepository.
type PostgresInstallationTokenRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresInstallationTokenRepository creates a new token repository.
func NewPostgresInstallationTokenRepository(pool *pgxpool.Pool) *PostgresInstallationTokenRepository {
	return &PostgresInstallationTokenRepository{pool: pool}
}

// Create creates a new installation token.
func (r *PostgresInstallationTokenRepository) Create(ctx context.Context, token *models.InstallationToken) error {
	query := `
		INSERT INTO installation_tokens (id, token_value, created_at, expires_at)
		VALUES ($1, $2, $3, $4)`

	_, err := r.pool.Exec(ctx, query,
		token.ID,
		token.TokenValue,
		time.Now(),
		token.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create installation token: %w", err)
	}

	return nil
}

// GetByValue retrieves a token by its value.
// Uses nullable types for agent_id and used_at so SQL NULLs scan correctly
// (unused tokens have NULL in those columns).
func (r *PostgresInstallationTokenRepository) GetByValue(ctx context.Context, value string) (*models.InstallationToken, error) {
	query := `
		SELECT id, token_value, agent_id, used, used_at, created_at, expires_at
		FROM installation_tokens
		WHERE token_value = $1`

	var (
		id        uuid.UUID
		tokenVal  string
		agentID   pgtype.UUID
		used      bool
		usedAt    sql.NullTime
		createdAt time.Time
		expiresAt time.Time
	)
	err := r.pool.QueryRow(ctx, query, value).Scan(
		&id,
		&tokenVal,
		&agentID,
		&used,
		&usedAt,
		&createdAt,
		&expiresAt,
	)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get installation token: %w", err)
	}

	token := &models.InstallationToken{
		ID:         id,
		TokenValue: tokenVal,
		Used:       used,
		CreatedAt:  createdAt,
		ExpiresAt:  expiresAt,
	}
	if agentID.Valid {
		token.AgentID = uuid.UUID(agentID.Bytes)
	}
	if usedAt.Valid {
		token.UsedAt = usedAt.Time
	}
	return token, nil
}

// MarkUsed marks a token as used by an agent.
func (r *PostgresInstallationTokenRepository) MarkUsed(ctx context.Context, id uuid.UUID, agentID uuid.UUID) error {
	query := `
		UPDATE installation_tokens SET used = TRUE, used_at = $2, agent_id = $3
		WHERE id = $1 AND used = FALSE`

	result, err := r.pool.Exec(ctx, query, id, time.Now(), agentID)
	if err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete deletes a token.
func (r *PostgresInstallationTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM installation_tokens WHERE id = $1`

	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete installation token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}

// DeleteExpired deletes tokens that have expired.
func (r *PostgresInstallationTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM installation_tokens WHERE expires_at < NOW() AND used = FALSE`

	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired tokens: %w", err)
	}

	return result.RowsAffected(), nil
}
