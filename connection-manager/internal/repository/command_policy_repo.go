// Package repository provides Command repository implementation.
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/connection-manager/pkg/models"
)

// CommandRepository defines the interface for command storage.
type CommandRepository interface {
	Create(ctx context.Context, cmd *models.Command) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Command, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.CommandStatus, result map[string]any, errorMsg string) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListByAgent(ctx context.Context, agentID uuid.UUID, limit, offset int) ([]*models.Command, int, error)
	GetPendingForAgent(ctx context.Context, agentID uuid.UUID) ([]*models.Command, error)

	// ListAll retrieves commands globally with pagination, filtering, and agent/user JOINs.
	ListAll(ctx context.Context, filter CommandListFilter) ([]CommandListItem, int64, error)

	// GetStats returns aggregate command counts by status.
	GetStats(ctx context.Context) (*CommandStats, error)
}

// CommandListFilter defines filters for the global command list.
type CommandListFilter struct {
	AgentID     *uuid.UUID
	Status      *string
	CommandType *string
	Limit       int
	Offset      int
	SortBy      string
	SortOrder   string
}

// CommandListItem extends Command with joined agent hostname and issuer username.
type CommandListItem struct {
	models.Command
	AgentHostname string `json:"agent_hostname"`
	IssuedByUser  string `json:"issued_by_user"`
}

// CommandStats holds aggregate command statistics.
type CommandStats struct {
	Total     int `json:"total"`
	Pending   int `json:"pending"`
	Sent      int `json:"sent"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
	Timeout   int `json:"timeout"`
	Cancelled int `json:"cancelled"`
}

// PostgresCommandRepository implements CommandRepository using PostgreSQL.
type PostgresCommandRepository struct {
	db *pgxpool.Pool
}

// NewPostgresCommandRepository creates a new command repository.
func NewPostgresCommandRepository(db *pgxpool.Pool) *PostgresCommandRepository {
	return &PostgresCommandRepository{db: db}
}

// Create inserts a new command.
func (r *PostgresCommandRepository) Create(ctx context.Context, cmd *models.Command) error {
	if cmd.ID == uuid.Nil {
		cmd.ID = uuid.New()
	}
	if cmd.IssuedAt.IsZero() {
		cmd.IssuedAt = time.Now()
	}
	if cmd.TimeoutSeconds == 0 {
		cmd.TimeoutSeconds = 300
	}
	if cmd.ExpiresAt.IsZero() {
		cmd.ExpiresAt = cmd.IssuedAt.Add(time.Duration(cmd.TimeoutSeconds) * time.Second)
	}

	// Serialize maps to JSON bytes for JSONB columns
	paramsJSON, _ := json.Marshal(cmd.Parameters)
	if paramsJSON == nil {
		paramsJSON = []byte("{}")
	}
	metaJSON, _ := json.Marshal(cmd.Metadata)
	if metaJSON == nil {
		metaJSON = []byte("{}")
	}

	query := `
		INSERT INTO commands (
			id, agent_id, command_type, parameters, priority, status,
			timeout_seconds, issued_at, expires_at, issued_by, metadata
		) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11::jsonb)`

	_, err := r.db.Exec(ctx, query,
		cmd.ID, cmd.AgentID, string(cmd.CommandType), paramsJSON, cmd.Priority,
		string(cmd.Status), cmd.TimeoutSeconds, cmd.IssuedAt, cmd.ExpiresAt,
		cmd.IssuedBy, metaJSON,
	)
	return err
}

// GetByID retrieves a command by ID.
func (r *PostgresCommandRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Command, error) {
	query := `
		SELECT id, agent_id, command_type, parameters, priority, status,
			result, COALESCE(error_message, ''), exit_code, timeout_seconds, issued_at,
			sent_at, acknowledged_at, started_at, completed_at, expires_at,
			issued_by, metadata
		FROM commands WHERE id = $1`

	cmd := &models.Command{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&cmd.ID, &cmd.AgentID, &cmd.CommandType, &cmd.Parameters,
		&cmd.Priority, &cmd.Status, &cmd.Result, &cmd.ErrorMessage,
		&cmd.ExitCode, &cmd.TimeoutSeconds, &cmd.IssuedAt, &cmd.SentAt,
		&cmd.AcknowledgedAt, &cmd.StartedAt, &cmd.CompletedAt,
		&cmd.ExpiresAt, &cmd.IssuedBy, &cmd.Metadata,
	)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	return cmd, err
}

// UpdateStatus updates the command status and result.
func (r *PostgresCommandRepository) UpdateStatus(
	ctx context.Context, id uuid.UUID,
	status models.CommandStatus, result map[string]any, errorMsg string,
) error {
	now := time.Now()
	rank := commandStatusRank(status)
	if rank == 0 {
		return fmt.Errorf("invalid command status %q", status)
	}

	// Serialize result to JSON bytes for JSONB column
	var resultJSON []byte
	if result != nil {
		var err error
		resultJSON, err = json.Marshal(result)
		if err != nil {
			return fmt.Errorf("encode command result: %w", err)
		}
	}

	// Compute timestamp columns in Go to avoid CASE expressions reusing $2
	statusStr := string(status)
	var completedAt, sentAt, startedAt, acknowledgedAt *time.Time

	switch statusStr {
	case "completed", "failed", "timeout", "cancelled":
		completedAt = &now
	case "executing":
		startedAt = &now
	case "sent":
		sentAt = &now
	case "acknowledged":
		acknowledgedAt = &now
	}

	query := `
		UPDATE commands SET
			status = CASE WHEN $9::int < 5 AND
				(CASE status WHEN 'pending' THEN 1 WHEN 'sent' THEN 2
				 WHEN 'acknowledged' THEN 3 WHEN 'executing' THEN 4 ELSE 5 END) > $9::int
				THEN status ELSE $1::varchar END,
			result = COALESCE($2::jsonb, result),
			error_message = CASE WHEN $9::int < 5 THEN error_message ELSE $3::text END,
			completed_at = COALESCE($4::timestamptz, completed_at),
			started_at = COALESCE($5::timestamptz, started_at),
			sent_at = COALESCE($6::timestamptz, sent_at),
			acknowledged_at = COALESCE($7::timestamptz, acknowledged_at)
		WHERE id = $8::uuid`

	result2, err := r.db.Exec(ctx, query,
		statusStr, resultJSON, errorMsg,
		completedAt, startedAt, sentAt, acknowledgedAt,
		id, rank,
	)
	if err != nil {
		return err
	}
	if result2.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func commandStatusRank(status models.CommandStatus) int {
	switch status {
	case models.CommandStatusPending:
		return 1
	case models.CommandStatusSent:
		return 2
	case models.CommandStatusAcknowledged:
		return 3
	case models.CommandStatusExecuting:
		return 4
	case models.CommandStatusCompleted, models.CommandStatusFailed, models.CommandStatusTimeout, models.CommandStatusCancelled:
		return 5
	default:
		return 0
	}
}

// Delete removes a command.
func (r *PostgresCommandRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, "DELETE FROM commands WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListByAgent retrieves commands for an agent.
func (r *PostgresCommandRepository) ListByAgent(
	ctx context.Context, agentID uuid.UUID, limit, offset int,
) ([]*models.Command, int, error) {
	// Count total
	var total int
	err := r.db.QueryRow(ctx,
		"SELECT COUNT(*) FROM commands WHERE agent_id = $1", agentID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Fetch commands
	query := `
		SELECT id, agent_id, command_type, parameters, priority, status,
			result, COALESCE(error_message, ''), issued_at, completed_at, issued_by
		FROM commands
		WHERE agent_id = $1
		ORDER BY issued_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, agentID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var commands []*models.Command
	for rows.Next() {
		cmd := &models.Command{}
		if err := rows.Scan(
			&cmd.ID, &cmd.AgentID, &cmd.CommandType, &cmd.Parameters,
			&cmd.Priority, &cmd.Status, &cmd.Result, &cmd.ErrorMessage,
			&cmd.IssuedAt, &cmd.CompletedAt, &cmd.IssuedBy,
		); err != nil {
			return nil, 0, err
		}
		commands = append(commands, cmd)
	}

	return commands, total, nil
}

// GetPendingForAgent retrieves pending commands for an agent.
func (r *PostgresCommandRepository) GetPendingForAgent(
	ctx context.Context, agentID uuid.UUID,
) ([]*models.Command, error) {
	query := `
		SELECT id, agent_id, command_type, parameters, priority, status,
			timeout_seconds, issued_at, expires_at, issued_by
		FROM commands
		WHERE agent_id = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY priority DESC, issued_at ASC`

	rows, err := r.db.Query(ctx, query, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var commands []*models.Command
	for rows.Next() {
		cmd := &models.Command{}
		if err := rows.Scan(
			&cmd.ID, &cmd.AgentID, &cmd.CommandType, &cmd.Parameters,
			&cmd.Priority, &cmd.Status, &cmd.TimeoutSeconds,
			&cmd.IssuedAt, &cmd.ExpiresAt, &cmd.IssuedBy,
		); err != nil {
			return nil, err
		}
		commands = append(commands, cmd)
	}

	return commands, nil
}

// ListAll retrieves commands globally with pagination, filtering, and agent/user JOINs.
func (r *PostgresCommandRepository) ListAll(ctx context.Context, filter CommandListFilter) ([]CommandListItem, int64, error) {
	if filter.Limit <= 0 {
		filter.Limit = 50
	}

	// Build WHERE clause dynamically
	where := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if filter.AgentID != nil {
		where += fmt.Sprintf(" AND c.agent_id = $%d", argIdx)
		args = append(args, *filter.AgentID)
		argIdx++
	}
	if filter.Status != nil && *filter.Status != "" {
		where += fmt.Sprintf(" AND c.status = $%d", argIdx)
		args = append(args, *filter.Status)
		argIdx++
	}
	if filter.CommandType != nil && *filter.CommandType != "" {
		where += fmt.Sprintf(" AND c.command_type = $%d", argIdx)
		args = append(args, *filter.CommandType)
		argIdx++
	}

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM commands c %s", where)
	var total int64
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count commands: %w", err)
	}

	// Sort
	sortCol := "c.issued_at"
	switch filter.SortBy {
	case "status":
		sortCol = "c.status"
	case "command_type":
		sortCol = "c.command_type"
	}
	sortDir := "DESC"
	if filter.SortOrder == "asc" {
		sortDir = "ASC"
	}

	// Data query — agent hostname JOIN + user username JOIN.
	// COALESCE priority for issued_by_user:
	//   1. u.username  → set when issued_by FK points to a real users row
	//   2. metadata->>'issued_by_username' → always set by ExecuteAgentCommand
	//                                         (stored even when issued_by FK is NULL
	//                                          to avoid FK constraint issues)
	//   3. ''          → final fallback (command was created by a system process)
	dataQuery := fmt.Sprintf(`
		SELECT c.id, c.agent_id, COALESCE(a.hostname, ''), c.command_type,
			COALESCE(c.parameters, '{}'::jsonb), c.priority, c.status,
			COALESCE(c.result, '{}'::jsonb), COALESCE(c.error_message, ''), c.exit_code,
			c.timeout_seconds, c.issued_at, c.sent_at, c.completed_at, c.expires_at,
			c.issued_by, COALESCE(u.username, c.metadata->>'issued_by_username', '')
		FROM commands c
		LEFT JOIN agents a ON a.id = c.agent_id
		LEFT JOIN users u ON u.id = c.issued_by
		%s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		where, sortCol, sortDir, argIdx, argIdx+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list commands: %w", err)
	}
	defer rows.Close()

	var items []CommandListItem
	for rows.Next() {
		var item CommandListItem
		err := rows.Scan(
			&item.ID, &item.AgentID, &item.AgentHostname, &item.CommandType,
			&item.Parameters, &item.Priority, &item.Status,
			&item.Result, &item.ErrorMessage, &item.ExitCode,
			&item.TimeoutSeconds, &item.IssuedAt, &item.SentAt, &item.CompletedAt, &item.ExpiresAt,
			&item.IssuedBy, &item.IssuedByUser,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan command: %w", err)
		}
		items = append(items, item)
	}

	return items, total, nil
}

// GetStats returns aggregate command counts by status.
func (r *PostgresCommandRepository) GetStats(ctx context.Context) (*CommandStats, error) {
	query := `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'pending'),
			COUNT(*) FILTER (WHERE status = 'sent'),
			COUNT(*) FILTER (WHERE status = 'completed'),
			COUNT(*) FILTER (WHERE status = 'failed'),
			COUNT(*) FILTER (WHERE status = 'timeout'),
			COUNT(*) FILTER (WHERE status = 'cancelled')
		FROM commands`

	stats := &CommandStats{}
	err := r.db.QueryRow(ctx, query).Scan(
		&stats.Total, &stats.Pending, &stats.Sent,
		&stats.Completed, &stats.Failed, &stats.Timeout, &stats.Cancelled,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get command stats: %w", err)
	}
	return stats, nil
}

// PolicyRepository - simplified version
type PolicyRepository interface {
	Create(ctx context.Context, policy *models.Policy) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error)
	Update(ctx context.Context, policy *models.Policy) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, limit, offset int) ([]*models.Policy, int, error)
	GetEnabledForAgent(ctx context.Context, agentID uuid.UUID) ([]*models.Policy, error)
}

// PostgresPolicyRepository implements PolicyRepository.
type PostgresPolicyRepository struct {
	db *pgxpool.Pool
}

// NewPostgresPolicyRepository creates a new policy repository.
func NewPostgresPolicyRepository(db *pgxpool.Pool) *PostgresPolicyRepository {
	return &PostgresPolicyRepository{db: db}
}

// Create inserts a new policy.
func (r *PostgresPolicyRepository) Create(ctx context.Context, policy *models.Policy) error {
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}

	query := `
		INSERT INTO policies (
			id, name, description, rules, targets, enabled, priority, created_by, tags, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING version, created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.Rules,
		policy.Targets, policy.Enabled, policy.Priority, policy.CreatedBy,
		policy.Tags, policy.Metadata,
	).Scan(&policy.Version, &policy.CreatedAt, &policy.UpdatedAt)
}

// GetByID retrieves a policy by ID.
func (r *PostgresPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	query := `
		SELECT id, name, description, rules, targets, enabled, priority,
			version, created_by, updated_by, created_at, updated_at, tags, metadata
		FROM policies WHERE id = $1`

	policy := &models.Policy{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&policy.ID, &policy.Name, &policy.Description, &policy.Rules,
		&policy.Targets, &policy.Enabled, &policy.Priority, &policy.Version,
		&policy.CreatedBy, &policy.UpdatedBy, &policy.CreatedAt, &policy.UpdatedAt,
		&policy.Tags, &policy.Metadata,
	)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	return policy, err
}

// Update updates a policy.
func (r *PostgresPolicyRepository) Update(ctx context.Context, policy *models.Policy) error {
	query := `
		UPDATE policies SET
			name = $2, description = $3, rules = $4, targets = $5,
			enabled = $6, priority = $7, updated_by = $8, tags = $9, metadata = $10
		WHERE id = $1
		RETURNING version, updated_at`

	err := r.db.QueryRow(ctx, query,
		policy.ID, policy.Name, policy.Description, policy.Rules,
		policy.Targets, policy.Enabled, policy.Priority, policy.UpdatedBy,
		policy.Tags, policy.Metadata,
	).Scan(&policy.Version, &policy.UpdatedAt)

	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	return err
}

// Delete removes a policy.
func (r *PostgresPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, "DELETE FROM policies WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// List retrieves policies with pagination.
func (r *PostgresPolicyRepository) List(ctx context.Context, limit, offset int) ([]*models.Policy, int, error) {
	var total int
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) FROM policies").Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `
		SELECT id, name, description, enabled, priority, version, created_at, updated_at
		FROM policies ORDER BY priority DESC, name LIMIT $1 OFFSET $2`

	rows, err := r.db.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var policies []*models.Policy
	for rows.Next() {
		p := &models.Policy{}
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Enabled,
			&p.Priority, &p.Version, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		policies = append(policies, p)
	}

	return policies, total, nil
}

// GetEnabledForAgent returns enabled policies that apply to an agent.
func (r *PostgresPolicyRepository) GetEnabledForAgent(ctx context.Context, agentID uuid.UUID) ([]*models.Policy, error) {
	query := `
		SELECT p.id, p.name, p.description, p.rules, p.targets, p.enabled, p.priority, p.version
		FROM policies p
		WHERE p.enabled = true
		AND (
			p.targets->>'apply_to_all' = 'true'
			OR p.targets->'agents' ? $1::text
			OR EXISTS (
				SELECT 1 FROM policy_agent_assignments pa
				WHERE pa.policy_id = p.id AND pa.agent_id = $1
			)
		)
		ORDER BY p.priority DESC`

	rows, err := r.db.Query(ctx, query, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*models.Policy
	for rows.Next() {
		p := &models.Policy{}
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Rules,
			&p.Targets, &p.Enabled, &p.Priority, &p.Version,
		); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}

	return policies, nil
}
