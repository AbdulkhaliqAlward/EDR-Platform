package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrDuplicateExecution is returned when an automation rule already produced
// an execution for the same alert (duplicate delivery / concurrent trigger).
var ErrDuplicateExecution = errors.New("an execution for this alert and rule already exists")

// SigmaAlertRecord is the response engine's view of a Sigma alert
// (table sigma_alerts, written by the sigma engine).
type SigmaAlertRecord struct {
	ID              string
	Timestamp       time.Time
	CreatedAt       time.Time
	AgentID         string
	RuleID          string
	RuleTitle       string
	Severity        string
	Category        string
	Status          string
	RiskScore       int
	MitreTactics    []string
	MitreTechniques []string
	MatchedFields   map[string]any
	ContextData     map[string]any
}

// ExecutionRecord is one playbook run (table playbook_executions).
type ExecutionRecord struct {
	ID                uuid.UUID       `json:"id"`
	AlertID           *uuid.UUID      `json:"alert_id,omitempty"`
	PlaybookID        uuid.UUID       `json:"playbook_id"`
	PlaybookName      string          `json:"playbook_name"`
	RuleID            *uuid.UUID      `json:"rule_id,omitempty"`
	AgentID           uuid.UUID       `json:"agent_id"`
	Status            string          `json:"status"`
	TriggerSource     string          `json:"trigger_source"`
	CreatedByUsername string          `json:"created_by_username"`
	StartedAt         time.Time       `json:"started_at"`
	CompletedAt       *time.Time      `json:"completed_at,omitempty"`
	CommandsExecuted  int             `json:"commands_executed"`
	CommandsTotal     int             `json:"commands_total"`
	Steps             json.RawMessage `json:"steps"`
	ErrorMessage      string          `json:"error_message,omitempty"`
	ExecutionTimeMs   int             `json:"execution_time_ms"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// ExecutionListFilter filters ListExecutions.
type ExecutionListFilter struct {
	AlertID    *uuid.UUID
	PlaybookID *uuid.UUID
	AgentID    *uuid.UUID
	Limit      int
}

// ResponseEngineRepository is the persistence used by the response engine.
type ResponseEngineRepository struct {
	pool *pgxpool.Pool
}

// NewResponseEngineRepository creates the repository.
func NewResponseEngineRepository(pool *pgxpool.Pool) *ResponseEngineRepository {
	return &ResponseEngineRepository{pool: pool}
}

func decodeJSONMap(b []byte) map[string]any {
	if len(b) == 0 {
		return map[string]any{}
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	return m
}

// GetSigmaAlert loads a Sigma alert by ID.
func (r *ResponseEngineRepository) GetSigmaAlert(ctx context.Context, id uuid.UUID) (*SigmaAlertRecord, error) {
	var (
		a                SigmaAlertRecord
		ruleTitle, cat   pgtype.Text
		status           pgtype.Text
		tactics, techs   pgtype.FlatArray[string]
		matched, ctxData []byte
	)
	err := r.pool.QueryRow(ctx, `
		SELECT id::text, timestamp, created_at, COALESCE(agent_id, ''), rule_id, rule_title, severity,
		       category, status, COALESCE(risk_score, 0),
		       COALESCE(mitre_tactics, '{}'), COALESCE(mitre_techniques, '{}'),
		       COALESCE(matched_fields, '{}'::jsonb), COALESCE(context_data, '{}'::jsonb)
		FROM sigma_alerts WHERE id = $1`, id).
		Scan(&a.ID, &a.Timestamp, &a.CreatedAt, &a.AgentID, &a.RuleID, &ruleTitle, &a.Severity,
			&cat, &status, &a.RiskScore, &tactics, &techs, &matched, &ctxData)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.RuleTitle, a.Category, a.Status = ruleTitle.String, cat.String, status.String
	a.MitreTactics, a.MitreTechniques = []string(tactics), []string(techs)
	a.MatchedFields, a.ContextData = decodeJSONMap(matched), decodeJSONMap(ctxData)
	return &a, nil
}

// ListUnclaimedSigmaAlerts returns IDs of Sigma alerts created after since
// (and at least settle ago, so in-flight inserts are committed) that the
// response engine has not claimed yet, oldest first.
func (r *ResponseEngineRepository) ListUnclaimedSigmaAlerts(ctx context.Context, since time.Time, settle time.Duration, limit int) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT a.id
		FROM sigma_alerts a
		WHERE a.created_at > $1
		  AND a.created_at < now() - make_interval(secs => $2)
		  AND NOT EXISTS (SELECT 1 FROM response_alert_inbox i WHERE i.alert_id = a.id)
		ORDER BY a.created_at ASC
		LIMIT $3`, since, settle.Seconds(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ClaimSigmaAlert atomically claims an alert for automated processing.
// Exactly one caller (across replicas) gets true.
func (r *ResponseEngineRepository) ClaimSigmaAlert(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`INSERT INTO response_alert_inbox (alert_id) VALUES ($1) ON CONFLICT (alert_id) DO NOTHING`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// CompleteInbox records the outcome of processing a claimed alert.
func (r *ResponseEngineRepository) CompleteInbox(ctx context.Context, id uuid.UUID, outcome string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE response_alert_inbox SET processed_at = now(), outcome = $2 WHERE alert_id = $1`, id, outcome)
	return err
}

// CleanupInbox deletes inbox rows older than the retention window.
func (r *ResponseEngineRepository) CleanupInbox(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM response_alert_inbox WHERE claimed_at < now() - make_interval(secs => $1)`, olderThan.Seconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// GetOrInitState returns the stored value for key, storing def first if absent.
func (r *ResponseEngineRepository) GetOrInitState(ctx context.Context, key, def string) (string, error) {
	var v string
	err := r.pool.QueryRow(ctx, `
		WITH ins AS (
			INSERT INTO response_engine_state (key, value) VALUES ($1, $2)
			ON CONFLICT (key) DO NOTHING RETURNING value
		)
		SELECT value FROM ins
		UNION ALL
		SELECT value FROM response_engine_state WHERE key = $1
		LIMIT 1`, key, def).Scan(&v)
	return v, err
}

// ReserveRule atomically records that a rule fires now for an endpoint,
// honouring the rule's cooldown for that endpoint. It returns false when the
// rule is disabled or still cooling down for this endpoint, so concurrent
// triggers (goroutines or replicas) cannot both run it. Other endpoints are
// unaffected: the cooldown is per (rule, endpoint).
func (r *ResponseEngineRepository) ReserveRule(ctx context.Context, ruleID, agentID uuid.UUID, cooldownMinutes int) (bool, error) {
	if cooldownMinutes < 0 {
		cooldownMinutes = 0
	}
	var enabled bool
	if err := r.pool.QueryRow(ctx, `SELECT enabled FROM automation_rules WHERE id = $1`, ruleID).Scan(&enabled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if !enabled {
		return false, nil
	}
	tag, err := r.pool.Exec(ctx, `
		INSERT INTO automation_rule_cooldowns (rule_id, agent_id, last_fired_at)
		VALUES ($1, $2, now())
		ON CONFLICT (rule_id, agent_id) DO UPDATE SET last_fired_at = now()
		WHERE automation_rule_cooldowns.last_fired_at <= now() - make_interval(mins => $3)`,
		ruleID, agentID, cooldownMinutes)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	// Display only: the rule list shows when it last fired.
	_, _ = r.pool.Exec(ctx, `UPDATE automation_rules SET last_execution = now(), updated_at = now() WHERE id = $1`, ruleID)
	return true, nil
}

// RefreshRuleSuccessRate recomputes a rule's success rate from its last 50
// finished executions (completed = success; partial/failed = failure).
func (r *ResponseEngineRepository) RefreshRuleSuccessRate(ctx context.Context, ruleID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE automation_rules r
		SET success_rate = COALESCE((
			SELECT avg(CASE WHEN s.status = 'completed' THEN 1.0 ELSE 0.0 END)
			FROM (
				SELECT status FROM playbook_executions
				WHERE rule_id = r.id AND status IN ('completed', 'partial', 'failed')
				ORDER BY started_at DESC LIMIT 50
			) s
		), 0), updated_at = now()
		WHERE r.id = $1`, ruleID)
	return err
}

const executionColumns = `id, alert_id, playbook_id, playbook_name, rule_id, agent_id, status, trigger_source,
	created_by_username, started_at, completed_at, COALESCE(commands_executed, 0), COALESCE(commands_total, 0),
	steps, COALESCE(error_message, ''), COALESCE(execution_time_ms, 0), updated_at`

func scanExecution(row pgx.Row) (*ExecutionRecord, error) {
	var e ExecutionRecord
	var steps []byte
	if err := row.Scan(&e.ID, &e.AlertID, &e.PlaybookID, &e.PlaybookName, &e.RuleID, &e.AgentID, &e.Status,
		&e.TriggerSource, &e.CreatedByUsername, &e.StartedAt, &e.CompletedAt, &e.CommandsExecuted,
		&e.CommandsTotal, &steps, &e.ErrorMessage, &e.ExecutionTimeMs, &e.UpdatedAt); err != nil {
		return nil, err
	}
	if len(steps) == 0 {
		steps = []byte("[]")
	}
	e.Steps = steps
	return &e, nil
}

// CreateExecution inserts an execution. For automation runs the (alert,
// rule) pair is unique: a duplicate returns ErrDuplicateExecution.
func (r *ResponseEngineRepository) CreateExecution(ctx context.Context, e *ExecutionRecord) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if len(e.Steps) == 0 {
		e.Steps = json.RawMessage("[]")
	}
	now := time.Now().UTC()
	e.StartedAt, e.UpdatedAt = now, now
	_, err := r.pool.Exec(ctx, `
		INSERT INTO playbook_executions (id, alert_id, playbook_id, playbook_name, rule_id, agent_id, status,
			trigger_source, created_by_username, started_at, commands_executed, commands_total, steps,
			error_message, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15)`,
		e.ID, e.AlertID, e.PlaybookID, e.PlaybookName, e.RuleID, e.AgentID, e.Status, e.TriggerSource,
		e.CreatedByUsername, e.StartedAt, e.CommandsExecuted, e.CommandsTotal, string(e.Steps),
		e.ErrorMessage, e.UpdatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrDuplicateExecution
	}
	return err
}

// UpdateExecution persists progress / the final result of an execution.
func (r *ResponseEngineRepository) UpdateExecution(ctx context.Context, e *ExecutionRecord) error {
	e.UpdatedAt = time.Now().UTC()
	_, err := r.pool.Exec(ctx, `
		UPDATE playbook_executions
		SET status = $2, completed_at = $3, commands_executed = $4, commands_total = $5,
		    steps = $6::jsonb, error_message = $7, execution_time_ms = $8, updated_at = $9
		WHERE id = $1`,
		e.ID, e.Status, e.CompletedAt, e.CommandsExecuted, e.CommandsTotal, string(e.Steps),
		e.ErrorMessage, e.ExecutionTimeMs, e.UpdatedAt)
	return err
}

// GetExecution loads one execution.
func (r *ResponseEngineRepository) GetExecution(ctx context.Context, id uuid.UUID) (*ExecutionRecord, error) {
	e, err := scanExecution(r.pool.QueryRow(ctx, `SELECT `+executionColumns+` FROM playbook_executions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// ListExecutions returns recent executions, newest first.
func (r *ResponseEngineRepository) ListExecutions(ctx context.Context, f ExecutionListFilter) ([]*ExecutionRecord, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT ` + executionColumns + ` FROM playbook_executions WHERE 1=1`
	args := []any{}
	if f.AlertID != nil {
		args = append(args, *f.AlertID)
		q += fmt.Sprintf(" AND alert_id = $%d", len(args))
	}
	if f.PlaybookID != nil {
		args = append(args, *f.PlaybookID)
		q += fmt.Sprintf(" AND playbook_id = $%d", len(args))
	}
	if f.AgentID != nil {
		args = append(args, *f.AgentID)
		q += fmt.Sprintf(" AND agent_id = $%d", len(args))
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d", len(args))

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ExecutionRecord{}
	for rows.Next() {
		e, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// FailOrphanedExecutions marks runs left "running" by a previous process
// (crash/restart) as failed, so they do not appear active forever.
func (r *ResponseEngineRepository) FailOrphanedExecutions(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := r.pool.Exec(ctx, `
		UPDATE playbook_executions
		SET status = 'failed', completed_at = now(), updated_at = now(),
		    error_message = 'interrupted: the server restarted while this playbook was running'
		WHERE status IN ('pending', 'running')
		  AND COALESCE(updated_at, started_at) < now() - make_interval(secs => $1)`, olderThan.Seconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
