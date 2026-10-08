package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ExceptionCondition is one field test of a detection exception.
type ExceptionCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// DetectionException suppresses known-benign matches of a Sigma rule (table
// detection_exceptions, owned by the sigma engine which applies it).
type DetectionException struct {
	ID            uuid.UUID            `json:"id"`
	Name          string               `json:"name"`
	RuleID        string               `json:"rule_id"` // "" = every rule
	RuleTitle     string               `json:"rule_title"`
	AgentID       string               `json:"agent_id"` // "" = every endpoint
	Hostname      string               `json:"hostname"`
	Conditions    []ExceptionCondition `json:"conditions"`
	Reason        string               `json:"reason"`
	Enabled       bool                 `json:"enabled"`
	ExpiresAt     *time.Time           `json:"expires_at,omitempty"`
	SourceAlertID *uuid.UUID           `json:"source_alert_id,omitempty"`
	CreatedBy     string               `json:"created_by"`
	CreatedAt     time.Time            `json:"created_at"`
	UpdatedAt     time.Time            `json:"updated_at"`
	HitCount      int64                `json:"hit_count"`
	LastHitAt     *time.Time           `json:"last_hit_at,omitempty"`
}

// DetectionExceptionRepository persists detection exceptions.
type DetectionExceptionRepository struct {
	pool *pgxpool.Pool
}

// NewDetectionExceptionRepository creates the repository.
func NewDetectionExceptionRepository(pool *pgxpool.Pool) *DetectionExceptionRepository {
	return &DetectionExceptionRepository{pool: pool}
}

const exceptionColumns = `id, name, COALESCE(rule_id, ''), rule_title, COALESCE(agent_id, ''), hostname, conditions,
	reason, enabled, expires_at, source_alert_id, created_by, created_at, updated_at, hit_count, last_hit_at`

func scanException(row pgx.Row) (*DetectionException, error) {
	var e DetectionException
	var conds []byte
	if err := row.Scan(&e.ID, &e.Name, &e.RuleID, &e.RuleTitle, &e.AgentID, &e.Hostname, &conds, &e.Reason,
		&e.Enabled, &e.ExpiresAt, &e.SourceAlertID, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt, &e.HitCount, &e.LastHitAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(conds, &e.Conditions); err != nil {
		e.Conditions = []ExceptionCondition{}
	}
	return &e, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// List returns exceptions, newest first.
func (r *DetectionExceptionRepository) List(ctx context.Context) ([]*DetectionException, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+exceptionColumns+` FROM detection_exceptions ORDER BY created_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DetectionException{}
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get loads one exception.
func (r *DetectionExceptionRepository) Get(ctx context.Context, id uuid.UUID) (*DetectionException, error) {
	e, err := scanException(r.pool.QueryRow(ctx, `SELECT `+exceptionColumns+` FROM detection_exceptions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// Create inserts an exception.
func (r *DetectionExceptionRepository) Create(ctx context.Context, e *DetectionException) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	conds, err := json.Marshal(e.Conditions)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	e.CreatedAt, e.UpdatedAt = now, now
	_, err = r.pool.Exec(ctx, `
		INSERT INTO detection_exceptions (id, name, rule_id, rule_title, agent_id, hostname, conditions, reason,
			enabled, expires_at, source_alert_id, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12, $13, $14)`,
		e.ID, e.Name, nullable(e.RuleID), e.RuleTitle, nullable(e.AgentID), e.Hostname, string(conds), e.Reason,
		e.Enabled, e.ExpiresAt, e.SourceAlertID, e.CreatedBy, e.CreatedAt, e.UpdatedAt)
	return err
}

// Update stores the mutable fields (enabled, expiry, reason).
func (r *DetectionExceptionRepository) Update(ctx context.Context, e *DetectionException) error {
	e.UpdatedAt = time.Now().UTC()
	tag, err := r.pool.Exec(ctx, `
		UPDATE detection_exceptions SET enabled = $2, expires_at = $3, reason = $4, updated_at = $5 WHERE id = $1`,
		e.ID, e.Enabled, e.ExpiresAt, e.Reason, e.UpdatedAt)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Delete removes an exception.
func (r *DetectionExceptionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM detection_exceptions WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
