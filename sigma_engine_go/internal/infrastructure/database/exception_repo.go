package database

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/sigma-engine/internal/application/detection"
)

// ExceptionRepository reads detection exceptions (managed by the Connection
// Manager) and records how often each one suppressed a match.
type ExceptionRepository struct {
	pool *pgxpool.Pool
}

// NewExceptionRepository creates the repository.
func NewExceptionRepository(pool *pgxpool.Pool) *ExceptionRepository {
	return &ExceptionRepository{pool: pool}
}

// LoadExceptions returns the enabled, unexpired exceptions.
func (r *ExceptionRepository) LoadExceptions(ctx context.Context) ([]detection.DetectionException, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, COALESCE(rule_id, ''), COALESCE(agent_id, ''), conditions, expires_at
		FROM detection_exceptions
		WHERE enabled AND (expires_at IS NULL OR expires_at > now())`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []detection.DetectionException
	for rows.Next() {
		var ex detection.DetectionException
		var conds []byte
		var exp *time.Time
		if err := rows.Scan(&ex.ID, &ex.RuleID, &ex.AgentID, &conds, &exp); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(conds, &ex.Conditions); err != nil {
			continue // malformed row: never suppress on it
		}
		ex.ExpiresAt = exp
		out = append(out, ex)
	}
	return out, rows.Err()
}

// RecordExceptionHits adds suppression counts.
func (r *ExceptionRepository) RecordExceptionHits(ctx context.Context, hits map[string]int64) error {
	return r.RecordExceptionHitBatch(ctx, uuid.NewString(), hits)
}

func (r *ExceptionRepository) RecordExceptionHitBatch(ctx context.Context, batchID string, hits map[string]int64) error {
	if len(hits) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `INSERT INTO detection_exception_hit_batches(id) VALUES($1::uuid) ON CONFLICT DO NOTHING`, batchID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM detection_exception_hit_batches WHERE created_at < now() - interval '30 days'`); err != nil {
		return err
	}
	ids := make([]string, 0, len(hits))
	for id := range hits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := hits[id]
		if n <= 0 {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE detection_exceptions SET hit_count = hit_count + $2, last_hit_at = now()
			WHERE id = $1::uuid`, id, n); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
