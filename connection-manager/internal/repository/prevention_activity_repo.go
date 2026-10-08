package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type PreventionActivity struct {
	EventRow
	IngestedAt time.Time
}

type PreventionActivityFilter struct {
	From, Through time.Time
	AfterAt       *time.Time
	AfterID       *uuid.UUID
	Limit         int
}

type PreventionActivityRepository interface {
	ListPreventionActivity(context.Context, PreventionActivityFilter) ([]PreventionActivity, error)
}

// The activity feed follows ingestion time, so a prevention event buffered on
// an offline endpoint is visible when it arrives, regardless of event time.
func (r *PostgresEventRepository) ListPreventionActivity(ctx context.Context, f PreventionActivityFilter) ([]PreventionActivity, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 200
	}
	rows, err := r.db.Query(ctx, `SELECT id, agent_id, event_type, severity, ts, summary, raw, created_at
		FROM events WHERE created_at >= $1 AND created_at <= $2
		AND COALESCE(raw->'data'->>'autonomous', raw->>'autonomous') = 'true'
		AND ($3::timestamptz IS NULL OR (created_at, id) > ($3::timestamptz, $4::uuid))
		ORDER BY created_at ASC, id ASC LIMIT $5`, f.From, f.Through, f.AfterAt, f.AfterID, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PreventionActivity{}
	for rows.Next() {
		var row PreventionActivity
		if err := rows.Scan(&row.ID, &row.AgentID, &row.EventType, &row.Severity, &row.Timestamp, &row.Summary, &row.Raw, &row.IngestedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
