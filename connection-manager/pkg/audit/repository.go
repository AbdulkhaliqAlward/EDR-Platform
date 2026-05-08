// Package audit provides the repository for querying security events.
package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecurityEventFilter specifies query filters for listing security events.
type SecurityEventFilter struct {
	EventType string
	Severity  string
	ActorID   *uuid.UUID
	Since     *time.Time
	Until     *time.Time
	Limit     int
	Offset    int
}

// SeveritySummaryRow holds one row from the 24-hour summary.
type SeveritySummaryRow struct {
	EventType string `json:"event_type"`
	Severity  string `json:"severity"`
	Count     int64  `json:"count"`
}

// Repository provides read access to security_events.
type Repository struct {
	pool *pgxpool.Pool
}

// NewRepository creates a new security events repository.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// List returns a paginated list of security events, newest first.
func (r *Repository) List(ctx context.Context, f SecurityEventFilter) ([]Event, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 500 {
		f.Limit = 500
	}

	where := []string{"1=1"}
	args := []interface{}{}
	n := 1

	if f.EventType != "" {
		where = append(where, fmt.Sprintf("event_type = $%d", n))
		args = append(args, f.EventType)
		n++
	}
	if f.Severity != "" {
		where = append(where, fmt.Sprintf("severity = $%d", n))
		args = append(args, f.Severity)
		n++
	}
	if f.ActorID != nil {
		where = append(where, fmt.Sprintf("actor_id = $%d", n))
		args = append(args, f.ActorID.String())
		n++
	}
	if f.Since != nil {
		where = append(where, fmt.Sprintf("created_at >= $%d", n))
		args = append(args, *f.Since)
		n++
	}
	if f.Until != nil {
		where = append(where, fmt.Sprintf("created_at <= $%d", n))
		args = append(args, *f.Until)
		n++
	}

	q := fmt.Sprintf(`
		SELECT id, event_type, severity, actor_id, actor_name, target_id, target_type,
		       ip_address, user_agent, description, metadata, created_at
		FROM security_events
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		strings.Join(where, " AND "), n, n+1)
	args = append(args, f.Limit, f.Offset)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var actorID, targetID *string
		var metaJSON string
		if err := rows.Scan(
			&e.ID, &e.EventType, &e.Severity,
			&actorID, &e.ActorName,
			&targetID, &e.TargetType,
			&e.IPAddress, &e.UserAgent, &e.Description,
			&metaJSON, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		if actorID != nil {
			if uid, err := uuid.Parse(*actorID); err == nil {
				e.ActorID = &uid
			}
		}
		if targetID != nil {
			if uid, err := uuid.Parse(*targetID); err == nil {
				e.TargetID = &uid
			}
		}
		// Metadata is already string->string in storage
		out = append(out, e)
	}
	return out, rows.Err()
}

// Summary returns counts of events grouped by event_type and severity
// for the last 24 hours.
func (r *Repository) Summary(ctx context.Context) ([]SeveritySummaryRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT event_type, severity, COUNT(*) AS cnt
		FROM security_events
		WHERE created_at >= NOW() - INTERVAL '24 hours'
		GROUP BY event_type, severity
		ORDER BY cnt DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SeveritySummaryRow
	for rows.Next() {
		var row SeveritySummaryRow
		if err := rows.Scan(&row.EventType, &row.Severity, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
