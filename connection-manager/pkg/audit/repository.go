// Package audit provides the repository for querying security events.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/edr-platform/shared/pagination"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecurityEventFilter specifies query filters for listing security events.
type SecurityEventFilter struct {
	Page      *pagination.Params
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
	ctx, cancel := context.WithTimeout(ctx, pagination.QueryTimeout)
	defer cancel()
	p := f.Page
	if p == nil {
		q := url.Values{}
		if f.Limit > 0 {
			q.Set("limit", fmt.Sprint(f.Limit))
		}
		if f.Offset != 0 {
			return nil, fmt.Errorf("security events require cursor pagination")
		}
		parsed, err := pagination.Parse(q, pagination.Options{Scope: "security/events", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}})
		if err != nil {
			return nil, err
		}
		p = &parsed
	}
	from, until := p.From, p.Until
	if f.Since != nil {
		from = *f.Since
	}
	if f.Until != nil && f.Until.Before(until) {
		until = *f.Until
	}
	args := []any{from, until}
	where := " WHERE created_at >= $1 AND created_at <= $2"
	add := func(column string, value any) {
		args = append(args, value)
		where += fmt.Sprintf(" AND %s = $%d", column, len(args))
	}
	if f.EventType != "" {
		add("event_type", f.EventType)
	}
	if f.Severity != "" {
		add("severity", f.Severity)
	}
	if f.ActorID != nil {
		add("actor_id", *f.ActorID)
	}
	seek, order, err := p.Keyset("created_at", "id", &args)
	if err != nil {
		return nil, err
	}
	args = append(args, p.Limit+1)
	rows, err := r.pool.Query(ctx, `SELECT id,event_type,severity,actor_id,actor_name,target_id,target_type,ip_address,''::text,left(description,256),'{}'::jsonb,created_at FROM security_events`+where+seek+" ORDER BY "+order+fmt.Sprintf(" LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *event)
	}
	return out, rows.Err()
}

func scanEvent(row interface{ Scan(...any) error }) (*Event, error) {
	var event Event
	var metadata []byte
	if err := row.Scan(&event.ID, &event.EventType, &event.Severity, &event.ActorID, &event.ActorName, &event.TargetID, &event.TargetType, &event.IPAddress, &event.UserAgent, &event.Description, &metadata, &event.CreatedAt); err != nil {
		return nil, err
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
			return nil, err
		}
	}
	return &event, nil
}

func (r *Repository) GetByID(ctx context.Context, id uuid.UUID) (*Event, error) {
	ctx, cancel := context.WithTimeout(ctx, pagination.QueryTimeout)
	defer cancel()
	return scanEvent(r.pool.QueryRow(ctx, `SELECT id,event_type,severity,actor_id,actor_name,target_id,target_type,ip_address,user_agent,description,metadata,created_at FROM security_events WHERE id=$1`, id))
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
