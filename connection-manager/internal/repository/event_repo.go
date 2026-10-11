package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/edr-platform/shared/pagination"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EventRow is the event row returned by search/list APIs.
// Raw is included so callers can extract typed fields (action, name, pid, etc.).
type EventRow struct {
	CreatedAt time.Time
	ID        uuid.UUID
	AgentID   uuid.UUID
	EventType string
	Severity  string
	Timestamp time.Time
	Summary   string
	Raw       json.RawMessage
}

// EventInsert is an insert payload (parsed/normalized from ingestion).
type EventInsert struct {
	ID        uuid.UUID
	AgentID   uuid.UUID
	BatchID   *uuid.UUID
	EventType string
	Severity  string
	Timestamp time.Time
	Summary   string
	Raw       json.RawMessage
}

// EventSearchFilter matches API EventFilter shape.
type EventSearchFilter struct {
	Field    string
	Operator string
	Value    interface{}
}

// EventSearchRequest matches API EventSearchRequest (without importing api package).
type EventSearchRequest struct {
	Page     *pagination.Params
	Filters  []EventSearchFilter
	Logic    string // AND/OR
	TimeFrom time.Time
	TimeTo   time.Time
	Limit    int
	Offset   int
}

// EventDetail is one row from `events` including JSONB raw.
type EventDetail struct {
	ID        uuid.UUID
	AgentID   uuid.UUID
	EventType string
	Severity  string
	Timestamp time.Time
	Summary   string
	Raw       json.RawMessage
}

type EventRepository interface {
	InsertMany(ctx context.Context, rows []EventInsert) error
	Search(ctx context.Context, req EventSearchRequest) ([]EventRow, int, error)
	ListByAgent(ctx context.Context, agentID uuid.UUID, limit, offset int) ([]EventRow, int, error)
	GetByID(ctx context.Context, id uuid.UUID) (*EventDetail, error)
}

type PostgresEventRepository struct {
	db *pgxpool.Pool
}

func NewPostgresEventRepository(db *pgxpool.Pool) *PostgresEventRepository {
	return &PostgresEventRepository{db: db}
}

func (r *PostgresEventRepository) InsertMany(ctx context.Context, rows []EventInsert) error {
	if len(rows) == 0 {
		return nil
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	b := &strings.Builder{}
	args := make([]interface{}, 0, len(rows)*8)
	b.WriteString("INSERT INTO events (id, agent_id, batch_id, event_type, severity, ts, summary, raw) VALUES ")
	for i, e := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		// 8 cols per row
		p := i*8 + 1
		fmt.Fprintf(b, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", p, p+1, p+2, p+3, p+4, p+5, p+6, p+7)
		args = append(args, e.ID, e.AgentID, e.BatchID, e.EventType, e.Severity, e.Timestamp, e.Summary, e.Raw)
	}
	b.WriteString(" ON CONFLICT (id) DO NOTHING")

	if _, err := tx.Exec(ctx, b.String(), args...); err != nil {
		return fmt.Errorf("insert events: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (r *PostgresEventRepository) ListByAgent(ctx context.Context, agentID uuid.UUID, limit, offset int) ([]EventRow, int, error) {
	if offset != 0 {
		return nil, 0, fmt.Errorf("offset is unsupported; use cursor")
	}
	return r.Search(ctx, EventSearchRequest{Limit: limit, Filters: []EventSearchFilter{{Field: "agent_id", Operator: "equals", Value: agentID.String()}}})
}

func (r *PostgresEventRepository) Search(ctx context.Context, req EventSearchRequest) ([]EventRow, int, error) {
	ctx, cancel := context.WithTimeout(ctx, pagination.QueryTimeout)
	defer cancel()
	p := req.Page
	if p == nil {
		q := url.Values{}
		if req.Limit > 0 {
			q.Set("limit", fmt.Sprint(req.Limit))
		}
		if req.Offset != 0 {
			return nil, 0, fmt.Errorf("offset is unsupported; use cursor")
		}
		parsed, err := pagination.Parse(q, pagination.Options{Scope: "events", DefaultSort: "created_at", Sorts: map[string]string{"created_at": "created_at"}})
		if err != nil {
			return nil, 0, err
		}
		p = &parsed
	}
	if req.TimeFrom.IsZero() {
		req.TimeFrom = p.From
	}
	if req.TimeTo.IsZero() {
		req.TimeTo = p.Until
	}

	where := []string{"ts >= $1", "ts <= $2"}
	args := []interface{}{req.TimeFrom, req.TimeTo}

	add := func(clause string, v interface{}) {
		where = append(where, clause)
		args = append(args, v)
	}

	for _, f := range req.Filters {
		field := strings.TrimSpace(strings.ToLower(f.Field))
		op := strings.TrimSpace(strings.ToLower(f.Operator))
		argPos := len(args) + 1

		switch field {
		// ── Indexed top-level columns ─────────────────────────────────────
		case "agent_id", "event_type", "severity":
			switch op {
			case "equals":
				add(fmt.Sprintf("%s = $%d", field, argPos), f.Value)
			case "contains":
				add(fmt.Sprintf("%s ILIKE $%d", field, argPos), "%"+fmt.Sprint(f.Value)+"%")
			case "regex":
				add(fmt.Sprintf("%s ~* $%d", field, argPos), fmt.Sprint(f.Value))
			}

		// ── JSONB raw fields (data.*) ─────────────────────────────────────
		// Supported keys: data.autonomous, data.action, data.name, data.matched_rule_id, etc.
		default:
			if !strings.HasPrefix(field, "data.") {
				continue
			}
			key := strings.TrimPrefix(field, "data.")
			// Whitelist keys we allow for JSONB extraction (safety guard)
			allowedJSONB := map[string]bool{
				"autonomous": true, "action": true, "name": true,
				"matched_rule_id": true, "matched_rule_title": true,
				"response_action": true, "decision_mode": true,
				"pid": true, "user_name": true,
			}
			if !allowedJSONB[key] {
				continue
			}
			jsonPath := fmt.Sprintf("COALESCE(raw->'data'->>'%s', raw->>'%s')", key, key)
			switch op {
			case "equals":
				val := fmt.Sprint(f.Value)
				if b, ok := f.Value.(bool); ok {
					// boolean stored as JSON "true"/"false" string in JSONB text extraction
					if b {
						val = "true"
					} else {
						val = "false"
					}
				}
				add(fmt.Sprintf("%s = $%d", jsonPath, argPos), val)
			case "contains":
				add(fmt.Sprintf("%s ILIKE $%d", jsonPath, argPos), "%"+fmt.Sprint(f.Value)+"%")
			case "in":
				// Value should be a []string or []interface{}
				// Render as: raw->>'action' = ANY($n::text[])
				var vals []string
				switch v := f.Value.(type) {
				case []string:
					vals = v
				case []interface{}:
					for _, vi := range v {
						vals = append(vals, fmt.Sprint(vi))
					}
				}
				if len(vals) > 0 {
					add(fmt.Sprintf("%s = ANY($%d::text[])", jsonPath, argPos), vals)
				}
			}
		}
	}

	joiner := " AND "
	if strings.EqualFold(req.Logic, "OR") {
		if len(where) > 2 {
			head := where[:2]
			user := where[2:]
			where = []string{strings.Join(head, " AND "), "(" + strings.Join(user, " OR ") + ")"}
			joiner = " AND "
		}
	}

	w := strings.Join(where, joiner)
	args = append(args, p.Until)
	w += fmt.Sprintf(" AND created_at <= $%d", len(args))
	var total int
	if p.IncludeTotal {
		countQ := "SELECT count(*) FROM (SELECT 1 FROM events WHERE " + w + " LIMIT 10001) capped"
		if err := r.db.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("count events: %w", err)
		}
	}
	seek, order, err := p.Keyset("created_at", "id", &args)
	if err != nil {
		return nil, 0, err
	}
	args = append(args, p.Limit+1)
	dataQ := `SELECT id,agent_id,event_type,severity,ts,left(summary,1024),created_at,
  jsonb_strip_nulls(jsonb_build_object(
   'action',COALESCE(raw->'data'->>'action',raw->>'action'),
   'name',left(COALESCE(raw->'data'->>'name',raw->>'name'),512),
   'process_name',left(COALESCE(raw->'data'->>'process_name',raw->>'process_name'),512),
   'pid',COALESCE(raw->'data'->'pid',raw->'pid'),
   'autonomous',COALESCE(raw->'data'->'autonomous',raw->'autonomous'),
   'matched_rule_id',COALESCE(raw->'data'->>'matched_rule_id',raw->>'matched_rule_id'),
   'matched_rule_title',left(COALESCE(raw->'data'->>'matched_rule_title',raw->>'matched_rule_title'),512),
   'response_action',COALESCE(raw->'data'->>'response_action',raw->>'response_action'),
   'decision_mode',COALESCE(raw->'data'->>'decision_mode',raw->>'decision_mode')
  ))
  FROM events WHERE ` + w + seek + ` ORDER BY ` + order + fmt.Sprintf(" LIMIT $%d", len(args))

	rs, err := r.db.Query(ctx, dataQ, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search events: %w", err)
	}
	defer rs.Close()

	out := []EventRow{}
	for rs.Next() {
		var e EventRow
		if err := rs.Scan(&e.ID, &e.AgentID, &e.EventType, &e.Severity, &e.Timestamp, &e.Summary, &e.CreatedAt, &e.Raw); err != nil {
			return nil, 0, fmt.Errorf("scan event: %w", err)
		}
		out = append(out, e)
	}
	return out, total, rs.Err()
}

func (r *PostgresEventRepository) GetByID(ctx context.Context, id uuid.UUID) (*EventDetail, error) {
	const q = `
		SELECT id, agent_id, event_type, severity, ts, summary, raw
		FROM events
		WHERE id = $1`
	var d EventDetail
	err := r.db.QueryRow(ctx, q, id).Scan(
		&d.ID, &d.AgentID, &d.EventType, &d.Severity, &d.Timestamp, &d.Summary, &d.Raw,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get event: %w", err)
	}
	return &d, nil
}

// ProcessAggRow is an aggregated process execution row.
type ProcessAggRow struct {
	Name       string   `json:"name"`
	Executable string   `json:"executable"`
	Count      int      `json:"count"`
	AgentCount int      `json:"agent_count"`
	Hostnames  []string `json:"hostnames"`
	LastSeen   string   `json:"last_seen"`
}

// GetProcessAnalytics aggregates process events by name within a time window.
// This runs a SQL GROUP BY query on the server-side for efficient aggregation.
func (r *PostgresEventRepository) GetProcessAnalytics(ctx context.Context, hoursBack int) ([]ProcessAggRow, int, error) {
	if hoursBack <= 0 {
		hoursBack = 24
	}

	const q = `
		WITH per_name AS (
			SELECT
				LOWER(COALESCE(raw->'data'->>'name', raw->>'name', 'unknown')) AS proc_name,
				COALESCE(raw->'data'->>'executable', raw->>'executable', '') AS executable,
				COUNT(*) AS exec_count,
				COUNT(DISTINCT agent_id) AS agent_count,
				MAX(ts) AS last_seen
			FROM events
			WHERE event_type = 'process'
			  AND ts >= NOW() - ($1 || ' hours')::interval
			GROUP BY proc_name, executable
		),
		per_hosts AS (
			SELECT
				LOWER(COALESCE(e.raw->'data'->>'name', e.raw->>'name', 'unknown')) AS proc_name,
				ARRAY_AGG(DISTINCT a.hostname ORDER BY a.hostname) FILTER (WHERE a.hostname IS NOT NULL AND a.hostname <> '') AS hostnames
			FROM events e
			JOIN agents a ON a.id = e.agent_id
			WHERE e.event_type = 'process'
			  AND e.ts >= NOW() - ($1 || ' hours')::interval
			GROUP BY proc_name
		)
		SELECT
			per_name.proc_name AS proc_name,
			-- pick the longest (most specific) executable path per process name
			(array_agg(executable ORDER BY length(executable) DESC))[1] AS executable,
			SUM(exec_count)::bigint AS exec_count,
			SUM(agent_count)::bigint AS agent_count,
			COALESCE(ph.hostnames, ARRAY[]::text[]) AS hostnames,
			MAX(last_seen) AS last_seen
		FROM per_name
		LEFT JOIN per_hosts ph ON ph.proc_name = per_name.proc_name
		GROUP BY per_name.proc_name, ph.hostnames
		ORDER BY exec_count DESC
		LIMIT 500`

	rows, err := r.db.Query(ctx, q, fmt.Sprintf("%d", hoursBack))
	if err != nil {
		return nil, 0, fmt.Errorf("process analytics query: %w", err)
	}
	defer rows.Close()

	var out []ProcessAggRow
	for rows.Next() {
		var r ProcessAggRow
		var lastSeen time.Time
		if err := rows.Scan(&r.Name, &r.Executable, &r.Count, &r.AgentCount, &r.Hostnames, &lastSeen); err != nil {
			return nil, 0, fmt.Errorf("scan process agg: %w", err)
		}
		r.LastSeen = lastSeen.Format(time.RFC3339)
		out = append(out, r)
	}

	// Total raw events count
	var total int
	_ = r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM events WHERE event_type = 'process' AND ts >= NOW() - ($1 || ' hours')::interval`,
		fmt.Sprintf("%d", hoursBack)).Scan(&total)

	return out, total, nil
}

// SoftwareInventoryRow is an aggregated installed software row.
type SoftwareInventoryRow struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Publisher    string   `json:"publisher"`
	InstallDate  string   `json:"install_date"`
	AgentCount   int      `json:"agent_count"`
	Hostnames    []string `json:"hostnames"`
	LastReported string   `json:"last_reported"`
}

// GetSoftwareInventory aggregates software_inventory events by app name.
func (r *PostgresEventRepository) GetSoftwareInventory(ctx context.Context) ([]SoftwareInventoryRow, error) {
	const q = `
		WITH per_hosts AS (
			SELECT
				COALESCE(e.raw->'data'->>'name', e.raw->>'name', 'unknown') AS app_name,
				COALESCE(e.raw->'data'->>'version', e.raw->>'version', '') AS version,
				COALESCE(e.raw->'data'->>'publisher', e.raw->>'publisher', '') AS publisher,
				ARRAY_AGG(DISTINCT a.hostname ORDER BY a.hostname) FILTER (WHERE a.hostname IS NOT NULL AND a.hostname <> '') AS hostnames
			FROM events e
			JOIN agents a ON a.id = e.agent_id
			WHERE e.event_type = 'software_inventory'
			GROUP BY app_name, version, publisher
		)
		SELECT
			app_name,
			version,
			publisher,
			MAX(COALESCE(raw->'data'->>'install_date', '')) AS install_date,
			COUNT(DISTINCT agent_id) AS agent_count,
			COALESCE(ph.hostnames, ARRAY[]::text[]) AS hostnames,
			MAX(ts) AS last_reported
		FROM events e
		LEFT JOIN per_hosts ph
		  ON ph.app_name = COALESCE(e.raw->'data'->>'name', e.raw->>'name', 'unknown')
		 AND ph.version  = COALESCE(e.raw->'data'->>'version', e.raw->>'version', '')
		 AND ph.publisher = COALESCE(e.raw->'data'->>'publisher', e.raw->>'publisher', '')
		WHERE e.event_type = 'software_inventory'
		GROUP BY app_name, version, publisher, ph.hostnames
		ORDER BY agent_count DESC, app_name ASC
		LIMIT 1000`

	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("software inventory query: %w", err)
	}
	defer rows.Close()

	var out []SoftwareInventoryRow
	for rows.Next() {
		var r SoftwareInventoryRow
		var lastReported time.Time
		if err := rows.Scan(&r.Name, &r.Version, &r.Publisher, &r.InstallDate, &r.AgentCount, &r.Hostnames, &lastReported); err != nil {
			return nil, fmt.Errorf("scan software inv: %w", err)
		}
		r.LastReported = lastReported.Format(time.RFC3339)
		out = append(out, r)
	}

	return out, nil
}

// GetSoftwareInventoryByAgent returns software inventory rows for a single agent.
// This is used by the EndpointDetail "Software" tab to show per-endpoint inventory.
func (r *PostgresEventRepository) GetSoftwareInventoryByAgent(ctx context.Context, agentID uuid.UUID) ([]SoftwareInventoryRow, error) {
	const q = `
		SELECT
			COALESCE(raw->'data'->>'name', raw->>'name', 'unknown') AS app_name,
			COALESCE(raw->'data'->>'version', raw->>'version', '') AS version,
			COALESCE(raw->'data'->>'publisher', raw->>'publisher', '') AS publisher,
			MAX(COALESCE(raw->'data'->>'install_date', '')) AS install_date,
			1 AS agent_count,
			ARRAY[]::text[] AS hostnames,
			MAX(ts) AS last_reported
		FROM events
		WHERE event_type = 'software_inventory'
		  AND agent_id = $1
		GROUP BY app_name, version, publisher
		ORDER BY app_name ASC, version ASC
		LIMIT 5000`

	rows, err := r.db.Query(ctx, q, agentID)
	if err != nil {
		return nil, fmt.Errorf("software inventory by agent query: %w", err)
	}
	defer rows.Close()

	var out []SoftwareInventoryRow
	for rows.Next() {
		var r SoftwareInventoryRow
		var lastReported time.Time
		if err := rows.Scan(&r.Name, &r.Version, &r.Publisher, &r.InstallDate, &r.AgentCount, &r.Hostnames, &lastReported); err != nil {
			return nil, fmt.Errorf("scan software inv by agent: %w", err)
		}
		r.LastReported = lastReported.Format(time.RFC3339)
		out = append(out, r)
	}
	return out, nil
}

// BandwidthAggRow is an aggregated network-activity-per-application row.
// Note: the agent's network events (Sysmon EventID 3) do not include
// bytes_sent/bytes_received. We track connection counts and unique
// destinations as a proxy for bandwidth/activity.
type BandwidthAggRow struct {
	ProcessName        string   `json:"process_name"`
	Executable         string   `json:"executable"`
	BytesSent          int64    `json:"bytes_sent"`
	BytesReceived      int64    `json:"bytes_received"`
	TotalBytes         int64    `json:"total_bytes"`
	Connections        int      `json:"connections"`
	UniqueDestinations int      `json:"unique_destinations"`
	UniquePorts        int      `json:"unique_ports"`
	AgentCount         int      `json:"agent_count"`
	Hostnames          []string `json:"hostnames"`
	LastSeen           string   `json:"last_seen"`
}

// GetBandwidthAnalytics aggregates network events by process name within a time window.
// Since the ETW/Sysmon telemetry doesn't include byte counts, this uses connection
// count and unique destinations as activity metrics.
func (r *PostgresEventRepository) GetBandwidthAnalytics(ctx context.Context, hoursBack int) ([]BandwidthAggRow, error) {
	if hoursBack <= 0 {
		hoursBack = 24
	}

	const q = `
		WITH per_proc AS (
			SELECT
				LOWER(COALESCE(raw->'data'->>'process_name', raw->>'process_name', raw->'data'->>'name', raw->>'name', 'unknown')) AS proc_name,
				COALESCE(raw->'data'->>'executable', raw->>'executable', raw->'data'->>'Image', '') AS executable,
				COALESCE(raw->'data'->>'bytes_sent', '0') AS bs,
				COALESCE(raw->'data'->>'bytes_received', '0') AS br,
				COALESCE(raw->'data'->>'destination_ip', raw->'data'->>'DestinationIp', '') AS dest_ip,
				COALESCE(raw->'data'->>'destination_port', raw->'data'->>'DestinationPort', '') AS dest_port,
				agent_id,
				ts
			FROM events
			WHERE event_type = 'network'
			  AND ts >= NOW() - ($1 || ' hours')::interval
		),
		per_hosts AS (
			SELECT
				p.proc_name,
				ARRAY_AGG(DISTINCT a.hostname ORDER BY a.hostname) FILTER (WHERE a.hostname IS NOT NULL AND a.hostname <> '') AS hostnames
			FROM per_proc p
			JOIN agents a ON a.id = p.agent_id
			GROUP BY p.proc_name
		)
		SELECT
			per_proc.proc_name AS proc_name,
			(array_agg(executable ORDER BY length(executable) DESC))[1] AS executable,
			COALESCE(SUM(CASE WHEN bs ~ '^\d+$' THEN bs::bigint ELSE 0 END), 0) AS total_sent,
			COALESCE(SUM(CASE WHEN br ~ '^\d+$' THEN br::bigint ELSE 0 END), 0) AS total_received,
			COALESCE(SUM(CASE WHEN bs ~ '^\d+$' THEN bs::bigint ELSE 0 END), 0) +
			COALESCE(SUM(CASE WHEN br ~ '^\d+$' THEN br::bigint ELSE 0 END), 0) AS total_bytes,
			COUNT(*) AS connections,
			COUNT(DISTINCT dest_ip) AS unique_destinations,
			COUNT(DISTINCT dest_port) AS unique_ports,
			COUNT(DISTINCT agent_id) AS agent_count,
			COALESCE(ph.hostnames, ARRAY[]::text[]) AS hostnames,
			MAX(ts) AS last_seen
		FROM per_proc
		LEFT JOIN per_hosts ph ON ph.proc_name = per_proc.proc_name
		GROUP BY per_proc.proc_name, ph.hostnames
		ORDER BY connections DESC
		LIMIT 200`

	rows, err := r.db.Query(ctx, q, fmt.Sprintf("%d", hoursBack))
	if err != nil {
		return nil, fmt.Errorf("bandwidth analytics query: %w", err)
	}
	defer rows.Close()

	var out []BandwidthAggRow
	for rows.Next() {
		var r BandwidthAggRow
		var lastSeen time.Time
		if err := rows.Scan(
			&r.ProcessName, &r.Executable,
			&r.BytesSent, &r.BytesReceived, &r.TotalBytes,
			&r.Connections, &r.UniqueDestinations, &r.UniquePorts,
			&r.AgentCount, &r.Hostnames, &lastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan bandwidth agg: %w", err)
		}
		r.LastSeen = lastSeen.Format(time.RFC3339)
		out = append(out, r)
	}

	return out, nil
}
