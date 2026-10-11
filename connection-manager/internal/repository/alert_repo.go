// Package repository provides Alert repository implementation.
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

// AlertRepository defines the interface for alert storage.
type AlertRepository interface {
	Create(ctx context.Context, alert *models.Alert) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Alert, error)
	Update(ctx context.Context, alert *models.Alert) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, filter AlertFilter) ([]*models.Alert, int, error)
	GetStats(ctx context.Context) (*AlertStats, error)
	// GetEndpointRiskSummary returns per-agent risk posture ordered by peak risk score DESC.
	// Added for Phase 2 Endpoint Risk Intelligence page.
	GetEndpointRiskSummary(ctx context.Context, since time.Time) ([]*models.EndpointRiskSummary, error)
}

// AlertFilter for querying alerts.
type AlertFilter struct {
	AgentID    *uuid.UUID
	Status     []models.AlertStatus
	Severity   []models.AlertSeverity
	AssignedTo *uuid.UUID
	RuleID     string
	FromTime   *time.Time
	ToTime     *time.Time
	Search     string
	Limit      int
	Offset     int
	SortBy     string
	SortOrder  string
}

// AlertStats contains alert statistics.
type AlertStats struct {
	Total         int            `json:"total"`
	Alerts24h     int            `json:"alerts_24h"`
	AvgConfidence float64        `json:"avg_confidence"`
	Open          int            `json:"open"`
	InProgress    int            `json:"in_progress"`
	Resolved      int            `json:"resolved"`
	ByStatus      map[string]int `json:"by_status"`
	BySeverity    map[string]int `json:"by_severity"`
}

// PostgresAlertRepository implements AlertRepository using PostgreSQL.
type PostgresAlertRepository struct {
	db *pgxpool.Pool
}

// NewPostgresAlertRepository creates a new alert repository.
func NewPostgresAlertRepository(db *pgxpool.Pool) *PostgresAlertRepository {
	return &PostgresAlertRepository{db: db}
}

// Create inserts a new alert.
func (r *PostgresAlertRepository) Create(ctx context.Context, alert *models.Alert) error {
	if alert.ID == uuid.Nil {
		alert.ID = uuid.New()
	}
	if alert.DetectedAt.IsZero() {
		alert.DetectedAt = time.Now()
	}

	contextSnapshotJSON, _ := json.Marshal(alert.ContextSnapshot)
	scoreBreakdownJSON, _ := json.Marshal(alert.ScoreBreakdown)
	if len(contextSnapshotJSON) == 0 || string(contextSnapshotJSON) == "null" {
		contextSnapshotJSON = []byte(`{}`)
	}
	if len(scoreBreakdownJSON) == 0 || string(scoreBreakdownJSON) == "null" {
		scoreBreakdownJSON = []byte(`{}`)
	}

	query := `
		INSERT INTO alerts (
			id, severity, title, description, agent_id, rule_id, rule_name,
			status, assigned_to, event_count, first_event_at, last_event_at,
			detected_at, tags, metadata, notes,
			risk_score, context_snapshot, score_breakdown, false_positive_risk
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		RETURNING created_at, updated_at`

	return r.db.QueryRow(ctx, query,
		alert.ID, alert.Severity, alert.Title, alert.Description,
		alert.AgentID, alert.RuleID, alert.RuleName, alert.Status,
		alert.AssignedTo, alert.EventCount, alert.FirstEventAt,
		alert.LastEventAt, alert.DetectedAt, alert.Tags, alert.Metadata, alert.Notes,
		alert.RiskScore, contextSnapshotJSON, scoreBreakdownJSON, alert.FalsePositiveRisk,
	).Scan(&alert.CreatedAt, &alert.UpdatedAt)
}

// GetByID retrieves an alert by ID.
func (r *PostgresAlertRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Alert, error) {
	query := `
		SELECT id, severity, title, description, agent_id, rule_id, rule_name,
			status, assigned_to, resolution, resolution_notes, event_count,
			first_event_at, last_event_at, detected_at, acknowledged_at,
			resolved_at, created_at, updated_at, tags, metadata, notes,
			risk_score, context_snapshot, score_breakdown, false_positive_risk
		FROM alerts WHERE id = $1`

	alert := &models.Alert{}
	var contextSnapshotJSON, scoreBreakdownJSON []byte
	err := r.db.QueryRow(ctx, query, id).Scan(
		&alert.ID, &alert.Severity, &alert.Title, &alert.Description,
		&alert.AgentID, &alert.RuleID, &alert.RuleName, &alert.Status,
		&alert.AssignedTo, &alert.Resolution, &alert.ResolutionNotes,
		&alert.EventCount, &alert.FirstEventAt, &alert.LastEventAt,
		&alert.DetectedAt, &alert.AcknowledgedAt, &alert.ResolvedAt,
		&alert.CreatedAt, &alert.UpdatedAt, &alert.Tags, &alert.Metadata, &alert.Notes,
		&alert.RiskScore, &contextSnapshotJSON, &scoreBreakdownJSON, &alert.FalsePositiveRisk,
	)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err == nil {
		if len(contextSnapshotJSON) > 0 {
			alert.ContextSnapshot = json.RawMessage(contextSnapshotJSON)
		}
		if len(scoreBreakdownJSON) > 0 {
			alert.ScoreBreakdown = json.RawMessage(scoreBreakdownJSON)
		}
	}
	return alert, err
}

// Update updates an existing alert.
func (r *PostgresAlertRepository) Update(ctx context.Context, alert *models.Alert) error {
	query := `
		UPDATE alerts SET
			severity = $2, title = $3, description = $4, status = $5,
			assigned_to = $6, resolution = $7, resolution_notes = $8,
			event_count = $9, acknowledged_at = $10, resolved_at = $11,
			tags = $12, metadata = $13, notes = $14
		WHERE id = $1
		RETURNING updated_at`

	err := r.db.QueryRow(ctx, query,
		alert.ID, alert.Severity, alert.Title, alert.Description, alert.Status,
		alert.AssignedTo, alert.Resolution, alert.ResolutionNotes,
		alert.EventCount, alert.AcknowledgedAt, alert.ResolvedAt,
		alert.Tags, alert.Metadata, alert.Notes,
	).Scan(&alert.UpdatedAt)

	if err == pgx.ErrNoRows {
		return ErrNotFound
	}
	return err
}

// Delete removes an alert.
func (r *PostgresAlertRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.Exec(ctx, "DELETE FROM alerts WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// List retrieves alerts with filtering.
func (r *PostgresAlertRepository) List(ctx context.Context, filter AlertFilter) ([]*models.Alert, int, error) {
	// Build query
	baseQuery := "FROM alerts WHERE 1=1"
	var args []interface{}
	argNum := 1

	if filter.AgentID != nil {
		baseQuery += fmt.Sprintf(" AND agent_id = $%d", argNum)
		args = append(args, *filter.AgentID)
		argNum++
	}

	if len(filter.Status) > 0 {
		baseQuery += fmt.Sprintf(" AND status = ANY($%d)", argNum)
		args = append(args, filter.Status)
		argNum++
	}

	if len(filter.Severity) > 0 {
		baseQuery += fmt.Sprintf(" AND severity = ANY($%d)", argNum)
		args = append(args, filter.Severity)
		argNum++
	}

	if filter.Search != "" {
		baseQuery += fmt.Sprintf(" AND (title ILIKE $%d OR description ILIKE $%d)", argNum, argNum)
		args = append(args, "%"+filter.Search+"%")
		argNum++
	}

	if filter.FromTime != nil {
		baseQuery += fmt.Sprintf(" AND detected_at >= $%d", argNum)
		args = append(args, *filter.FromTime)
		argNum++
	}

	if filter.ToTime != nil {
		baseQuery += fmt.Sprintf(" AND detected_at <= $%d", argNum)
		args = append(args, *filter.ToTime)
		argNum++
	}

	// Count total
	var total int
	err := r.db.QueryRow(ctx, "SELECT COUNT(*) "+baseQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Add sorting and pagination
	sortBy := "detected_at"
	sortOrder := "DESC"
	if filter.SortBy != "" {
		sortBy = filter.SortBy
	}
	if filter.SortOrder != "" {
		sortOrder = filter.SortOrder
	}

	query := fmt.Sprintf(`
		SELECT id, severity, title, description, agent_id, rule_id, rule_name,
			status, assigned_to, event_count, detected_at, created_at, updated_at,
			risk_score, context_snapshot, score_breakdown, false_positive_risk
		%s ORDER BY %s %s LIMIT $%d OFFSET $%d`,
		baseQuery, sortBy, sortOrder, argNum, argNum+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var alerts []*models.Alert
	for rows.Next() {
		alert := &models.Alert{}
		var contextSnapshotJSON, scoreBreakdownJSON []byte
		if err := rows.Scan(
			&alert.ID, &alert.Severity, &alert.Title, &alert.Description,
			&alert.AgentID, &alert.RuleID, &alert.RuleName, &alert.Status,
			&alert.AssignedTo, &alert.EventCount, &alert.DetectedAt,
			&alert.CreatedAt, &alert.UpdatedAt,
			&alert.RiskScore, &contextSnapshotJSON, &scoreBreakdownJSON, &alert.FalsePositiveRisk,
		); err != nil {
			return nil, 0, err
		}
		if len(contextSnapshotJSON) > 0 {
			alert.ContextSnapshot = json.RawMessage(contextSnapshotJSON)
		}
		if len(scoreBreakdownJSON) > 0 {
			alert.ScoreBreakdown = json.RawMessage(scoreBreakdownJSON)
		}
		alerts = append(alerts, alert)
	}

	return alerts, total, nil
}

// GetStats returns aggregated statistics for all alerts.
func (r *PostgresAlertRepository) GetStats(ctx context.Context) (*AlertStats, error) {
	stats := &AlertStats{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	query := `
		SELECT 
			COUNT(*),
			COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours'),
			COALESCE(AVG(risk_score), 0),
			COUNT(*) FILTER (WHERE status = 'open'),
			COUNT(*) FILTER (WHERE status = 'in_progress'),
			COUNT(*) FILTER (WHERE status = 'resolved')
		FROM alerts
	`
	err := r.db.QueryRow(ctx, query).Scan(
		&stats.Total,
		&stats.Alerts24h,
		&stats.AvgConfidence,
		&stats.Open,
		&stats.InProgress,
		&stats.Resolved,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to count alerts stats: %w", err)
	}

	stats.ByStatus["open"] = stats.Open
	stats.ByStatus["in_progress"] = stats.InProgress
	stats.ByStatus["resolved"] = stats.Resolved

	// Get severity breakdown
	sevQuery := `SELECT severity, COUNT(*) FROM alerts GROUP BY severity`
	rows, err := r.db.Query(ctx, sevQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get severity stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			continue
		}
		stats.BySeverity[sev] = count
	}

	return stats, nil
}
// GetEndpointRiskSummary returns a per-endpoint risk posture summary ordered by peak_risk_score DESC.
// It canonicalizes historical alert rows to the current logical endpoint identity to avoid duplicate
// rows after re-enrollment (where agent UUID rotates but hostname remains the same).
//
// Canonicalization strategy:
//   1) Direct match: sigma_alerts.agent_id == agents.id
//   2) Re-enrollment bridge: sigma_alerts.agent_id == agents.metadata.previous_agent_id
//
// Alerts that map to no existing (non-deleted) agent are excluded: a removed
// endpoint leaves the board. since bounds how recently an alert must have been
// active (last_seen_at) to count.
func (r *PostgresAlertRepository) GetEndpointRiskSummary(ctx context.Context, since time.Time) ([]*models.EndpointRiskSummary, error) {
	// Only alerts that still need attention count toward risk:
	//   - active statuses only (suppressed / resolved / false_positive / closed
	//     never inflate an endpoint's score);
	//   - active within the window (last_seen_at, so a recurring alert stays
	//     current while a stale one ages out);
	//   - the endpoint must exist and not be deleted: removing an agent removes
	//     it from the board. Re-enrolled agents inherit alerts filed under
	//     their previous_agent_id.
	// Tiers match the engine's risk levels: critical >= 90, high 70-89, medium 40-69.
	query := `
		WITH mapped AS (
			SELECT
				COALESCE(curr.id, prev.id)            AS agent_uuid,
				sa.risk_score,
				sa.status,
				COALESCE(sa.last_seen_at, sa.timestamp) AS seen_at
			FROM sigma_alerts sa
			LEFT JOIN agents curr ON curr.id::text = sa.agent_id
			LEFT JOIN agents prev ON curr.id IS NULL AND prev.metadata->>'previous_agent_id' = sa.agent_id
			WHERE sa.status IN ('open', 'acknowledged', 'in_progress', 'investigating')
			  AND COALESCE(sa.last_seen_at, sa.timestamp) >= $1
		)
		SELECT
			a.id::text,
			COUNT(*)                                                   AS total_alerts,
			MAX(m.risk_score)                                          AS peak_risk_score,
			ROUND(AVG(m.risk_score)::numeric, 1)::float8               AS avg_risk_score,
			COUNT(*) FILTER (WHERE m.risk_score >= 90)                 AS critical_count,
			COUNT(*) FILTER (WHERE m.risk_score >= 70 AND m.risk_score < 90) AS high_count,
			COUNT(*) FILTER (WHERE m.risk_score >= 40 AND m.risk_score < 70) AS medium_count,
			COUNT(*) FILTER (WHERE m.status = 'open')                  AS open_count,
			MAX(m.seen_at)                                             AS last_alert_at,
			COALESCE(a.hostname, ''), COALESCE(a.os_type, ''), COALESCE(a.status, ''),
			COALESCE(a.metadata->>'device_criticality', ''), COALESCE(a.metadata->>'role_risk', ''),
			COALESCE(a.metadata->>'network_anomaly', '')
		FROM mapped m
		JOIN agents a ON a.id = m.agent_uuid AND a.status <> 'deleted'
		GROUP BY a.id
		ORDER BY peak_risk_score DESC, critical_count DESC, high_count DESC, a.id
		LIMIT 5000`

	rows, err := r.db.Query(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("endpoint risk summary query failed: %w", err)
	}
	defer rows.Close()

	var summaries []*models.EndpointRiskSummary
	for rows.Next() {
		s := &models.EndpointRiskSummary{}
		var avgRisk float64
		if err := rows.Scan(
			&s.AgentID,
			&s.TotalAlerts,
			&s.PeakRiskScore,
			&avgRisk,
			&s.CriticalCount,
			&s.HighCount,
			&s.MediumCount,
			&s.OpenCount,
			&s.LastAlertAt,
			&s.Hostname, &s.OSType, &s.AgentStatus,
			&s.DeviceCriticality, &s.RoleRisk, &s.NetworkAnomaly,
		); err != nil {
			return nil, fmt.Errorf("endpoint risk summary scan failed: %w", err)
		}
		s.AvgRiskScore = avgRisk
		summaries = append(summaries, s)
	}
	if summaries == nil {
		summaries = []*models.EndpointRiskSummary{}
	}
	return summaries, rows.Err()
}
