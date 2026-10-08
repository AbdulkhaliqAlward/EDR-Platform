// Package database provides repository interfaces and models.
package database

import (
	"context"
	"time"
)

// =============================================================================
// Alert Models
// =============================================================================

// Alert represents a Sigma detection alert stored in the database.
type Alert struct {
	ID                 string                 `json:"id"`
	Timestamp          time.Time              `json:"timestamp"`
	AgentID            string                 `json:"agent_id"`
	RuleID             string                 `json:"rule_id"`
	RuleTitle          string                 `json:"rule_title"`
	Severity           string                 `json:"severity"`
	Category           string                 `json:"category"`
	EventCount         int                    `json:"event_count"`
	EventIDs           []string               `json:"event_ids"`
	MitreTactics       []string               `json:"mitre_tactics"`
	MitreTechniques    []string               `json:"mitre_techniques"`
	MatchedFields      map[string]interface{} `json:"matched_fields"`
	MatchedSelections  []string               `json:"matched_selections"`
	ContextData        map[string]interface{} `json:"context_data"`
	Status             string                 `json:"status"`
	AssignedTo         string                 `json:"assigned_to,omitempty"`
	ResolutionNotes    string                 `json:"resolution_notes,omitempty"`
	Confidence         *float64               `json:"confidence,omitempty"`
	FalsePositiveRisk  *float64               `json:"false_positive_risk,omitempty"`
	MatchCount         *int                   `json:"match_count,omitempty"`
	RelatedRuleIDs     []string               `json:"related_rule_ids,omitempty"`
	RelatedRules       []string               `json:"related_rules,omitempty"`
	CombinedConfidence *float64               `json:"combined_confidence,omitempty"`
	SeverityPromoted   *bool                  `json:"severity_promoted,omitempty"`
	OriginalSeverity   string                 `json:"original_severity,omitempty"`

	// Context-Aware Risk Scoring (Phase 1) — populated after migration 014
	RiskScore       int            `json:"risk_score"`
	ContextSnapshot map[string]any `json:"context_snapshot,omitempty"`
	ScoreBreakdown  map[string]any `json:"score_breakdown,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AlertFilters contains filter options for querying alerts.
type AlertFilters struct {
	AgentID   string
	RuleID    string
	Severity  []string
	Status    []string
	DateFrom  time.Time
	DateTo    time.Time
	Search    string
	Limit     int
	Offset    int
	SortBy    string
	SortOrder string
}

// AlertStats contains aggregate statistics for alerts.
type AlertStats struct {
	TotalAlerts   int64            `json:"total_alerts"`
	BySeverity    map[string]int64 `json:"by_severity"`
	ByStatus      map[string]int64 `json:"by_status"`
	ByRule        map[string]int64 `json:"by_rule"`
	ByAgent       map[string]int64 `json:"by_agent"`
	ByTactic      map[string]int64 `json:"by_tactic"`
	Last24Hours   int64            `json:"last_24h"`
	Last7Days     int64            `json:"last_7d"`
	AvgConfidence float64          `json:"avg_confidence"`
}

// TimelineDataPoint represents a single point in the alert timeline.
type TimelineDataPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	Critical      int64     `json:"critical"`
	High          int64     `json:"high"`
	Medium        int64     `json:"medium"`
	Low           int64     `json:"low"`
	Informational int64     `json:"informational"`
}

// AlertRepository defines the interface for alert data access.
type AlertRepository interface {
	// Create inserts a new alert into the database.
	Create(ctx context.Context, alert *Alert) (*Alert, error)

	// GetByID retrieves an alert by its ID.
	GetByID(ctx context.Context, id string) (*Alert, error)

	// List retrieves alerts matching the given filters.
	List(ctx context.Context, filters AlertFilters) ([]*Alert, int64, error)

	// Update updates an existing alert.
	Update(ctx context.Context, id string, alert *Alert) (*Alert, error)

	// UpdateStatus updates just the status of an alert.
	UpdateStatus(ctx context.Context, id string, status string, notes string) error

	// Delete removes an alert from the database.
	Delete(ctx context.Context, id string) error

	// GetStats retrieves aggregate alert statistics.
	GetStats(ctx context.Context) (*AlertStats, error)

	// GetTimeline retrieves timeline data for the alert chart.
	GetTimeline(ctx context.Context, from, to, granularity string) ([]*TimelineDataPoint, error)

	// UpsertWithDedup atomically inserts a new alert or increments the
	// event_count of an existing alert within the deduplication window.
	// Returns (alert, true, nil) for new inserts; (alert, false, nil) for dedup.
	UpsertWithDedup(ctx context.Context, alert *Alert, dedupWindow time.Duration) (*Alert, bool, error)

	// FindRecent finds recent similar alerts for deduplication.
	FindRecent(ctx context.Context, agentID, ruleID string, since time.Time) (*Alert, error)

	// IncrementEventCount increments the event count for an existing alert.
	IncrementEventCount(ctx context.Context, id string, eventIDs []string) error

	// BulkUpdateStatus updates the status of multiple alerts at once.
	BulkUpdateStatus(ctx context.Context, ids []string, status string) error

	// Close closes the repository.
	Close() error
}

// =============================================================================
// Rule Models
// =============================================================================

// Rule represents a Sigma rule stored in the database.
type Rule struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Author          string                 `json:"author"`
	Content         string                 `json:"content"` // Full YAML
	Enabled         bool                   `json:"enabled"`
	Status          string                 `json:"status"`
	Product         string                 `json:"product"`
	Category        string                 `json:"category"`
	Service         string                 `json:"service"`
	Severity        string                 `json:"severity"`
	MitreTactics    []string               `json:"mitre_tactics"`
	MitreTechniques []string               `json:"mitre_techniques"`
	Tags            []string               `json:"tags"`
	References      []string               `json:"references"`
	Version         int                    `json:"version"`
	DateCreated     *time.Time             `json:"date_created,omitempty"`
	DateModified    *time.Time             `json:"date_modified,omitempty"`
	Source          string                 `json:"source"`
	SourceURL       string                 `json:"source_url,omitempty"`
	CustomMetadata  map[string]interface{} `json:"custom_metadata,omitempty"`
	FalsePositives  []string               `json:"false_positives,omitempty"`
	AvgMatchTimeMs  *float64               `json:"avg_match_time_ms,omitempty"`
	TotalMatches    *int64                 `json:"total_matches,omitempty"`
	LastMatchedAt   *time.Time             `json:"last_matched_at,omitempty"`
	CreatedAt       *time.Time             `json:"created_at,omitempty"`
	UpdatedAt       *time.Time             `json:"updated_at,omitempty"`
}

// RuleFilters contains filter options for querying rules.
type RuleFilters struct {
	Enabled   *bool
	Product   string
	Category  string
	Severity  string
	Status    string
	Source    string
	Search    string
	Tags      []string
	Limit     int
	Offset    int
	SortBy    string
	SortOrder string
}

// RuleStats contains aggregate statistics for rules.
type RuleStats struct {
	TotalRules    int64            `json:"total_rules"`
	EnabledRules  int64            `json:"enabled_rules"`
	DisabledRules int64            `json:"disabled_rules"`
	BySeverity    map[string]int64 `json:"by_severity"`
	ByProduct     map[string]int64 `json:"by_product"`
	ByCategory    map[string]int64 `json:"by_category"`
	BySource      map[string]int64 `json:"by_source"`
	ByStatus      map[string]int64 `json:"by_status"`
}

// RuleRepository defines the interface for rule data access.
type RuleRepository interface {
	// LoadAll loads all enabled rules for the detection engine.
	LoadAll(ctx context.Context) ([]*Rule, error)

	// GetByID retrieves a rule by its ID.
	GetByID(ctx context.Context, id string) (*Rule, error)

	// List retrieves rules matching the given filters.
	List(ctx context.Context, filters RuleFilters) ([]*Rule, int64, error)

	// Create inserts a new rule into the database.
	Create(ctx context.Context, rule *Rule) (*Rule, error)

	// Update updates an existing rule.
	Update(ctx context.Context, id string, rule *Rule) (*Rule, error)

	// Delete removes a rule from the database.
	Delete(ctx context.Context, id string) error

	// Enable enables a rule.
	Enable(ctx context.Context, id string) error

	// Disable disables a rule.
	Disable(ctx context.Context, id string) error

	// GetStats retrieves aggregate rule statistics.
	GetStats(ctx context.Context) (*RuleStats, error)

	// UpdateMatchStats updates the match statistics for a rule.
	UpdateMatchStats(ctx context.Context, id string, matchTimeMs float64) error

	// BulkCreate inserts multiple rules.
	BulkCreate(ctx context.Context, rules []*Rule) (int, error)

	// Close closes the repository.
	Close() error
}
