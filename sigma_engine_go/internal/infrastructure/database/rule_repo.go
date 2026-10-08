// Package database provides PostgreSQL rule repository implementation.
package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRuleRepository implements RuleRepository using PostgreSQL.
type PostgresRuleRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRuleRepository creates a new PostgreSQL rule repository.
func NewPostgresRuleRepository(pool *pgxpool.Pool) *PostgresRuleRepository {
	return &PostgresRuleRepository{pool: pool}
}

// LoadAll loads all enabled rules for the detection engine.
func (r *PostgresRuleRepository) LoadAll(ctx context.Context) ([]*Rule, error) {
	query := `
		SELECT id, title, description, author, content, enabled, status,
			product, category, service, severity,
			mitre_tactics, mitre_techniques, tags, "references",
			version, date_created, date_modified, source, source_url,
			custom_metadata, false_positives,
			avg_match_time_ms, total_matches, last_matched_at,
			created_at, updated_at
		FROM sigma_rules
		WHERE enabled = true
		ORDER BY severity DESC, title ASC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}
	defer rows.Close()

	var rules []*Rule
	for rows.Next() {
		rule, err := r.scanRuleRow(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, rows.Err()
}

// GetByID retrieves a rule by its ID.
func (r *PostgresRuleRepository) GetByID(ctx context.Context, id string) (*Rule, error) {
	query := `
		SELECT id, title, description, author, content, enabled, status,
			product, category, service, severity,
			mitre_tactics, mitre_techniques, tags, "references",
			version, date_created, date_modified, source, source_url,
			custom_metadata, false_positives,
			avg_match_time_ms, total_matches, last_matched_at,
			created_at, updated_at
		FROM sigma_rules
		WHERE id = $1`

	return r.scanRule(r.pool.QueryRow(ctx, query, id))
}

// List retrieves rules matching the given filters.
func (r *PostgresRuleRepository) List(ctx context.Context, filters RuleFilters) ([]*Rule, int64, error) {
	var conditions []string
	var args []interface{}
	argNum := 1

	if filters.Enabled != nil {
		conditions = append(conditions, fmt.Sprintf("enabled = $%d", argNum))
		args = append(args, *filters.Enabled)
		argNum++
	}
	if filters.Product != "" {
		conditions = append(conditions, fmt.Sprintf("product = $%d", argNum))
		args = append(args, filters.Product)
		argNum++
	}
	if filters.Category != "" {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argNum))
		args = append(args, filters.Category)
		argNum++
	}
	if filters.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argNum))
		args = append(args, filters.Severity)
		argNum++
	}
	if filters.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argNum))
		args = append(args, filters.Status)
		argNum++
	}
	if filters.Source != "" {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argNum))
		args = append(args, filters.Source)
		argNum++
	}
	if filters.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR description ILIKE $%d)", argNum, argNum))
		args = append(args, "%"+filters.Search+"%")
		argNum++
	}
	if len(filters.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argNum))
		args = append(args, filters.Tags)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	sortBy := "title"
	if filters.SortBy != "" {
		sortBy = filters.SortBy
	}
	sortOrder := "ASC"
	if filters.SortOrder == "desc" {
		sortOrder = "DESC"
	}

	limit := 50
	if filters.Limit > 0 {
		limit = filters.Limit
	}
	offset := filters.Offset

	// Count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sigma_rules %s", whereClause)
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count rules: %w", err)
	}

	// Data
	dataQuery := fmt.Sprintf(`
		SELECT id, title, description, author, content, enabled, status,
			product, category, service, severity,
			mitre_tactics, mitre_techniques, tags, "references",
			version, date_created, date_modified, source, source_url,
			custom_metadata, false_positives,
			avg_match_time_ms, total_matches, last_matched_at,
			created_at, updated_at
		FROM sigma_rules %s
		ORDER BY %s %s
		LIMIT %d OFFSET %d`,
		whereClause, sortBy, sortOrder, limit, offset)

	rows, err := r.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list rules: %w", err)
	}
	defer rows.Close()

	var rules []*Rule
	for rows.Next() {
		rule, err := r.scanRuleRow(rows)
		if err != nil {
			return nil, 0, err
		}
		rules = append(rules, rule)
	}

	return rules, total, nil
}

// Create inserts a new rule into the database.
func (r *PostgresRuleRepository) Create(ctx context.Context, rule *Rule) (*Rule, error) {
	metadataJSON, _ := json.Marshal(rule.CustomMetadata)

	query := `
		INSERT INTO sigma_rules (
			id, title, description, author, content, enabled, status,
			product, category, service, severity,
			mitre_tactics, mitre_techniques, tags, "references",
			version, date_created, date_modified, source, source_url,
			custom_metadata, false_positives
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11,
			$12, $13, $14, $15,
			$16, $17, $18, $19, $20,
			$21, $22
		) RETURNING created_at, updated_at`

	err := r.pool.QueryRow(ctx, query,
		rule.ID, rule.Title, rule.Description, rule.Author, rule.Content, rule.Enabled, rule.Status,
		rule.Product, rule.Category, rule.Service, rule.Severity,
		rule.MitreTactics, rule.MitreTechniques, rule.Tags, rule.References,
		rule.Version, rule.DateCreated, rule.DateModified, rule.Source, rule.SourceURL,
		metadataJSON, rule.FalsePositives,
	).Scan(&rule.CreatedAt, &rule.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create rule: %w", err)
	}

	return rule, nil
}

// Update updates an existing rule.
func (r *PostgresRuleRepository) Update(ctx context.Context, id string, rule *Rule) (*Rule, error) {
	metadataJSON, _ := json.Marshal(rule.CustomMetadata)

	query := `
		UPDATE sigma_rules SET
			title = $2, description = $3, author = $4, content = $5,
			enabled = $6, status = $7,
			product = $8, category = $9, service = $10, severity = $11,
			mitre_tactics = $12, mitre_techniques = $13, tags = $14, "references" = $15,
			version = version + 1, date_modified = CURRENT_DATE,
			custom_metadata = $16, false_positives = $17
		WHERE id = $1
		RETURNING version, updated_at`

	err := r.pool.QueryRow(ctx, query,
		id, rule.Title, rule.Description, rule.Author, rule.Content,
		rule.Enabled, rule.Status,
		rule.Product, rule.Category, rule.Service, rule.Severity,
		rule.MitreTactics, rule.MitreTechniques, rule.Tags, rule.References,
		metadataJSON, rule.FalsePositives,
	).Scan(&rule.Version, &rule.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to update rule: %w", err)
	}

	rule.ID = id
	return rule, nil
}

// Delete removes a rule from the database.
func (r *PostgresRuleRepository) Delete(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM sigma_rules WHERE id = $1", id)
	return err
}

// Enable enables a rule.
func (r *PostgresRuleRepository) Enable(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "UPDATE sigma_rules SET enabled = true WHERE id = $1", id)
	return err
}

// Disable disables a rule.
func (r *PostgresRuleRepository) Disable(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "UPDATE sigma_rules SET enabled = false WHERE id = $1", id)
	return err
}

// GetStats retrieves aggregate rule statistics.
func (r *PostgresRuleRepository) GetStats(ctx context.Context) (*RuleStats, error) {
	stats := &RuleStats{
		BySeverity: make(map[string]int64),
		ByProduct:  make(map[string]int64),
		ByCategory: make(map[string]int64),
		BySource:   make(map[string]int64),
		ByStatus:   make(map[string]int64),
	}

	r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM sigma_rules").Scan(&stats.TotalRules)
	r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM sigma_rules WHERE enabled = true").Scan(&stats.EnabledRules)
	r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM sigma_rules WHERE enabled = false").Scan(&stats.DisabledRules)

	// By severity
	rows, _ := r.pool.Query(ctx, "SELECT severity, COUNT(*) FROM sigma_rules WHERE severity IS NOT NULL GROUP BY severity")
	for rows.Next() {
		var sev string
		var count int64
		rows.Scan(&sev, &count)
		stats.BySeverity[sev] = count
	}
	rows.Close()

	// By product
	rows, _ = r.pool.Query(ctx, "SELECT product, COUNT(*) FROM sigma_rules WHERE product IS NOT NULL GROUP BY product")
	for rows.Next() {
		var prod string
		var count int64
		rows.Scan(&prod, &count)
		stats.ByProduct[prod] = count
	}
	rows.Close()

	return stats, nil
}

// UpdateMatchStats updates the match statistics for a rule.
func (r *PostgresRuleRepository) UpdateMatchStats(ctx context.Context, id string, matchTimeMs float64) error {
	query := `
		UPDATE sigma_rules SET
			total_matches = total_matches + 1,
			last_matched_at = CURRENT_TIMESTAMP,
			avg_match_time_ms = CASE 
				WHEN avg_match_time_ms IS NULL THEN $2
				ELSE (avg_match_time_ms * 0.9 + $2 * 0.1)
			END
		WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id, matchTimeMs)
	return err
}

// BulkCreate inserts multiple rules.
func (r *PostgresRuleRepository) BulkCreate(ctx context.Context, rules []*Rule) (int, error) {
	batch := &pgx.Batch{}

	for _, rule := range rules {
		metadataJSON, _ := json.Marshal(rule.CustomMetadata)

		batch.Queue(`
			INSERT INTO sigma_rules (
				id, title, description, author, content, enabled, status,
				product, category, service, severity,
				mitre_tactics, mitre_techniques, tags, "references",
				version, date_created, date_modified, source
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
			ON CONFLICT (id) DO UPDATE SET
				title = EXCLUDED.title,
				content = EXCLUDED.content,
				version = sigma_rules.version + 1`,
			rule.ID, rule.Title, rule.Description, rule.Author, rule.Content,
			rule.Enabled, rule.Status, rule.Product, rule.Category, rule.Service,
			rule.Severity, rule.MitreTactics, rule.MitreTechniques, rule.Tags, rule.References,
			rule.Version, rule.DateCreated, rule.DateModified, rule.Source,
		)
		_ = metadataJSON // Used in full version
	}

	results := r.pool.SendBatch(ctx, batch)
	defer results.Close()

	inserted := 0
	for range rules {
		if _, err := results.Exec(); err == nil {
			inserted++
		}
	}

	return inserted, nil
}

// Close closes the repository.
func (r *PostgresRuleRepository) Close() error {
	return nil
}

// scanRule scans a single rule from QueryRow.
func (r *PostgresRuleRepository) scanRule(row pgx.Row) (*Rule, error) {
	var rule Rule
	var metadataJSON []byte
	var description, author, service, sourceURL *string

	err := row.Scan(
		&rule.ID, &rule.Title, &description, &author, &rule.Content,
		&rule.Enabled, &rule.Status, &rule.Product, &rule.Category, &service, &rule.Severity,
		&rule.MitreTactics, &rule.MitreTechniques, &rule.Tags, &rule.References,
		&rule.Version, &rule.DateCreated, &rule.DateModified, &rule.Source, &sourceURL,
		&metadataJSON, &rule.FalsePositives,
		&rule.AvgMatchTimeMs, &rule.TotalMatches, &rule.LastMatchedAt,
		&rule.CreatedAt, &rule.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(metadataJSON, &rule.CustomMetadata)
	if description != nil {
		rule.Description = *description
	}
	if author != nil {
		rule.Author = *author
	}
	if service != nil {
		rule.Service = *service
	}
	if sourceURL != nil {
		rule.SourceURL = *sourceURL
	}

	return &rule, nil
}

// scanRuleRow scans a single rule from Rows.
func (r *PostgresRuleRepository) scanRuleRow(rows pgx.Rows) (*Rule, error) {
	var rule Rule
	var metadataJSON []byte
	var description, author, service, sourceURL *string

	err := rows.Scan(
		&rule.ID, &rule.Title, &description, &author, &rule.Content,
		&rule.Enabled, &rule.Status, &rule.Product, &rule.Category, &service, &rule.Severity,
		&rule.MitreTactics, &rule.MitreTechniques, &rule.Tags, &rule.References,
		&rule.Version, &rule.DateCreated, &rule.DateModified, &rule.Source, &sourceURL,
		&metadataJSON, &rule.FalsePositives,
		&rule.AvgMatchTimeMs, &rule.TotalMatches, &rule.LastMatchedAt,
		&rule.CreatedAt, &rule.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(metadataJSON, &rule.CustomMetadata)
	if description != nil {
		rule.Description = *description
	}
	if author != nil {
		rule.Author = *author
	}
	if service != nil {
		rule.Service = *service
	}
	if sourceURL != nil {
		rule.SourceURL = *sourceURL
	}

	return &rule, nil
}

// Ensure interface compliance
var _ RuleRepository = (*PostgresRuleRepository)(nil)
