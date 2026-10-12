package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentNetworkContext is where an agent connects from (as seen by the
// server, geolocated) and its measured clock offset (table
// agent_network_context).
type AgentNetworkContext struct {
	AgentID         uuid.UUID  `json:"agent_id"`
	Hostname        string     `json:"hostname,omitempty"`
	PublicIP        string     `json:"public_ip,omitempty"`
	NetworkScope    string     `json:"network_scope"`
	CountryCode     string     `json:"country_code,omitempty"`
	Country         string     `json:"country,omitempty"`
	Region          string     `json:"region,omitempty"`
	City            string     `json:"city,omitempty"`
	GeoSource       string     `json:"geo_source,omitempty"`
	GeoResolvedAt   *time.Time `json:"geo_resolved_at,omitempty"`
	ClockOffsetMs   *int64     `json:"clock_offset_ms,omitempty"`
	ClockMeasuredAt *time.Time `json:"clock_measured_at,omitempty"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AgentNetworkContextRepository persists AgentNetworkContext rows.
type AgentNetworkContextRepository struct{ pool *pgxpool.Pool }

// NewAgentNetworkContextRepository creates the repository.
func NewAgentNetworkContextRepository(pool *pgxpool.Pool) *AgentNetworkContextRepository {
	return &AgentNetworkContextRepository{pool: pool}
}

// Upsert stores the latest context. Rows for unknown agents are ignored
// (the foreign key would reject them).
func (r *AgentNetworkContextRepository) Upsert(ctx context.Context, c *AgentNetworkContext) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO agent_network_context (agent_id, public_ip, network_scope, country_code, country, region, city,
			geo_source, geo_resolved_at, clock_offset_ms, clock_measured_at, updated_at)
		SELECT $1, NULLIF($2,''), $3, NULLIF($4,''), NULLIF($5,''), NULLIF($6,''), NULLIF($7,''),
			NULLIF($8,''), $9, $10, $11, NOW()
		WHERE EXISTS (SELECT 1 FROM agents WHERE id = $1)
		ON CONFLICT (agent_id) DO UPDATE SET
			public_ip = EXCLUDED.public_ip, network_scope = EXCLUDED.network_scope,
			country_code = EXCLUDED.country_code, country = EXCLUDED.country,
			region = EXCLUDED.region, city = EXCLUDED.city,
			geo_source = EXCLUDED.geo_source, geo_resolved_at = EXCLUDED.geo_resolved_at,
			clock_offset_ms = COALESCE(EXCLUDED.clock_offset_ms, agent_network_context.clock_offset_ms),
			clock_measured_at = COALESCE(EXCLUDED.clock_measured_at, agent_network_context.clock_measured_at),
			updated_at = NOW()`,
		c.AgentID, c.PublicIP, c.NetworkScope, c.CountryCode, c.Country, c.Region, c.City,
		c.GeoSource, c.GeoResolvedAt, c.ClockOffsetMs, c.ClockMeasuredAt)
	return err
}

const networkContextColumns = `n.agent_id, COALESCE(a.hostname,''), COALESCE(n.public_ip,''), n.network_scope,
	COALESCE(n.country_code,''), COALESCE(n.country,''), COALESCE(n.region,''), COALESCE(n.city,''),
	COALESCE(n.geo_source,''), n.geo_resolved_at, n.clock_offset_ms, n.clock_measured_at, n.updated_at`

func scanNetworkContext(row pgx.Row) (*AgentNetworkContext, error) {
	var c AgentNetworkContext
	err := row.Scan(&c.AgentID, &c.Hostname, &c.PublicIP, &c.NetworkScope, &c.CountryCode, &c.Country, &c.Region,
		&c.City, &c.GeoSource, &c.GeoResolvedAt, &c.ClockOffsetMs, &c.ClockMeasuredAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Get returns one agent's context, or nil when none is stored.
func (r *AgentNetworkContextRepository) Get(ctx context.Context, agentID uuid.UUID) (*AgentNetworkContext, error) {
	c, err := scanNetworkContext(r.pool.QueryRow(ctx, `SELECT `+networkContextColumns+`
		FROM agent_network_context n LEFT JOIN agents a ON a.id = n.agent_id WHERE n.agent_id = $1`, agentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

// GetMany returns the stored contexts of the given agents (missing ones are
// simply absent).
func (r *AgentNetworkContextRepository) GetMany(ctx context.Context, agentIDs []uuid.UUID) ([]AgentNetworkContext, error) {
	if len(agentIDs) == 0 {
		return []AgentNetworkContext{}, nil
	}
	rows, err := r.pool.Query(ctx, `SELECT `+networkContextColumns+`
		FROM agent_network_context n LEFT JOIN agents a ON a.id = n.agent_id WHERE n.agent_id = ANY($1)`, agentIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AgentNetworkContext, 0, len(agentIDs))
	for rows.Next() {
		c, err := scanNetworkContext(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}
