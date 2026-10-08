package baselines

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Behavioral baseline model (UEBA, statistical — no machine learning)
//
// The unit of observation is the number of times a process started on a host
// within one clock hour (UTC), keyed to the EVENT time. For a given process
// and hour-of-day h, the baseline is computed over the host's "active slots":
// the past days (within the retention window, excluding the current hour) in
// which the host reported any process start at hour h. Days the host was off
// do not count; days it was on but the process did not run count as zero.
//
//	mean   = Σ count / active_slots
//	stddev = sqrt(Σ count² / active_slots − mean²)
//
// This is a proper per-hour rate distribution, comparable with the observed
// count of the current hour.

const (
	// BaselineWindowDays is the history used for baselines (and retained).
	BaselineWindowDays = 14
)

// ProcessBaseline is the computed baseline for (agent, process, hour-of-day).
type ProcessBaseline struct {
	AgentID     string `json:"agent_id"`
	ProcessName string `json:"process_name"`
	HourOfDay   int    `json:"hour_of_day"` // 0–23 UTC

	// HostActiveSlots: past same-hour slots in which the host was active.
	HostActiveSlots int `json:"host_active_slots"`
	// PresentSlots: of those, slots in which this process ran.
	PresentSlots int `json:"present_slots"`
	// AvgExecutionsPerHour / StddevExecutions: per-slot rate (zeros included).
	AvgExecutionsPerHour float64 `json:"avg_executions_per_hour"`
	StddevExecutions     float64 `json:"stddev_executions"`
	// FirstSeenAt: first hour this process ran on the host (any hour).
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
	// HostObservedDays: distinct days with any activity from the host.
	HostObservedDays int `json:"host_observed_days"`
	// ConfidenceScore = min(HostActiveSlots / BaselineWindowDays, 1).
	ConfidenceScore float64 `json:"confidence_score"`
}

// AggregationInput is one observed process start.
type AggregationInput struct {
	AgentID     string
	ProcessName string
	ObservedAt  time.Time // event time (UTC)
}

// HourlyCount is a batched increment of one (agent, process, hour) bucket.
type HourlyCount struct {
	AgentID     string
	ProcessName string
	Hour        time.Time // truncated to the hour, UTC
	Count       int
}

// BaselineRepository persists hourly counts and computes baselines.
type BaselineRepository interface {
	AddCounts(ctx context.Context, counts []HourlyCount) error
	// GetBaseline computes the baseline for hour-of-day hourOfDay using
	// history strictly before `before` (normally the current event's hour).
	GetBaseline(ctx context.Context, agentID, processName string, hourOfDay int, before time.Time) (*ProcessBaseline, error)
	Prune(ctx context.Context, olderThan time.Time) (int64, error)
}

// BatchCountRepository makes uncertain database commits safe to retry.
type BatchCountRepository interface {
	AddBatchCounts(context.Context, string, []HourlyCount) error
}

// RecentCountRepository restores observed rates after a service restart.
// It is optional for custom repositories; reads run at startup, outside scoring.
type RecentCountRepository interface {
	RecentCounts(ctx context.Context, from, through time.Time, limit int) ([]HourlyCount, error)
}

func (r *PostgresBaselineRepository) RecentCounts(ctx context.Context, from, through time.Time, limit int) ([]HourlyCount, error) {
	rows, err := r.pool.Query(ctx, `SELECT agent_id, process_name, hour_bucket, executions
		FROM process_activity_hourly WHERE hour_bucket >= $1 AND hour_bucket <= $2
		ORDER BY hour_bucket DESC, agent_id, process_name LIMIT $3`, from.UTC(), through.UTC(), limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]HourlyCount, 0)
	for rows.Next() {
		var c HourlyCount
		if err := rows.Scan(&c.AgentID, &c.ProcessName, &c.Hour, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, fmt.Errorf("recent baseline counts exceed the %d bucket capacity", limit)
	}
	return out, nil
}

func (r *InMemoryBaselineRepository) RecentCounts(_ context.Context, from, through time.Time, limit int) ([]HourlyCount, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []HourlyCount
	for k, n := range r.counts {
		if !k.hour.Before(from) && !k.hour.After(through) {
			out = append(out, HourlyCount{k.agent, k.process, k.hour, n})
			if len(out) > limit {
				return nil, fmt.Errorf("recent baseline counts exceed capacity")
			}
		}
	}
	return out, nil
}

func finishBaseline(b *ProcessBaseline, sum, sumSq float64) {
	if b.HostActiveSlots > 0 {
		n := float64(b.HostActiveSlots)
		b.AvgExecutionsPerHour = sum / n
		v := sumSq/n - b.AvgExecutionsPerHour*b.AvgExecutionsPerHour
		b.StddevExecutions = math.Sqrt(math.Max(v, 0))
	}
	b.ConfidenceScore = math.Min(float64(b.HostActiveSlots)/BaselineWindowDays, 1)
}

// ─────────────────────────────────────────────────────────────────────────────
// PostgreSQL implementation (table process_activity_hourly, migration 019)
// ─────────────────────────────────────────────────────────────────────────────

// PostgresBaselineRepository stores hourly counts in PostgreSQL.
type PostgresBaselineRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresBaselineRepository creates the repository.
func NewPostgresBaselineRepository(pool *pgxpool.Pool) *PostgresBaselineRepository {
	return &PostgresBaselineRepository{pool: pool}
}

// AddCounts adds the batched increments (one statement per bucket, in one
// transaction).
func (r *PostgresBaselineRepository) AddCounts(ctx context.Context, counts []HourlyCount) error {
	return r.AddBatchCounts(ctx, uuid.NewString(), counts)
}

func (r *PostgresBaselineRepository) AddBatchCounts(ctx context.Context, batchID string, counts []HourlyCount) error {
	if len(counts) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `INSERT INTO baseline_count_batches(id) VALUES($1::uuid) ON CONFLICT DO NOTHING`, batchID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return tx.Commit(ctx)
	}
	for _, c := range counts {
		if _, err := tx.Exec(ctx, `
			INSERT INTO process_activity_hourly (agent_id, process_name, hour_bucket, executions)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (agent_id, process_name, hour_bucket)
			DO UPDATE SET executions = process_activity_hourly.executions + EXCLUDED.executions`,
			c.AgentID, c.ProcessName, c.Hour.UTC(), c.Count); err != nil {
			return fmt.Errorf("baseline add count (%s/%s): %w", c.AgentID, c.ProcessName, err)
		}
	}
	return tx.Commit(ctx)
}

// GetBaseline computes the baseline from the hourly counts.
func (r *PostgresBaselineRepository) GetBaseline(ctx context.Context, agentID, processName string, hourOfDay int, before time.Time) (*ProcessBaseline, error) {
	cutoff := before.UTC().Truncate(time.Hour)
	from := cutoff.Add(-BaselineWindowDays * 24 * time.Hour)
	b := &ProcessBaseline{AgentID: agentID, ProcessName: processName, HourOfDay: hourOfDay}
	var sum, sumSq float64
	err := r.pool.QueryRow(ctx, `
		WITH slots AS (
			SELECT DISTINCT hour_bucket FROM process_activity_hourly
			WHERE agent_id = $1 AND hour_bucket >= $3 AND hour_bucket < $4
			  AND EXTRACT(HOUR FROM hour_bucket AT TIME ZONE 'UTC') = $5
		), proc AS (
			SELECT p.executions FROM process_activity_hourly p
			JOIN slots s ON s.hour_bucket = p.hour_bucket
			WHERE p.agent_id = $1 AND p.process_name = $2
		)
		SELECT
			(SELECT count(*) FROM slots),
			(SELECT count(*) FROM proc),
			COALESCE((SELECT sum(executions)::float8 FROM proc), 0),
			COALESCE((SELECT sum(executions::float8 * executions) FROM proc), 0),
			(SELECT min(hour_bucket) FROM process_activity_hourly WHERE agent_id = $1 AND process_name = $2 AND hour_bucket < $4),
			(SELECT count(DISTINCT date_trunc('day', hour_bucket)) FROM process_activity_hourly
			  WHERE agent_id = $1 AND hour_bucket >= $3 AND hour_bucket < $4)`,
		agentID, processName, from, cutoff, hourOfDay,
	).Scan(&b.HostActiveSlots, &b.PresentSlots, &sum, &sumSq, &b.FirstSeenAt, &b.HostObservedDays)
	if err != nil {
		return nil, fmt.Errorf("baseline query (%s/%s/h%d): %w", agentID, processName, hourOfDay, err)
	}
	finishBaseline(b, sum, sumSq)
	return b, nil
}

// Prune deletes buckets older than the retention window.
func (r *PostgresBaselineRepository) Prune(ctx context.Context, olderThan time.Time) (int64, error) {
	if _, err := r.pool.Exec(ctx, `DELETE FROM baseline_count_batches WHERE created_at < $1`, time.Now().UTC().Add(-30*24*time.Hour)); err != nil {
		return 0, err
	}
	tag, err := r.pool.Exec(ctx, `DELETE FROM process_activity_hourly WHERE hour_bucket < $1`, olderThan.UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// In-memory implementation (tests and DB-less operation)
// ─────────────────────────────────────────────────────────────────────────────

type bucketKey struct {
	agent, process string
	hour           time.Time
}

// InMemoryBaselineRepository keeps hourly counts in memory.
type InMemoryBaselineRepository struct {
	mu     sync.Mutex
	counts map[bucketKey]int
}

// NewInMemoryBaselineRepository creates an empty repository.
func NewInMemoryBaselineRepository() *InMemoryBaselineRepository {
	return &InMemoryBaselineRepository{counts: map[bucketKey]int{}}
}

// AddCounts implements BaselineRepository.
func (r *InMemoryBaselineRepository) AddCounts(_ context.Context, counts []HourlyCount) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range counts {
		r.counts[bucketKey{c.AgentID, strings.ToLower(c.ProcessName), c.Hour.UTC().Truncate(time.Hour)}] += c.Count
	}
	return nil
}

// GetBaseline implements BaselineRepository.
func (r *InMemoryBaselineRepository) GetBaseline(_ context.Context, agentID, processName string, hourOfDay int, before time.Time) (*ProcessBaseline, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := before.UTC().Truncate(time.Hour)
	from := cutoff.Add(-BaselineWindowDays * 24 * time.Hour)
	proc := strings.ToLower(processName)
	b := &ProcessBaseline{AgentID: agentID, ProcessName: processName, HourOfDay: hourOfDay}
	slots := map[time.Time]bool{}
	days := map[time.Time]bool{}
	var sum, sumSq float64
	for k, n := range r.counts {
		if k.agent != agentID {
			continue
		}
		if k.process == proc && k.hour.Before(cutoff) && (b.FirstSeenAt == nil || k.hour.Before(*b.FirstSeenAt)) {
			h := k.hour
			b.FirstSeenAt = &h
		}
		if k.hour.Before(from) || !k.hour.Before(cutoff) {
			continue
		}
		days[k.hour.Truncate(24*time.Hour)] = true
		if k.hour.Hour() == hourOfDay {
			slots[k.hour] = true
			if k.process == proc {
				b.PresentSlots++
				sum += float64(n)
				sumSq += float64(n) * float64(n)
			}
		}
	}
	b.HostActiveSlots = len(slots)
	b.HostObservedDays = len(days)
	finishBaseline(b, sum, sumSq)
	return b, nil
}

// Prune implements BaselineRepository.
func (r *InMemoryBaselineRepository) Prune(_ context.Context, olderThan time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for k := range r.counts {
		if k.hour.Before(olderThan) {
			delete(r.counts, k)
			n++
		}
	}
	return n, nil
}

// Buckets returns the stored buckets (test helper), sorted by hour.
func (r *InMemoryBaselineRepository) Buckets() []HourlyCount {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]HourlyCount, 0, len(r.counts))
	for k, n := range r.counts {
		out = append(out, HourlyCount{AgentID: k.agent, ProcessName: k.process, Hour: k.hour, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hour.Before(out[j].Hour) })
	return out
}
