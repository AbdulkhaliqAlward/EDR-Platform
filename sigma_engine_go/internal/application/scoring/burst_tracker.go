package scoring

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// =============================================================================
// BurstTracker Interface
// =============================================================================

// BurstTracker tracks how many times a given (agentID, category) combination
// has fired within a rolling time window. It is used to compute the Temporal
// Burst Bonus component of the risk score.
//
// The production implementation uses Redis INCR + EXPIRE.
// The test implementation is in-memory.
type BurstTracker interface {
	// IncrAndGet increments the counter for (agentID, category) and returns
	// the new count. The counter auto-expires after the tracker's window TTL.
	// Returns (0, error) on infrastructure failure; callers treat 0 as "no burst".
	IncrAndGet(ctx context.Context, agentID, category string) (int64, error)

	// Get returns the current count without incrementing. Returns 0 on miss.
	Get(ctx context.Context, agentID, category string) (int64, error)

	// Reset removes the counter for (agentID, category). Used for testing.
	Reset(ctx context.Context, agentID, category string) error

	// DistinctRules records that ruleID fired on the agent and returns how
	// many DIFFERENT rules fired on it within the sliding window. Distinct
	// detections in a short window indicate attack progression; one rule
	// repeating indicates a recurring (often benign, automated) pattern and
	// must not raise the score.
	DistinctRules(ctx context.Context, agentID, ruleID string) (int64, error)
}

// =============================================================================
// RedisBurstTracker — Production Implementation
// =============================================================================

const (
	// burstWindowTTL is the rolling window for burst detection.
	// 5 minutes is large enough to detect rapid enumeration but small enough
	// to avoid counting activity across separate attack phases as a single burst.
	burstWindowTTL = 5 * time.Minute

	// burstKeyPrefix scopes all burst keys in Redis.
	burstKeyPrefix = "burst"
)

// RedisBurstTracker implements BurstTracker using Redis INCR + EXPIRE.
//
// Key schema:
//
//	"burst:{agentID}:{category}"  →  Redis counter (integer string)
//
// TTL behaviour:
//   - First call: INCR creates key (value=1) → EXPIRE sets TTL=5min.
//   - Subsequent calls within TTL: INCR increments; TTL is NOT re-reset.
//     This is a "tumbling window", not a strictly sliding window.
//     This keeps the hot path to a single Redis INCR per event after the
//     first hit, which is critical for maintaining low processing latency.
//   - After TTL: key vanishes; next call restarts the counter at 1.
type RedisBurstTracker struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedisBurstTracker creates a burst tracker backed by Redis.
func NewRedisBurstTracker(client *redis.Client) *RedisBurstTracker {
	return &RedisBurstTracker{client: client, ttl: burstWindowTTL}
}

// NewRedisBurstTrackerWithTTL creates a burst tracker with a custom TTL.
// Used in integration tests where 5-minute windows are impractical.
func NewRedisBurstTrackerWithTTL(client *redis.Client, ttl time.Duration) *RedisBurstTracker {
	return &RedisBurstTracker{client: client, ttl: ttl}
}

func (bt *RedisBurstTracker) burstKey(agentID, category string) string {
	return fmt.Sprintf("%s:%s:%s", burstKeyPrefix, agentID, strings.ToLower(category))
}

// IncrAndGet atomically increments the burst counter and returns the new count.
// EXPIRE is only set on the first increment (count==1) to minimise Redis RTTs.
func (bt *RedisBurstTracker) IncrAndGet(ctx context.Context, agentID, category string) (int64, error) {
	key := bt.burstKey(agentID, category)

	count, err := bt.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("burst INCR key=%s: %w", key, err)
	}

	// Set TTL only on first increment — starts the tumbling window.
	if count == 1 {
		_ = bt.client.Expire(ctx, key, bt.ttl).Err()
	}

	return count, nil
}

// Get returns the current burst count without incrementing.
// Returns (0, nil) if the key is expired or has never been set.
func (bt *RedisBurstTracker) Get(ctx context.Context, agentID, category string) (int64, error) {
	key := bt.burstKey(agentID, category)

	val, err := bt.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("burst GET key=%s: %w", key, err)
	}
	return val, nil
}

// Reset deletes the burst counter. Primarily used for tests.
func (bt *RedisBurstTracker) Reset(ctx context.Context, agentID, category string) error {
	key := bt.burstKey(agentID, category)
	if err := bt.client.Del(ctx, key).Err(); err != nil && err != redis.Nil {
		return fmt.Errorf("burst Reset key=%s: %w", key, err)
	}
	return nil
}

// =============================================================================
// InMemoryBurstTracker — Test Implementation
// =============================================================================

// inMemoryBurstEntry holds a counter and its expiry time.
type inMemoryBurstEntry struct {
	count     int64
	expiresAt time.Time
}

// InMemoryBurstTracker implements BurstTracker using a Go map + mutex.
// It mirrors the tumbling-window semantics of RedisBurstTracker.
// Used in unit tests that do not require a real Redis connection.
type InMemoryBurstTracker struct {
	mu       sync.Mutex
	entries  map[string]*inMemoryBurstEntry
	distinct map[string]map[string]time.Time // agent → rule → last seen
	ttl      time.Duration
}

// NewInMemoryBurstTracker creates a new in-memory burst tracker with the given TTL.
func NewInMemoryBurstTracker(ttl time.Duration) *InMemoryBurstTracker {
	if ttl <= 0 {
		ttl = burstWindowTTL
	}
	return &InMemoryBurstTracker{
		entries: make(map[string]*inMemoryBurstEntry),
		ttl:     ttl,
	}
}

func (bt *InMemoryBurstTracker) burstKey(agentID, category string) string {
	return fmt.Sprintf("%s:%s:%s", burstKeyPrefix, agentID, strings.ToLower(category))
}

func (bt *InMemoryBurstTracker) IncrAndGet(_ context.Context, agentID, category string) (int64, error) {
	key := bt.burstKey(agentID, category)
	now := time.Now()

	bt.mu.Lock()
	defer bt.mu.Unlock()

	e, ok := bt.entries[key]
	if !ok || now.After(e.expiresAt) {
		bt.entries[key] = &inMemoryBurstEntry{count: 1, expiresAt: now.Add(bt.ttl)}
		return 1, nil
	}
	e.count++
	return e.count, nil
}

func (bt *InMemoryBurstTracker) Get(_ context.Context, agentID, category string) (int64, error) {
	key := bt.burstKey(agentID, category)
	now := time.Now()

	bt.mu.Lock()
	defer bt.mu.Unlock()

	e, ok := bt.entries[key]
	if !ok || now.After(e.expiresAt) {
		return 0, nil
	}
	return e.count, nil
}

func (bt *InMemoryBurstTracker) Reset(_ context.Context, agentID, category string) error {
	key := bt.burstKey(agentID, category)
	bt.mu.Lock()
	delete(bt.entries, key)
	bt.mu.Unlock()
	return nil
}

// ─── Distinct-rule sliding window ────────────────────────────────────────────

func distinctKey(agentID string) string {
	return fmt.Sprintf("%s:distinct:%s", burstKeyPrefix, agentID)
}

// DistinctRules implements BurstTracker with a Redis sorted set per agent
// (member = rule ID, score = last-seen unix ms), trimmed to the window.
func (bt *RedisBurstTracker) DistinctRules(ctx context.Context, agentID, ruleID string) (int64, error) {
	key := distinctKey(agentID)
	now := time.Now()
	cutoff := now.Add(-bt.ttl).UnixMilli()
	pipe := bt.client.TxPipeline()
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now.UnixMilli()), Member: strings.ToLower(ruleID)})
	pipe.ZRemRangeByScore(ctx, key, "-inf", fmt.Sprintf("(%d", cutoff))
	card := pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, bt.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("burst distinct key=%s: %w", key, err)
	}
	return card.Val(), nil
}

// DistinctRules implements BurstTracker in memory.
func (bt *InMemoryBurstTracker) DistinctRules(_ context.Context, agentID, ruleID string) (int64, error) {
	now := time.Now()
	key := distinctKey(agentID)
	bt.mu.Lock()
	defer bt.mu.Unlock()
	if bt.distinct == nil {
		bt.distinct = make(map[string]map[string]time.Time)
	}
	set := bt.distinct[key]
	if set == nil {
		set = make(map[string]time.Time)
		bt.distinct[key] = set
	}
	set[strings.ToLower(ruleID)] = now
	for r, seen := range set {
		if now.Sub(seen) > bt.ttl {
			delete(set, r)
		}
	}
	return int64(len(set)), nil
}
