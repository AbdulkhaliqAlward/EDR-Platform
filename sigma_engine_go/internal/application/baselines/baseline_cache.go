// Package baselines provides BaselineCache — a thin in-process read cache
// that sits in front of the BaselineRepository for scoring-time lookups.
//
// Motivation:
//
//	The RiskScorer is called synchronously inside the EventLoop's detection
//	worker goroutines.  Each call would normally require a DB roundtrip to
//	fetch the baseline for a (agent, process, hour) tuple.  At typical SOC
//	event rates this would add 2–5 ms per alert.
//
//	BaselineCache uses a simple TTL map: entries are cached for 10 minutes,
//	which is long enough to be highly effective (hot processes repeat rapidly)
//	while staying fresh enough that a machine learning a new process pattern
//	quickly appears in the scorer without a service restart.
package baselines

import (
	"context"
	"strings"
	"sync"
	"time"
)

const (
	// defaultCacheTTL is how long a baseline entry is held in memory.
	// 10 minutes balances freshness vs DB load.
	defaultCacheTTL = 10 * time.Minute

	// defaultCleanupInterval controls how often expired entries are evicted.
	defaultCleanupInterval = 5 * time.Minute
)

// =============================================================================
// BaselineProvider interface
// =============================================================================

// BaselineProvider is the interface the RiskScorer uses to look up baselines.
// Implemented by BaselineCache (production) and InMemoryBaselineRepository
// (unit tests, via the adapter below).
type BaselineProvider interface {
	// Lookup returns the baseline for the given (agentID, processName, hourOfDay).
	// Returns nil, nil if no baseline is found (process not yet profiled).
	// The hour-of-day and the history cutoff are taken from `at` (event time).
	Lookup(ctx context.Context, agentID, processName string, at time.Time) (*ProcessBaseline, error)
}

// =============================================================================
// BaselineCache
// =============================================================================

type cacheEntry struct {
	baseline  *ProcessBaseline // nil → "not profiled" (negative cached)
	expiresAt time.Time
}

// BaselineCache wraps a BaselineRepository with an in-process TTL cache.
type BaselineCache struct {
	repo    BaselineRepository
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

// NewBaselineCache creates a new read cache around the given repository.
// ttl=0 uses the default (10 minutes).
func NewBaselineCache(repo BaselineRepository, ttl time.Duration) *BaselineCache {
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	c := &BaselineCache{
		repo:    repo,
		ttl:     ttl,
		entries: make(map[string]*cacheEntry),
		stop:    make(chan struct{}), done: make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// Lookup returns the cached baseline, fetching from DB if not cached.
func (c *BaselineCache) Lookup(ctx context.Context, agentID, processName string, at time.Time) (*ProcessBaseline, error) {
	hour := at.UTC().Truncate(time.Hour)
	processName = strings.ToLower(processName)
	key := agentID + "|" + processName + "|" + hour.Format(time.RFC3339)

	// Fast path: cache hit
	c.mu.RLock()
	if entry, ok := c.entries[key]; ok && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return copyBaseline(entry.baseline), nil
	}
	c.mu.RUnlock()

	// Slow path: DB fetch
	baseline, err := c.repo.GetBaseline(ctx, agentID, processName, hour.Hour(), hour)
	if err != nil {
		return nil, err
	}

	// Cache the result (including nil → negative cache so we don't hammer DB for new processes)
	c.mu.Lock()
	if len(c.entries) >= maxPendingBuckets {
		for k, e := range c.entries {
			if time.Now().After(e.expiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= maxPendingBuckets {
			// Skip caching this lookup rather than exceed the fixed memory bound.
			c.mu.Unlock()
			return baseline, nil
		}
	}
	c.entries[key] = &cacheEntry{
		baseline:  copyBaseline(baseline),
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()

	return baseline, nil
}

// cleanupLoop evicts expired entries periodically to prevent unbounded growth.
func (c *BaselineCache) cleanupLoop() {
	defer close(c.done)
	ticker := time.NewTicker(defaultCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
		}
		now := time.Now()
		c.mu.Lock()
		for k, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}

func (c *BaselineCache) Stop() {
	c.once.Do(func() { close(c.stop) })
	<-c.done
}

func copyBaseline(b *ProcessBaseline) *ProcessBaseline {
	if b == nil {
		return nil
	}
	copy := *b
	if b.FirstSeenAt != nil {
		first := *b.FirstSeenAt
		copy.FirstSeenAt = &first
	}
	return &copy
}

// =============================================================================
// RepositoryProviderAdapter
// =============================================================================

// RepositoryProviderAdapter adapts an InMemoryBaselineRepository to the
// BaselineProvider interface for use in unit tests that bypass the cache.
type RepositoryProviderAdapter struct {
	repo BaselineRepository
}

// NewRepositoryProviderAdapter wraps any BaselineRepository as a BaselineProvider.
func NewRepositoryProviderAdapter(repo BaselineRepository) *RepositoryProviderAdapter {
	return &RepositoryProviderAdapter{repo: repo}
}

// Lookup delegates directly to the repository (no caching).
func (a *RepositoryProviderAdapter) Lookup(ctx context.Context, agentID, processName string, at time.Time) (*ProcessBaseline, error) {
	hour := at.UTC().Truncate(time.Hour)
	return a.repo.GetBaseline(ctx, agentID, strings.ToLower(processName), hour.Hour(), hour)
}

// =============================================================================
// NoopBaselineProvider (for when DB is unavailable)
// =============================================================================

// NoopBaselineProvider always returns nil (no baseline profiled).
// Used when the PostgreSQL pool is not available at startup.
type NoopBaselineProvider struct{}

// Lookup always returns nil, nil.
func (NoopBaselineProvider) Lookup(_ context.Context, _, _ string, _ time.Time) (*ProcessBaseline, error) {
	return nil, nil
}
