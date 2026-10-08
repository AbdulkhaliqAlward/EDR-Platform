// Package baselines maintains per-host process execution baselines (UEBA,
// statistical) from process-start telemetry.
//
// Process starts are counted per (agent, process, UTC hour of the EVENT) in
// memory and flushed to PostgreSQL in batches, so the detection pipeline does
// no per-event database writes. The aggregator also keeps the counts of the
// current and previous hour in memory so the risk scorer can compare the
// observed rate with the baseline without a database round trip.
package baselines

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/google/uuid"
)

const (
	defaultFlushInterval = 30 * time.Second
	maxPendingBuckets    = 50000 // bound memory if the database is down
	// maxEventAge: older events (e.g. replayed from an agent's disk queue)
	// are outside the baseline window and are not counted.
	maxEventAge = BaselineWindowDays * 24 * time.Hour
	// maxClockSkew: events dated further in the future are clamped to now.
	maxClockSkew = 5 * time.Minute
)

// BaselineAggregator counts process starts and flushes them periodically.
type BaselineAggregator struct {
	repo     BaselineRepository
	interval time.Duration

	mu         sync.Mutex
	flushMu    sync.Mutex
	pending    map[bucketKey]int // not yet written
	inflightID string
	inflight   []HourlyCount
	startOnce  sync.Once
	recent     map[bucketKey]int // current/previous hour, for CurrentCount
	cancel     context.CancelFunc
	done       chan struct{}

	Dropped uint64
	Saved   uint64
}

// NewBaselineAggregator creates an aggregator. The two size arguments are
// kept for API compatibility; flushInterval <= 0 uses the default.
func NewBaselineAggregator(repo BaselineRepository, _ int, _ int) *BaselineAggregator {
	return &BaselineAggregator{
		repo:     repo,
		interval: defaultFlushInterval,
		pending:  map[bucketKey]int{},
		recent:   map[bucketKey]int{},
	}
}

// Start launches the flush loop.
func (a *BaselineAggregator) Start(ctx context.Context) { a.startOnce.Do(func() { a.start(ctx) }) }

func (a *BaselineAggregator) start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.done = make(chan struct{})
	// Call Start before accepting events. Restore only observed counts; these
	// persisted buckets must never be put back into the pending write buffer.
	if reader, ok := a.repo.(RecentCountRepository); ok {
		now := time.Now().UTC().Truncate(time.Hour)
		rctx, rcancel := context.WithTimeout(ctx, 10*time.Second)
		counts, err := reader.RecentCounts(rctx, now.Add(-time.Hour), now.Add(time.Hour), maxPendingBuckets)
		rcancel()
		if err != nil {
			logger.Warnf("Observed baseline rate restoration unavailable: %v", err)
		} else {
			a.mu.Lock()
			for _, c := range counts {
				a.recent[bucketKey{c.AgentID, strings.ToLower(c.ProcessName), c.Hour.UTC().Truncate(time.Hour)}] += c.Count
			}
			a.mu.Unlock()
		}
	}
	go func() {
		defer close(a.done)
		flush := time.NewTicker(a.interval)
		defer flush.Stop()
		prune := time.NewTicker(time.Hour)
		defer prune.Stop()
		for {
			select {
			case <-ctx.Done():
				a.Flush(context.Background())
				return
			case <-flush.C:
				a.Flush(ctx)
			case <-prune.C:
				pctx, c := context.WithTimeout(ctx, time.Minute)
				if n, err := a.repo.Prune(pctx, time.Now().Add(-maxEventAge-24*time.Hour)); err != nil {
					logger.Warnf("Baseline prune failed: %v", err)
				} else if n > 0 {
					logger.Debugf("Baseline pruned %d old hourly buckets", n)
				}
				c()
			}
		}
	}()
	logger.Infof("BaselineAggregator started (hourly execution counts, flush every %s)", a.interval)
}

// Stop flushes and stops the aggregator.
func (a *BaselineAggregator) Stop() {
	if a.cancel != nil {
		a.cancel()
		<-a.done
	}
}

// eventHour clamps the event time and returns its UTC hour; ok is false for
// events too old to belong to the baseline window.
func eventHour(t time.Time, now time.Time) (time.Time, bool) {
	if t.IsZero() || t.After(now.Add(maxClockSkew)) {
		t = now
	}
	if now.Sub(t) > maxEventAge {
		return time.Time{}, false
	}
	return t.UTC().Truncate(time.Hour), true
}

// Record counts one process start. Never blocks on I/O.
func (a *BaselineAggregator) Record(in AggregationInput) {
	proc := strings.ToLower(strings.TrimSpace(in.ProcessName))
	if in.AgentID == "" || proc == "" {
		return
	}
	now := time.Now().UTC()
	hour, ok := eventHour(in.ObservedAt, now)
	if !ok {
		return
	}
	k := bucketKey{in.AgentID, proc, hour}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.pending[k]; !exists && len(a.pending) >= maxPendingBuckets {
		a.Dropped++
		return
	}
	a.pending[k]++
	if now.Sub(hour) < 2*time.Hour {
		if _, exists := a.recent[k]; exists || len(a.recent) < maxPendingBuckets {
			a.recent[k]++
		} else {
			a.Dropped++
		}
	}
}

// CurrentCount returns the process starts counted for the agent/process in
// the hour of `at` (only the current and previous hour are kept).
func (a *BaselineAggregator) CurrentCount(agentID, processName string, at time.Time) int {
	if a == nil {
		return 0
	}
	hour, ok := eventHour(at, time.Now().UTC())
	if !ok {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recent[bucketKey{agentID, strings.ToLower(strings.TrimSpace(processName)), hour}]
}

// Flush writes pending counts. On failure they are kept for the next try.
func (a *BaselineAggregator) Flush(ctx context.Context) {
	a.flushMu.Lock()
	defer a.flushMu.Unlock()
	// Retry the immutable in-flight batch before new observations. A commit
	// whose acknowledgement was lost must reuse the same idempotency token.
	for pass := 0; pass < 2; pass++ {
		a.mu.Lock()
		if len(a.inflight) == 0 {
			if len(a.pending) == 0 {
				a.pruneRecentLocked()
				a.mu.Unlock()
				return
			}
			for k, n := range a.pending {
				a.inflight = append(a.inflight, HourlyCount{k.agent, k.process, k.hour, n})
			}
			a.inflightID = uuid.NewString()
			a.pending = map[bucketKey]int{}
		}
		batch, id := a.inflight, a.inflightID
		a.pruneRecentLocked()
		a.mu.Unlock()
		wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		var err error
		if repo, ok := a.repo.(BatchCountRepository); ok {
			err = repo.AddBatchCounts(wctx, id, batch)
		} else {
			err = a.repo.AddCounts(wctx, batch)
		}
		cancel()
		if err != nil {
			logger.Warnf("Baseline flush failed (%d buckets retained for retry): %v", len(batch), err)
			return
		}
		a.mu.Lock()
		a.Saved += uint64(len(batch))
		a.inflight = nil
		a.inflightID = ""
		a.mu.Unlock()
	}
}

func (a *BaselineAggregator) pruneRecentLocked() {
	cut := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	for k := range a.recent {
		if k.hour.Before(cut) {
			delete(a.recent, k)
		}
	}
}

// =============================================================================
// ShouldRecord determines whether an event should contribute to the baseline.
// Only real process starts count (agent process_creation, Sysmon 1, 4688).
// =============================================================================

// ShouldRecord returns true if the event data represents a process creation.
// The agent wraps process fields inside a "data" sub-map, so both the
// top-level key and the nested key are checked.
func ShouldRecord(eventData map[string]interface{}) bool {
	if eventData == nil {
		return false
	}

	resolveVal := func(key string) interface{} {
		if v, ok := eventData[key]; ok && v != nil {
			return v
		}
		if sub, ok := eventData["data"]; ok && sub != nil {
			if m, ok := sub.(map[string]interface{}); ok {
				if v, ok := m[key]; ok && v != nil {
					return v
				}
			}
		}
		return nil
	}

	// Agent telemetry: event_type "process" plus the collector's action.
	// Only real process starts count as executions; terminations and the
	// start-up inventory snapshot would otherwise distort per-hour counts.
	// (An empty action is accepted for agents that predate the field.)
	if et, ok := eventData["event_type"].(string); ok && et != "" {
		if !strings.EqualFold(et, "process") {
			return false
		}
		action, _ := resolveVal("action").(string)
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "", "process_creation":
			return true
		default:
			return false
		}
	}

	// Event Log / Sysmon telemetry: numeric provider event code only. The
	// agent's top-level "event_id" is a record UUID, never a code.
	for _, v := range []interface{}{eventData["EventID"], eventData["event.code"], resolveVal("EventID"), resolveVal("event_code")} {
		if code, ok := domain.ParseEventCode(v); ok {
			return code == 1 || code == 4688
		}
	}
	if data, ok := eventData["data"].(map[string]interface{}); ok {
		if code, ok := domain.ParseEventCode(data["event_id"]); ok {
			return code == 1 || code == 4688
		}
	}

	return false
}

// ExtractAggregationInput converts a raw event payload into an
// AggregationInput, using the event's own timestamp (not the processing
// time, which is wrong for delayed or replayed events).
func ExtractAggregationInput(agentID string, eventData map[string]interface{}) AggregationInput {
	in := AggregationInput{AgentID: agentID, ObservedAt: EventTime(eventData)}
	get := func(key string) string {
		if v, ok := eventData[key].(string); ok && v != "" {
			return v
		}
		if sub, ok := eventData["data"].(map[string]interface{}); ok {
			if v, ok := sub[key].(string); ok {
				return v
			}
		}
		return ""
	}
	in.ProcessName = get("name")
	if in.ProcessName == "" {
		if p := get("executable"); p != "" {
			if i := strings.LastIndexAny(p, `\/`); i >= 0 {
				p = p[i+1:]
			}
			in.ProcessName = p
		}
	}
	return in
}

// EventTime returns the event's timestamp (RFC 3339, top-level "timestamp"
// or "@timestamp"), or the zero time when absent/invalid.
func EventTime(eventData map[string]interface{}) time.Time {
	for _, k := range []string{"timestamp", "@timestamp"} {
		if s, ok := eventData[k].(string); ok && s != "" {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}
