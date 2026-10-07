// Package baselines provides the BaselineAggregator — an event-driven
// worker that incrementally updates process behavioral profiles.
//
// Design choice — Event-Driven vs Cron:
//
//	We chose an event-driven model (trigger on each process event) rather than
//	a periodic cron job for two key reasons:
//
//	1. Near-Real-Time Model: The baseline model starts capturing data from the
//	   first observed execution.  Within hours of agent deployment, the UEBA
//	   component begins contributing signal to the risk score.
//
//	2. Graduation Project Feasibility: A cron-based aggregator would require
//	   either pg_cron (complex PostgreSQL setup) or a separate scheduler
//	   service.  The event-driven model runs inside the existing EventLoop
//	   goroutine with zero added infrastructure.
//
// The aggregator is FIRE-AND-FORGET: it enqueues the update on a non-blocking
// buffered channel and a background goroutine drains it.  The detection
// pipeline is never blocked by a slow DB write.
package baselines

import (
	"context"
	"strings"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
)

const (
	// defaultQueueSize is the number of aggregation inputs that can be buffered
	// before the aggregator starts dropping events (non-fatal, just no baseline update).
	defaultQueueSize = 4096

	// defaultWorkers is the number of background DB writer goroutines.
	defaultWorkers = 2
)

// BaselineAggregator receives process events from the EventLoop and
// asynchronously UPSERTs behavioral baseline data into PostgreSQL.
//
// Usage:
//
//	agg := NewBaselineAggregator(repo, 0, 0) // defaults
//	agg.Start(ctx)
//	// in event processing loop:
//	agg.Record(AggregationInput{...})
//	// on shutdown:
//	agg.Stop()
type BaselineAggregator struct {
	repo      BaselineRepository
	queue     chan AggregationInput
	queueSize int
	workers   int
	cancel    context.CancelFunc

	Dropped uint64 // monotonic counter for observability
	Saved   uint64
}

// NewBaselineAggregator creates a new aggregator.
// queueSize = 0 → defaultQueueSize; workers = 0 → defaultWorkers.
func NewBaselineAggregator(repo BaselineRepository, queueSize, workers int) *BaselineAggregator {
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	if workers <= 0 {
		workers = defaultWorkers
	}
	return &BaselineAggregator{
		repo:      repo,
		queueSize: queueSize,
		workers:   workers,
		queue:     make(chan AggregationInput, queueSize),
	}
}

// Start launches the background writer goroutines.
func (a *BaselineAggregator) Start(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	for i := 0; i < a.workers; i++ {
		go a.worker(workerCtx)
	}
	logger.Infof("BaselineAggregator started (%d workers, queue=%d)", a.workers, a.queueSize)
}

// Record enqueues an aggregation input for async processing.
// This is non-blocking: if the queue is full the event is silently dropped
// (the baseline is best-effort, not required for correctness).
func (a *BaselineAggregator) Record(in AggregationInput) {
	if in.ObservedAt.IsZero() {
		in.ObservedAt = time.Now().UTC()
	}
	select {
	case a.queue <- in:
	default:
		a.Dropped++
	}
}

// Stop gracefully shuts down the background workers.
func (a *BaselineAggregator) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
}

// worker drains the queue and calls repo.Upsert for each item.
func (a *BaselineAggregator) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Drain any remaining queued events before exiting
			for {
				select {
				case in := <-a.queue:
					a.upsert(in)
				default:
					return
				}
			}
		case in := <-a.queue:
			a.upsert(in)
		}
	}
}

func (a *BaselineAggregator) upsert(in AggregationInput) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := a.repo.Upsert(ctx, in); err != nil {
		logger.Warnf("BaselineAggregator upsert failed (%s/%s): %v", in.AgentID, in.ProcessName, err)
		return
	}
	a.Saved++
}

// =============================================================================
// ShouldRecord determines whether an event should contribute to the baseline.
// We only track process-creation events (EventID 4688 on Windows / Sysmon ID 1).
// =============================================================================

// ShouldRecord returns true if the event data represents a process creation.
// It's a pure-function helper used by the EventLoop before calling Record().
//
// The agent wraps process fields inside a "data" sub-map, so we check both
// the top-level key and the nested key.
func ShouldRecord(eventData map[string]interface{}) bool {
	if eventData == nil {
		return false
	}

	// resolveVal checks top-level key first, then data.* sub-map.
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

	// Event Log / Sysmon telemetry: numeric provider event code only.
	// The agent's top-level "event_id" is a record UUID, never a code, so it
	// is deliberately not consulted here (it previously made this function
	// return false for every agent event, so UEBA never trained).
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

// ExtractAggregationInput converts a raw event payload into an AggregationInput.
// Reads fields from both the top-level map and the nested data.{} sub-map
// to support the Windows Agent's event format.
func ExtractAggregationInput(agentID string, eventData map[string]interface{}) AggregationInput {
	// Extract the nested data sub-map once.
	var dataSub map[string]interface{}
	if sub, ok := eventData["data"]; ok && sub != nil {
		if m, ok := sub.(map[string]interface{}); ok {
			dataSub = m
		}
	}
	resolveFn := func(key string) interface{} {
		if v, ok := eventData[key]; ok && v != nil {
			return v
		}
		if dataSub != nil {
			if v, ok := dataSub[key]; ok && v != nil {
				return v
			}
		}
		return nil
	}
	getString := func(key string) string {
		if v := resolveFn(key); v != nil {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	getBool := func(key string) bool {
		if v := resolveFn(key); v != nil {
			if b, ok := v.(bool); ok {
				return b
			}
			if s, ok := v.(string); ok {
				return s == "1" || s == "true"
			}
		}
		return false
	}

	return AggregationInput{
		AgentID:        agentID,
		ProcessName:    getString("name"),
		ProcessPath:    getString("executable"),
		SigStatus:      getString("signature_status"),
		IntegrityLevel: getString("integrity_level"),
		IsElevated:     getBool("is_elevated"),
		ParentName:     getString("parent_name"),
		ObservedAt:     time.Now().UTC(),
	}
}
