// Package kafka provides the integrated event loop for Kafka-based processing.
package kafka

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/edr-platform/sigma-engine/internal/analytics"
	"github.com/edr-platform/sigma-engine/internal/automation"
	"github.com/edr-platform/sigma-engine/internal/application/alert"
	"github.com/edr-platform/sigma-engine/internal/application/baselines"
	"github.com/edr-platform/sigma-engine/internal/application/detection"
	"github.com/edr-platform/sigma-engine/internal/application/scoring"
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/cache"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/database"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	metricsPkg "github.com/edr-platform/sigma-engine/internal/metrics"
)

// EventLoopConfig configures the integrated event loop.
type EventLoopConfig struct {
	Workers         int           `yaml:"workers"`          // Detection worker count
	EventBuffer     int           `yaml:"event_buffer"`     // Event channel buffer size
	AlertBuffer     int           `yaml:"alert_buffer"`     // Alert channel buffer size
	StatsInterval   time.Duration `yaml:"stats_interval"`   // Statistics reporting interval
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"` // Graceful shutdown timeout
}

// DefaultEventLoopConfig returns default event loop configuration.
func DefaultEventLoopConfig() EventLoopConfig {
	return EventLoopConfig{
		Workers:         4,
		EventBuffer:     1000,
		AlertBuffer:     500,
		StatsInterval:   10 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}
}

// EventLoopMetrics tracks event loop statistics.
type EventLoopMetrics struct {
	EventsReceived        uint64
	EventsProcessed       uint64
	AlertsGenerated       uint64
	AlertsPublished       uint64
	AlertsSuppressed      uint64
	AlertFallbackUsed     uint64
	AlertsDropped         uint64
	AlertPublishFailures  uint64
	AlertDBQueueFailures  uint64
	ProcessingErrors      uint64
	AverageLatencyMs      float64
	AverageRuleMatchingMs float64
	CurrentEPS            float64
	mu                    sync.RWMutex
}

// Snapshot returns a copy of current metrics.
func (m *EventLoopMetrics) Snapshot() EventLoopMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return EventLoopMetrics{
		EventsReceived:        atomic.LoadUint64(&m.EventsReceived),
		EventsProcessed:       atomic.LoadUint64(&m.EventsProcessed),
		AlertsGenerated:       atomic.LoadUint64(&m.AlertsGenerated),
		AlertsPublished:       atomic.LoadUint64(&m.AlertsPublished),
		AlertsSuppressed:      atomic.LoadUint64(&m.AlertsSuppressed),
		AlertFallbackUsed:     atomic.LoadUint64(&m.AlertFallbackUsed),
		AlertsDropped:         atomic.LoadUint64(&m.AlertsDropped),
		AlertPublishFailures:  atomic.LoadUint64(&m.AlertPublishFailures),
		AlertDBQueueFailures:  atomic.LoadUint64(&m.AlertDBQueueFailures),
		ProcessingErrors:      atomic.LoadUint64(&m.ProcessingErrors),
		AverageLatencyMs:      m.AverageLatencyMs,
		AverageRuleMatchingMs: m.AverageRuleMatchingMs,
		CurrentEPS:            m.CurrentEPS,
	}
}

// =============================================================================
// Alert Suppression Cache (Anti-Flooding / Deduplication)
// =============================================================================

const defaultSuppressionTTL = 60 * time.Second
const cleanupInterval = 30 * time.Second

// suppressionCache is a thread-safe, TTL-based cache for alert deduplication.
// Key: "ruleID|agentID" — suppresses duplicate alerts from the same rule+agent
// within a configurable time window.
type suppressionCache struct {
	mu      sync.RWMutex
	entries map[string]time.Time // key → first-seen timestamp
	ttl     time.Duration
}

func newSuppressionCache(ttl time.Duration) *suppressionCache {
	if ttl <= 0 {
		ttl = defaultSuppressionTTL
	}
	return &suppressionCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// shouldSuppress returns true if an alert with this key was already seen
// within the TTL window. If not suppressed, records the key.
func (sc *suppressionCache) shouldSuppress(key string) bool {
	now := time.Now()

	sc.mu.RLock()
	if ts, exists := sc.entries[key]; exists && now.Sub(ts) < sc.ttl {
		sc.mu.RUnlock()
		return true
	}
	sc.mu.RUnlock()

	sc.mu.Lock()
	defer sc.mu.Unlock()
	// Double-check after write lock
	if ts, exists := sc.entries[key]; exists && now.Sub(ts) < sc.ttl {
		return true
	}
	sc.entries[key] = now
	return false
}

// cleanup removes expired entries to prevent unbounded memory growth.
func (sc *suppressionCache) cleanup() {
	now := time.Now()
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for key, ts := range sc.entries {
		if now.Sub(ts) >= sc.ttl {
			delete(sc.entries, key)
		}
	}
}

// size returns the current number of entries (for stats logging).
func (sc *suppressionCache) size() int {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return len(sc.entries)
}

// EventLoop coordinates Kafka consumer, detection engine, and alert producer.
type EventLoop struct {
	consumer        *EventConsumer
	producer        *AlertProducer
	detectionEngine *detection.SigmaDetectionEngine
	alertGenerator  *alert.AlertGenerator
	config          EventLoopConfig
	metrics         *EventLoopMetrics
	suppression     *suppressionCache
	alertWriter     *database.AlertWriter // Writes alerts to PostgreSQL

	// lineageCache stores the contextual snapshot of every observed process
	// for a short TTL window. It is hydrated BEFORE Sigma rule evaluation so
	// that the upcoming RiskScorer can resolve ancestry chains on demand.
	// If nil (Redis unavailable), lineage hydration is silently skipped.
	lineageCache cache.LineageCache

	// S2 FIX: Async lineage write channel + workers.
	// Detection workers push entries here (non-blocking), dedicated writer
	// goroutines drain the channel and persist to Redis.
	lineageWriteCh chan *cache.ProcessLineageEntry

	// riskScorer computes the context-aware risk score for every matched alert.
	// If nil, alerts are forwarded with RiskScore=0 (no context enrichment).
	riskScorer scoring.RiskScorer

	// alertCorrelator records time-decayed same-rule / time-window edges between
	// consecutive alerts (in-memory). If nil, correlation is skipped.
	alertCorrelator *analytics.CorrelationManager

	// baselineAggregator records process events for UEBA behavioral profiling.
	// Fire-and-forget: it enqueues into a buffered channel and never blocks.
	// If nil, behavioral baseline aggregation is skipped (no UEBA).
	baselineAggregator *baselines.BaselineAggregator

	// playbooks runs server-side automation (Slack, webhooks, etc.) per generated alert.
	// If nil, no playbook execution is performed.
	playbooks *automation.PlaybookManager
	// escalations tracks alerts for time-based escalation rules (see StartBackgroundChecker in main).
	// If nil, escalation tracking is skipped.
	escalations *automation.EscalationManager

	lineageCacheErrors atomic.Uint64 // monotonic counter for cache write failures

	alertChan chan *domain.Alert
	doneChan  chan struct{}

	running atomic.Bool
	wg       sync.WaitGroup
	workerWG sync.WaitGroup // detection workers only (shutdown ordering)
}

const (
	// lineageWriteBuffer is the bounded channel size for async lineage writes (S2).
	lineageWriteBuffer = 4096
	// lineageWriteWorkers is the number of background Redis writer goroutines.
	lineageWriteWorkers = 2
)

// NewEventLoop creates a new integrated event loop.
func NewEventLoop(
	consumer *EventConsumer,
	producer *AlertProducer,
	detectionEngine *detection.SigmaDetectionEngine,
	alertGenerator *alert.AlertGenerator,
	config EventLoopConfig,
) *EventLoop {
	if config.Workers <= 0 {
		config.Workers = 4
	}
	if config.AlertBuffer <= 0 {
		config.AlertBuffer = 5000 // S6 FIX: increased from 500 to 5000
	}

	return &EventLoop{
		consumer:        consumer,
		producer:        producer,
		detectionEngine: detectionEngine,
		alertGenerator:  alertGenerator,
		config:          config,
		metrics:         &EventLoopMetrics{},
		suppression:     newSuppressionCache(defaultSuppressionTTL),
		alertChan:       make(chan *domain.Alert, config.AlertBuffer),
		lineageWriteCh:  make(chan *cache.ProcessLineageEntry, lineageWriteBuffer),
		doneChan:        make(chan struct{}),
	}
}

// SetAlertWriter injects an AlertWriter for database persistence.
// Call this before Start().
func (el *EventLoop) SetAlertWriter(writer *database.AlertWriter) {
	el.alertWriter = writer
}

// SetLineageCache injects a LineageCache implementation for process context
// hydration. Call this before Start(). Passing nil disables lineage caching
// without affecting the rest of the pipeline.
func (el *EventLoop) SetLineageCache(lc cache.LineageCache) {
	el.lineageCache = lc
}

// SetRiskScorer injects a RiskScorer for context-aware alert enrichment.
// Call this before Start(). When nil, alerts are emitted with RiskScore=0.
func (el *EventLoop) SetRiskScorer(rs scoring.RiskScorer) {
	el.riskScorer = rs
}

// SetCorrelationManager injects an in-memory alert correlator (same-rule and
// time-based chain edges). Call before Start(). Nil disables correlation.
func (el *EventLoop) SetCorrelationManager(m *analytics.CorrelationManager) {
	el.alertCorrelator = m
}

// SetBaselineAggregator injects a BaselineAggregator for UEBA behavioral profiling.
// Call this before Start(). When nil, baseline aggregation is silently skipped.
func (el *EventLoop) SetBaselineAggregator(agg *baselines.BaselineAggregator) {
	el.baselineAggregator = agg
}

// SetPlaybookManager injects playbook automation. Call before Start().
func (el *EventLoop) SetPlaybookManager(m *automation.PlaybookManager) {
	el.playbooks = m
}

// SetEscalationManager injects timed escalation tracking. Call before Start().
func (el *EventLoop) SetEscalationManager(m *automation.EscalationManager) {
	el.escalations = m
}

// Start begins the event processing loop.
func (el *EventLoop) Start(ctx context.Context) error {
	if el.running.Load() {
		return nil
	}
	el.running.Store(true)

	logger.Infof("Starting event loop with %d detection workers", el.config.Workers)

	// Start Kafka consumer
	if err := el.consumer.Start(ctx); err != nil {
		return err
	}

	// Start Kafka producer
	if err := el.producer.Start(ctx); err != nil {
		el.consumer.Stop()
		return err
	}

	// Start detection workers (tracked separately so shutdown can wait for
	// them before closing the alert channel they send on).
	for i := 0; i < el.config.Workers; i++ {
		el.workerWG.Add(1)
		go el.detectionWorker(ctx, i)
	}

	// S2 FIX: Start async lineage write workers (decouple Redis I/O from detection)
	if el.lineageCache != nil {
		for i := 0; i < lineageWriteWorkers; i++ {
			el.wg.Add(1)
			go el.lineageWriteWorker(ctx, i)
		}
		logger.Infof("Lineage write workers started (%d workers, buffer=%d)", lineageWriteWorkers, lineageWriteBuffer)
	}

	// Start alert publisher
	el.wg.Add(1)
	go el.alertPublisher(ctx)

	// Start stats reporter
	el.wg.Add(1)
	go el.statsReporter(ctx)

	// Start suppression cache cleanup
	el.wg.Add(1)
	go el.suppressionCleaner(ctx)

	logger.Infof("Event loop started (alert suppression: %v window, alert buffer: %d)", el.suppression.ttl, el.config.AlertBuffer)
	return nil
}

// detectionWorker processes events from consumer and generates alerts.
// Drains eventChan until it is closed (by the consumer), then exits.
func (el *EventLoop) detectionWorker(ctx context.Context, workerID int) {
	defer el.workerWG.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("Panic recovered in detectionWorker %d: %v", workerID, r)
		}
	}()
	logger.Debugf("Detection worker %d started", workerID)

	eventChan := el.consumer.Events()

	for event := range eventChan {
		el.processOneEvent(event) // recovers its own panics
		// Commit the Kafka offset only now that the event is fully handled.
		event.Ack()
	}

	logger.Debugf("Detection worker %d stopped (event channel closed)", workerID)
}

// processOneEvent runs detection on a single event with panic isolation.
//
// Execution order:
//  1. Hydrate the lineage cache for process events (when configured)
//  2. Run Sigma rule evaluation (DetectAggregated)
//  3. If matched → generate alert → risk score → correlate → suppression → alertChan
func (el *EventLoop) processOneEvent(event *domain.LogEvent) {
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("Panic recovered while processing event: %v", r)
			atomic.AddUint64(&el.metrics.ProcessingErrors, 1)
		}
	}()

	atomic.AddUint64(&el.metrics.EventsReceived, 1)
	start := time.Now()

	// ── Step 1: LINEAGE CACHE HYDRATION ──────────────────────────────────────
	// Every process creation event is written to Redis regardless of whether
	// a Sigma rule matches. This provides a 12-minute ancestry window that
	// the RiskScorer (Sprint 2) can query for any subsequently matched event.
	if el.lineageCache != nil {
		el.hydrateLineageCache(event)
	}

	// ── Step 1b: UEBA BASELINE AGGREGATION ───────────────────────────────────
	// Record every process-creation event into the behavioral baseline model.
	// This is fire-and-forget (buffered channel); the detection pipeline is
	// never blocked by a slow DB write.
	if el.baselineAggregator != nil && baselines.ShouldRecord(event.RawData) {
		agentID, _ := event.GetField("agent_id")
		agentStr := ""
		if agentID != nil {
			agentStr, _ = agentID.(string)
		}
		in := baselines.ExtractAggregationInput(agentStr, event.RawData)
		el.baselineAggregator.Record(in)
	}
	// ─────────────────────────────────────────────────────────────────────────

	matchStart := time.Now()
	matchResult := el.detectionEngine.DetectAggregated(event)
	matchLatency := float64(time.Since(matchStart).Microseconds()) / 1000.0

	if matchResult != nil && matchResult.HasMatches() {
		baseAlert := el.alertGenerator.GenerateAggregatedAlert(matchResult)
		if baseAlert != nil {
			atomic.AddUint64(&el.metrics.AlertsGenerated, 1)

			// ── Step 2: CONTEXT-AWARE RISK SCORING ───────────────────────────────
			// Call RiskScorer immediately after alert generation so it can query
			// the lineage cache and burst tracker to compute the enriched score.
			// The scorer is non-blocking: errors are logged but never drop alerts.
			agentID, _ := event.GetField("agent_id")
			agentStr := ""
			if agentID != nil {
				agentStr, _ = agentID.(string)
			}

			if el.riskScorer != nil {
				scoringInput := scoring.ScoringInput{
					MatchResult: matchResult,
					Event:       event,
					AgentID:     agentStr,
				}
				scoreOut, scoreErr := el.riskScorer.Score(context.Background(), scoringInput)
				if scoreErr != nil {
					logger.Warnf("RiskScorer error for rule %s: %v — using base score", baseAlert.RuleID, scoreErr)
				} else {
					baseAlert.RiskScore = scoreOut.RiskScore
					baseAlert.FalsePositiveRisk = scoreOut.FalsePositiveRisk
					// Marshal ContextSnapshot and ScoreBreakdown to map[string]any
					if snap := scoreOut.Snapshot; snap != nil {
						importJson, _ := json.Marshal(snap)
						_ = json.Unmarshal(importJson, &baseAlert.ContextSnapshot)
						// Extract breakdown into its own top-level field for indexed querying
						bdJson, _ := json.Marshal(snap.ScoreBreakdown)
						_ = json.Unmarshal(bdJson, &baseAlert.ScoreBreakdown)
					}
					logger.Debugf("Risk scored alert %s: score=%d fp=%.2f lineage=%s",
						baseAlert.RuleID, scoreOut.RiskScore, scoreOut.FalsePositiveRisk,
						scoreOut.Snapshot.LineageSuspicion)
				}
			}
			// ─────────────────────────────────────────────────────────────────────

			// Correlation runs in the alert publisher, after persistence, so
			// edges reference the canonical (database) alert ID.

			// Suppression identity: rule + agent + the category-specific
			// subject of the event, so distinct activity (another DNS name,
			// destination, file or key) from one process is not merged.
			suppressKey := baseAlert.RuleID + "|" + agentStr + "|" + suppressionSubject(event)

			if el.suppression.shouldSuppress(suppressKey) {
				atomic.AddUint64(&el.metrics.AlertsSuppressed, 1)
			} else {
				// S6 FIX: Use 5s backpressure instead of silent drop.
				// Security alerts are too valuable to silently discard.
				select {
				case el.alertChan <- baseAlert:
				case <-time.After(5 * time.Second):
					// Backpressure fallback path:
					// Try direct best-effort publish/write so alerts are not lost when the
					// alert channel is saturated.
					// The database assigns the canonical identity, so when a
					// writer exists the alert goes to its retrying queue; Kafka
					// is used directly only when there is no writer.
					fallbackOK := false
					if el.alertWriter != nil {
						if err := el.alertWriter.Write(baseAlert); err == nil {
							fallbackOK = true
						}
					} else if err := el.producer.Publish(baseAlert); err == nil {
						atomic.AddUint64(&el.metrics.AlertsPublished, 1)
						fallbackOK = true
					}
					if !fallbackOK {
						atomic.AddUint64(&el.metrics.ProcessingErrors, 1)
						atomic.AddUint64(&el.metrics.AlertsDropped, 1)
						metricsPkg.DefaultMetrics.RecordError("alert_drop_channel_saturated")
						logger.Errorf("Alert channel full for 5s — ALERT DROPPED: rule=%s agent=%s", baseAlert.RuleID, agentStr)
					} else {
						atomic.AddUint64(&el.metrics.AlertFallbackUsed, 1)
						metricsPkg.DefaultMetrics.RecordError("alert_fallback_delivery_used")
						logger.Warnf("Alert channel saturated; used fallback delivery path: rule=%s agent=%s", baseAlert.RuleID, agentStr)
					}
				}
			}
		}
	}

	atomic.AddUint64(&el.metrics.EventsProcessed, 1)

	latency := float64(time.Since(start).Microseconds()) / 1000.0
	el.metrics.mu.Lock()
	el.metrics.AverageLatencyMs = (el.metrics.AverageLatencyMs*0.9 + latency*0.1)
	el.metrics.AverageRuleMatchingMs = (el.metrics.AverageRuleMatchingMs*0.9 + matchLatency*0.1)
	el.metrics.mu.Unlock()
}

// alertPublisher sends alerts to Kafka producer AND writes to PostgreSQL.
// Drains alertChan until it is closed, then exits.
func (el *EventLoop) alertPublisher(ctx context.Context) {
	defer el.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("Panic recovered in alertPublisher: %v", r)
		}
	}()
	logger.Debug("Alert publisher started")

	for alert := range el.alertChan {
		// 1. Persist first (dedup + retries). The writer sets alert.ID to the
		//    canonical database ID — the new row's or the merged alert's.
		//    A dedicated context lets alerts drained at shutdown still persist.
		isNew := true
		if el.alertWriter != nil {
			pctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, created, err := el.alertWriter.Persist(pctx, alert)
			cancel()
			if err != nil {
				atomic.AddUint64(&el.metrics.AlertDBQueueFailures, 1)
				metricsPkg.DefaultMetrics.RecordError("alert_db_persist_failed")
			} else {
				isNew = created
			}
		}

		// 2. Correlate new alerts under their canonical ID and store the
		//    resulting summary on the alert row.
		if isNew && el.alertCorrelator != nil {
			if rels := el.alertCorrelator.CorrelateAlert(alert); len(rels) > 0 {
				logger.Debugf("Correlations for alert %s: %d edge(s)", alert.ID, len(rels))
				if el.alertWriter != nil {
					if summary, ok := alert.ContextSnapshot["correlation"]; ok {
						cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						if err := el.alertWriter.UpdateCorrelationSummary(cctx, alert.ID, map[string]any{"correlation": summary}); err != nil {
							logger.Warnf("Failed to store correlation summary for alert %s: %v", alert.ID, err)
						}
						cancel()
					}
				}
			}
		}

		// 3. Publish to Kafka (same canonical ID as the database row)
		if err := el.producer.Publish(alert); err != nil {
			logger.Warnf("Failed to publish alert to Kafka: %v", err)
			atomic.AddUint64(&el.metrics.ProcessingErrors, 1)
			atomic.AddUint64(&el.metrics.AlertPublishFailures, 1)
			metricsPkg.DefaultMetrics.RecordError("alert_publish_failed")
		} else {
			atomic.AddUint64(&el.metrics.AlertsPublished, 1)
		}

		if el.escalations != nil {
			el.escalations.TrackAlert(alert)
		}
		// Response playbooks run once per incident: a deduplicated repeat of
		// an open alert must not re-trigger automated actions.
		if el.playbooks != nil && isNew {
			el.playbooks.ExecuteForAlert(ctx, alert)
		}
	}

	logger.Debug("Alert publisher stopped (alert channel closed)")
}

// statsReporter periodically reports statistics.
func (el *EventLoop) statsReporter(ctx context.Context) {
	defer el.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("Panic recovered in statsReporter: %v", r)
		}
	}()

	ticker := time.NewTicker(el.config.StatsInterval)
	defer ticker.Stop()

	var lastProcessed uint64
	lastTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-el.doneChan:
			return
		case <-ticker.C:
			processed := atomic.LoadUint64(&el.metrics.EventsProcessed)
			now := time.Now()
			duration := now.Sub(lastTime).Seconds()

			if duration > 0 {
				eps := float64(processed-lastProcessed) / duration
				el.metrics.mu.Lock()
				el.metrics.CurrentEPS = eps
				el.metrics.mu.Unlock()
			}

			consumerMetrics := el.consumer.Metrics()
			producerMetrics := el.producer.Metrics()
			loopMetrics := el.metrics.Snapshot()

			lineageCacheStatus := "disabled"
			if el.lineageCache != nil {
				lineageCacheErrors := el.lineageCacheErrors.Load()
				if lineageCacheErrors == 0 {
					lineageCacheStatus = "ok"
				} else {
					lineageCacheStatus = "degraded"
				}
			}

			logger.Infof("📊 Stats | Events: %d | Alerts: %d (suppressed: %d, cache: %d) | EPS: %.1f | Latency: %.1fms | Published: %d | Errors: %d | LineageCache: %s",
				loopMetrics.EventsProcessed,
				loopMetrics.AlertsGenerated,
				loopMetrics.AlertsSuppressed,
				el.suppression.size(),
				loopMetrics.CurrentEPS,
				loopMetrics.AverageLatencyMs,
				producerMetrics.AlertsPublished,
				consumerMetrics.DeserializeErrors+loopMetrics.ProcessingErrors,
				lineageCacheStatus,
			)

			lastProcessed = processed
			lastTime = now
		}
	}
}

// suppressionCleaner periodically purges expired entries from the dedup cache.
func (el *EventLoop) suppressionCleaner(ctx context.Context) {
	defer el.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("Panic recovered in suppressionCleaner: %v", r)
		}
	}()

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-el.doneChan:
			return
		case <-ticker.C:
			el.suppression.cleanup()
		}
	}
}

// Stop gracefully stops the event loop with correct drain ordering:
//  1. Stop consumer (closes eventChan → workers drain remaining events)
//  2. Wait for detection workers to finish (they exit when eventChan is closed)
//  3. Close alertChan → alert publisher drains remaining alerts
//  4. Signal statsReporter to stop
//  5. Wait for publisher + statsReporter to finish
//  6. Stop Kafka producer (flushes final batch)
func (el *EventLoop) Stop() error {
	if !el.running.Load() {
		return nil
	}
	el.running.Store(false)

	logger.Info("Stopping event loop (draining buffers)...")

	// Step 1: stop fetching. The consumer closes eventChan once its fetch
	// loops exit; workers drain what was already delivered.
	el.consumer.StopFetching()

	// Step 2: wait for the detection workers to drain and acknowledge.
	workersDone := make(chan struct{})
	go func() {
		el.workerWG.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
	case <-time.After(el.config.ShutdownTimeout):
		logger.Warn("Shutdown timeout waiting for detection workers; unacknowledged events will be re-delivered")
	}

	// Step 3: commit acknowledged offsets and close the reader.
	if err := el.consumer.Close(); err != nil {
		logger.Errorf("Error closing consumer: %v", err)
	}

	// Step 4: no worker can send any more (or they timed out). Closing the
	// alert channel lets the publisher drain and exit. (Previously this
	// happened after a fixed 2s sleep, racing workers still sending → panic
	// "send on closed channel" and lost alerts.)
	select {
	case <-workersDone:
		close(el.alertChan)
	default:
		logger.Warn("Detection workers still running; alert channel left open to avoid a send-on-closed panic")
	}
	close(el.doneChan) // stats reporter and other helpers exit

	// Step 5: wait for the publisher and helpers with timeout.
	allDone := make(chan struct{})
	go func() {
		el.wg.Wait()
		close(allDone)
	}()

	select {
	case <-allDone:
		logger.Info("All workers and publisher stopped")
	case <-time.After(el.config.ShutdownTimeout):
		logger.Warn("Shutdown timeout, some goroutines may still be running")
	}

	// Step 6: Stop Kafka producer (flushes the final writer batch)
	if err := el.producer.Stop(); err != nil {
		logger.Errorf("Error stopping producer: %v", err)
	}

	logger.Info("Event loop stopped")
	return nil
}

// Metrics returns current event loop metrics.
func (el *EventLoop) Metrics() EventLoopMetrics {
	return el.metrics.Snapshot()
}

// IsRunning returns whether the event loop is running.
func (el *EventLoop) IsRunning() bool {
	return el.running.Load()
}

// --- PerformanceMetricsProvider interface implementation ---

// GetEventsPerSecond returns the current events per second rate.
func (el *EventLoop) GetEventsPerSecond() float64 {
	el.metrics.mu.RLock()
	defer el.metrics.mu.RUnlock()
	return el.metrics.CurrentEPS
}

// GetAlertsPerSecond returns the current alerts per second rate.
func (el *EventLoop) GetAlertsPerSecond() float64 {
	published := atomic.LoadUint64(&el.metrics.AlertsPublished)
	processed := atomic.LoadUint64(&el.metrics.EventsProcessed)
	if processed == 0 {
		return 0
	}
	// Approximate alerts/sec as ratio of alerts to events × EPS
	el.metrics.mu.RLock()
	eps := el.metrics.CurrentEPS
	el.metrics.mu.RUnlock()
	return (float64(published) / float64(processed)) * eps
}

// GetAverageLatencyMs returns the average event processing latency in ms.
func (el *EventLoop) GetAverageLatencyMs() float64 {
	el.metrics.mu.RLock()
	defer el.metrics.mu.RUnlock()
	return el.metrics.AverageLatencyMs
}

// GetProcessingErrors returns the total number of processing errors.
func (el *EventLoop) GetProcessingErrors() uint64 {
	return atomic.LoadUint64(&el.metrics.ProcessingErrors)
}

// GetAverageRuleMatchingMs returns the average rule matching latency in ms.
func (el *EventLoop) GetAverageRuleMatchingMs() float64 {
	el.metrics.mu.RLock()
	defer el.metrics.mu.RUnlock()
	return el.metrics.AverageRuleMatchingMs
}

// GetAverageDatabaseQueryMs returns the average database write latency for alerts in ms.
func (el *EventLoop) GetAverageDatabaseQueryMs() float64 {
	if el.alertWriter != nil {
		return el.alertWriter.Metrics().AvgWriteLatencyMs
	}
	return 0.0
}

// GetEventsProcessed returns the total number of events processed.
func (el *EventLoop) GetEventsProcessed() uint64 {
	return atomic.LoadUint64(&el.metrics.EventsProcessed)
}

// GetAlertsDropped returns alerts dropped after fallback attempts fail.
func (el *EventLoop) GetAlertsDropped() uint64 {
	return atomic.LoadUint64(&el.metrics.AlertsDropped)
}

// GetAlertFallbackUsed returns alerts delivered via fallback path.
func (el *EventLoop) GetAlertFallbackUsed() uint64 {
	return atomic.LoadUint64(&el.metrics.AlertFallbackUsed)
}

// =============================================================================
// Lineage Cache Hydration (Context-Aware Detection — Sprint 1)
//
// S2 FIX: Writes are now ASYNCHRONOUS. hydrateLineageCache builds the entry
// and pushes it to lineageWriteCh (non-blocking). Dedicated lineageWriteWorker
// goroutines drain the channel and persist to Redis. Detection workers never
// block on Redis I/O for lineage hydration.
// =============================================================================

// hydrateLineageCache builds a ProcessLineageEntry from a process event and
// enqueues it for asynchronous Redis persistence. This method is NON-BLOCKING.
func (el *EventLoop) hydrateLineageCache(event *domain.LogEvent) {
	// Only process events carry the context we need.
	eventType, _ := event.GetField("event_type")
	if eventType != nil {
		et, _ := eventType.(string)
		if !strings.EqualFold(et, "process") {
			return
		}
	} else {
		// Fallback: skip if there is no pid field
		if v, ok := event.GetField("pid"); !ok || v == nil {
			return
		}
	}

	// Extract agent_id from the event payload.
	agentID := ""
	if v, ok := event.GetField("agent_id"); ok && v != nil {
		agentID, _ = v.(string)
	}
	if agentID == "" {
		if v, ok := event.GetField("source.agent_id"); ok && v != nil {
			agentID, _ = v.(string)
		}
	}
	if agentID == "" {
		return // cannot key the cache without an agent identifier
	}

	// Build a ProcessLineageEntry from the event's flat RawData map.
	entry := cache.NewProcessLineageEntry(agentID, event.RawData)

	logger.Debugf("[LINEAGE] hydrate agent=%s pid=%d ppid=%d name=%q exe=%q parentName=%q",
		agentID[:min(8, len(agentID))], entry.PID, entry.PPID,
		entry.Name, entry.Executable, entry.ParentName)

	if entry.PID == 0 {
		return // pid is required; skip events where it is missing or zero
	}

	// S2 FIX: Non-blocking enqueue to async writer channel.
	// If the channel is full, the write is skipped (best-effort).
	select {
	case el.lineageWriteCh <- entry:
	default:
		el.lineageCacheErrors.Add(1)
		if el.lineageCacheErrors.Load()%500 == 1 {
			logger.Warnf("[LINEAGE] write channel full (total drops=%d)", el.lineageCacheErrors.Load())
		}
	}
}

// lineageWriteWorker drains the lineageWriteCh and persists entries to Redis.
// Runs as a background goroutine alongside the detection workers.
func (el *EventLoop) lineageWriteWorker(ctx context.Context, workerID int) {
	defer el.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("Panic recovered in lineageWriteWorker %d: %v", workerID, r)
		}
	}()
	logger.Debugf("Lineage write worker %d started", workerID)

	for {
		select {
		case entry, ok := <-el.lineageWriteCh:
			if !ok {
				logger.Debugf("Lineage write worker %d stopped (channel closed)", workerID)
				return
			}
			writeCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
			if err := el.lineageCache.WriteEntry(writeCtx, entry); err != nil {
				el.lineageCacheErrors.Add(1)
				if el.lineageCacheErrors.Load()%100 == 1 {
					logger.Warnf("lineage cache write error (total=%d): %v",
						el.lineageCacheErrors.Load(), err)
				}
			}
			cancel()

		case <-ctx.Done():
			// Drain remaining entries before exiting
			for {
				select {
				case entry := <-el.lineageWriteCh:
					drainCtx, drainCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
					_ = el.lineageCache.WriteEntry(drainCtx, entry)
					drainCancel()
				default:
					logger.Debugf("Lineage write worker %d stopped (ctx done, drained)", workerID)
					return
				}
			}
		}
	}
}

// =============================================================================
// Event Field Extractors (used by suppression key + lineage)
// =============================================================================

// extractString retrieves a string from a flat or nested data map.
// suppressionSubject returns the category-specific subject of an event used
// in the alert suppression key: the process (name + pid) plus what it acted
// on — DNS name, network destination, file, registry key, pipe or target
// process. Two different subjects from the same process are distinct
// activity and must not suppress each other.
func suppressionSubject(event *domain.LogEvent) string {
	raw := event.RawData
	// File/registry events carry the acting process in process_name ("name"
	// is the file's name there); process events use name.
	name := extractString(raw, "process_name")
	if name == "" {
		name = extractString(raw, "name")
	}
	pid := extractInt64(raw, "pid")
	var object string
	switch event.Category {
	case domain.EventCategoryDNSQuery:
		object = extractString(raw, "query_name")
	case domain.EventCategoryNetworkConnection:
		object = extractString(raw, "destination_ip") + ":" + strconv.FormatInt(extractInt64(raw, "destination_port"), 10)
	case domain.EventCategoryFileEvent, domain.EventCategoryFileDelete, domain.EventCategoryFileRename:
		object = extractString(raw, "path")
		if object == "" {
			object = extractString(raw, "target_filename")
		}
	case domain.EventCategoryRegistrySet, domain.EventCategoryRegistryAdd, domain.EventCategoryRegistryDelete,
		domain.EventCategoryRegistryRename, domain.EventCategoryRegistryEvent:
		object = extractString(raw, "TargetObject")
		if object == "" {
			object = extractString(raw, "key_path")
		}
	case domain.EventCategoryPipeCreated, domain.EventCategoryPipeConnected:
		object = extractString(raw, "pipe_name")
	case domain.EventCategoryProcessAccess:
		object = strconv.FormatInt(extractInt64(raw, "target_pid"), 10)
	default:
		// Process events: the command line distinguishes re-use of a PID.
		object = extractString(raw, "command_line")
	}
	return name + "|" + strconv.FormatInt(pid, 10) + "|" + strings.ToLower(object)
}

func extractString(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	if v, ok := data[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	if sub, ok := data["data"]; ok && sub != nil {
		if m, ok := sub.(map[string]interface{}); ok {
			if v, ok := m[key]; ok && v != nil {
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

// extractInt64 retrieves an int64 from a flat or nested data map.
func extractInt64(data map[string]interface{}, key string) int64 {
	resolveVal := func(v interface{}) int64 {
		switch n := v.(type) {
		case int64:
			return n
		case int:
			return int64(n)
		case float64:
			return int64(n)
		case uint32:
			return int64(n)
		case uint64:
			return int64(n)
		}
		return 0
	}
	if data == nil {
		return 0
	}
	if v, ok := data[key]; ok && v != nil {
		return resolveVal(v)
	}
	if sub, ok := data["data"]; ok && sub != nil {
		if m, ok := sub.(map[string]interface{}); ok {
			if v, ok := m[key]; ok && v != nil {
				return resolveVal(v)
			}
		}
	}
	return 0
}

// min returns the smaller of a and b (Go 1.20 doesn't have built-in min for ints).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
