// Package database provides alert writer that bridges detection and storage.
package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/jackc/pgx/v5/pgconn"
)

// AlertWriterConfig configures the alert writer.
type AlertWriterConfig struct {
	DeduplicationWindow time.Duration `yaml:"deduplication_window"`
	BatchSize           int           `yaml:"batch_size"`
	FlushInterval       time.Duration `yaml:"flush_interval"`
	MaxQueueSize        int           `yaml:"max_queue_size"`
}

// DefaultAlertWriterConfig returns default configuration.
func DefaultAlertWriterConfig() AlertWriterConfig {
	return AlertWriterConfig{
		// Sliding: measured from the LAST occurrence of the same rule on the
		// same endpoint (bounded to 24 h per alert in UpsertWithDedup).
		DeduplicationWindow: 30 * time.Minute,
		// Low-latency defaults so alerts show up near real-time in the dashboard.
		// Throughput is still protected by batching; the writer flushes at most every 100ms
		// unless BatchSize is hit first.
		BatchSize:     25,
		FlushInterval: 100 * time.Millisecond,
		MaxQueueSize:  10000,
	}
}

// AlertWriterMetrics tracks writer statistics.
type AlertWriterMetrics struct {
	AlertsWritten      uint64
	AlertsDeduplicated uint64
	AlertsDropped      uint64
	WriteErrors        uint64
	BatchesWritten     uint64
	AvgWriteLatencyMs  float64
	mu                 sync.RWMutex
}

// Snapshot returns a copy of metrics.
func (m *AlertWriterMetrics) Snapshot() AlertWriterMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return AlertWriterMetrics{
		AlertsWritten:      atomic.LoadUint64(&m.AlertsWritten),
		AlertsDeduplicated: atomic.LoadUint64(&m.AlertsDeduplicated),
		AlertsDropped:      atomic.LoadUint64(&m.AlertsDropped),
		WriteErrors:        atomic.LoadUint64(&m.WriteErrors),
		BatchesWritten:     atomic.LoadUint64(&m.BatchesWritten),
		AvgWriteLatencyMs:  m.AvgWriteLatencyMs,
	}
}

// AlertWriter writes alerts to PostgreSQL with deduplication.
type AlertWriter struct {
	repo    AlertRepository
	config  AlertWriterConfig
	metrics *AlertWriterMetrics
	// onAlertPersisted is an optional callback fired after an alert is
	// successfully inserted into storage. It is used to fan out real-time
	// notifications (e.g. WebSocket broadcast) without coupling writer logic
	// to transport concerns.
	onAlertPersisted func(*Alert)

	alertChan chan *domain.Alert
	doneChan  chan struct{}

	running atomic.Bool
	wg      sync.WaitGroup
}

// NewAlertWriter creates a new alert writer.
func NewAlertWriter(repo AlertRepository, config AlertWriterConfig) *AlertWriter {
	if config.MaxQueueSize <= 0 {
		config.MaxQueueSize = 10000
	}

	return &AlertWriter{
		repo:      repo,
		config:    config,
		metrics:   &AlertWriterMetrics{},
		alertChan: make(chan *domain.Alert, config.MaxQueueSize),
		doneChan:  make(chan struct{}),
	}
}

// Start begins the background writer.
func (w *AlertWriter) Start(ctx context.Context) error {
	if w.running.Load() {
		return nil
	}
	w.running.Store(true)

	logger.Info("Starting alert writer...")

	w.wg.Add(1)
	go w.writeLoop(ctx)

	return nil
}

// writeLoop processes alerts queued through Write (the asynchronous
// fallback path). Each alert is persisted with the same retry policy as
// Persist.
func (w *AlertWriter) writeLoop(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.config.FlushInterval)
	defer ticker.Stop()

	batch := make([]*domain.Alert, 0, w.config.BatchSize)

	flush := func(fctx context.Context) {
		if len(batch) == 0 {
			return
		}
		for _, alert := range batch {
			// Errors are logged (with the full alert) inside Persist.
			_, _, _ = w.Persist(fctx, alert)
		}
		atomic.AddUint64(&w.metrics.BatchesWritten, 1)
		batch = batch[:0]
	}
	// finalFlush drains on shutdown with its own bounded context: the
	// caller's ctx is already cancelled, which used to make every queued
	// alert fail to write.
	finalFlush := func() {
		for {
			select {
			case alert, ok := <-w.alertChan:
				if !ok {
					goto done
				}
				batch = append(batch, alert)
			default:
				goto done
			}
		}
	done:
		fctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		flush(fctx)
	}

	for {
		select {
		case <-ctx.Done():
			finalFlush()
			return
		case <-w.doneChan:
			finalFlush()
			return
		case alert, ok := <-w.alertChan:
			if !ok {
				finalFlush()
				return
			}
			batch = append(batch, alert)
			if len(batch) >= w.config.BatchSize {
				flush(ctx)
			}
		case <-ticker.C:
			flush(ctx)
		}
	}
}

// Persist retry policy: transient failures (connection loss, timeouts,
// serialisation/lock conflicts) are retried with exponential backoff; data
// and integrity errors fail fast because retrying cannot succeed.
const (
	persistMaxAttempts = 5
	persistBaseBackoff = 100 * time.Millisecond
	persistMaxBackoff  = 2 * time.Second
)

func isRetryablePersistError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case strings.HasPrefix(pgErr.Code, "22"), // data exception
			strings.HasPrefix(pgErr.Code, "23"), // integrity constraint violation
			strings.HasPrefix(pgErr.Code, "42"): // syntax error / undefined object
			return false
		}
	}
	return true
}

// Persist writes an alert synchronously (with deduplication and retries)
// and returns its canonical ID: the alert's own ID when a new row was
// inserted, or the ID of the existing alert it was merged into. The domain
// alert's ID is updated to the canonical ID so every downstream sink (Kafka,
// correlation, playbooks, WebSocket) uses the same identity as the database.
func (w *AlertWriter) Persist(ctx context.Context, domainAlert *domain.Alert) (string, bool, error) {
	start := time.Now()
	var lastErr error
	backoff := persistBaseBackoff
	for attempt := 1; attempt <= persistMaxAttempts; attempt++ {
		dbAlert := w.convertToDBAlert(domainAlert)
		result, isNew, err := w.repo.UpsertWithDedup(ctx, dbAlert, w.config.DeduplicationWindow)
		if err == nil {
			canonical := dbAlert.ID
			if result != nil && result.ID != "" {
				canonical = result.ID
			}
			domainAlert.ID = canonical

			latency := float64(time.Since(start).Milliseconds())
			w.metrics.mu.Lock()
			w.metrics.AvgWriteLatencyMs = w.metrics.AvgWriteLatencyMs*0.9 + latency*0.1
			w.metrics.mu.Unlock()

			if isNew {
				atomic.AddUint64(&w.metrics.AlertsWritten, 1)
			} else {
				atomic.AddUint64(&w.metrics.AlertsDeduplicated, 1)
			}
			// Merged evidence also needs a live UI refresh under the canonical ID.
			if w.onAlertPersisted != nil && result != nil {
				w.onAlertPersisted(result)
			}
			return canonical, isNew, nil
		}

		lastErr = err
		atomic.AddUint64(&w.metrics.WriteErrors, 1)
		if !isRetryablePersistError(err) || attempt == persistMaxAttempts {
			break
		}
		logger.Warnf("Alert persist attempt %d/%d failed (rule=%s): %v — retrying in %v",
			attempt, persistMaxAttempts, domainAlert.RuleID, err, backoff)
		select {
		case <-ctx.Done():
			lastErr = ctx.Err()
			attempt = persistMaxAttempts
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > persistMaxBackoff {
			backoff = persistMaxBackoff
		}
	}

	atomic.AddUint64(&w.metrics.AlertsDropped, 1)
	// Do not copy potentially sensitive command/script evidence into error logs.
	logger.Errorf("Alert persistence failed after retries (rule=%s): %v", domainAlert.RuleID, lastErr)
	return "", false, fmt.Errorf("persist alert: %w", lastErr)
}

// UpdateCorrelationSummary merges correlation information into a stored
// alert's context_snapshot (used after correlation runs on the canonical ID).
func (w *AlertWriter) UpdateCorrelationSummary(ctx context.Context, alertID string, summary map[string]any) error {
	updater, ok := w.repo.(interface {
		MergeContextSnapshot(ctx context.Context, id string, patch map[string]any) error
	})
	if !ok || alertID == "" || len(summary) == 0 {
		return nil
	}
	return updater.MergeContextSnapshot(ctx, alertID, summary)
}

// SetOnAlertPersisted registers an optional callback invoked for newly created
// alerts (not deduplicated updates).
func (w *AlertWriter) SetOnAlertPersisted(fn func(*Alert)) {
	w.onAlertPersisted = fn
}

// convertToDBAlert converts a domain Alert to database Alert.
func (w *AlertWriter) convertToDBAlert(da *domain.Alert) *Alert {
	// Extract MITRE tactics/techniques from alert
	tactics := make([]string, 0, len(da.MITRETactics))
	tactics = append(tactics, da.MITRETactics...)

	techniques := make([]string, 0, len(da.MITRETechniques))
	techniques = append(techniques, da.MITRETechniques...)

	// Generate event ID from EventID pointer
	eventID := ""
	if da.EventID != nil {
		eventID = *da.EventID
	}

	// Get original severity string
	origSeverity := ""
	if da.OriginalSeverity != 0 {
		origSeverity = da.OriginalSeverity.String()
	}

	// Extract agent_id from event data
	agentID := ""
	if da.EventData != nil {
		if aid, ok := da.EventData["agent_id"]; ok {
			if s, ok := aid.(string); ok {
				agentID = s
			}
		}
	}

	return &Alert{
		ID:                 da.ID, // canonical identity; the repository validates it
		Timestamp:          da.Timestamp,
		AgentID:            agentID,
		RuleID:             da.RuleID,
		RuleTitle:          da.RuleTitle,
		Severity:           da.Severity.String(),
		Category:           string(da.EventCategory),
		EventCount:         1,
		EventIDs:           []string{eventID},
		MitreTactics:       tactics,
		MitreTechniques:    techniques,
		MatchedFields:      da.MatchedFields,
		MatchedSelections:  da.MatchedSelections,
		ContextData:        da.EventData,
		Status:             "open",
		Confidence:         &da.Confidence,
		FalsePositiveRisk:  &da.FalsePositiveRisk,
		MatchCount:         &da.MatchCount,
		RelatedRules:       da.RelatedRules,
		RelatedRuleIDs:     da.RelatedRuleIDs,
		CombinedConfidence: &da.CombinedConfidence,
		SeverityPromoted:   &da.SeverityPromoted,
		OriginalSeverity:   origSeverity,
		// Context-Aware Risk Scoring fields (Phase 1)
		RiskScore:       da.RiskScore,
		ContextSnapshot: da.ContextSnapshot,
		ScoreBreakdown:  da.ScoreBreakdown,
	}
}

// Write queues an alert for writing.
func (w *AlertWriter) Write(alert *domain.Alert) error {
	if !w.running.Load() {
		return fmt.Errorf("alert writer is not running")
	}

	select {
	case w.alertChan <- alert:
		return nil
	default:
		atomic.AddUint64(&w.metrics.AlertsDropped, 1)
		return fmt.Errorf("alert writer queue full")
	}
}

// Metrics returns writer metrics.
func (w *AlertWriter) Metrics() AlertWriterMetrics {
	return w.metrics.Snapshot()
}

// Stop gracefully stops the writer.
func (w *AlertWriter) Stop() error {
	if !w.running.Load() {
		return nil
	}
	w.running.Store(false)

	logger.Info("Stopping alert writer...")
	close(w.doneChan)
	w.wg.Wait()

	logger.Info("Alert writer stopped")
	return nil
}

// IsRunning returns whether the writer is running.
func (w *AlertWriter) IsRunning() bool {
	return w.running.Load()
}
