// Package handlers provides gRPC handler implementations.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/pkg/kafka"
	"github.com/edr-platform/connection-manager/pkg/metrics"
)

// =========================================================================
// ASYNC FALLBACK STORE
// =========================================================================

// fallbackItem is one unit of work for the async fallback writer.
type fallbackItem struct {
	batchID  string
	agentID  string
	payload  []byte
	metadata map[string]string
}

// EventFallbackStore provides PostgreSQL-based fallback storage for event
// batches when the primary Kafka pipeline is unavailable.
//
// DESIGN: All writes are asynchronous via a bounded channel. A pool of
// worker goroutines drains the channel and performs INSERT operations.
// This prevents a Kafka outage from blocking the gRPC Recv() loop —
// the main pipeline stays responsive even under high fallback load.
//
// Schema expected:
//
//	CREATE TABLE IF NOT EXISTS event_batches_fallback (
//	    id          BIGSERIAL PRIMARY KEY,
//	    batch_id    TEXT NOT NULL UNIQUE,
//	    agent_id    TEXT NOT NULL,
//	    payload     BYTEA NOT NULL,
//	    metadata    JSONB,
//	    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//	    replayed    BOOLEAN NOT NULL DEFAULT FALSE,
//	    replayed_at TIMESTAMPTZ
//	);
//	CREATE INDEX idx_fallback_unreplayed ON event_batches_fallback (replayed) WHERE NOT replayed;
type EventFallbackStore struct {
	pool    *pgxpool.Pool
	metrics *metrics.Metrics
	logger  *logrus.Logger
	writeCh chan fallbackItem
	wg      sync.WaitGroup

	enqueuedAsync        atomic.Uint64
	channelFull          atomic.Uint64
	syncWriteUsed        atomic.Uint64
	syncWriteFailedDrops atomic.Uint64
	dbWriteFailed        atomic.Uint64
	marshalFailed        atomic.Uint64
}

const (
	// fallbackChanSize is the bounded buffer for async fallback writes.
	// When full, the oldest batches are dropped (data loss is already
	// the failure mode — at least the server stays responsive).
	fallbackChanSize = 4096

	// fallbackWorkers is the number of concurrent DB writer goroutines.
	fallbackWorkers = 4
)

// NewEventFallbackStore creates a new async fallback store.
// Returns nil if pool is nil (DB not configured), allowing callers to
// simply nil-check before use. Starts background workers immediately.
func NewEventFallbackStore(pool *pgxpool.Pool, m *metrics.Metrics, logger *logrus.Logger) *EventFallbackStore {
	if pool == nil {
		return nil
	}
	s := &EventFallbackStore{
		pool:    pool,
		metrics: m,
		logger:  logger,
		writeCh: make(chan fallbackItem, fallbackChanSize),
	}
	// Start writer workers
	for i := 0; i < fallbackWorkers; i++ {
		s.wg.Add(1)
		go s.writerWorker(i)
	}
	logger.Infof("Fallback store started with %d async writer workers (buffer=%d)", fallbackWorkers, fallbackChanSize)
	return s
}

// Store enqueues an event batch for asynchronous PostgreSQL persistence.
// This method is NON-BLOCKING: it pushes to a bounded channel and returns
// immediately. If the channel is full, the batch is dropped with a log warning.
func (s *EventFallbackStore) Store(_ context.Context, batchID, agentID string, payload []byte, metadata map[string]string) error {
	item := fallbackItem{
		batchID:  batchID,
		agentID:  agentID,
		payload:  payload,
		metadata: metadata,
	}
	select {
	case s.writeCh <- item:
		s.enqueuedAsync.Add(1)
		return nil
	default:
		// Reliability fallback: attempt synchronous write with bounded timeout
		// before declaring data loss.
		s.channelFull.Add(1)
		if s.metrics != nil {
			s.metrics.RecordError("fallback_channel_full")
		}
		syncCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.persistItemSync(syncCtx, item); err != nil {
			s.syncWriteFailedDrops.Add(1)
			if s.metrics != nil {
				s.metrics.RecordError("fallback_sync_write_failed")
			}
			s.logger.WithError(err).WithFields(logrus.Fields{
				"batch_id": batchID,
				"agent_id": agentID,
				"size":     len(payload),
			}).Error("Fallback channel full and sync write failed — event batch DROPPED")
			return fmt.Errorf("fallback channel full and sync write failed: %w", err)
		}
		s.syncWriteUsed.Add(1)
		s.logger.WithFields(logrus.Fields{
			"batch_id": batchID,
			"agent_id": agentID,
			"size":     len(payload),
		}).Warn("Fallback channel full — batch persisted via synchronous write")
		if s.metrics != nil {
			s.metrics.RecordError("fallback_sync_write_used")
		}
		return nil
	}
}

// writerWorker drains the write channel and persists batches to PostgreSQL.
func (s *EventFallbackStore) writerWorker(id int) {
	defer s.wg.Done()
	for item := range s.writeCh {
		s.persistItem(item)
	}
	s.logger.Debugf("Fallback writer worker %d stopped", id)
}

// persistItem performs the actual INSERT for one fallback batch.
func (s *EventFallbackStore) persistItem(item fallbackItem) {
	metadataJSON, err := json.Marshal(item.metadata)
	if err != nil {
		s.marshalFailed.Add(1)
		if s.metrics != nil {
			s.metrics.RecordError("fallback_marshal_failed")
		}
		s.logger.WithError(err).Error("Fallback: failed to marshal metadata")
		return
	}

	query := `
		INSERT INTO event_batches_fallback (batch_id, agent_id, payload, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (batch_id) DO NOTHING
	`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = s.pool.Exec(ctx, query, item.batchID, item.agentID, item.payload, metadataJSON, time.Now().UTC())
	if err != nil {
		s.dbWriteFailed.Add(1)
		if s.metrics != nil {
			s.metrics.RecordError("fallback_db_write_failed")
		}
		s.logger.WithError(err).WithFields(logrus.Fields{
			"batch_id": item.batchID,
			"agent_id": item.agentID,
		}).Error("Fallback DB write failed — event data may be lost")
		return
	}

	s.logger.WithFields(logrus.Fields{
		"batch_id": item.batchID,
		"agent_id": item.agentID,
		"size":     len(item.payload),
	}).Warn("Event batch saved to DB fallback (Kafka unavailable)")
}

// persistItemSync performs a bounded synchronous fallback write.
// StoreSync durably writes a batch to the fallback table before returning.
// Ingestion uses it so a batch is acknowledged to the agent only after its
// data is committed somewhere (Kafka or this table).
func (s *EventFallbackStore) StoreSync(ctx context.Context, batchID, agentID string, payload []byte, metadata map[string]string) error {
	s.syncWriteUsed.Add(1)
	return s.persistItemSync(ctx, fallbackItem{batchID: batchID, agentID: agentID, payload: payload, metadata: metadata})
}

func (s *EventFallbackStore) persistItemSync(ctx context.Context, item fallbackItem) error {
	metadataJSON, err := json.Marshal(item.metadata)
	if err != nil {
		s.marshalFailed.Add(1)
		return fmt.Errorf("marshal metadata: %w", err)
	}

	query := `
		INSERT INTO event_batches_fallback (batch_id, agent_id, payload, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (batch_id) DO NOTHING
	`

	_, err = s.pool.Exec(ctx, query, item.batchID, item.agentID, item.payload, metadataJSON, time.Now().UTC())
	if err != nil {
		s.dbWriteFailed.Add(1)
		return fmt.Errorf("sync fallback insert: %w", err)
	}
	return nil
}

// EventFallbackStats is a lightweight snapshot for operational monitoring.
type EventFallbackStats struct {
	ChannelLen          int    `json:"channel_len"`
	ChannelCap          int    `json:"channel_cap"`
	EnqueuedAsync       uint64 `json:"enqueued_async"`
	ChannelFull         uint64 `json:"channel_full"`
	SyncWriteUsed       uint64 `json:"sync_write_used"`
	SyncWriteFailedDrop uint64 `json:"sync_write_failed_drop"`
	DBWriteFailed       uint64 `json:"db_write_failed"`
	MarshalFailed       uint64 `json:"marshal_failed"`
}

// Stats returns a snapshot of fallback store reliability counters.
func (s *EventFallbackStore) Stats() EventFallbackStats {
	if s == nil {
		return EventFallbackStats{}
	}
	return EventFallbackStats{
		ChannelLen:          len(s.writeCh),
		ChannelCap:          cap(s.writeCh),
		EnqueuedAsync:       s.enqueuedAsync.Load(),
		ChannelFull:         s.channelFull.Load(),
		SyncWriteUsed:       s.syncWriteUsed.Load(),
		SyncWriteFailedDrop: s.syncWriteFailedDrops.Load(),
		DBWriteFailed:       s.dbWriteFailed.Load(),
		MarshalFailed:       s.marshalFailed.Load(),
	}
}

// Close stops all writer workers and waits for them to drain.
func (s *EventFallbackStore) Close() {
	close(s.writeCh)
	s.wg.Wait()
	s.logger.Info("Fallback store closed (all workers drained)")
}

// EnsureTable creates the fallback table if it doesn't exist.
// Call this during server startup so the fallback path is always available.
func (s *EventFallbackStore) EnsureTable(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS event_batches_fallback (
			id          BIGSERIAL PRIMARY KEY,
			batch_id    TEXT NOT NULL UNIQUE,
			agent_id    TEXT NOT NULL,
			payload     BYTEA NOT NULL,
			metadata    JSONB,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			replayed    BOOLEAN NOT NULL DEFAULT FALSE,
			replayed_at TIMESTAMPTZ
		);
		CREATE INDEX IF NOT EXISTS idx_fallback_unreplayed
			ON event_batches_fallback (replayed) WHERE NOT replayed;
	`

	_, err := s.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("create fallback table: %w", err)
	}

	s.logger.Info("Event fallback table ensured")
	return nil
}

// =========================================================================
// FALLBACK REPLAY WORKER
// =========================================================================

// FallbackReplayWorker periodically reads unreplayed event batches from the
// PostgreSQL fallback table and re-publishes them to Kafka. Once successfully
// published, the row is marked replayed=true.
//
// This closes the data-loss gap: events that landed in the fallback during
// a Kafka outage are automatically re-injected when Kafka recovers.
type FallbackReplayWorker struct {
	pool     *pgxpool.Pool
	producer *kafka.EventProducer
	logger   *logrus.Logger
	interval time.Duration
	batchSz  int
}

// NewFallbackReplayWorker creates a new replay worker.
// Returns nil if either pool or producer is nil (both required for replay).
func NewFallbackReplayWorker(pool *pgxpool.Pool, producer *kafka.EventProducer, logger *logrus.Logger) *FallbackReplayWorker {
	if pool == nil || producer == nil {
		return nil
	}
	return &FallbackReplayWorker{
		pool:     pool,
		producer: producer,
		logger:   logger,
		interval: 30 * time.Second,
		batchSz:  100,
	}
}

// Start begins the replay loop. Blocks until ctx is cancelled.
func (w *FallbackReplayWorker) Start(ctx context.Context) {
	w.logger.Info("Fallback replay worker started (interval=30s, batch=100)")
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("Fallback replay worker stopped")
			return
		case <-ticker.C:
			w.replayBatch(ctx)
		}
	}
}

// replayBatch claims up to batchSz unreplayed rows, re-publishes them to
// Kafka and marks them replayed — all inside one transaction, so the
// FOR UPDATE SKIP LOCKED row locks are held until the rows are marked and
// two replicas can never replay the same batch. (Previously the SELECT ran
// in autocommit mode, so its locks were released immediately.)
func (w *FallbackReplayWorker) replayBatch(ctx context.Context) {
	txCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	tx, err := w.pool.Begin(txCtx)
	if err != nil {
		w.logger.WithError(err).Warn("Fallback replay: begin transaction failed")
		return
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck // no-op after commit

	rows, err := tx.Query(txCtx, `
		SELECT id, batch_id, agent_id, payload
		FROM event_batches_fallback
		WHERE replayed = FALSE
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`, w.batchSz)
	if err != nil {
		w.logger.WithError(err).Warn("Fallback replay: failed to query unreplayed batches")
		return
	}
	type row struct {
		id      int64
		batchID string
		agentID string
		payload []byte
	}
	var claimed []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.batchID, &r.agentID, &r.payload); err != nil {
			w.logger.WithError(err).Warn("Fallback replay: row scan error")
			continue
		}
		claimed = append(claimed, r)
	}
	rows.Close()
	if len(claimed) == 0 {
		return
	}

	replayed := 0
	for _, r := range claimed {
		// Stored payloads are JSON arrays of already-normalised events (the
		// same objects the primary path publishes).
		var events []json.RawMessage
		if err := json.Unmarshal(r.payload, &events); err != nil {
			// A raw (e.g. undecompressable) batch cannot be turned into
			// events; publishing it would only poison the topic. Keep it in
			// the table for forensic recovery and stop retrying it.
			w.logger.WithError(err).WithField("batch_id", r.batchID).
				Error("Fallback replay: payload is not a JSON event array — retained in event_batches_fallback, not re-published")
		} else if len(events) > 0 {
			msgs := make([]kafka.EventMessage, len(events))
			for i, evtRaw := range events {
				msgs[i] = kafka.EventMessage{Value: evtRaw, Headers: map[string]string{
					"batch_id":    r.batchID,
					"agent_id":    r.agentID,
					"event_index": strconv.Itoa(i),
					"event_count": strconv.Itoa(len(events)),
					"replay":      "true",
				}}
			}
			if _, pubErr := w.producer.SendEvents(txCtx, r.agentID, msgs); pubErr != nil {
				w.logger.WithError(pubErr).WithField("batch_id", r.batchID).Warn("Fallback replay: Kafka publish failed — will retry")
				continue // stays unreplayed; retried next cycle (at-least-once)
			}
		}

		if _, err := tx.Exec(txCtx, `
			UPDATE event_batches_fallback
			SET replayed = TRUE, replayed_at = $1
			WHERE id = $2
		`, time.Now().UTC(), r.id); err != nil {
			w.logger.WithError(err).WithField("batch_id", r.batchID).Warn("Fallback replay: failed to mark as replayed")
			continue
		}
		replayed++
	}

	if err := tx.Commit(txCtx); err != nil {
		w.logger.WithError(err).Warn("Fallback replay: commit failed — batches will be replayed again")
		return
	}
	if replayed > 0 {
		w.logger.Infof("Fallback replay: successfully re-published %d batch(es) to Kafka", replayed)
	}
}
