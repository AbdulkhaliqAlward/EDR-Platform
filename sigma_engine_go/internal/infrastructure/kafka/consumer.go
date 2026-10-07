// Package kafka provides Kafka consumer and producer for Sigma Engine.
// This enables real-time event processing from Kafka topics instead of file-based input.
package kafka

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	metricsPkg "github.com/edr-platform/sigma-engine/internal/metrics"
	"github.com/segmentio/kafka-go"
)

// ConsumerConfig configures the Kafka consumer.
type ConsumerConfig struct {
	Brokers        []string      `yaml:"brokers"`
	Topic          string        `yaml:"topic"`
	GroupID        string        `yaml:"group_id"`
	MinBytes       int           `yaml:"min_bytes"`
	MaxBytes       int           `yaml:"max_bytes"`
	MaxWait        time.Duration `yaml:"max_wait"`
	CommitInterval time.Duration `yaml:"commit_interval"`
	StartOffset    int64         `yaml:"start_offset"` // -1 = latest, -2 = earliest
	// S1 FIX: Number of parallel reader goroutines that call ReadMessage().
	// More readers = better partition-level parallelism for multi-partition topics.
	ConsumerReaders int `yaml:"consumer_readers"`
}

// DefaultConsumerConfig returns default consumer configuration.
func DefaultConsumerConfig() ConsumerConfig {
	return ConsumerConfig{
		Brokers:         []string{"localhost:9092"},
		Topic:           "events-raw",
		GroupID:         "sigma-engine-group",
		MinBytes:        1,
		MaxBytes:        10e6, // 10MB
		MaxWait:         5 * time.Second,
		CommitInterval:  1 * time.Second,
		StartOffset:     kafka.LastOffset, // -1 = latest
		ConsumerReaders: 2,                // S1 FIX: default 2 parallel readers
	}
}

// ConsumerMetrics tracks consumer statistics.
type ConsumerMetrics struct {
	MessagesConsumed  uint64
	MessagesProcessed uint64
	DeserializeErrors uint64
	ProcessingErrors  uint64
	BatchesProcessed  uint64
	LastMessageTime   time.Time
	ConsumerLag       int64
	mu                sync.RWMutex
}

// Snapshot returns a copy of current metrics.
func (m *ConsumerMetrics) Snapshot() ConsumerMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ConsumerMetrics{
		MessagesConsumed:  atomic.LoadUint64(&m.MessagesConsumed),
		MessagesProcessed: atomic.LoadUint64(&m.MessagesProcessed),
		DeserializeErrors: atomic.LoadUint64(&m.DeserializeErrors),
		ProcessingErrors:  atomic.LoadUint64(&m.ProcessingErrors),
		BatchesProcessed:  atomic.LoadUint64(&m.BatchesProcessed),
		LastMessageTime:   m.LastMessageTime,
		ConsumerLag:       atomic.LoadInt64(&m.ConsumerLag),
	}
}

// EventConsumer consumes events from Kafka and converts them to LogEvent.
type EventConsumer struct {
	reader  *kafka.Reader
	config  ConsumerConfig
	metrics *ConsumerMetrics

	eventChan chan *domain.LogEvent
	errorChan chan error
	doneChan  chan struct{}

	running   atomic.Bool
	wg        sync.WaitGroup
	closeOnce sync.Once // S1 FIX: protect channel close from multiple goroutines

	// tracker commits an offset only after every earlier message of its
	// partition has been processed (at-least-once delivery).
	tracker      *offsetTracker
	readerClosed atomic.Bool
	stopOnce     sync.Once
	commitErrors atomic.Uint64
}

// NewEventConsumer creates a new Kafka event consumer.
func NewEventConsumer(config ConsumerConfig, eventBuffer int) (*EventConsumer, error) {
	if eventBuffer <= 0 {
		eventBuffer = 1000
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        config.Brokers,
		Topic:          config.Topic,
		GroupID:        config.GroupID,
		MinBytes:       config.MinBytes,
		MaxBytes:       config.MaxBytes,
		MaxWait:        config.MaxWait,
		CommitInterval: config.CommitInterval,
		StartOffset:    config.StartOffset,
		ErrorLogger:    kafka.LoggerFunc(func(msg string, args ...interface{}) { logger.Errorf(msg, args...) }),
	})

	return &EventConsumer{
		reader:    reader,
		config:    config,
		metrics:   &ConsumerMetrics{},
		eventChan: make(chan *domain.LogEvent, eventBuffer),
		errorChan: make(chan error, 100),
		doneChan:  make(chan struct{}),
		tracker:   newOffsetTracker(),
	}, nil
}

// Start begins consuming messages from Kafka.
func (c *EventConsumer) Start(ctx context.Context) error {
	if c.running.Load() {
		return nil
	}
	c.running.Store(true)

	readers := c.config.ConsumerReaders
	if readers <= 0 {
		readers = 2
	}

	logger.Infof("Starting Kafka consumer: brokers=%v topic=%s group=%s readers=%d",
		c.config.Brokers, c.config.Topic, c.config.GroupID, readers)

	// S1 FIX: Spawn multiple consumeLoop goroutines for partition-parallel reads.
	// segmentio/kafka-go Reader.ReadMessage() is concurrency-safe in consumer-group mode.
	for i := 0; i < readers; i++ {
		c.wg.Add(1)
		go c.consumeLoop(ctx, i)
	}

	return nil
}

// consumeLoop is the main consumer loop. Multiple instances may run in parallel (S1).
func (c *EventConsumer) consumeLoop(ctx context.Context, readerID int) {
	defer c.wg.Done()
	// Only close channels once across all goroutines (first to exit wins).
	defer c.closeOnce.Do(func() {
		close(c.eventChan)
		close(c.errorChan)
	})
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("Panic recovered in consumeLoop[%d]: %v", readerID, r)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Consumer context cancelled, stopping...")
			return
		case <-c.doneChan:
			logger.Info("Consumer stop requested, shutting down...")
			return
		default:
			// FetchMessage does NOT commit: offsets are committed by ack()
			// once the event has been processed. (ReadMessage auto-committed
			// on read, so a crash or a drop lost events silently.)
			readCtx, cancel := context.WithTimeout(ctx, c.config.MaxWait)
			msg, err := c.reader.FetchMessage(readCtx)
			cancel()

			if err != nil {
				if ctx.Err() != nil {
					return // Context cancelled
				}
				// Read timeout is expected during low/idle traffic polling.
				// kafka-go may wrap this as "fetching message: context deadline exceeded".
				if err == context.DeadlineExceeded || strings.Contains(err.Error(), "context deadline exceeded") {
					continue // No messages, retry
				}
				logger.Warnf("Error fetching Kafka message: %v", err)
				select {
				case c.errorChan <- err:
				default:
				}
				continue
			}

			atomic.AddUint64(&c.metrics.MessagesConsumed, 1)
			c.metrics.mu.Lock()
			c.metrics.LastMessageTime = time.Now()
			c.metrics.mu.Unlock()
			c.tracker.add(msg)

			// Convert to LogEvent. An unparseable message can never succeed,
			// so it is logged and acknowledged (it must not block its
			// partition's commits forever).
			event, err := c.parseMessage(msg)
			if err != nil {
				atomic.AddUint64(&c.metrics.DeserializeErrors, 1)
				metricsPkg.DefaultMetrics.RecordError("consumer_deserialize_failed")
				logger.Warnf("Discarding unparseable Kafka message partition=%d offset=%d: %v", msg.Partition, msg.Offset, err)
				c.ack(msg)
				continue
			}
			m := msg
			event.SetAck(func() { c.ack(m) })

			// Backpressure instead of dropping: when the detection workers
			// are saturated the consumer simply stops fetching; Kafka keeps
			// the data and consumer lag grows visibly. Events are never
			// discarded for being slow.
			select {
			case c.eventChan <- event:
				atomic.AddUint64(&c.metrics.MessagesProcessed, 1)
			case <-c.doneChan:
				return // not acked → re-delivered after restart
			case <-ctx.Done():
				return
			}
		}
	}
}

// ack marks a message processed and commits the partition's contiguous
// processed prefix. With CommitInterval > 0 kafka-go batches the commits.
func (c *EventConsumer) ack(msg kafka.Message) {
	commitMsg, ok := c.tracker.done(msg)
	if !ok || c.readerClosed.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.reader.CommitMessages(ctx, commitMsg); err != nil {
		// Typically a rebalance moved the partition; the new owner resumes
		// from the last committed offset (duplicates, never loss).
		c.commitErrors.Add(1)
		logger.Warnf("Kafka offset commit failed partition=%d offset=%d: %v", commitMsg.Partition, commitMsg.Offset, err)
	}
}

// parseMessage converts a Kafka message to LogEvent.
func (c *EventConsumer) parseMessage(msg kafka.Message) (*domain.LogEvent, error) {
	// Parse JSON payload
	var rawData map[string]interface{}
	if err := json.Unmarshal(msg.Value, &rawData); err != nil {
		return nil, err
	}

	// Add Kafka metadata
	rawData["_kafka_partition"] = msg.Partition
	rawData["_kafka_offset"] = msg.Offset
	rawData["_kafka_topic"] = msg.Topic
	rawData["_kafka_key"] = string(msg.Key)
	rawData["_kafka_time"] = msg.Time.Format(time.RFC3339)

	// Create LogEvent
	return domain.NewLogEvent(rawData)
}

// Events returns the channel for receiving parsed events.
func (c *EventConsumer) Events() <-chan *domain.LogEvent {
	return c.eventChan
}

// Errors returns the channel for receiving errors.
func (c *EventConsumer) Errors() <-chan error {
	return c.errorChan
}

// Metrics returns consumer metrics.
func (c *EventConsumer) Metrics() ConsumerMetrics {
	return c.metrics.Snapshot()
}

// StopFetching stops reading new messages and closes the event channel once
// every fetch loop has exited. Already-delivered events are still processed
// and acknowledged by the caller; call Close afterwards to commit them.
func (c *EventConsumer) StopFetching() {
	if !c.running.Load() {
		return
	}
	c.stopOnce.Do(func() {
		logger.Info("Stopping Kafka consumer fetch loops...")
		close(c.doneChan)
	})
	c.wg.Wait()
}

// Close flushes pending offset commits and closes the reader. Call it after
// the workers have drained and acknowledged their events.
func (c *EventConsumer) Close() error {
	if !c.running.Swap(false) {
		return nil
	}
	if n := c.tracker.inFlight(); n > 0 {
		logger.Warnf("Kafka consumer closing with %d unprocessed message(s); they will be re-delivered", n)
	}
	c.readerClosed.Store(true)
	if err := c.reader.Close(); err != nil { // Close flushes queued commits
		logger.Errorf("Error closing Kafka reader: %v", err)
		return err
	}
	logger.Info("Kafka consumer stopped")
	return nil
}

// Stop stops fetching and closes the reader (no draining). Prefer
// StopFetching + Close when events are being processed concurrently.
func (c *EventConsumer) Stop() error {
	c.StopFetching()
	return c.Close()
}

// IsRunning returns whether the consumer is running.
func (c *EventConsumer) IsRunning() bool {
	return c.running.Load()
}

// Lag returns the current consumer lag.
func (c *EventConsumer) Lag() int64 {
	return atomic.LoadInt64(&c.metrics.ConsumerLag)
}
