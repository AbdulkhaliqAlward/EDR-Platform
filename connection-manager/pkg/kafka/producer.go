// Package kafka provides Kafka producer and consumer implementations for event streaming.
package kafka

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/pkg/metrics"
)

// ProducerConfig holds Kafka producer configuration.
type ProducerConfig struct {
	Brokers     []string
	Topic       string
	DLQTopic    string
	Compression string // "snappy", "gzip", "lz4", "zstd"
	Acks        string // "none", "one", "all"
	MaxRetries  int
	BatchSize   int
	Timeout     time.Duration
}

// DefaultProducerConfig returns sensible defaults.
func DefaultProducerConfig(brokers []string) *ProducerConfig {
	return &ProducerConfig{
		Brokers:     brokers,
		Topic:       "events-raw",
		DLQTopic:    "events-dlq",
		Compression: "snappy",
		Acks:        "all",
		MaxRetries:  3,
		BatchSize:   16384,
		Timeout:     30 * time.Second,
	}
}

// EventProducer sends event batches to Kafka.
type EventProducer struct {
	writer    *kafka.Writer
	dlqWriter *kafka.Writer
	config    *ProducerConfig
	metrics   *metrics.Metrics
	logger    *logrus.Logger
}

// NewEventProducer creates a new Kafka event producer.
func NewEventProducer(cfg *ProducerConfig, m *metrics.Metrics, logger *logrus.Logger) (*EventProducer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, fmt.Errorf("at least one broker is required")
	}

	// Configure compression
	var compression kafka.Compression
	switch cfg.Compression {
	case "snappy":
		compression = kafka.Snappy
	case "gzip":
		compression = kafka.Gzip
	case "lz4":
		compression = kafka.Lz4
	case "zstd":
		compression = kafka.Zstd
	default:
		compression = kafka.Snappy
	}

	// Configure acks
	var requiredAcks kafka.RequiredAcks
	switch cfg.Acks {
	case "none":
		requiredAcks = kafka.RequireNone
	case "one":
		requiredAcks = kafka.RequireOne
	default:
		requiredAcks = kafka.RequireAll
	}

	// Main writer for events
	writer := &kafka.Writer{
		Addr:                   kafka.TCP(cfg.Brokers...),
		Topic:                  cfg.Topic,
		Balancer:               &kafka.Hash{}, // Partition by key (agent_id)
		Compression:            compression,
		RequiredAcks:           requiredAcks,
		MaxAttempts:            cfg.MaxRetries,
		BatchSize:              cfg.BatchSize,
		BatchTimeout:           10 * time.Millisecond,
		WriteTimeout:           cfg.Timeout,
		AllowAutoTopicCreation: false,
	}

	// DLQ writer for failed events
	dlqWriter := &kafka.Writer{
		Addr:                   kafka.TCP(cfg.Brokers...),
		Topic:                  cfg.DLQTopic,
		Compression:            compression,
		RequiredAcks:           kafka.RequireAll,
		MaxAttempts:            3,
		WriteTimeout:           10 * time.Second,
		AllowAutoTopicCreation: false,
	}

	logger.WithFields(logrus.Fields{
		"brokers":     cfg.Brokers,
		"topic":       cfg.Topic,
		"dlq_topic":   cfg.DLQTopic,
		"compression": cfg.Compression,
		"acks":        cfg.Acks,
	}).Info("Kafka producer initialized")

	return &EventProducer{
		writer:    writer,
		dlqWriter: dlqWriter,
		config:    cfg,
		metrics:   m,
		logger:    logger,
	}, nil
}

// SendEventBatch sends a serialized event batch to Kafka.
// The key is used for partitioning (typically agent_id).
func (p *EventProducer) SendEventBatch(ctx context.Context, key string, payload []byte, headers map[string]string) error {
	start := time.Now()

	// Build Kafka headers
	kafkaHeaders := make([]kafka.Header, 0, len(headers))
	for k, v := range headers {
		kafkaHeaders = append(kafkaHeaders, kafka.Header{Key: k, Value: []byte(v)})
	}

	// Create message
	msg := kafka.Message{
		Key:     []byte(key),
		Value:   payload,
		Headers: kafkaHeaders,
		Time:    time.Now(),
	}

	// Send to Kafka
	err := p.writer.WriteMessages(ctx, msg)
	duration := time.Since(start)

	if err != nil {
		p.logger.WithFields(logrus.Fields{
			"key":      key,
			"duration": duration,
			"error":    err.Error(),
		}).Error("Failed to send event batch to Kafka")

		if p.metrics != nil {
			p.metrics.ErrorsTotal.WithLabelValues("kafka_write").Inc()
		}

		// Send to DLQ
		p.sendToDLQ(ctx, key, payload, headers, err.Error())
		return fmt.Errorf("kafka write failed: %w", err)
	}

	if p.metrics != nil {
		p.metrics.EventBatchesReceived.Inc()
		p.metrics.RequestDuration.WithLabelValues("kafka_produce").Observe(duration.Seconds())
	}

	p.logger.WithFields(logrus.Fields{
		"key":      key,
		"duration": duration,
		"size":     len(payload),
	}).Debug("Event batch sent to Kafka")

	return nil
}

// EventMessage is one event to publish with SendEvents.
type EventMessage struct {
	Value   []byte
	Headers map[string]string
}

// SendEvents publishes several events (same partition key) in a single
// WriteMessages call — one round trip instead of one per event. It returns
// the indexes of the messages that were NOT written (nil when all were), so
// the caller can persist exactly those elsewhere without duplicating the
// ones Kafka already accepted. Failed events are not sent to the DLQ here;
// the caller owns their durability.
func (p *EventProducer) SendEvents(ctx context.Context, key string, events []EventMessage) ([]int, error) {
	if len(events) == 0 {
		return nil, nil
	}
	start := time.Now()
	now := time.Now()
	msgs := make([]kafka.Message, len(events))
	for i, ev := range events {
		hdrs := make([]kafka.Header, 0, len(ev.Headers))
		for k, v := range ev.Headers {
			hdrs = append(hdrs, kafka.Header{Key: k, Value: []byte(v)})
		}
		msgs[i] = kafka.Message{Key: []byte(key), Value: ev.Value, Headers: hdrs, Time: now}
	}

	err := p.writer.WriteMessages(ctx, msgs...)
	duration := time.Since(start)
	if err == nil {
		if p.metrics != nil {
			p.metrics.EventBatchesReceived.Inc()
			p.metrics.RequestDuration.WithLabelValues("kafka_produce").Observe(duration.Seconds())
		}
		return nil, nil
	}

	if p.metrics != nil {
		p.metrics.ErrorsTotal.WithLabelValues("kafka_write").Inc()
	}
	var failed []int
	var werrs kafka.WriteErrors
	if errors.As(err, &werrs) && len(werrs) == len(msgs) {
		for i, e := range werrs {
			if e != nil {
				failed = append(failed, i)
			}
		}
	} else {
		// Not a per-message error: treat every message as unwritten.
		failed = make([]int, len(msgs))
		for i := range msgs {
			failed[i] = i
		}
	}
	p.logger.WithFields(logrus.Fields{
		"key":      key,
		"events":   len(msgs),
		"failed":   len(failed),
		"duration": duration,
		"error":    err.Error(),
	}).Error("Failed to publish events to Kafka")
	return failed, fmt.Errorf("kafka write failed for %d/%d events: %w", len(failed), len(msgs), err)
}

// sendToDLQ sends failed messages to the Dead Letter Queue.
func (p *EventProducer) sendToDLQ(ctx context.Context, key string, payload []byte, headers map[string]string, errMsg string) {
	dlqHeaders := []kafka.Header{
		{Key: "original_key", Value: []byte(key)},
		{Key: "error", Value: []byte(errMsg)},
		{Key: "failed_at", Value: []byte(time.Now().UTC().Format(time.RFC3339))},
	}
	for k, v := range headers {
		dlqHeaders = append(dlqHeaders, kafka.Header{Key: "original_" + k, Value: []byte(v)})
	}

	msg := kafka.Message{
		Key:     []byte(key),
		Value:   payload,
		Headers: dlqHeaders,
		Time:    time.Now(),
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := p.dlqWriter.WriteMessages(ctx, msg); err != nil {
		p.logger.WithFields(logrus.Fields{
			"key":   key,
			"error": err.Error(),
		}).Error("Failed to write to DLQ")

		if p.metrics != nil {
			p.metrics.ErrorsTotal.WithLabelValues("kafka_dlq_write").Inc()
		}
	} else {
		p.logger.WithField("key", key).Warn("Event sent to DLQ")

		if p.metrics != nil {
			p.metrics.ErrorsTotal.WithLabelValues("kafka_dlq_entry").Inc()
		}
	}
}

// Stats returns producer statistics.
func (p *EventProducer) Stats() kafka.WriterStats {
	return p.writer.Stats()
}

// Close closes the producer connections.
func (p *EventProducer) Close() error {
	p.logger.Info("Closing Kafka producer...")

	if err := p.writer.Close(); err != nil {
		p.logger.WithError(err).Error("Error closing main writer")
	}

	if err := p.dlqWriter.Close(); err != nil {
		p.logger.WithError(err).Error("Error closing DLQ writer")
	}

	p.logger.Info("Kafka producer closed")
	return nil
}

// HealthCheck verifies the producer can connect to Kafka.
func (p *EventProducer) HealthCheck(ctx context.Context) error {
	// Try to connect to the first broker
	conn, err := kafka.DialContext(ctx, "tcp", p.config.Brokers[0])
	if err != nil {
		return fmt.Errorf("failed to connect to Kafka: %w", err)
	}
	defer conn.Close()

	// Get controller to verify cluster is responsive
	_, err = conn.Controller()
	if err != nil {
		return fmt.Errorf("failed to get Kafka controller: %w", err)
	}

	return nil
}
