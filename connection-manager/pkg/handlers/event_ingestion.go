// Package handlers provides gRPC handler implementations.
package handlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/golang/snappy"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/contextkeys"
	"github.com/edr-platform/connection-manager/pkg/kafka"
	"github.com/edr-platform/connection-manager/pkg/metrics"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// EventHandler handles event ingestion RPCs.
// It implements a multi-tier delivery pipeline:
//  1. Primary:  Kafka (events-raw topic)
//  2. DLQ:      Kafka (events-dlq topic) — automatic on primary write failure
//  3. Fallback: PostgreSQL (event_batches_fallback table) — when Kafka is entirely down
//
// This ensures zero data loss: every event batch reaches durable storage
// regardless of individual component failures.
type EventHandler struct {
	logger        *logrus.Logger
	redis         *cache.RedisClient
	rateLimiter   *cache.RateLimiter
	kafkaProducer *kafka.EventProducer
	metrics       *metrics.Metrics
	fallbackStore *EventFallbackStore          // PostgreSQL fallback when Kafka is unavailable
	registry      *AgentRegistry               // Live agent presence and command routing
	agentService  service.AgentService         // Persists status to PostgreSQL
	commandRepo    repository.CommandRepository    // Re-delivers pending commands on reconnect
	quarantineRepo repository.QuarantineRepository // Optional: quarantine inventory from telemetry
	eventRepo      repository.EventRepository      // Optional: durable event store for REST search
	vulnRepo       repository.VulnerabilityRepository
}

// NewEventHandler creates a new event handler.
// All dependencies except logger are optional — the handler degrades
// gracefully when components are nil.
func NewEventHandler(
	logger *logrus.Logger,
	redis *cache.RedisClient,
	rateLimiter *cache.RateLimiter,
	kafkaProducer *kafka.EventProducer,
	m *metrics.Metrics,
) *EventHandler {
	return &EventHandler{
		logger:        logger,
		redis:         redis,
		rateLimiter:   rateLimiter,
		kafkaProducer: kafkaProducer,
		metrics:       m,
	}
}

// SetAgentRegistry sets the agent registry for real-time presence and command routing.
func (h *EventHandler) SetAgentRegistry(registry *AgentRegistry) {
	h.registry = registry
}

// SetAgentService sets the AgentService for PostgreSQL status persistence.
func (h *EventHandler) SetAgentService(svc service.AgentService) {
	h.agentService = svc
}

// SetCommandRepo sets the CommandRepository for pending command re-delivery.
// When set, on every agent stream open (including reconnects) the handler will
// query for any commands in status pending/sent and re-push them to the agent.
func (h *EventHandler) SetCommandRepo(repo repository.CommandRepository) {
	h.commandRepo = repo
}

// SetQuarantineRepo sets optional persistence for per-agent quarantine inventory.
func (h *EventHandler) SetQuarantineRepo(repo repository.QuarantineRepository) {
	h.quarantineRepo = repo
}

// SetEventRepo sets optional durable event repository for search/list APIs.
func (h *EventHandler) SetEventRepo(repo repository.EventRepository) {
	h.eventRepo = repo
}

// SetVulnerabilityRepo sets optional vulnerability repository for scanner telemetry ingestion.
func (h *EventHandler) SetVulnerabilityRepo(repo repository.VulnerabilityRepository) {
	h.vulnRepo = repo
}

// SetFallbackStore sets the PostgreSQL fallback store.
// Called from main.go after handler creation if DB is available.
func (h *EventHandler) SetFallbackStore(store *EventFallbackStore) {
	h.fallbackStore = store
}

// GetFallbackStore returns the configured PostgreSQL fallback store (may be nil).
func (h *EventHandler) GetFallbackStore() *EventFallbackStore {
	return h.fallbackStore
}

// StreamEvents handles bidirectional streaming for event ingestion.
// On stream open:  validates agent in DB, registers in AgentRegistry, updates PostgreSQL to 'online'.
// On stream close: deregisters agent, updates PostgreSQL to 'offline'.
// A dedicated goroutine drains the agent's command channel and pushes
// CommandBatch messages over the stream for real-time C2 delivery.
func (h *EventHandler) StreamEvents(stream edrv1.EventIngestionService_StreamEventsServer) error {
	ctx := stream.Context()
	agentID := extractAgentIDFromContext(ctx)

	// ── STRICT VALIDATION: Reject unknown/revoked agents ──
	// The agent MUST exist in the PostgreSQL database (created during RegisterAgent).
	// If the DB was wiped or the agent was revoked, reject with Unauthenticated
	// so the agent can detect this and re-enroll automatically.
	if h.agentService != nil {
		agentUUID, err := uuid.Parse(agentID)
		if err != nil {
			h.logger.WithField("agent_id", agentID).Warn("Rejected: invalid agent UUID")
			return status.Errorf(codes.Unauthenticated, "invalid agent ID format")
		}

		if _, err := h.agentService.GetByID(ctx, agentUUID); err != nil {
			// Only a genuinely missing agent means "re-enroll". A transient DB
			// error (e.g. Postgres restarting) must not tell the agent its
			// identity is invalid — the agent tears down its command stream on
			// Unauthenticated, so return a retryable Unavailable instead.
			if !errors.Is(err, repository.ErrNotFound) {
				h.logger.WithError(err).WithField("agent_id", agentID).Warn("Agent lookup failed (transient) — asking agent to retry")
				return status.Errorf(codes.Unavailable, "agent lookup temporarily unavailable — retry later")
			}
			h.logger.WithField("agent_id", agentID).Warn("Rejected: agent not found in database — must re-enroll")
			return status.Errorf(codes.Unauthenticated,
				"agent %s is not registered — re-enrollment required", agentID)
		}
	}

	h.logger.WithField("agent_id", agentID).Info("=== Agent came ONLINE (stream opened) ===")

	// 1. Register agent in the in-memory registry for command routing
	var cmdChan chan *edrv1.Command
	if h.registry != nil {
		cmdChan = h.registry.Register(agentID)
	}

	// 2. Mark agent as online in Redis (skip when Redis unavailable)
	if h.redis != nil {
		if err := h.redis.SetAgentStatus(ctx, agentID, "online", 10*time.Minute); err != nil {
			h.logger.WithError(err).Warn("Failed to set agent status in Redis")
		}
	}

	// 3. Persist 'online' status to PostgreSQL (source of truth)
	h.updateAgentDBStatus(agentID, "online")

	// 4. Re-deliver any commands that were lost during previous stream disconnect.
	//    Query for pending/sent commands and push them into the command channel so
	//    the agent receives them even after a reconnect.
	if h.commandRepo != nil && cmdChan != nil {
		go h.redeliverPendingCommands(ctx, agentID, cmdChan)
	}

	// 4. Ensure we mark agent offline when stream closes (graceful or crash)
	//    EXCEPTION: if agent was deliberately stopped (stop_agent command),
	//    SendCommandResult already set status='suspended'. We must NOT overwrite
	//    it with 'offline', as that would lose the distinction between
	//    "machine off" and "agent service stopped, machine still on".
	defer func() {
		h.logger.WithField("agent_id", agentID).Info("=== Agent went OFFLINE (stream closed/timeout) ===")

		// Deregister from in-memory registry
		if h.registry != nil {
			h.registry.Deregister(agentID)
		}

		// Update Redis (always mark offline in Redis — short TTL cache)
		if h.redis != nil {
			offlineCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := h.redis.SetAgentStatus(offlineCtx, agentID, "offline", 5*time.Minute); err != nil {
				h.logger.WithError(err).Warn("Failed to update agent status on stream close")
			}
		}

		// Persist to PostgreSQL — but only if agent is NOT in a deliberate terminal
		// or intentionally-stopped state. stop_agent sets `suspended` and the
		// uninstall path sets `pending_uninstall`/`uninstalled` before the stream
		// closes; overwriting any of these with `offline` would destroy meaningful
		// UI signals.
		currentStatus := h.fetchAgentStatus(agentID)
		switch currentStatus {
		case "suspended", "uninstalled", "pending_uninstall":
			h.logger.WithFields(logrus.Fields{"agent_id": agentID, "status": currentStatus}).
				Info("Stream closed — preserving explicit agent state (no offline overwrite)")
		default:
			h.updateAgentDBStatus(agentID, "offline")
		}
	}()

	// 5. Keepalive ticker: refreshes Redis TTL and PostgreSQL last_seen every
	//    2 minutes while the gRPC stream is alive. This prevents the agent
	//    from flipping to "offline" during idle periods with no event batches.
	keepAliveTicker := time.NewTicker(2 * time.Minute)
	go func() {
		defer keepAliveTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-keepAliveTicker.C:
				// Read current DB status to avoid overwriting deliberate states
				// (e.g. 'suspended' from stop_agent; 'uninstalled'/'pending_uninstall'
				// from the server-ordered uninstall flow).
				currentStatus := h.fetchAgentStatus(agentID)
				preserve := currentStatus == "suspended" || currentStatus == "uninstalled" || currentStatus == "pending_uninstall"
				statusToWrite := "online"
				if preserve {
					statusToWrite = currentStatus
				}
				if h.redis != nil {
					if err := h.redis.SetAgentStatus(ctx, agentID, statusToWrite, 10*time.Minute); err != nil {
						h.logger.WithError(err).WithField("agent_id", agentID).Debug("Keepalive: failed to refresh Redis TTL")
					}
				}
				if !preserve {
					h.updateAgentDBStatus(agentID, "online")
				}
				h.logger.WithField("agent_id", agentID).Debug("Keepalive: refreshed Redis TTL and DB last_seen")
			}
		}
	}()

	// 6. Unified send architecture: gRPC stream.Send() is NOT thread-safe.
	//    We use a single sendChan and a dedicated sender goroutine to serialize
	//    all writes (event responses + C2 commands) to the stream.
	sendChan := make(chan *edrv1.CommandBatch, 100)
	sendDone := make(chan error, 1)

	// Sender goroutine: the ONLY goroutine that calls stream.Send()
	go func() {
		for batch := range sendChan {
			if err := stream.Send(batch); err != nil {
				h.logger.WithError(err).WithField("agent_id", agentID).Warn("Stream send error")
				sendDone <- err
				return
			}
		}
		sendDone <- nil
	}()

	// 7. Command forwarder: drains the agent's command channel and pushes
	//    CommandBatch messages into sendChan for delivery via the sender goroutine.
	if cmdChan != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case cmd, ok := <-cmdChan:
					if !ok {
						return // channel closed — agent deregistered
					}
					if cmd == nil {
						continue
					}
					batch := &edrv1.CommandBatch{
						BatchId:      uuid.New().String(),
						Timestamp:    timestamppb.Now(),
						ServerStatus: edrv1.ServerStatus_SERVER_STATUS_OK,
						Commands:     []*edrv1.Command{cmd},
					}
					select {
					case sendChan <- batch:
						h.logger.WithFields(logrus.Fields{
							"agent_id":   agentID,
							"command_id": cmd.GetCommandId(),
							"type":       cmd.GetType().String(),
						}).Info("Command queued for agent stream delivery")
					default:
						h.logger.WithField("agent_id", agentID).Warn("Send channel full, dropping command")
					}
				}
			}
		}()
	}

	// 8. Process incoming event batches — recv runs in the main goroutine,
	//    responses are pushed into sendChan (never calling stream.Send directly).
	for {
		select {
		case err := <-sendDone:
			// Sender goroutine hit an error
			return status.Errorf(codes.Internal, "stream send error: %v", err)
		default:
		}

		batch, err := stream.Recv()
		if err == io.EOF {
			h.logger.WithField("agent_id", agentID).Info("Client closed stream gracefully")
			close(sendChan)
			return nil
		}
		if err != nil {
			h.logger.WithError(err).WithField("agent_id", agentID).Warn("Stream receive error")
			close(sendChan)
			return status.Errorf(codes.Internal, "stream receive error: %v", err)
		}

		// ── PER-BATCH RATE LIMITING (#1) ──
		// This is the critical check that was missing: rate limits are applied
		// on EVERY batch inside the stream, not just at stream establishment.
		// Each batch consumes batch.EventCount tokens from the bucket.
		if h.rateLimiter != nil {
			eventCount := int(batch.EventCount)
			if eventCount <= 0 {
				eventCount = 1
			}
			allowed, count, rlErr := h.rateLimiter.Allow(ctx, agentID, eventCount)
			if rlErr != nil {
				h.logger.WithError(rlErr).WithField("agent_id", agentID).Warn("Rate limiter error (fail-open)")
			} else if !allowed {
				h.logger.WithFields(logrus.Fields{
					"agent_id": agentID,
					"count":    count,
					"batch_id": batch.BatchId,
				}).Warn("Per-batch rate limit exceeded — dropping batch")
				if h.metrics != nil {
					h.metrics.RecordError("rate_limit_batch")
				}
				continue // Drop this batch, keep stream alive
			}
		}

		// Process the batch
		resp, err := h.processBatch(ctx, agentID, batch)
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"agent_id": agentID,
				"batch_id": batch.BatchId,
			}).Warn("Batch processing error")
			// Continue processing, don't close stream on batch error
			continue
		}

		// Queue response for sending (via the sender goroutine)
		if resp != nil {
			select {
			case sendChan <- resp:
			default:
				h.logger.WithField("agent_id", agentID).Warn("Send channel full, dropping batch response")
			}
		}

		// Update agent status TTL (skip when Redis unavailable)
		if h.redis != nil {
			h.redis.SetAgentStatus(ctx, agentID, "online", 10*time.Minute)
		}
	}
}

// commandPushLoop drains the agent's command channel and sends CommandBatch
// messages over the bidirectional stream. This enables the REST API to push
// commands to live agents in real-time without polling.
// Returns when the command channel is closed (agent deregistered) or ctx is done.
func (h *EventHandler) commandPushLoop(
	ctx context.Context,
	agentID string,
	stream edrv1.EventIngestionService_StreamEventsServer,
	cmdChan chan *edrv1.Command,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd, ok := <-cmdChan:
			if !ok {
				// Channel closed — agent deregistered
				return
			}
			if cmd == nil {
				continue
			}

			batch := &edrv1.CommandBatch{
				BatchId:      uuid.New().String(),
				Timestamp:    timestamppb.Now(),
				ServerStatus: edrv1.ServerStatus_SERVER_STATUS_OK,
				Commands:     []*edrv1.Command{cmd},
			}

			if err := stream.Send(batch); err != nil {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"agent_id":   agentID,
					"command_id": cmd.GetCommandId(),
				}).Warn("Failed to push command over stream")
				return
			}

			h.logger.WithFields(logrus.Fields{
				"agent_id":   agentID,
				"command_id": cmd.GetCommandId(),
				"type":       cmd.GetType().String(),
			}).Info("Command pushed to agent via stream")
		}
	}
}

// updateAgentDBStatus updates the agent status in PostgreSQL.
// Uses a fresh background context because this may be called during
// stream teardown when the stream context is already cancelled.
func (h *EventHandler) updateAgentDBStatus(agentID, status string) {
	if h.agentService == nil {
		return
	}

	agentUUID, err := uuid.Parse(agentID)
	if err != nil {
		h.logger.WithField("agent_id", agentID).Warn("Cannot update DB status: invalid UUID")
		return
	}

	dbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.agentService.UpdateStatus(dbCtx, agentUUID, status, nil); err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"agent_id": agentID,
			"status":   status,
		}).Warn("Failed to update agent status in PostgreSQL")
	} else {
		h.logger.WithFields(logrus.Fields{
			"agent_id": agentID,
			"status":   status,
		}).Info("Agent status updated in PostgreSQL")
	}
}

// fetchAgentStatus reads the current agent status from DB.
// Called by the stream-close defer to avoid overwriting 'suspended' with 'offline'.
// Returns "" (empty) when agentService is nil or UUID is invalid (treated as non-suspended).
func (h *EventHandler) fetchAgentStatus(agentID string) string {
	if h.agentService == nil {
		return ""
	}
	agentUUID, err := uuid.Parse(agentID)
	if err != nil {
		return ""
	}
	dbCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	agent, err := h.agentService.GetByID(dbCtx, agentUUID)
	if err != nil || agent == nil {
		return ""
	}
	return agent.Status
}

// redeliverPendingCommands queries the DB for commands in status pending/sent
// for the given agent and pushes them back into the command channel so the
// agent receives them after a reconnect. This closes the race window where the
// gRPC stream disconnects between Send() and actual delivery.
func (h *EventHandler) redeliverPendingCommands(ctx context.Context, agentID string, cmdChan chan *edrv1.Command) {
	agentUUID, err := uuid.Parse(agentID)
	if err != nil {
		return
	}

	dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pendingCmds, err := h.commandRepo.GetPendingForAgent(dbCtx, agentUUID)
	if err != nil {
		h.logger.WithError(err).WithField("agent_id", agentID).Warn("[C2] Failed to query pending commands for re-delivery")
		return
	}

	if len(pendingCmds) == 0 {
		return
	}

	h.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"count":    len(pendingCmds),
	}).Infof("[C2] Re-delivering %d pending command(s) to reconnected agent", len(pendingCmds))

	for _, dbCmd := range pendingCmds {
		// Map DB command_type string back to proto enum
		cmdType := mapDBCommandTypeToProto(string(dbCmd.CommandType))

		// Build proto Command from DB record
		params := make(map[string]string)
		for k, v := range dbCmd.Parameters {
			if str, ok := v.(string); ok {
				params[k] = str
			}
		}

		cmd := &edrv1.Command{
			CommandId:  dbCmd.ID.String(),
			Timestamp:  timestamppb.New(dbCmd.IssuedAt),
			Type:       cmdType,
			Parameters: params,
			Priority:   int32(dbCmd.Priority),
		}
		if !dbCmd.ExpiresAt.IsZero() {
			cmd.ExpiresAt = timestamppb.New(dbCmd.ExpiresAt)
		}

		select {
		case cmdChan <- cmd:
			h.logger.WithFields(logrus.Fields{
				"agent_id":   agentID,
				"command_id": dbCmd.ID,
				"type":       dbCmd.CommandType,
			}).Info("[C2] Pending command re-queued for delivery")
		case <-ctx.Done():
			h.logger.WithField("agent_id", agentID).Warn("[C2] Context done during pending command re-delivery")
			return
		default:
			h.logger.WithField("agent_id", agentID).Warn("[C2] Command channel full — skipping re-delivery for this command")
		}
	}
}

// mapDBCommandTypeToProto maps the human-readable DB command type strings back
// to proto CommandType values for re-delivery after agent reconnect.
func mapDBCommandTypeToProto(cmdType string) edrv1.CommandType {
	switch cmdType {
	case "terminate_process", "kill_process":
		return edrv1.CommandType_COMMAND_TYPE_TERMINATE_PROCESS
	case "collect_forensics", "collect_logs", "scan_file", "scan_memory":
		return edrv1.CommandType_COMMAND_TYPE_COLLECT_FORENSICS
	case "quarantine_file":
		return edrv1.CommandType(13) // COMMAND_TYPE_QUARANTINE_FILE
	case "block_ip":
		return edrv1.CommandType(14)
	case "unblock_ip":
		return edrv1.CommandType(15)
	case "block_domain":
		return edrv1.CommandType(16)
	case "unblock_domain":
		return edrv1.CommandType(17)
	case "update_signatures":
		return edrv1.CommandType(18)
	case "isolate_network", "isolate":
		return edrv1.CommandType_COMMAND_TYPE_ISOLATE
	case "restore_network", "unisolate_network", "unisolate":
		return edrv1.CommandType_COMMAND_TYPE_UNISOLATE
	case "restart_service", "restart_agent", "start_agent", "start_service", "stop_agent", "stop_service":
		return edrv1.CommandType_COMMAND_TYPE_RESTART_SERVICE
	case "enable_sysmon", "disable_sysmon":
		// Sysmon management routes through UPDATE_CONFIG on the agent side.
		// The agent's updateConfig handler checks params["mode"] and delegates
		// to enableSysmon() / disableSysmon() accordingly.
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_CONFIG
	case "update_agent":
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_AGENT
	case "uninstall_agent":
		return edrv1.CommandType(21)
	case "update_config", "update_policy":
		return edrv1.CommandType_COMMAND_TYPE_UPDATE_CONFIG
	case "update_filter_policy":
		return edrv1.CommandType(12) // COMMAND_TYPE_UPDATE_FILTER_POLICY
	case "adjust_rate":
		return edrv1.CommandType_COMMAND_TYPE_ADJUST_RATE
	case "run_cmd", "custom":
		return edrv1.CommandType(9) // COMMAND_TYPE_RUN_CMD
	case "restart", "restart_machine":
		return edrv1.CommandType(10)
	case "shutdown", "shutdown_machine":
		return edrv1.CommandType(11)
	case "restore_quarantine_file":
		return edrv1.CommandType(19)
	case "delete_quarantine_file":
		return edrv1.CommandType(20)
	default:
		return edrv1.CommandType_COMMAND_TYPE_UNSPECIFIED
	}
}

// processBatch processes a single event batch.
func (h *EventHandler) processBatch(ctx context.Context, agentID string, batch *edrv1.EventBatch) (*edrv1.CommandBatch, error) {
	logger := h.logger.WithFields(logrus.Fields{
		"agent_id":    agentID,
		"batch_id":    batch.BatchId,
		"event_count": batch.EventCount,
	})

	// 1. Validate batch
	if err := h.validateBatch(batch); err != nil {
		logger.WithError(err).Warn("Invalid batch")
		return nil, err
	}

	// 2. Check for duplicates (skip when Redis unavailable — assume batch is new)
	if h.redis != nil {
		duplicate, err := h.redis.IsBatchProcessed(ctx, batch.BatchId)
		if err != nil {
			logger.WithError(err).Warn("Duplicate check failed")
			// Continue on Redis error
		} else if duplicate {
			logger.Debug("Duplicate batch ignored")
			return nil, nil // Silently ignore duplicates (idempotent)
		}
	}

	// 3. Verify checksum if provided
	if batch.Checksum != "" {
		if !h.verifyChecksum(batch.Payload, batch.Checksum) {
			logger.Warn("Checksum mismatch")
			return nil, status.Error(codes.InvalidArgument, "checksum mismatch")
		}
	}

	// 4. Decompress payload if needed
	// Production requirement: agents may use either Snappy (fast, default)
	// or Gzip (better ratio for bandwidth-constrained links). Both must work.
	payload := batch.Payload
	switch batch.Compression {
	case edrv1.Compression_COMPRESSION_SNAPPY:
		decompressed, err := snappy.Decode(nil, batch.Payload)
		if err != nil {
			logger.WithError(err).Error("Snappy decompression failed — routing raw batch to DB fallback")
			h.storeToFallback(ctx, batch, batch.Payload)
			return nil, nil // Do not crash pipeline; data preserved in fallback
		}
		payload = decompressed

	case edrv1.Compression_COMPRESSION_GZIP:
		// Gzip decompression with io.LimitReader (32MB) to prevent zip-bomb DoS attacks.
		gzReader, err := gzip.NewReader(bytes.NewReader(batch.Payload))
		if err != nil {
			logger.WithError(err).Error("Gzip reader creation failed — routing raw batch to DB fallback")
			h.storeToFallback(ctx, batch, batch.Payload)
			return nil, nil
		}
		const maxDecompressedSize = 32 * 1024 * 1024 // 32MB limit
		decompressed, err := io.ReadAll(io.LimitReader(gzReader, maxDecompressedSize))
		gzReader.Close()
		if err != nil {
			logger.WithError(err).Error("Gzip decompression failed — routing raw batch to DB fallback")
			h.storeToFallback(ctx, batch, batch.Payload)
			return nil, nil
		}
		payload = decompressed

	case edrv1.Compression_COMPRESSION_NONE:
		// No decompression needed
	default:
		logger.WithField("compression", batch.Compression).Warn("Unknown compression type — treating payload as uncompressed")
	}

	// 5. Parse decompressed payload as JSON array of events (contract for downstream Sigma Engine).
	var events []map[string]interface{}
	if err := json.Unmarshal(payload, &events); err != nil {
		logger.WithError(err).Error("Failed to unmarshal decompressed payload as JSON array — routing raw batch to DB fallback")
		h.storeToFallback(ctx, batch, batch.Payload)
		return nil, nil // Ack batch so pipeline does not crash or retry indefinitely
	}
	if len(events) == 0 {
		logger.Warn("Decompressed payload is empty array — skipping Kafka publish, storing raw batch to fallback")
		h.storeToFallback(ctx, batch, batch.Payload)
		return nil, nil
	}

	// 5b. STRICT JSON SCHEMA VALIDATION (#3)
	// Every event MUST have event_type (string), timestamp (string), and severity (string).
	// Events that fail validation are logged and dropped; valid events continue.
	validEvents := make([]map[string]interface{}, 0, len(events))
	for i, ev := range events {
		// Normalize critical context fields using best-effort fallbacks so
		// missing top-level fields can still be recovered from nested payloads.
		enrichEventContextFields(ev)

		// Ensure required context fields exist for quality scoring.
		// evaluateEventContextQuality() requires agent_id, but we only injected it
		// in a later step; this caused systematic quality degradation (P0 gap).
		ev["agent_id"] = agentID
		ev["batch_id"] = batch.BatchId

		if err := validateEventSchema(ev); err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"event_index": i,
				"batch_id":    batch.BatchId,
			}).Warn("Event failed schema validation — dropped")
			if h.metrics != nil {
				h.metrics.RecordError("schema_validation_failed")
			}
			continue
		}

		quality, missing := evaluateEventContextQuality(ev)
		ev["context_quality_score"] = quality
		if len(missing) > 0 {
			ev["missing_context_fields"] = missing
		}

		// Optional strict mode for production hardening:
		// EDR_EVENT_CONTEXT_MODE=strict will drop events that miss required
		// context fields after fallback enrichment.
		if isStrictContextMode() && len(missing) > 0 {
			logger.WithFields(logrus.Fields{
				"event_index": i,
				"batch_id":    batch.BatchId,
				"missing":     strings.Join(missing, ","),
			}).Warn("Event dropped by strict context mode")
			if h.metrics != nil {
				h.metrics.RecordError("context_quality_strict_drop")
			}
			continue
		}

		if len(missing) > 0 {
			logger.WithFields(logrus.Fields{
				"event_index": i,
				"batch_id":    batch.BatchId,
				"missing":     strings.Join(missing, ","),
				"quality":     quality,
			}).Debug("Event accepted with partial context (soft mode)")
		}

		validEvents = append(validEvents, ev)
	}
	if len(validEvents) == 0 {
		logger.WithField("batch_id", batch.BatchId).Warn("All events in batch failed schema validation")
		return nil, nil
	}
	events = validEvents

	h.noteAutonomousResponseEvents(logger, agentID, batch, events)
	h.persistQuarantineFromEvents(ctx, agentID, events)
	if h.vulnRepo != nil {
		if err := h.ingestVulnerabilityEvents(ctx, agentID, events); err != nil {
			logger.WithError(err).Warn("Failed to ingest vulnerability telemetry events")
		}
	}

	// 6b. Persist searchable events to PostgreSQL for REST /events/search.
	// This is independent from Kafka: even when Kafka is enabled, we still
	// store a searchable subset so the dashboard can investigate without
	// needing a separate event warehouse.
	if h.eventRepo != nil {
		if err := h.persistEventsToDB(ctx, agentID, batch, events); err != nil {
			logger.WithError(err).Warn("Failed to persist events to DB (search UI may show empty results)")
		}
	}

	// 7. Publish each event individually to Kafka (agent_id as partition key). Respect context cancellation.
	if h.kafkaProducer != nil {
		for i, ev := range events {
			select {
			case <-ctx.Done():
				logger.WithError(ctx.Err()).Warn("Context cancelled during event publish — routing batch to DB fallback")
				h.storeToFallback(ctx, batch, payload)
				code := codes.Canceled
				if ctx.Err() == context.DeadlineExceeded {
					code = codes.DeadlineExceeded
				}
				return nil, status.Error(code, ctx.Err().Error())
			default:
			}
			eventJSON, err := json.Marshal(ev)
			if err != nil {
				logger.WithError(err).WithField("event_index", i).Error("Failed to marshal event — routing batch to DB fallback")
				h.storeToFallback(ctx, batch, payload)
				return nil, nil
			}
			headers := map[string]string{
				"batch_id":    batch.BatchId,
				"agent_id":    batch.AgentId,
				"event_index": fmt.Sprintf("%d", i),
				"event_count": fmt.Sprintf("%d", len(events)),
			}
			if err := h.kafkaProducer.SendEventBatch(ctx, batch.AgentId, eventJSON, headers); err != nil {
				logger.WithError(err).WithField("event_index", i).Warn("Kafka write failed — routing batch to DB fallback")
				h.storeToFallback(ctx, batch, payload)
				return nil, nil // Do not crash pipeline; data preserved in fallback
			}
		}
		logger.WithField("events", len(events)).Debug("Events sent to Kafka individually")
	} else {
		logger.Debug("Kafka disabled — storing batch via DB fallback")
		h.storeToFallback(ctx, batch, payload)
	}

	// 8. Record metrics
	if h.metrics != nil {
		h.metrics.RecordEventBatch(int(batch.EventCount), len(batch.Payload))
	}

	// 9. Mark batch as processed (skip when Redis unavailable)
	if h.redis != nil {
		if err := h.redis.SetBatchProcessed(ctx, batch.BatchId, 24*time.Hour); err != nil {
			logger.WithError(err).Warn("Failed to mark batch as processed")
		}
	}

	// 10. Prepare response
	return &edrv1.CommandBatch{
		BatchId:      uuid.New().String(),
		Timestamp:    timestamppb.Now(),
		ServerStatus: edrv1.ServerStatus_SERVER_STATUS_OK,
		AckBatchId:   batch.BatchId,
	}, nil
}

func (h *EventHandler) ingestVulnerabilityEvents(ctx context.Context, agentID string, events []map[string]interface{}) error {
	aid, err := uuid.Parse(agentID)
	if err != nil {
		return fmt.Errorf("invalid agent_id %q: %w", agentID, err)
	}
	items := make([]repository.VulnerabilityFindingInput, 0, 128)
	for _, ev := range events {
		etype, _ := ev["event_type"].(string)
		if !strings.EqualFold(strings.TrimSpace(etype), "vulnerability_finding") {
			continue
		}
		data, _ := ev["data"].(map[string]interface{})
		if data == nil {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(asString(data["cve"])))
		if cve == "" {
			continue
		}
		var cvss *float64
		if v := asFloat64(data["cvss"]); v > 0 {
			cvss = &v
		}
		var publishedAt *time.Time
		if s := strings.TrimSpace(asString(data["published_at"])); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				publishedAt = &t
			}
		}
		items = append(items, repository.VulnerabilityFindingInput{
			AgentID:          aid,
			CVE:              cve,
			Title:            strings.TrimSpace(asString(data["title"])),
			Description:      strings.TrimSpace(asString(data["description"])),
			Severity:         strings.ToLower(strings.TrimSpace(asString(data["severity"]))),
			CVSS:             cvss,
			Source:           strings.ToLower(strings.TrimSpace(asString(data["source"]))),
			PackageName:      strings.TrimSpace(asString(data["package_name"])),
			InstalledVersion: strings.TrimSpace(asString(data["installed_version"])),
			FixedVersion:     strings.TrimSpace(asString(data["fixed_version"])),
			ReferenceURL:     strings.TrimSpace(asString(data["reference_url"])),
			PublishedAt:      publishedAt,
		})
	}
	if len(items) == 0 {
		return nil
	}
	inserted, updated, err := h.vulnRepo.BulkUpsert(ctx, items)
	if err != nil {
		return err
	}
	h.logger.WithFields(logrus.Fields{
		"agent_id": agentID,
		"parsed":   len(items),
		"inserted": inserted,
		"updated":  updated,
	}).Info("Vulnerability telemetry ingested")
	return nil
}

func asString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return fmt.Sprintf("%g", t)
	case int:
		return fmt.Sprintf("%d", t)
	default:
		return ""
	}
}

func asFloat64(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		var f float64
		fmt.Sscanf(strings.TrimSpace(t), "%f", &f)
		return f
	default:
		return 0
	}
}

func (h *EventHandler) persistEventsToDB(ctx context.Context, agentID string, batch *edrv1.EventBatch, events []map[string]interface{}) error {
	agentUUID, err := uuid.Parse(agentID)
	if err != nil {
		return fmt.Errorf("invalid agent_id: %w", err)
	}

	var batchUUID *uuid.UUID
	if batch != nil && batch.GetBatchId() != "" {
		if bid, err := uuid.Parse(batch.GetBatchId()); err == nil {
			batchUUID = &bid
		}
	}

	rows := make([]repository.EventInsert, 0, len(events))
	for _, ev := range events {
		raw, err := json.Marshal(ev)
		if err != nil {
			continue
		}

		etype, _ := ev["event_type"].(string)
		severity, _ := ev["severity"].(string)
		if severity == "" {
			severity = "informational"
		}
		tsStr, _ := ev["timestamp"].(string)
		ts, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			// best-effort: allow timestamp-less persistence to now
			ts = time.Now().UTC()
		}

		summary := ""
		if s, ok := ev["summary"].(string); ok {
			summary = s
		} else if data, ok := ev["data"].(map[string]interface{}); ok {
			// common field used by many agents
			if s, ok := data["summary"].(string); ok {
				summary = s
			}
		}
		if summary == "" {
			summary = fmt.Sprintf("%s event", etype)
		}

		rows = append(rows, repository.EventInsert{
			ID:        uuid.New(),
			AgentID:   agentUUID,
			BatchID:   batchUUID,
			EventType: etype,
			Severity:  severity,
			Timestamp: ts.UTC(),
			Summary:   summary,
			Raw:       raw,
		})
	}
	if len(rows) == 0 {
		return nil
	}

	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return h.eventRepo.InsertMany(dbCtx, rows)
}

// validateBatch validates the event batch structure.
func (h *EventHandler) validateBatch(batch *edrv1.EventBatch) error {
	if batch.BatchId == "" {
		return status.Error(codes.InvalidArgument, "batch_id is required")
	}
	if batch.AgentId == "" {
		return status.Error(codes.InvalidArgument, "agent_id is required")
	}
	if batch.EventCount <= 0 {
		return status.Error(codes.InvalidArgument, "event_count must be positive")
	}
	if len(batch.Payload) == 0 {
		return status.Error(codes.InvalidArgument, "payload is required")
	}

	// Check payload size (max 10MB)
	const maxPayloadSize = 10 * 1024 * 1024
	if len(batch.Payload) > maxPayloadSize {
		return status.Errorf(codes.InvalidArgument,
			"payload too large: %d bytes (max: %d)", len(batch.Payload), maxPayloadSize)
	}

	return nil
}

// verifyChecksum verifies the SHA256 checksum of the payload.
func (h *EventHandler) verifyChecksum(payload []byte, expectedChecksum string) bool {
	hash := sha256.Sum256(payload)
	actualChecksum := hex.EncodeToString(hash[:])
	return actualChecksum == expectedChecksum
}

// extractAgentIDFromContext gets agent ID from context (set by auth stream interceptor).
func extractAgentIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(contextkeys.AgentIDKey).(string); ok {
		return id
	}
	return "unknown"
}

// ============================================================================
// JSON SCHEMA VALIDATION (#3)
// ============================================================================

// validateEventSchema enforces a strict contract on each event before Kafka
// ingestion. Required fields: event_type, timestamp, severity (all strings).
// Also applies a per-event size limit to prevent oversized objects from
// reaching Kafka.
func validateEventSchema(ev map[string]interface{}) error {
	const maxEventSize = 1 * 1024 * 1024 // 1 MB per individual event

	// Required string fields
	requiredStrings := []string{"event_type", "timestamp", "severity"}
	for _, field := range requiredStrings {
		val, exists := ev[field]
		if !exists {
			return fmt.Errorf("missing required field: %s", field)
		}
		// Defense-in-depth: coerce numeric severity to string so older agents
		// that send severity as a number (e.g., 1, 2) are not dropped.
		if _, ok := val.(string); !ok {
			if num, isNum := val.(float64); isNum && field == "severity" {
				ev[field] = fmt.Sprintf("%d", int(num))
			} else {
				return fmt.Errorf("field %s must be a string, got %T", field, val)
			}
		}
	}

	// event_type must not be empty
	if ev["event_type"].(string) == "" {
		return fmt.Errorf("event_type must not be empty")
	}

	// Per-event size check (marshal to check serialized size)
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("event is not valid JSON: %w", err)
	}
	if len(raw) > maxEventSize {
		return fmt.Errorf("event too large: %d bytes (max %d)", len(raw), maxEventSize)
	}

	return nil
}

// noteAutonomousResponseEvents logs when the agent performed a local response (quarantine / process rule)
// and emitted telemetry so operators can confirm the platform received it.
func (h *EventHandler) noteAutonomousResponseEvents(logger *logrus.Entry, agentID string, batch *edrv1.EventBatch, events []map[string]interface{}) {
	if batch != nil && batch.GetMetadata() != nil {
		if batch.GetMetadata()["autonomous_response"] == "true" {
			logger.WithFields(logrus.Fields{
				"agent_id": agentID,
				"batch_id": batch.GetBatchId(),
			}).Info("[AutonomousResponse] Agent flagged batch containing local response actions")
		}
	}
	for i, ev := range events {
		data, _ := ev["data"].(map[string]interface{})
		if data == nil || !interfaceTruthyAutonomous(data["autonomous"]) {
			continue
		}
		action, _ := data["action"].(string)
		threat, _ := data["threat_name"].(string)
		bid := ""
		if batch != nil {
			bid = batch.GetBatchId()
		}
		logger.WithFields(logrus.Fields{
			"agent_id":    agentID,
			"batch_id":    bid,
			"event_index": i,
			"event_type":  ev["event_type"],
			"action":      action,
			"threat_name": threat,
		}).Info("[AutonomousResponse] Local endpoint action ingested (telemetry path)")
	}
}

func interfaceTruthyAutonomous(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	default:
		return false
	}
}

// enrichEventContextFields populates normalized top-level fields from known
// nested paths so scoring components can still use them when agents provide
// slightly different payload shapes.
func enrichEventContextFields(ev map[string]interface{}) {
	if ev == nil {
		return
	}

	// agent_id may be nested in source.* for some emitters.
	if getString(ev, "agent_id") == "" {
		if v := getString(ev, "source.agent_id"); v != "" {
			ev["agent_id"] = v
		}
	}

	// user_name may arrive in nested data fields.
	if getString(ev, "user_name") == "" {
		if v := getString(ev, "data.user_name"); v != "" {
			ev["user_name"] = v
		}
	}

	// Source IP can arrive in various keys.
	if getString(ev, "ip_address") == "" {
		for _, key := range []string{"source.ip_address", "data.ip_address", "source_ip"} {
			if v := getString(ev, key); v != "" {
				ev["ip_address"] = v
				break
			}
		}
	}

	// Normalize common process fields expected by downstream scoring logic.
	normalizeFromData(ev, "pid")
	normalizeFromData(ev, "ppid")
	normalizeFromData(ev, "name")
	normalizeFromData(ev, "executable")
	normalizeFromData(ev, "command_line")
	normalizeFromData(ev, "user_sid")
	normalizeFromData(ev, "integrity_level")
	normalizeFromData(ev, "signature_status")
	normalizeFromData(ev, "is_elevated")
}

func normalizeFromData(ev map[string]interface{}, field string) {
	if _, exists := ev[field]; exists {
		return
	}
	if data, ok := ev["data"].(map[string]interface{}); ok {
		if v, ok := data[field]; ok {
			ev[field] = v
		}
	}
}

// evaluateEventContextQuality returns a score [0..100] and missing field list
// for the minimum context-aware dataset used by policy matching and scoring.
func evaluateEventContextQuality(ev map[string]interface{}) (float64, []string) {
	required := []string{
		"agent_id",
		"user_name",
		"ip_address",
		"pid",
		"name",
		"command_line",
	}
	missing := make([]string, 0, len(required))
	present := 0
	for _, f := range required {
		if hasUsableValue(ev, f) {
			present++
			continue
		}
		missing = append(missing, f)
	}
	score := (float64(present) / float64(len(required))) * 100.0
	return score, missing
}

func hasUsableValue(ev map[string]interface{}, key string) bool {
	v, ok := ev[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) != ""
	default:
		return true
	}
}

func getString(ev map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	var cur interface{} = ev
	for _, p := range parts {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		n, ok := m[p]
		if !ok {
			return ""
		}
		cur = n
	}
	s, ok := cur.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func isStrictContextMode() bool {
	mode := strings.TrimSpace(strings.ToLower(os.Getenv("EDR_EVENT_CONTEXT_MODE")))
	return mode == "strict"
}

// ============================================================================
// ASYNC FALLBACK (#2)
// ============================================================================

// storeToFallback enqueues an event batch for asynchronous PostgreSQL storage.
// This is NON-BLOCKING: the fallback store uses a bounded channel internally.
// If the channel is full, the batch is dropped (logged as error).
func (h *EventHandler) storeToFallback(_ context.Context, batch *edrv1.EventBatch, payload []byte) {
	if h.fallbackStore == nil {
		h.logger.WithFields(logrus.Fields{
			"batch_id": batch.BatchId,
			"agent_id": batch.AgentId,
			"size":     len(payload),
		}).Error("EVENT DATA LOST: Kafka unavailable and no DB fallback configured")
		if h.metrics != nil {
			h.metrics.RecordError("event_data_lost")
		}
		return
	}

	metadata := map[string]string{
		"event_count": fmt.Sprintf("%d", batch.EventCount),
		"compression": batch.Compression.String(),
	}
	if batch.Metadata != nil {
		for k, v := range batch.Metadata {
			metadata[k] = v
		}
	}

	// Async enqueue — returns immediately, never blocks the gRPC stream.
	if err := h.fallbackStore.Store(nil, batch.BatchId, batch.AgentId, payload, metadata); err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"batch_id": batch.BatchId,
			"agent_id": batch.AgentId,
		}).Error("Async fallback enqueue failed — event data may be lost")
		if h.metrics != nil {
			h.metrics.RecordError("fallback_enqueue_failed")
		}
	}
}
