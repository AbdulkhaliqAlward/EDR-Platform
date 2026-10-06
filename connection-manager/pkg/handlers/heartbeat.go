// Package handlers provides gRPC handler implementations.
package handlers

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"google.golang.org/grpc/metadata"

	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/internal/service"
	"github.com/edr-platform/connection-manager/pkg/contextkeys"
	edrv1 "github.com/edr-platform/connection-manager/proto/v1"
)

// HeartbeatHandler handles agent heartbeat RPCs.
// It persists agent health data to TWO stores:
//   - Redis: Real-time status for dashboards (10-min TTL, ephemeral)
//   - PostgreSQL: Source of truth for agent state and metrics history
//
// The Redis write happens first (faster, for live dashboards), then the
// DB write follows. DB errors are warn-logged but never block the
// heartbeat response — we always send the agent its health check back.
type HeartbeatHandler struct {
	logger       *logrus.Logger
	redis        *cache.RedisClient
	agentService service.AgentService // Persists status/metrics to PostgreSQL
}

// NewHeartbeatHandler creates a new heartbeat handler.
// agentService is optional — if nil, metrics are only stored in Redis.
func NewHeartbeatHandler(logger *logrus.Logger, redis *cache.RedisClient, agentSvc service.AgentService) *HeartbeatHandler {
	return &HeartbeatHandler{
		logger:       logger,
		redis:        redis,
		agentService: agentSvc,
	}
}

// Heartbeat processes a heartbeat request from an agent.
func (h *HeartbeatHandler) Heartbeat(ctx context.Context, req *edrv1.HeartbeatRequest) (*edrv1.HeartbeatResponse, error) {
	// Use the AUTHENTICATED agent ID from the TLS certificate (set by auth
	// interceptor), NOT the self-reported req.AgentId. This is consistent with
	// StreamEvents and prevents heartbeat misrouting when config UUID diverges
	// from the certificate CN after re-installation.
	agentID := extractHeartbeatAgentID(ctx)
	if agentID == "" {
		// Fallback for unauthenticated/test contexts
		agentID = req.AgentId
	}
	if agentID == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}

	logger := h.logger.WithField("agent_id", agentID)
	logger.Debug("Heartbeat received")

	// 1. Update agent status in Redis (skip when Redis unavailable)
	if h.redis != nil {
		if err := h.redis.SetAgentStatus(ctx, agentID, mapAgentStatus(req.Status), 10*time.Minute); err != nil {
			logger.WithError(err).Warn("Failed to update agent status")
		}
	}

	// 2. Calculate health score
	healthScore := calculateHealthScore(req)

	// 3. Update health in Redis (skip when Redis unavailable)
	if h.redis != nil {
		healthKey := "agent:health:" + agentID
		h.redis.Client().HSet(ctx, healthKey, map[string]interface{}{
			"score":     healthScore,
			"status":    getHealthStatus(healthScore),
			"timestamp": time.Now().Unix(),
		})
		h.redis.Client().Expire(ctx, healthKey, 10*time.Minute)
	}

	// 4. Check if certificate renewal is needed
	certRenewalNeeded := false
	if req.CertExpiresAt > 0 {
		daysUntilExpiry := (req.CertExpiresAt - time.Now().Unix()) / (24 * 3600)
		certRenewalNeeded = daysUntilExpiry <= 7 // Renew if expires within 7 days
	}

	// 5. Log metrics (debug level to avoid spam)
	logger.WithFields(logrus.Fields{
		"cpu_usage":        req.CpuUsage,
		"memory_mb":        req.MemoryUsedMb,
		"queue_depth":      req.QueueDepth,
		"events_generated": req.EventsGenerated,
		"events_sent":      req.EventsSent,
		"events_dropped":   req.EventsDropped,
		"ip_addresses":     req.IpAddresses,
		"health_score":     healthScore,
	}).Debug("Agent metrics received")

	// 6. Persist to PostgreSQL (source of truth)
	// Redis is ephemeral (5-min TTL) — without DB persistence, all agent
	// state and metrics history is lost on Redis restart or TTL expiry.
	// The AgentService handles both UpdateStatus() and UpdateMetrics()
	// which write to the agents table in PostgreSQL.
	if h.agentService != nil {
		agentUUID, parseErr := uuid.Parse(agentID)
		if parseErr != nil {
			logger.WithError(parseErr).Warn("Invalid agent_id format (cannot persist to DB)")
		} else {
			dbStatus := mapAgentStatus(req.Status)
			dbMetrics := &service.AgentMetrics{
				CPUUsage:        float64(req.CpuUsage),
				MemoryUsedMB:    req.MemoryUsedMb,
				MemoryTotalMB:   req.MemoryTotalMb,
				QueueDepth:      int(req.QueueDepth),
				EventsGenerated: req.EventsGenerated,
				EventsSent:      req.EventsSent,
				EventsDropped:   req.EventsDropped,
				AgentVersion:    req.AgentVersion,
				IPAddresses:     req.IpAddresses,
				CpuCount:        int(req.DiskTotalMb), // CPU count sent via DiskTotalMb field
				HealthScore:     healthScore,
				SysmonInstalled: req.SysmonInstalled,
				SysmonRunning:   req.SysmonRunning,
			}

			// UpdateStatus writes status + last_seen + optional metrics in one call.
			// We pass metrics here so it's a single DB round-trip.
			if err := h.agentService.UpdateStatus(ctx, agentUUID, dbStatus, dbMetrics); err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					// Unknown agent, or a device removed from the dashboard
					// (status writes are ignored for it by design).
					logger.Debug("Heartbeat not persisted: agent not registered or removed from dashboard")
				} else {
					// Warn but don't fail the heartbeat — the agent must always
					// get its response. DB issues are transient; heartbeats are not.
					logger.WithError(err).Warn("Failed to persist heartbeat to database")
				}
			} else {
				logger.Debug("Heartbeat persisted to database")
			}
		}
	}

	// 7. Update device-reported tags from gRPC metadata.
	// The agent sends these as x-agent-* headers to avoid proto schema changes.
	// The DB update runs in a goroutine so it never delays the heartbeat response.
	if h.agentService != nil {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			profile := ""
			loggedInUser := ""
			signatureServerVersion := ""
			if vals := md.Get("x-agent-profile"); len(vals) > 0 {
				profile = vals[0]
			}
			if vals := md.Get("x-agent-logged-in-user"); len(vals) > 0 {
				loggedInUser = vals[0]
			}
			if vals := md.Get("x-agent-signature-server-version"); len(vals) > 0 {
				signatureServerVersion = vals[0]
			}
			if profile != "" || loggedInUser != "" || signatureServerVersion != "" {
				if agentUUID, parseErr := uuid.Parse(agentID); parseErr == nil {
					go func(id uuid.UUID, p, u, sv string) {
						upCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						if err := h.agentService.UpdateDeviceInfo(upCtx, id, p, u, sv); err != nil {
							logger.WithError(err).Warn("Failed to update device info tags")
						}
					}(agentUUID, profile, loggedInUser, signatureServerVersion)
				}
			}
		}
	}

	// 8. Prepare response
	return &edrv1.HeartbeatResponse{
		AgentId:             agentID,
		ServerTimestamp:     timestamppb.Now(),
		ServerStatus:        edrv1.ServerStatus_SERVER_STATUS_OK,
		HasPendingCommands:  false, // Phase 2 will implement command queue
		CertRenewalRequired: certRenewalNeeded,
	}, nil
}

// mapAgentStatus maps proto AgentStatus to string.
func mapAgentStatus(status edrv1.AgentStatus) string {
	switch status {
	case edrv1.AgentStatus_AGENT_STATUS_HEALTHY:
		return "online"
	case edrv1.AgentStatus_AGENT_STATUS_DEGRADED:
		return "degraded"
	case edrv1.AgentStatus_AGENT_STATUS_CRITICAL:
		return "degraded"
	case edrv1.AgentStatus_AGENT_STATUS_UPDATING:
		return "degraded"
	case edrv1.AgentStatus_AGENT_STATUS_ISOLATED:
		return "suspended"
	default:
		return "degraded"
	}
}

// calculateHealthScore calculates health score based on agent metrics.
//
// FIX ISSUE-11: Unified with Agent.CalculateHealthScore() — both now use the
// same 4-factor model. Previously, the heartbeat handler used a 2-factor
// formula (delivery×0.7 + status×0.3) while the Agent model used 3-factor
// (delivery×0.5 + status×0.3 + drop×0.2). This produced inconsistent scores.
//
// Unified Industry-Standard Health Model (NIST SP 800-137 aligned):
//
//	health_score = delivery×0.40 + status×0.30 + dropRate×0.20 + resource×0.10
//
// Factor breakdown:
//  1. Delivery Quality (40%): events_sent / events_generated × 100
//     - Measures telemetry pipeline integrity. Low delivery indicates
//     buffer overflow, network failure, or potential attacker interference.
//  2. Operational Status (30%): maps reported agent status to a 0–100 score
//     - Online=100, Degraded=80, Critical=50, Unknown=60, Offline=0
//  3. Drop Rate Penalty (20%): penalizes high event drop ratios
//     - >20% drops: score=0 (potential blinding attack per MITRE T1562)
//     - 5–20%: linear degradation from 100→0
//     - <5%: score=100 (acceptable operational loss)
//  4. Resource Pressure (10%): CPU and memory utilization
//     - >90% CPU or >95% memory: score=0 (resource exhaustion)
//     - Linear scale from 100→0 as utilization increases
//
// This unified formula is used for:
//   - Real-time health display in the dashboard
//   - Agent "offline" detection and alerting
//   - Response automation (isolation decisions require health context)
func calculateHealthScore(req *edrv1.HeartbeatRequest) float64 {
	// Factor 1: Delivery Quality (40% weight)
	var deliveryRatio float64 = 100.0
	if req.EventsGenerated > 0 {
		deliveryRatio = float64(req.EventsSent) / float64(req.EventsGenerated) * 100
		if deliveryRatio > 100.0 {
			deliveryRatio = 100.0
		}
	}

	// Factor 2: Status Score (30% weight)
	statusScore := 100.0
	switch req.Status {
	case edrv1.AgentStatus_AGENT_STATUS_HEALTHY:
		statusScore = 100.0
	case edrv1.AgentStatus_AGENT_STATUS_DEGRADED:
		statusScore = 80.0
	case edrv1.AgentStatus_AGENT_STATUS_CRITICAL:
		statusScore = 50.0
	default:
		statusScore = 60.0
	}

	// Factor 3: Drop Rate Penalty (20% weight)
	// >20% drops indicates potential blinding attack (MITRE T1562.001)
	dropScore := 100.0
	if req.EventsGenerated > 0 {
		dropRate := float64(req.EventsDropped) / float64(req.EventsGenerated)
		switch {
		case dropRate > 0.20:
			dropScore = 0.0 // Severe: potential blinding attack
		case dropRate > 0.05:
			// Linear degradation from 100→0 between 5% and 20%
			dropScore = (0.20 - dropRate) / 0.15 * 100
		}
	}

	// Factor 4: Resource Pressure (10% weight)
	// High CPU or memory signals resource exhaustion / potential DoS
	resourceScore := 100.0
	cpuUsage := float64(req.CpuUsage)
	if cpuUsage > 90.0 {
		resourceScore -= 50.0 // Heavy CPU penalty
	} else if cpuUsage > 70.0 {
		resourceScore -= (cpuUsage - 70.0) / 20.0 * 30.0 // Gradual CPU penalty
	}
	if req.MemoryTotalMb > 0 {
		memUsagePercent := float64(req.MemoryUsedMb) / float64(req.MemoryTotalMb) * 100
		if memUsagePercent > 95.0 {
			resourceScore -= 50.0
		} else if memUsagePercent > 80.0 {
			resourceScore -= (memUsagePercent - 80.0) / 15.0 * 30.0
		}
	}
	if resourceScore < 0 {
		resourceScore = 0
	}

	// Combined score with industry-standard weights
	return (deliveryRatio * 0.40) + (statusScore * 0.30) + (dropScore * 0.20) + (resourceScore * 0.10)
}

// getHealthStatus returns a status string based on health score.
// Thresholds aligned with NIST SP 800-137 continuous monitoring tiers:
//   - Excellent (≥90): All factors nominal, full operational capability
//   - Good (≥75): Minor degradation, acceptable for operations
//   - Fair (≥50): Notable degradation, requires attention
//   - Degraded (≥25): Significant issues, investigation required
//   - Critical (<25): Agent may be under attack or failing
func getHealthStatus(score float64) string {
	switch {
	case score >= 90:
		return "excellent"
	case score >= 75:
		return "good"
	case score >= 50:
		return "fair"
	case score >= 25:
		return "degraded"
	default:
		return "critical"
	}
}

// extractHeartbeatAgentID extracts the authenticated agent ID from context.
// The auth interceptor sets this from the TLS certificate CN.
func extractHeartbeatAgentID(ctx context.Context) string {
	if id, ok := ctx.Value(contextkeys.AgentIDKey).(string); ok {
		return id
	}
	return ""
}
