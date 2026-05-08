// Package service provides the business logic layer.
package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/edr-platform/connection-manager/internal/cache"
	"github.com/edr-platform/connection-manager/internal/repository"
	"github.com/edr-platform/connection-manager/pkg/models"
	"github.com/edr-platform/connection-manager/pkg/security"
)

// AgentService provides business logic for agent operations.
type AgentService interface {
	// Register registers a new agent with the system.
	Register(ctx context.Context, req *RegisterAgentRequest) (*RegisterAgentResponse, error)

	// GetByID retrieves an agent by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.Agent, error)

	// UpdateStatus updates agent status and optionally metrics.
	UpdateStatus(ctx context.Context, id uuid.UUID, status string, metrics *AgentMetrics) error

	// UpdateMetrics updates agent metrics from a heartbeat.
	UpdateMetrics(ctx context.Context, id uuid.UUID, metrics *AgentMetrics) error

	// GetOnlineAgents returns all currently online agents.
	GetOnlineAgents(ctx context.Context) ([]*models.Agent, error)

	// ListAgents returns agents matching the given filter.
	ListAgents(ctx context.Context, filter repository.AgentFilter) ([]*models.Agent, error)

	// CountAgents returns the count of agents matching the given filter.
	CountAgents(ctx context.Context, filter repository.AgentFilter) (int64, error)

	// Suspend suspends an agent.
	Suspend(ctx context.Context, id uuid.UUID, reason string) error

	// Approve approves a pending agent.
	Approve(ctx context.Context, id uuid.UUID, approvedBy uuid.UUID) error

	// SetIsolation updates the is_isolated flag for an agent.
	SetIsolation(ctx context.Context, id uuid.UUID, isolated bool) error

	// UpdateBusinessContext updates the agent's asset-context fields (criticality, business_unit, environment).
	// Triggers automatic recompute of vulnerability priority_score for the agent's findings.
	UpdateBusinessContext(ctx context.Context, id uuid.UUID, ctxFields repository.AgentBusinessContext) error

	// UpdateDeviceInfo persists device-reported tags received
	// from the agent via heartbeat gRPC metadata. Non-empty values only.
	UpdateDeviceInfo(ctx context.Context, id uuid.UUID, profile, loggedInUser, signatureServerVersion string) error
}

// RegisterAgentRequest contains registration request data.
type RegisterAgentRequest struct {
	InstallationToken string
	Hostname          string
	OSType            string
	OSVersion         string
	HardwareID        string
	CPUCount          int
	MemoryMB          int64
	AgentVersion      string
	CSRData           []byte
	IPAddresses       []string
	Tags              map[string]string
}

// RegisterAgentResponse contains registration response data.
type RegisterAgentResponse struct {
	AgentID     uuid.UUID
	Status      string
	Certificate []byte
	CACert      []byte
	AccessToken string
}

// AgentMetrics contains agent performance metrics.
type AgentMetrics struct {
	CPUUsage        float64
	MemoryUsedMB    int64
	MemoryTotalMB   int64
	QueueDepth      int
	EventsGenerated int64
	EventsSent      int64
	EventsDropped   int64
	AgentVersion    string
	IPAddresses     []string
	CpuCount        int
	HealthScore     float64
	SysmonInstalled bool
	SysmonRunning   bool
}

// RegistrationStatusApproved is the status string for approved (cert-issued) registration.
const RegistrationStatusApproved = "approved"

// agentServiceImpl implements AgentService.
type agentServiceImpl struct {
	agentRepo           repository.AgentRepository
	tokenRepo           repository.InstallationTokenRepository
	enrollmentTokenRepo repository.EnrollmentTokenRepository
	auditRepo           repository.AuditLogRepository
	redis               *cache.RedisClient
	logger              *logrus.Logger
	certService         CertificateService
}

// NewAgentService creates a new AgentService.
// certService may be nil; if so, Register will succeed but return pending status with no certificate.
func NewAgentService(
	agentRepo repository.AgentRepository,
	tokenRepo repository.InstallationTokenRepository,
	enrollmentTokenRepo repository.EnrollmentTokenRepository,
	auditRepo repository.AuditLogRepository,
	redis *cache.RedisClient,
	logger *logrus.Logger,
	certService CertificateService,
) AgentService {
	return &agentServiceImpl{
		agentRepo:           agentRepo,
		tokenRepo:           tokenRepo,
		enrollmentTokenRepo: enrollmentTokenRepo,
		auditRepo:           auditRepo,
		redis:               redis,
		logger:              logger,
		certService:         certService,
	}
}

// Register registers a new agent using First-Touch Provisioning.
//
// This method implements auto-enrollment: when a valid installation token and
// CSR are presented, the agent is immediately activated (status = 'online'),
// its CSR is signed by the CA, and the certificate is returned in the first
// response. The token is only burned after successful cert issuance, preventing
// the "Enrollment Catch-22" where a burned token + pending status left the
// agent unable to obtain its certificate.
func (s *agentServiceImpl) Register(ctx context.Context, req *RegisterAgentRequest) (*RegisterAgentResponse, error) {
	if req.HardwareID == "" {
		if s.logger != nil {
			s.logger.WithFields(logrus.Fields{
				"missing_hardware_id": true,
				"token_present":       strings.TrimSpace(req.InstallationToken) != "",
				"hostname_present":    strings.TrimSpace(req.Hostname) != "",
				"os_type_present":     strings.TrimSpace(req.OSType) != "",
				"csr_present":         len(req.CSRData) > 0,
			}).Warn("[ENROLL] Rejecting registration: missing required fields (hardware_id)")
		}
		// HardwareID is required to make enrollment idempotent per-device
		// and to prevent double consumption of max_uses during retries.
		return nil, ErrInvalidRequest
	}

	// 1. Validate token: new binaries send build_id in Tags; fall back to token-hash lookup.
	var legacyToken *models.InstallationToken
	var enrollmentToken *models.EnrollmentToken

	if s.enrollmentTokenRepo != nil {
		// ── BuildID path (new binaries, zero token material in binary) ──────────
		// New agent binaries embed only BuildID + HMAC binding (no ciphertext/key).
		// The agent sends build_id via req.Tags["build_id"] and the raw token via
		// req.InstallationToken. We look up by BuildID, then verify token_hash.
		if buildIDStr, ok := req.Tags["build_id"]; ok && buildIDStr != "" {
			if buildID, parseErr := uuid.Parse(strings.TrimSpace(buildIDStr)); parseErr == nil {
				if et, err := s.enrollmentTokenRepo.GetByBuildID(ctx, buildID); err == nil {
					// Verify the token hash matches — ensures the token matches the BuildID record.
					if et.TokenHash == security.HashToken(req.InstallationToken) {
						// Token validated; apply the same expiry/max_uses/active checks as below.
						if et.ExpiresAt != nil && time.Now().After(*et.ExpiresAt) {
							return nil, ErrExpiredToken
						}
						if et.MaxUses != nil && et.UseCount >= *et.MaxUses {
							consumed, cErr := s.enrollmentTokenRepo.HasConsumption(ctx, et.ID, req.HardwareID)
							if cErr != nil || !consumed {
								return nil, ErrExpiredToken
							}
						}
						if !et.IsActive {
							consumed, cErr := s.enrollmentTokenRepo.HasConsumption(ctx, et.ID, req.HardwareID)
							if cErr != nil || !consumed {
								return nil, ErrExpiredToken
							}
						}
						enrollmentToken = et
						s.logger.WithField("build_id", buildIDStr).Info("[ENROLL] BuildID path: token validated")
					} else {
						s.logger.WithField("build_id", buildIDStr).Warn("[ENROLL] BuildID found but token hash mismatch — rejecting")
						return nil, ErrInvalidToken
					}
				}
			}
		}

		// ── Token-hash path (legacy binaries and fallback) ────────────────────
		if enrollmentToken == nil {
			if et, err := s.enrollmentTokenRepo.GetByTokenHash(ctx, security.HashToken(req.InstallationToken)); err == nil {
				if et.ExpiresAt != nil && time.Now().After(*et.ExpiresAt) {
					return nil, ErrExpiredToken
				}
				if et.MaxUses != nil && et.UseCount >= *et.MaxUses {
					consumed, cErr := s.enrollmentTokenRepo.HasConsumption(ctx, et.ID, req.HardwareID)
					if cErr != nil {
						s.logger.WithError(cErr).Warn("Failed to check token consumption")
						return nil, fmt.Errorf("token consumption check failed: %w", cErr)
					}
					if !consumed {
						s.logger.Warnf("Enrollment token %s exhausted (max_uses reached)", et.ID)
						return nil, ErrExpiredToken
					}
				}
				if !et.IsActive {
					consumed, cErr := s.enrollmentTokenRepo.HasConsumption(ctx, et.ID, req.HardwareID)
					if cErr != nil {
						s.logger.WithError(cErr).Warn("Failed to check token consumption")
						return nil, fmt.Errorf("token consumption check failed: %w", cErr)
					}
					if !consumed {
						s.logger.Warnf("Enrollment token %s is inactive (revoked/deactivated)", et.ID)
						return nil, ErrExpiredToken
					}
				}
				enrollmentToken = et
			}
		}
	}

	// Fall back to legacy one-time installation token if enrollment token not found
	if enrollmentToken == nil {
		token, err := s.tokenRepo.GetByValue(ctx, req.InstallationToken)
		if err != nil {
			return nil, ErrInvalidToken
		}
		if !token.IsValid() {
			return nil, ErrExpiredToken
		}
		legacyToken = token
	}

	// 2. Handle duplicate hostname — allow re-enrollment (reinstall / rebuild scenario).
	//    The agents table has a UNIQUE constraint on hostname, so we use
	//    UpsertByHostname (ON CONFLICT DO UPDATE) which atomically replaces
	//    the old agent record. This supports:
	//    - OS reinstalls with fresh agent binary
	//    - Dashboard-built agents replacing manually installed ones
	//    - Recovery from broken enrollment state
	existing, err := s.agentRepo.GetByHostname(ctx, req.Hostname)
	if err == nil && existing != nil {
		s.logger.WithFields(logrus.Fields{
			"old_agent_id": existing.ID,
			"hostname":     req.Hostname,
		}).Info("Re-enrollment detected: will replace existing agent with same hostname")
	}

	// 3. Generate agent ID.
	//    On re-enrollment (same hostname), reuse the existing UUID so that all
	//    FK-linked historical data (vulnerability_findings, alerts, events, etc.)
	//    stays attached to this device instead of becoming orphaned.
	agentID := uuid.New()
	if existing != nil {
		agentID = existing.ID
		s.logger.WithFields(logrus.Fields{
			"agent_id": agentID,
			"hostname": req.Hostname,
		}).Info("Re-enrollment: reusing existing agent ID to preserve historical data")
	}
	now := time.Now()

	// 4. Create/replace agent record using UPSERT.
	//    The agents table has UNIQUE(hostname), so a plain INSERT would fail
	//    on re-enrollment. UpsertByHostname uses ON CONFLICT (hostname) DO UPDATE
	//    which atomically replaces the previous agent row — keeping audit trail
	//    via metadata["previous_agent_id"].
	agent := &models.Agent{
		ID:            agentID,
		Hostname:      req.Hostname,
		Status:        models.AgentStatusPending,
		OSType:        req.OSType,
		OSVersion:     req.OSVersion,
		HardwareID:    req.HardwareID,
		CPUCount:      req.CPUCount,
		MemoryMB:      req.MemoryMB,
		AgentVersion:  req.AgentVersion,
		InstalledDate: &now,
		LastSeen:      now,
		Tags:          req.Tags,
		HealthScore:   100.0,
	}

	// Preserve previous agent ID in metadata for audit trail
	if existing != nil {
		if agent.Metadata == nil {
			agent.Metadata = make(map[string]string)
		}
		agent.Metadata["previous_agent_id"] = existing.ID.String()
	}

	if err := s.agentRepo.UpsertByHostname(ctx, agent); err != nil {
		s.logger.WithError(err).Error("Failed to upsert agent")
		return nil, fmt.Errorf("failed to persist agent registration: %w", err)
	}

	// 5. Attempt certificate issuance (agent row now exists → FK satisfied).
	var issued *IssuedCertificate
	certIssued := false
	if s.certService != nil && len(req.CSRData) > 0 {
		issued, err = s.certService.Issue(ctx, agentID, req.CSRData)
		if err != nil {
			s.logger.WithError(err).Warn("Certificate issuance failed; agent stays pending, token NOT burned (retryable)")
		} else {
			certIssued = true
		}
	}

	// 6. Post-issuance: activate agent and burn token only on cert success.
	if certIssued {
		// Promote agent from 'pending' → 'online'
		if err := s.agentRepo.UpdateStatus(ctx, agentID, models.AgentStatusOnline, now); err != nil {
			s.logger.WithError(err).Error("Failed to activate agent after cert issuance")
			// Non-fatal: cert was issued, agent can still connect; status will
			// be corrected on first heartbeat.
		}

		// Burn/retire token ONLY after successful cert issuance.
		//
		// Policy: an enrollment token is a one-time install secret. Once an agent has
		// been accepted and received its mTLS identity, the token has served its entire
		// purpose and is permanently destroyed — both from the dashboard listing and
		// from the database — so it can never be replayed to impersonate another agent.
		if enrollmentToken != nil {
			// Idempotent consumption: count distinct (token_id, hardware_id) pairs, so the
			// same device can't consume multiple seats by retrying enrollment.
			inserted, err := s.enrollmentTokenRepo.RecordConsumption(ctx, enrollmentToken.ID, req.HardwareID, agentID)
			if err != nil {
				s.logger.WithError(err).WithFields(logrus.Fields{
					"token_id":            enrollmentToken.ID,
					"agent_id":            agentID,
					"hardware_id_present": strings.TrimSpace(req.HardwareID) != "",
				}).Error("Failed to record enrollment token consumption")
				return nil, fmt.Errorf("failed to record enrollment token consumption: %w", err)
			}

			if inserted {
				if err := s.enrollmentTokenRepo.IncrementUsage(ctx, enrollmentToken.ID); err != nil {
					s.logger.WithError(err).Error("Failed to increment enrollment token usage")
				}
			}

			// Deactivate once exhausted (do not delete; needed for idempotency checks).
			if inserted {
				if fresh, err := s.enrollmentTokenRepo.GetByID(ctx, enrollmentToken.ID); err == nil && fresh != nil {
					if fresh.MaxUses != nil && fresh.UseCount >= *fresh.MaxUses {
						if err := s.enrollmentTokenRepo.Revoke(ctx, fresh.ID); err != nil {
							s.logger.WithError(err).Error("Failed to deactivate exhausted enrollment token")
						} else {
							s.logger.Infof("Enrollment token %s deactivated after final registration", fresh.ID)
						}
					}
				}
			}
		} else if legacyToken != nil {
			// Legacy one-shot installation token: also deleted for the same reason —
			// a consumed token should not linger in the DB where it can be harvested.
			if err := s.tokenRepo.MarkUsed(ctx, legacyToken.ID, agentID); err != nil {
				s.logger.WithError(err).Error("Failed to mark legacy installation token as used")
			}
			if err := s.tokenRepo.Delete(ctx, legacyToken.ID); err != nil {
				s.logger.WithError(err).Error("Failed to delete legacy installation token after use")
			} else {
				s.logger.Infof("Legacy installation token %s deleted after successful registration", legacyToken.ID)
			}
		}
	}
	// If cert failed: agent stays 'pending', token stays valid → agent can retry.

	// 7. Create audit log
	audit := models.NewAuditLog(uuid.Nil, "system", models.AuditActionAgentRegistered, "agent", agentID)
	audit.WithDetails("hostname: " + req.Hostname)
	s.auditRepo.Create(ctx, audit)

	// 8. Notify dashboard via Redis pub/sub (skip when Redis unavailable)
	if s.redis != nil {
		channel := "agents:registered"
		if certIssued {
			channel = "agents:activated"
		}
		s.redis.Publish(ctx, channel, agentID.String())
	}

	// 9. Build response
	resp := &RegisterAgentResponse{
		AgentID: agentID,
	}

	if certIssued {
		resp.Status = RegistrationStatusApproved
		resp.Certificate = issued.Certificate
		resp.CACert = issued.CACert
		s.logger.WithFields(logrus.Fields{
			"agent_id": agentID,
			"hostname": req.Hostname,
			"status":   models.AgentStatusOnline,
		}).Info("Agent registered and certificate issued (First-Touch Provisioning)")
	} else {
		resp.Status = models.AgentStatusPending
		s.logger.WithFields(logrus.Fields{
			"agent_id": agentID,
			"hostname": req.Hostname,
			"status":   models.AgentStatusPending,
		}).Info("Agent registered (pending — certificate not issued)")
	}

	return resp, nil
}

// GetByID retrieves an agent by ID.
func (s *agentServiceImpl) GetByID(ctx context.Context, id uuid.UUID) (*models.Agent, error) {
	return s.agentRepo.GetByID(ctx, id)
}

// UpdateStatus updates agent status.
func (s *agentServiceImpl) UpdateStatus(ctx context.Context, id uuid.UUID, status string, metrics *AgentMetrics) error {
	// Update database
	if err := s.agentRepo.UpdateStatus(ctx, id, status, time.Now()); err != nil {
		return err
	}

	// Update Redis cache (skip when Redis unavailable)
	if s.redis != nil {
		s.redis.SetAgentStatus(ctx, id.String(), status, 5*time.Minute)
	}

	// Update metrics if provided
	if metrics != nil {
		return s.UpdateMetrics(ctx, id, metrics)
	}

	return nil
}

// UpdateMetrics updates agent metrics.
func (s *agentServiceImpl) UpdateMetrics(ctx context.Context, id uuid.UUID, metrics *AgentMetrics) error {
	return s.agentRepo.UpdateMetrics(ctx, id,
		metrics.CPUUsage,
		metrics.MemoryUsedMB,
		metrics.MemoryTotalMB,
		metrics.QueueDepth,
		metrics.EventsGenerated,
		metrics.EventsSent,
		metrics.EventsDropped,
		metrics.AgentVersion,
		metrics.IPAddresses,
		metrics.CpuCount,
		metrics.HealthScore,
		metrics.SysmonInstalled,
		metrics.SysmonRunning,
	)
}

// GetOnlineAgents returns all online agents.
func (s *agentServiceImpl) GetOnlineAgents(ctx context.Context) ([]*models.Agent, error) {
	return s.agentRepo.GetOnlineAgents(ctx)
}

// ListAgents returns agents matching the given filter.
func (s *agentServiceImpl) ListAgents(ctx context.Context, filter repository.AgentFilter) ([]*models.Agent, error) {
	return s.agentRepo.List(ctx, filter)
}

// CountAgents returns the count of agents matching the given filter.
func (s *agentServiceImpl) CountAgents(ctx context.Context, filter repository.AgentFilter) (int64, error) {
	return s.agentRepo.Count(ctx, filter)
}

// Suspend suspends an agent.
func (s *agentServiceImpl) Suspend(ctx context.Context, id uuid.UUID, reason string) error {
	if err := s.agentRepo.UpdateStatus(ctx, id, models.AgentStatusSuspended, time.Now()); err != nil {
		return err
	}

	// Audit log
	audit := models.NewAuditLog(uuid.Nil, "system", models.AuditActionAgentSuspended, "agent", id)
	audit.WithDetails(reason)
	s.auditRepo.Create(ctx, audit)

	return nil
}

// Approve approves a pending agent.
func (s *agentServiceImpl) Approve(ctx context.Context, id uuid.UUID, approvedBy uuid.UUID) error {
	if err := s.agentRepo.UpdateStatus(ctx, id, models.AgentStatusOnline, time.Now()); err != nil {
		return err
	}

	// Audit log
	audit := models.NewAuditLog(approvedBy, "", models.AuditActionAgentApproved, "agent", id)
	s.auditRepo.Create(ctx, audit)

	return nil
}

// SetIsolation updates the is_isolated flag for an agent.
func (s *agentServiceImpl) SetIsolation(ctx context.Context, id uuid.UUID, isolated bool) error {
	return s.agentRepo.SetIsolation(ctx, id, isolated)
}

// UpdateBusinessContext updates asset-context fields (criticality, business_unit, environment).
// The DB trigger on criticality auto-recomputes priority_score for vulnerability findings.
func (s *agentServiceImpl) UpdateBusinessContext(ctx context.Context, id uuid.UUID, ctxFields repository.AgentBusinessContext) error {
	return s.agentRepo.UpdateBusinessContext(ctx, id, ctxFields)
}

// UpdateDeviceInfo persists agent-reported tags to the DB.
func (s *agentServiceImpl) UpdateDeviceInfo(ctx context.Context, id uuid.UUID, profile, loggedInUser, signatureServerVersion string) error {
	return s.agentRepo.UpdateDeviceInfo(ctx, id, profile, loggedInUser, signatureServerVersion)
}
