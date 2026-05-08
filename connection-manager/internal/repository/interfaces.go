// Package repository defines the interfaces for data access.
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/edr-platform/connection-manager/pkg/models"
)

// AgentRepository defines the interface for agent data access.
type AgentRepository interface {
	// Create creates a new agent record.
	Create(ctx context.Context, agent *models.Agent) error

	// GetByID retrieves an agent by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.Agent, error)

	// GetByHostname retrieves an agent by its hostname.
	GetByHostname(ctx context.Context, hostname string) (*models.Agent, error)

	// Update updates an existing agent.
	Update(ctx context.Context, agent *models.Agent) error

	// UpdateStatus updates the agent's status and last_seen timestamp.
	UpdateStatus(ctx context.Context, id uuid.UUID, status string, lastSeen time.Time) error

	// UpdateMetrics updates the agent's metrics from a heartbeat.
	UpdateMetrics(ctx context.Context, id uuid.UUID, cpuUsage float64, memoryUsedMB int64,
		memoryTotalMB int64, queueDepth int, eventsGenerated, eventsSent, eventsDropped int64,
		agentVersion string, ipAddresses []string, cpuCount int, healthScore float64,
		sysmonInstalled, sysmonRunning bool) error

	// Delete soft-deletes an agent (sets status to deleted).
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves agents with optional filters.
	List(ctx context.Context, filter AgentFilter) ([]*models.Agent, error)

	// Count returns the number of agents matching the filter.
	Count(ctx context.Context, filter AgentFilter) (int64, error)

	// GetOnlineAgents retrieves all agents with status "online".
	GetOnlineAgents(ctx context.Context) ([]*models.Agent, error)

	// GetAgentsNeedingCertRenewal retrieves agents whose certs expire within the given duration.
	GetAgentsNeedingCertRenewal(ctx context.Context, within time.Duration) ([]*models.Agent, error)

	// MarkStaleOffline marks agents as offline if their last_seen timestamp is older than the threshold.
	// Returns the number of agents that were marked offline.
	MarkStaleOffline(ctx context.Context, threshold time.Duration) (int64, error)

	// SetIsolation updates the is_isolated flag on an agent.
	SetIsolation(ctx context.Context, id uuid.UUID, isolated bool) error

	// UpdateBusinessContext updates asset-context fields (criticality, business_unit, environment).
	// A DB trigger on criticality auto-recomputes priority_score for all linked vulnerability findings.
	UpdateBusinessContext(ctx context.Context, id uuid.UUID, ctxFields AgentBusinessContext) error

	// UpdateDeviceInfo updates the agent's device-reported tags
	// (profile, logged_in_user, signature_server_version)
	// received from the agent via heartbeat gRPC metadata.
	// Only non-empty values overwrite existing entries; other tags are preserved.
	UpdateDeviceInfo(ctx context.Context, id uuid.UUID, profile, loggedInUser, signatureServerVersion string) error

	// UpsertByHostname performs an INSERT ... ON CONFLICT (hostname) DO UPDATE,
	// atomically creating or replacing the agent record for the given hostname.
	// On collision (re-install / re-image scenario), the old agent ID is replaced
	// by the new one in a single statement, preserving DB integrity without a
	// manual delete step. Returns the final agent as stored.
	UpsertByHostname(ctx context.Context, agent *models.Agent) error
}

// AgentFilter defines filters for listing agents.
type AgentFilter struct {
	Status    *string
	OSType    *string
	Search    *string // Search in hostname
	Limit     int
	Offset    int
	SortBy    string
	SortOrder string // "asc" or "desc"
}

// CertificateRepository defines the interface for certificate data access.
type CertificateRepository interface {
	// Create creates a new certificate record.
	Create(ctx context.Context, cert *models.Certificate) error

	// GetByID retrieves a certificate by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.Certificate, error)

	// GetByFingerprint retrieves a certificate by its fingerprint.
	GetByFingerprint(ctx context.Context, fingerprint string) (*models.Certificate, error)

	// GetActiveByAgentID retrieves the active certificate for an agent.
	GetActiveByAgentID(ctx context.Context, agentID uuid.UUID) (*models.Certificate, error)

	// Update updates an existing certificate.
	Update(ctx context.Context, cert *models.Certificate) error

	// Revoke marks a certificate as revoked.
	Revoke(ctx context.Context, id uuid.UUID, revokedBy uuid.UUID, reason string) error

	// MarkSuperseded marks a certificate as superseded by a new one.
	MarkSuperseded(ctx context.Context, id uuid.UUID) error

	// SupersedeAllForAgent marks all active certs for an agent as "superseded".
	SupersedeAllForAgent(ctx context.Context, agentID uuid.UUID) error

	// GetExpiring retrieves certificates expiring within the given duration.
	GetExpiring(ctx context.Context, within time.Duration) ([]*models.Certificate, error)

	// List retrieves certificates with optional filters.
	List(ctx context.Context, agentID uuid.UUID, status *string) ([]*models.Certificate, error)

	// UpdateLastSeen updates last_seen_at for a certificate identified by fingerprint.
	UpdateLastSeen(ctx context.Context, fingerprint string) error

	// AddToCRL inserts a serial number into the certificate_revocation_list table.
	AddToCRL(ctx context.Context, serialNumber, fingerprint, reason string) error

	// GetCRLFingerprints returns all revoked fingerprints from the CRL table.
	GetCRLFingerprints(ctx context.Context) ([]string, error)

	// GetStale returns active certs whose last_seen_at is older than the given duration.
	GetStale(ctx context.Context, threshold time.Duration) ([]*models.Certificate, error)
}

// CSRRepository defines the interface for CSR data access.
type CSRRepository interface {
	// Create creates a new CSR record.
	Create(ctx context.Context, csr *models.CSR) error

	// GetByID retrieves a CSR by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.CSR, error)

	// GetByAgentID retrieves the pending CSR for an agent.
	GetByAgentID(ctx context.Context, agentID uuid.UUID) (*models.CSR, error)

	// Approve marks a CSR as approved.
	Approve(ctx context.Context, id uuid.UUID, approvedBy uuid.UUID) error

	// Delete deletes a CSR.
	Delete(ctx context.Context, id uuid.UUID) error

	// GetPending retrieves all pending CSRs.
	GetPending(ctx context.Context) ([]*models.CSR, error)

	// DeleteExpired deletes CSRs that have expired.
	DeleteExpired(ctx context.Context) (int64, error)
}

// InstallationTokenRepository defines the interface for installation token data access.
type InstallationTokenRepository interface {
	// Create creates a new installation token.
	Create(ctx context.Context, token *models.InstallationToken) error

	// GetByValue retrieves a token by its value.
	GetByValue(ctx context.Context, value string) (*models.InstallationToken, error)

	// MarkUsed marks a token as used by an agent.
	MarkUsed(ctx context.Context, id uuid.UUID, agentID uuid.UUID) error

	// Delete deletes a token.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteExpired deletes tokens that have expired.
	DeleteExpired(ctx context.Context) (int64, error)
}

// EnrollmentTokenRepository defines the interface for dynamic enrollment token management.
type EnrollmentTokenRepository interface {
	// Create creates a new enrollment token.
	Create(ctx context.Context, token *models.EnrollmentToken) error

	// GetByID retrieves an enrollment token by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.EnrollmentToken, error)

	// GetByToken retrieves an enrollment token by its raw token string.
	// Deprecated for security-sensitive lookups: prefer GetByTokenHash.
	GetByToken(ctx context.Context, token string) (*models.EnrollmentToken, error)

	// GetByTokenHash retrieves an enrollment token by its SHA-256 hex hash.
	// The caller must hash the raw incoming token with security.HashToken()
	// before passing it here.  This is the correct lookup path for agent
	// registration — the raw token never travels to the DB layer.
	GetByTokenHash(ctx context.Context, hash string) (*models.EnrollmentToken, error)

	// IncrementBuildCount atomically increments build_count from 0 to 1.
	// Returns ErrTokenAlreadyBuilt if build_count is already >= 1 (CAS: WHERE build_count = 0).
	// One token is allowed to produce exactly one agent binary — no exceptions.
	IncrementBuildCount(ctx context.Context, tokenID uuid.UUID) error

	// StoreKeyB persists the hex-encoded second key half (key_b) onto the token row.
	// Called by agent-builder immediately after split-key generation.
	// Returns ErrNotFound if the tokenID does not exist.
	StoreKeyB(ctx context.Context, tokenID uuid.UUID, keyB string) error

	// ServeKeyB atomically serves and NULLs the key_b value in one CTE.
	// Returns the key_b string on success, ErrKeyBAlreadyServed if the
	// CAS predicate fails (already served / revoked / expired / not found).
	// This MUST be a single atomic SQL statement — no SELECT then UPDATE.
	ServeKeyB(ctx context.Context, tokenID uuid.UUID) (string, error)

	// List retrieves all enrollment tokens ordered by creation date.
	List(ctx context.Context) ([]*models.EnrollmentToken, error)

	// IncrementUsage increments the use_count of a token.
	IncrementUsage(ctx context.Context, id uuid.UUID) error

	// Revoke deactivates an enrollment token.
	Revoke(ctx context.Context, id uuid.UUID) error

	// Delete deletes an enrollment token.
	// Deprecated for enrollment idempotency: prefer Revoke/expiry so consumption checks remain possible.
	Delete(ctx context.Context, id uuid.UUID) error

	// HasConsumption returns true if this hardware_id has already consumed this token.
	HasConsumption(ctx context.Context, tokenID uuid.UUID, hardwareID string) (bool, error)

	// RecordConsumption inserts a (token_id, hardware_id) consumption record.
	// Returns inserted=true if this is the first time this hardware_id consumes the token.
	RecordConsumption(ctx context.Context, tokenID uuid.UUID, hardwareID string, agentID uuid.UUID) (inserted bool, err error)
}

// UserRepository defines the interface for user data access.
type UserRepository interface {
	// Create creates a new user.
	Create(ctx context.Context, user *models.User) error

	// GetByID retrieves a user by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)

	// GetByUsername retrieves a user by username.
	GetByUsername(ctx context.Context, username string) (*models.User, error)

	// GetByEmail retrieves a user by email.
	GetByEmail(ctx context.Context, email string) (*models.User, error)

	// Update updates an existing user.
	Update(ctx context.Context, user *models.User) error

	// UpdatePassword updates the user's password hash.
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error

	// Delete soft-deletes a user.
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves users with optional filters.
	List(ctx context.Context, filter UserFilter) ([]*models.User, error)

	// Count returns the number of rows matching the same filters as List (ignores Limit/Offset).
	Count(ctx context.Context, filter UserFilter) (int64, error)
}

// UserFilter defines filters for listing users.
type UserFilter struct {
	Role   *string
	Status *string
	Search *string
	Limit  int
	Offset int
}

// RoleRepository defines the interface for role and permission data access.
type RoleRepository interface {
	// ListRoles retrieves all roles with their permissions.
	ListRoles(ctx context.Context) ([]*models.Role, error)

	// GetRoleByName retrieves a single role by name, including permissions.
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)

	// CreateRole creates a new custom role.
	CreateRole(ctx context.Context, role *models.Role) error

	// UpdateRolePermissions replaces the permission set for a role.
	UpdateRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error

	// DeleteRole deletes a custom role (built-in roles cannot be deleted).
	DeleteRole(ctx context.Context, id uuid.UUID) error

	// ListPermissions retrieves all available permissions.
	ListPermissions(ctx context.Context) ([]*models.Permission, error)

	// GetPermissionsForRoleName retrieves the permission keys for a role name.
	// Returns slice of "resource:action" strings.
	GetPermissionsForRoleName(ctx context.Context, roleName string) ([]string, error)
}

// AuditLogRepository defines the interface for audit log data access.
type AuditLogRepository interface {
	// Create creates a new audit log entry.
	Create(ctx context.Context, log *models.AuditLog) error

	// GetByID retrieves an audit log by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error)

	// List retrieves audit logs with optional filters.
	List(ctx context.Context, filter AuditLogFilter) ([]*models.AuditLog, error)

	// Count returns the number of audit logs matching the filter.
	Count(ctx context.Context, filter AuditLogFilter) (int64, error)
}

// ContextPolicyRepository defines CRUD and listing for context-aware policy controls.
type ContextPolicyRepository interface {
	List(ctx context.Context) ([]*models.ContextPolicy, error)
	GetByID(ctx context.Context, id int64) (*models.ContextPolicy, error)
	Create(ctx context.Context, policy *models.ContextPolicy) error
	Update(ctx context.Context, policy *models.ContextPolicy) error
	Delete(ctx context.Context, id int64) error
}

// QuarantineRepository persists agent quarantine inventory (from telemetry + C2 ACKs).
type QuarantineRepository interface {
	Upsert(ctx context.Context, row *models.QuarantineItem) error
	ListByAgent(ctx context.Context, agentID uuid.UUID, includeResolved bool) ([]*models.QuarantineItem, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.QuarantineItem, error)
	SetState(ctx context.Context, id uuid.UUID, state models.QuarantineItemState) error
}

// ForensicRepository stores forensic log collections and events (collect_logs/collect_forensics).
type ForensicRepository interface {
	ListCollectionsByAgent(ctx context.Context, agentID uuid.UUID, limit int) ([]ForensicCollectionSummary, error)
	ListEvents(ctx context.Context, agentID, commandID uuid.UUID, logType string, limit int, cursorID *int64) (rows []ForensicEventRow, nextCursor *int64, err error)
	UpsertCollection(ctx context.Context, c ForensicCollectionSummary) error
	ReplaceEvents(ctx context.Context, agentID, commandID uuid.UUID, logType string, events []ForensicEventRow) error
}

type AgentPackageRow struct {
	ID          uuid.UUID
	AgentID     uuid.UUID // Package is bound to exactly one agent (download link is personal)
	SHA256      string
	Filename    string
	StoragePath string
	BuildParams map[string]any
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ConsumedAt  *time.Time // Set on first successful download — link becomes single-use
}

type AgentPackageRepository interface {
	Create(ctx context.Context, row AgentPackageRow) error
	Get(ctx context.Context, id uuid.UUID) (*AgentPackageRow, error)
	// MarkConsumed flags a package as used so subsequent downloads are refused.
	MarkConsumed(ctx context.Context, id uuid.UUID) error
	// Delete removes a package row (used after expiry cleanup or successful consumption).
	Delete(ctx context.Context, id uuid.UUID) error
	// ListExpired returns rows with expires_at < now that still have a storage_path to clean up.
	ListExpired(ctx context.Context, before time.Time) ([]*AgentPackageRow, error)
}

type AgentPatchProfileRepository interface {
	Get(ctx context.Context, agentID uuid.UUID) (map[string]any, error)
	Upsert(ctx context.Context, agentID uuid.UUID, profile map[string]any) error
}

// AuditLogFilter defines filters for listing audit logs.
type AuditLogFilter struct {
	UserID       *uuid.UUID
	Action       *string
	ResourceType *string
	ResourceID   *uuid.UUID
	Result       *string
	StartTime    *time.Time
	EndTime      *time.Time
	Limit        int
	Offset       int
}

// AlertRepository and AlertFilter interfaces are defined in alert_repo.go

// ResponsePlaybookRepository defines the interface for response playbook data access.
type ResponsePlaybookRepository interface {
	// Create creates a new response playbook.
	Create(ctx context.Context, playbook *models.ResponsePlaybook) error

	// GetByID retrieves a playbook by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.ResponsePlaybook, error)

	// Update updates an existing playbook.
	Update(ctx context.Context, playbook *models.ResponsePlaybook) error

	// Delete soft-deletes a playbook.
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves playbooks with optional filters.
	List(ctx context.Context, filter PlaybookFilter) ([]*models.ResponsePlaybook, error)

	// Count returns the number of playbooks matching the filter.
	Count(ctx context.Context, filter PlaybookFilter) (int64, error)
}

// PlaybookFilter defines filters for listing playbooks.
type PlaybookFilter struct {
	Category *string
	Enabled  *string
	Search   *string
	Limit    int
	Offset   int
}

// AutomationRuleRepository defines the interface for automation rule data access.
type AutomationRuleRepository interface {
	// Create creates a new automation rule.
	Create(ctx context.Context, rule *models.AutomationRule) error

	// GetByID retrieves a rule by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.AutomationRule, error)

	// Update updates an existing rule.
	Update(ctx context.Context, rule *models.AutomationRule) error

	// Delete soft-deletes a rule.
	Delete(ctx context.Context, id uuid.UUID) error

	// List retrieves automation rules.
	List(ctx context.Context) ([]*models.AutomationRule, error)

	// GetMatchingRules retrieves rules that match an alert.
	GetMatchingRules(ctx context.Context, alert *models.Alert) ([]*models.AutomationRule, error)
}

// PlaybookExecutionRepository defines the interface for playbook execution data access.
type PlaybookExecutionRepository interface {
	// Create creates a new playbook execution record.
	Create(ctx context.Context, execution *models.PlaybookExecution) error

	// GetByID retrieves an execution by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*models.PlaybookExecution, error)

	// Update updates an existing execution.
	Update(ctx context.Context, execution *models.PlaybookExecution) error

	// List retrieves executions with optional filters.
	List(ctx context.Context, filter ExecutionFilter) ([]*models.PlaybookExecution, error)

	// GetByAlertID retrieves executions for a specific alert.
	GetByAlertID(ctx context.Context, alertID uuid.UUID) ([]*models.PlaybookExecution, error)

	// CreateSuggestion creates a new playbook suggestion.
	CreateSuggestion(ctx context.Context, suggestion *models.PlaybookSuggestion) error

	// GetSuggestions retrieves suggestions for a specific alert.
	GetSuggestions(ctx context.Context, alertID uuid.UUID) ([]models.PlaybookSuggestion, error)
}

// ExecutionFilter defines filters for listing executions.
type ExecutionFilter struct {
	AlertID    *uuid.UUID
	PlaybookID *uuid.UUID
	Status     *string
	AgentID    *uuid.UUID
	Limit      int
	Offset     int
}

// AutomationMetricsRepository defines the interface for automation metrics data access.
type AutomationMetricsRepository interface {
	// GetRuleMetrics retrieves metrics for a specific rule.
	GetRuleMetrics(ctx context.Context, ruleID uuid.UUID, since time.Time) (*models.AutomationMetrics, error)

	// RecordRuleExecution records a rule execution for metrics.
	RecordRuleExecution(ctx context.Context, ruleID uuid.UUID, success bool, executionTime time.Duration) error

	// GetMetrics retrieves overall automation metrics.
	GetMetrics(ctx context.Context, timeRange string) (*models.AutomationMetricsSummary, error)
}

// MalwareHashRepository manages the server-side malicious SHA-256 hash feed.
type MalwareHashRepository interface {
	// InsertMany bulk-inserts hashes using ON CONFLICT (sha256) DO NOTHING.
	// Returns the number of rows actually inserted (duplicates are skipped).
	InsertMany(ctx context.Context, hashes []*models.MalwareHash) (inserted int64, err error)

	// ListSinceVersion returns hashes with version > sinceVersion, ordered ASC.
	ListSinceVersion(ctx context.Context, sinceVersion int64, limit int) ([]*models.MalwareHash, error)

	// GetMaxVersion returns the highest version number currently in the table.
	GetMaxVersion(ctx context.Context) (int64, error)

	// Count returns the total number of hashes in the table.
	Count(ctx context.Context) (int64, error)

	// SourceBreakdown returns a map of source → count for stats.
	SourceBreakdown(ctx context.Context) (map[string]int64, error)

	// GetLatest returns the most recently inserted hashes, ordered newest-first.
	GetLatest(ctx context.Context, limit int) ([]*models.MalwareHash, error)

	// GetSyncHistory returns the N most recent completed sync generations, newest first.
	GetSyncHistory(ctx context.Context, limit int) ([]*SyncEpoch, error)

	// CountEpochs returns the number of successfully committed sync generations.
	CountEpochs(ctx context.Context) (int64, error)
}
