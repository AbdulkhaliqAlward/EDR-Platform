// Package api provides API request/response models.
package api

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// COMMON MODELS
// ============================================================================

// PaginationRequest for paginated endpoints.
type PaginationRequest struct {
	Limit  int `query:"limit" validate:"min=1,max=1000"`
	Offset int `query:"offset" validate:"min=0"`
}

// PaginationResponse for paginated responses.
type PaginationResponse struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
}

// TimeRange for time-based queries.
type TimeRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ResponseMeta for all responses.
type ResponseMeta struct {
	RequestID string `json:"request_id"`
	Timestamp string `json:"timestamp"`
}

// ErrorResponse for error responses.
type ErrorResponse struct {
	Error     string      `json:"error"`
	ErrorCode string      `json:"error_code,omitempty"`
	Message   string      `json:"message"`
	Details   interface{} `json:"details,omitempty"`
	RequestID string      `json:"request_id"`
	Timestamp string      `json:"timestamp"`
}

// ============================================================================
// AUTH MODELS
// ============================================================================

// LoginRequest for user login.
type LoginRequest struct {
	Username string `json:"username" validate:"required,min=3"`
	Password string `json:"password" validate:"required,min=8"`
}

// LoginResponse after successful login.
//
// Two shapes:
//
//  1. Full login — AccessToken/RefreshToken/User populated, MFARequired=false.
//  2. MFA challenge — AccessToken empty, MFARequired=true, MFAChallenge
//     describes where the code was sent and which challenge_id to POST back
//     to /auth/login/mfa.
type LoginResponse struct {
	AccessToken  string       `json:"access_token,omitempty"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	ExpiresIn    int64        `json:"expires_in,omitempty"`
	TokenType    string       `json:"token_type,omitempty"`
	User         UserResponse `json:"user"`

	// MFA step-up (when the account has mfa_enabled=true).
	MFARequired  bool                 `json:"mfa_required,omitempty"`
	MFAChallenge *MFAChallengeSummary `json:"mfa_challenge,omitempty"`
}

// MFAChallengeSummary is the client-facing description of a pending OTP
// challenge. The code itself is never sent over the API — only where it
// was delivered.
type MFAChallengeSummary struct {
	ID          string    `json:"id"`
	MaskedEmail string    `json:"masked_email"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// MFAVerifyRequest is the body of POST /auth/login/mfa.
type MFAVerifyRequest struct {
	ChallengeID string `json:"challenge_id" validate:"required"`
	Code        string `json:"code" validate:"required,min=4,max=10"`
}

// RefreshTokenRequest for token refresh.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshTokenResponse after token refresh.
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"` // new rotated opaque token
	ExpiresIn    int64  `json:"expires_in"`
}

// ============================================================================
// AGENT MODELS
// ============================================================================

// AgentListRequest for listing agents.
type AgentListRequest struct {
	PaginationRequest
	Status    string `query:"status"`
	OSType    string `query:"os_type"`
	Search    string `query:"search"`
	SortBy    string `query:"sort_by" validate:"omitempty,oneof=hostname status last_seen health_score"`
	SortOrder string `query:"sort_order" validate:"omitempty,oneof=asc desc"`
}

// AgentListResponse for agent list.
type AgentListResponse struct {
	Data       []AgentSummary     `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
	Meta       ResponseMeta       `json:"meta"`
}

// AgentSummary for list views.
// NOTE: The dashboard renders agent details from the list API data,
// so this DTO must include ALL fields the frontend needs.
type AgentSummary struct {
	ID              uuid.UUID         `json:"id"`
	Hostname        string            `json:"hostname"`
	Status          string            `json:"status"`
	OSType          string            `json:"os_type"`
	OSVersion       string            `json:"os_version"`
	AgentVersion    string            `json:"agent_version"`
	LastSeen        time.Time         `json:"last_seen"`
	HealthScore     float64           `json:"health_score"`
	EventsDelivered int64             `json:"events_delivered"`
	CertExpiresAt   *time.Time        `json:"cert_expires_at,omitempty"`
	CPUCount        int               `json:"cpu_count"`
	MemoryMB        int64             `json:"memory_mb"`
	IPAddresses     []string          `json:"ip_addresses"`
	IsIsolated      bool              `json:"is_isolated"`
	EventsCollected int64             `json:"events_collected"`
	EventsDropped   int64             `json:"events_dropped"`
	CPUUsage        float64           `json:"cpu_usage"`
	MemoryUsedMB    int64             `json:"memory_used_mb"`
	QueueDepth      int               `json:"queue_depth"`
	CurrentCertID   *uuid.UUID        `json:"current_cert_id,omitempty"`
	InstalledDate   *time.Time        `json:"installed_date,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	Tags            map[string]string `json:"tags,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	SysmonInstalled bool              `json:"sysmon_installed"`
	SysmonRunning   bool              `json:"sysmon_running"`
	Criticality     string            `json:"criticality"`
	BusinessUnit    string            `json:"business_unit"`
	Environment     string            `json:"environment"`
}

// AgentDetailResponse for single agent.
type AgentDetailResponse struct {
	Data AgentDetail  `json:"data"`
	Meta ResponseMeta `json:"meta"`
}

// AgentDetail for detailed view.
type AgentDetail struct {
	AgentSummary
	InstalledDate   time.Time         `json:"installed_date"`
	IPAddresses     []string          `json:"ip_addresses"`
	CPUCount        int               `json:"cpu_count"`
	MemoryMB        int64             `json:"memory_mb"`
	Tags            map[string]string `json:"tags"`
	CurrentCertID   *uuid.UUID        `json:"current_cert_id,omitempty"`
	EventsGenerated int64             `json:"events_generated"`
	EventsSent      int64             `json:"events_sent"`
	CPUUsage        float64           `json:"cpu_usage"`
	MemoryUsedMB    int64             `json:"memory_used_mb"`
	QueueDepth      int               `json:"queue_depth"`
	SysmonInstalled bool              `json:"sysmon_installed"`
	SysmonRunning   bool              `json:"sysmon_running"`
}

// AgentUpdateRequest for updating agent.
type AgentUpdateRequest struct {
	Tags map[string]string `json:"tags"`
}

// AgentStatsResponse for agent statistics.
type AgentStatsResponse struct {
	Total     int            `json:"total"`
	Online    int            `json:"online"`
	Offline   int            `json:"offline"`
	Degraded  int            `json:"degraded"`
	Pending   int            `json:"pending"`
	Suspended int            `json:"suspended"`
	ByOSType  map[string]int `json:"by_os_type"`
	ByVersion map[string]int `json:"by_version"`
	AvgHealth float64        `json:"avg_health"`
	Meta      ResponseMeta   `json:"meta"`
}

// ============================================================================
// COMMAND MODELS
// ============================================================================

// CommandRequest for executing a command.
type CommandRequest struct {
	CommandType string            `json:"command_type" validate:"required,oneof=kill_process terminate_process quarantine_file restore_quarantine_file delete_quarantine_file collect_logs collect_forensics update_policy update_config update_filter_policy restart_agent restart_service stop_agent stop_service start_agent start_service restart_machine shutdown_machine isolate_network isolate restore_network unisolate_network unisolate scan_file scan_memory custom update_agent uninstall_agent adjust_rate run_cmd block_ip unblock_ip block_domain unblock_domain update_signatures enable_sysmon disable_sysmon post_isolation_triage process_tree_snapshot persistence_scan lsass_access_audit filesystem_timeline network_last_seen agent_integrity_check memory_dump"`
	Parameters  map[string]string `json:"parameters"`
	Timeout     int               `json:"timeout" validate:"min=0,max=3600"`
	// Compatibility with external test plans and older clients.
	TimeoutSeconds int `json:"timeout_seconds" validate:"min=0,max=3600"`

	// ApprovalToken is the single-use, OTP-derived token returned by
	// POST /commands/approval/verify. Required when EC2_EMAIL_VERIFY is
	// configured and the server has the approval gate enabled. Clients
	// should normally send it via the X-Approval-Token header instead;
	// this field is just a convenience for tools that can't set headers.
	ApprovalToken string `json:"approval_token,omitempty"`

	// Reason is a mandatory human justification for a custom command
	// (command_type "custom"). Recorded in the audit log. Ignored for other types.
	Reason string `json:"reason,omitempty"`
}

// CommandResponse for command execution.
type CommandResponse struct {
	CommandID string    `json:"command_id"`
	Status    string    `json:"status"`
	IssuedAt  time.Time `json:"issued_at"`
}

// ProcessExceptionRequest asks the server to push an allow-exception to an endpoint.
type ProcessExceptionRequest struct {
	ProcessName string `json:"process_name" validate:"required,min=3"`
	Reason      string `json:"reason"`
}

// CommandListResponse for command history.
type CommandListResponse struct {
	Data       []CommandSummary   `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
	Meta       ResponseMeta       `json:"meta"`
}

// CommandSummary for command history.
type CommandSummary struct {
	ID          uuid.UUID         `json:"id"`
	CommandType string            `json:"command_type"`
	Parameters  map[string]string `json:"parameters"`
	Status      string            `json:"status"`
	IssuedAt    time.Time         `json:"issued_at"`
	IssuedBy    string            `json:"issued_by"`
	ExecutedAt  *time.Time        `json:"executed_at,omitempty"`
	Result      interface{}       `json:"result,omitempty"`
}

// ============================================================================
// ALERT MODELS
// ============================================================================

// AlertSearchRequest for searching alerts.
type AlertSearchRequest struct {
	Severity  []string  `json:"severity"`
	Status    []string  `json:"status"`
	AgentID   string    `json:"agent_id"`
	RuleID    string    `json:"rule_id"`
	TimeRange TimeRange `json:"time_range"`
	Query     string    `json:"query"`
	Limit     int       `json:"limit" validate:"max=1000"`
	Offset    int       `json:"offset"`
	SortBy    string    `json:"sort_by"`
	SortOrder string    `json:"sort_order"`
}

// AlertListResponse for alert list.
type AlertListResponse struct {
	Data       []AlertSummary     `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
	Meta       ResponseMeta       `json:"meta"`
}

// AlertSummary for list views.
type AlertSummary struct {
	ID         uuid.UUID  `json:"id"`
	Severity   string     `json:"severity"`
	Title      string     `json:"title"`
	Status     string     `json:"status"`
	AgentID    uuid.UUID  `json:"agent_id"`
	AgentName  string     `json:"agent_name"`
	EventCount int        `json:"event_count"`
	DetectedAt time.Time  `json:"detected_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	AssignedTo *string    `json:"assigned_to,omitempty"`
}

// AlertDetailResponse for single alert.
type AlertDetailResponse struct {
	Data AlertDetail  `json:"data"`
	Meta ResponseMeta `json:"meta"`
}

// AlertDetail for detailed view.
type AlertDetail struct {
	AlertSummary
	Description string            `json:"description"`
	RuleID      *uuid.UUID        `json:"rule_id,omitempty"`
	RuleName    string            `json:"rule_name,omitempty"`
	EventIDs    []uuid.UUID       `json:"event_ids"`
	Resolution  string            `json:"resolution,omitempty"`
	Notes       string            `json:"notes,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Metadata    interface{}       `json:"metadata,omitempty"`
}

// AlertUpdateRequest for updating alert.
type AlertUpdateRequest struct {
	Status     string `json:"status" validate:"omitempty,oneof=open in_progress resolved"`
	AssignedTo string `json:"assigned_to"`
}

// AlertResolveRequest for resolving alert.
type AlertResolveRequest struct {
	Resolution string `json:"resolution" validate:"required,oneof=false_positive remediated escalated"`
	Notes      string `json:"notes"`
}

// AlertNoteRequest for adding note.
type AlertNoteRequest struct {
	Note string `json:"note" validate:"required,min=1"`
}

// AlertStatsResponse for alert statistics.
type AlertStatsResponse struct {
	Total         int            `json:"total"`
	Alerts24h     int            `json:"alerts_24h"`
	AvgConfidence float64        `json:"avg_confidence"`
	Open          int            `json:"open"`
	InProgress    int            `json:"in_progress"`
	Resolved      int            `json:"resolved"`
	ByStatus      map[string]int `json:"by_status"`
	BySeverity    map[string]int `json:"by_severity"`
	Meta          ResponseMeta   `json:"meta"`
}

// ============================================================================
// USER MODELS
// ============================================================================

// UserResponse for user data.
type UserResponse struct {
	ID         uuid.UUID  `json:"id"`
	Username   string     `json:"username"`
	Email      string     `json:"email"`
	FullName   string     `json:"full_name"`
	Role       string     `json:"role"`
	Status     string     `json:"status"`
	MFAEnabled bool       `json:"mfa_enabled"`
	LastLogin  *time.Time `json:"last_login,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// UserCreateRequest for creating user.
type UserCreateRequest struct {
	Username   string `json:"username" validate:"required,min=3,max=50"`
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required,min=12"`
	FullName   string `json:"full_name" validate:"required"`
	Role       string `json:"role" validate:"required,oneof=admin security analyst operations viewer"`
	MFAEnabled bool   `json:"mfa_enabled"`
}

// UserUpdateRequest for updating user.
//
// MFAEnabled is a pointer so the handler can distinguish "omit"
// from "false" — otherwise turning MFA off would look identical to not
// touching the flag at all.
type UserUpdateRequest struct {
	Email      string `json:"email" validate:"omitempty,email"`
	FullName   string `json:"full_name"`
	Role       string `json:"role" validate:"omitempty,oneof=admin security analyst operations viewer"`
	Status     string `json:"status" validate:"omitempty,oneof=active inactive locked"`
	MFAEnabled *bool  `json:"mfa_enabled,omitempty"`
}

// PasswordChangeRequest for changing password.
type PasswordChangeRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=12"`
}

// ============================================================================
// ROLE & PERMISSION MODELS
// ============================================================================

// RoleResponse for role data.
type RoleResponse struct {
	ID          uuid.UUID            `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	IsBuiltIn   bool                 `json:"is_built_in"`
	Permissions []PermissionResponse `json:"permissions,omitempty"`
}

// RoleCreateRequest for creating a custom role.
type RoleCreateRequest struct {
	Name          string      `json:"name" validate:"required,min=2,max=50"`
	Description   string      `json:"description"`
	PermissionIDs []uuid.UUID `json:"permission_ids"`
}

// RoleUpdatePermissionsRequest for updating role permissions.
type RoleUpdatePermissionsRequest struct {
	PermissionIDs []uuid.UUID `json:"permission_ids" validate:"required"`
}

// PermissionResponse for permission data.
type PermissionResponse struct {
	ID          uuid.UUID `json:"id"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
}

// ============================================================================
// POLICY MODELS
// ============================================================================

// PolicyListResponse for policy list.
type PolicyListResponse struct {
	Data       []PolicySummary    `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
	Meta       ResponseMeta       `json:"meta"`
}

// PolicySummary for list views.
type PolicySummary struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	Priority    int       `json:"priority"`
	AgentCount  int       `json:"agent_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PolicyCreateRequest for creating policy.
type PolicyCreateRequest struct {
	Name        string        `json:"name" validate:"required,min=3"`
	Description string        `json:"description"`
	Enabled     bool          `json:"enabled"`
	Priority    int           `json:"priority"`
	Rules       []PolicyRule  `json:"rules" validate:"required,min=1"`
	Targets     PolicyTargets `json:"targets"`
}

// PolicyRule defines a single policy rule.
type PolicyRule struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Action     string                 `json:"action" validate:"oneof=allow block alert"`
	Conditions map[string]interface{} `json:"conditions"`
}

// PolicyTargets defines policy targets.
type PolicyTargets struct {
	Agents     []string `json:"agents"`
	Groups     []string `json:"groups"`
	ApplyToAll bool     `json:"apply_to_all"`
}

// ============================================================================
// EVENT MODELS
// ============================================================================

// EventSearchRequest for searching events.
type EventSearchRequest struct {
	Filters   []EventFilter `json:"filters"`
	Logic     string        `json:"logic" validate:"oneof=AND OR"`
	TimeRange TimeRange     `json:"time_range"`
	Limit     int           `json:"limit" validate:"max=10000"`
	Offset    int           `json:"offset"`
}

// EventFilter for event filtering.
type EventFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator" validate:"oneof=equals contains regex gt lt gte lte in"`
	Value    interface{} `json:"value"`
}

// EventListResponse for event list.
type EventListResponse struct {
	Data       []EventSummary     `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
	Meta       ResponseMeta       `json:"meta"`
}

// EventSummary for list views.
// Data contains the nested event payload (action, name, pid, matched_rule_id, etc.)
// so the dashboard can display process termination details without a secondary fetch.
type EventSummary struct {
	ID        uuid.UUID              `json:"id"`
	AgentID   uuid.UUID              `json:"agent_id"`
	EventType string                 `json:"event_type"`
	Severity  string                 `json:"severity"`
	Timestamp time.Time              `json:"timestamp"`
	Summary   string                 `json:"summary"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// EventDetail is a single stored event including the ingestion JSON payload.
type EventDetail struct {
	ID        uuid.UUID       `json:"id"`
	AgentID   uuid.UUID       `json:"agent_id"`
	EventType string          `json:"event_type"`
	Severity  string          `json:"severity"`
	Timestamp time.Time       `json:"timestamp"`
	Summary   string          `json:"summary"`
	Raw       json.RawMessage `json:"raw"`
}

// EventExportRequest for exporting events.
type EventExportRequest struct {
	EventSearchRequest
	Format string `json:"format" validate:"oneof=json csv"`
}

// ============================================================================
// POST-ISOLATION INCIDENT MODELS
// ============================================================================

// IncidentResponse wraps the full incident payload for a given agent.
type IncidentResponse struct {
	Data IncidentData `json:"data"`
	Meta ResponseMeta `json:"meta"`
}

// IncidentData is the aggregated post-isolation incident for a single agent.
type IncidentData struct {
	AgentID    string              `json:"agent_id"`
	IsIsolated bool                `json:"is_isolated"`
	Run        *PlaybookRunDTO     `json:"run,omitempty"`
	Steps      []PlaybookStepDTO   `json:"steps"`
	Snapshots  []TriageSnapshotDTO `json:"snapshots"`
	Iocs       []IocEnrichmentDTO  `json:"iocs"`
}

// PlaybookRunDTO is the API representation of a playbook run.
type PlaybookRunDTO struct {
	ID         int64          `json:"id"`
	Playbook   string         `json:"playbook"`
	Trigger    string         `json:"trigger"`
	Status     string         `json:"status"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Summary    map[string]any `json:"summary,omitempty"`
}

// PlaybookStepDTO is the API representation of a single playbook step.
type PlaybookStepDTO struct {
	ID          int64      `json:"id"`
	StepName    string     `json:"step_name"`
	CommandType string     `json:"command_type"`
	Status      string     `json:"status"`
	CommandID   *string    `json:"command_id,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// TriageSnapshotDTO is the API representation of a triage snapshot.
type TriageSnapshotDTO struct {
	ID        int64          `json:"id"`
	Kind      string         `json:"kind"`
	Payload   map[string]any `json:"payload"`
	CreatedAt time.Time      `json:"created_at"`
}

// IocEnrichmentDTO is the API representation of an IOC enrichment record.
type IocEnrichmentDTO struct {
	ID        int64     `json:"id"`
	IocType   string    `json:"ioc_type"`
	IocValue  string    `json:"ioc_value"`
	Provider  string    `json:"provider"`
	Verdict   string    `json:"verdict"`
	Score     int       `json:"score"`
	FetchedAt time.Time `json:"fetched_at"`
}

// CollectMemoryRequest triggers a manual memory dump.
type CollectMemoryRequest struct {
	OutputDir string `json:"output_dir"`
	Confirm   bool   `json:"confirm" validate:"required"`
}

// PlaybookRunListResponse for listing playbook runs.
type PlaybookRunListResponse struct {
	Data       []PlaybookRunDTO   `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
	Meta       ResponseMeta       `json:"meta"`
}
