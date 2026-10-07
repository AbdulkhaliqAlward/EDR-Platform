import axios, { type AxiosInstance } from 'axios';

// Configuration - all from environment variables
// IMPORTANT: When VITE_* vars are set to "" (empty string) via Docker build args,
// we must use "" as the baseURL so Axios sends RELATIVE requests (same-origin).
// Nginx then proxies /api/v1/* to the correct backend.
// The localhost fallbacks are ONLY for local `npm run dev` outside Docker.
const envOrDefault = (envVal: string | undefined, fallback: string): string => {
    // undefined = env var not set at all (local dev) → use fallback
    // ""        = explicitly set to empty (Docker)   → use "" (same-origin)
    return envVal === undefined ? fallback : envVal;
};

const config = {
    sigmaEngineUrl: envOrDefault(import.meta.env.VITE_API_URL, 'http://localhost:8080'),
    connectionManagerUrl: envOrDefault(import.meta.env.VITE_CONNECTION_MANAGER_URL, 'http://localhost:8082'),
    wsUrl: envOrDefault(import.meta.env.VITE_WS_URL, 'ws://localhost:8080'),
};

// Create axios instance for Sigma Engine
const createApiClient = (baseURL: string): AxiosInstance => {
    const client = axios.create({
        baseURL,
        timeout: 10000,
        headers: { 'Content-Type': 'application/json' },
    });

    // Request interceptor for auth
    client.interceptors.request.use((cfg) => {
        const token = localStorage.getItem('auth_token');
        if (token) {
            cfg.headers.Authorization = `Bearer ${token}`;
        }
        return cfg;
    });

    // Response interceptor for error handling
    client.interceptors.response.use(
        (response) => response,
        (error) => {
            if (error.response?.status === 401) {
                // Token expired or revoked (e.g. after password change) — force re-login
                localStorage.removeItem('auth_token');
                localStorage.removeItem('user');
                window.location.href = '/login';
            }
            // 403: RBAC denied — don't redirect, let the caller show an error
            return Promise.reject(error);
        }
    );

    return client;
};

// API clients for each service
export const sigmaApi = createApiClient(config.sigmaEngineUrl);
export const connectionApi = createApiClient(config.connectionManagerUrl);

// For backward compatibility
export const api = sigmaApi;

// ============================================================================
// Command-approval (out-of-band OTP) — module-level glue
// ============================================================================
//
// When the server is configured with EC2_EMAIL_VERIFY, every manual command
// (POST /agents/:id/commands) returns 403 with error_code=APPROVAL_REQUIRED
// until the dashboard supplies a single-use token. We solve that here at
// the axios layer so individual call sites do NOT have to know about the
// flow. The CommandApprovalProvider mounts at the App root and registers
// a resolver via setApprovalTokenResolver(); when the interceptor sees
// APPROVAL_REQUIRED / APPROVAL_INVALID it calls the resolver to obtain a
// fresh token, then replays the original request once with the
// X-Approval-Token header.

/** Context carried into the resolver so the modal can describe what's being approved. */
export interface ApprovalContext {
    agentId?: string;
    commandType?: string;
    summary?: string;
    /** Set to true on a retry after APPROVAL_INVALID so the modal can say "code rejected, try again". */
    invalidPrevious?: boolean;
}

/** A resolver returns a fresh approval_token (already verified server-side) or rejects on cancel. */
export type ApprovalTokenResolver = (ctx: ApprovalContext) => Promise<string>;

let approvalTokenResolver: ApprovalTokenResolver | null = null;

/** Called by CommandApprovalProvider on mount. Pass null on unmount. */
export function setApprovalTokenResolver(fn: ApprovalTokenResolver | null) {
    approvalTokenResolver = fn;
}

/** Low-level API used by the provider's modal. Keeps the network shape in one place. */
export const commandApprovalApi = {
    issue: async (payload: { agent_id?: string; command_type?: string; summary?: string }) => {
        const r = await connectionApi.post<{ approval_id: string; masked_email: string; expires_at: string }>(
            '/api/v1/commands/approval',
            payload,
            // Skip the approval interceptor on this call — it's how we
            // GET the token, it can't itself require one.
            { headers: { 'X-Skip-Approval-Interceptor': '1' } } as any,
        );
        return r.data;
    },
    verify: async (payload: { approval_id: string; code: string }) => {
        const r = await connectionApi.post<{ approval_token: string; expires_at: string }>(
            '/api/v1/commands/approval/verify',
            payload,
            { headers: { 'X-Skip-Approval-Interceptor': '1' } } as any,
        );
        return r.data;
    },
};

// Codes the server uses to ask for an approval token.
const APPROVAL_NEEDED_CODES = new Set(['APPROVAL_REQUIRED', 'APPROVAL_INVALID', 'APPROVAL_EXPIRED']);

// Pull a short summary out of the original POST body if we can. Best-effort —
// it's only used to decorate the email and the modal copy, never for security.
function summariseRequest(cfg: any): ApprovalContext {
    const out: ApprovalContext = {};
    try {
        // /api/v1/agents/:id/commands → extract :id
        const url: string = cfg?.url || '';
        const m = url.match(/\/agents\/([0-9a-fA-F-]{8,})\/commands?\b/);
        if (m) out.agentId = m[1];
        const data = typeof cfg?.data === 'string' ? JSON.parse(cfg.data) : cfg?.data;
        if (data && typeof data === 'object') {
            if (typeof data.command_type === 'string') out.commandType = data.command_type;
        }
        if (out.commandType) {
            out.summary = out.agentId
                ? `${out.commandType} on agent ${out.agentId.slice(0, 8)}`
                : out.commandType;
        }
    } catch {
        // best-effort — fall through
    }
    return out;
}

// Install the response interceptor on connectionApi (NOT sigmaApi — Sigma
// engine doesn't issue commands).
connectionApi.interceptors.response.use(
    (r) => r,
    async (error) => {
        const resp = error?.response;
        const cfg = error?.config || {};
        if (!resp || resp.status !== 403) {
            return Promise.reject(error);
        }
        const code: string | undefined = resp.data?.error_code;
        if (!code || !APPROVAL_NEEDED_CODES.has(code)) {
            return Promise.reject(error);
        }
        // Avoid infinite loops: only one transparent retry per request.
        if (cfg.__approvalRetried) {
            return Promise.reject(error);
        }
        if (cfg.headers && cfg.headers['X-Skip-Approval-Interceptor']) {
            return Promise.reject(error);
        }
        if (!approvalTokenResolver) {
            // Provider not mounted — surface the original error.
            return Promise.reject(error);
        }

        let token: string;
        try {
            token = await approvalTokenResolver({
                ...summariseRequest(cfg),
                invalidPrevious: code === 'APPROVAL_INVALID',
            });
        } catch (cancelled) {
            // Operator dismissed the modal. Re-reject with the original error
            // so the caller's onError fires once (and only once).
            return Promise.reject(error);
        }

        cfg.__approvalRetried = true;
        cfg.headers = { ...(cfg.headers || {}), 'X-Approval-Token': token };
        return connectionApi.request(cfg);
    },
);

// ============================================================================
// API Types
// ============================================================================

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type AlertStatus = 'open' | 'in_progress' | 'acknowledged' | 'resolved' | 'closed' | 'false_positive';
export type AgentStatus = 'online' | 'offline' | 'degraded' | 'pending' | 'suspended' | 'pending_uninstall' | 'uninstalled';
export type CommandType = 'kill_process' | 'terminate_process' | 'quarantine_file' | 'collect_logs' | 'collect_forensics' | 'update_policy' |
    'restart_agent' | 'restart_service' | 'stop_agent' | 'start_agent' |
    'isolate_network' | 'restore_network' | 'scan_file' | 'scan_memory' | 'custom' |
    'restart_machine' | 'shutdown_machine' | 'update_filter_policy' |
    'run_cmd' | 'block_ip' | 'unblock_ip' | 'block_domain' | 'unblock_domain' | 'update_signatures' | 'update_config' | 'update_vuln_config' |
    'unisolate_network' | 'restore_quarantine_file' | 'delete_quarantine_file' |
    'enable_sysmon' | 'disable_sysmon' | 'update_agent' | 'uninstall_agent';
export type CommandStatus = 'pending' | 'sent' | 'acknowledged' | 'executing' | 'completed' | 'failed' | 'timeout' | 'cancelled';

// Sprint 4 context-aware scoring types
export interface AncestorEntry {
    pid: number;
    name: string;
    path?: string;
    user_sid?: string;
    integrity?: string;
    is_elevated: boolean;
    sig_status?: string;
    seen_at: number; // Unix seconds
}

export interface ScoreBreakdown {
    base_score: number;
    lineage_bonus: number;
    privilege_bonus: number;
    burst_bonus: number;
    fp_discount: number;
    ueba_bonus: number;
    ueba_discount: number;
    ueba_signal: 'anomaly' | 'normal' | 'none' | string;
    interaction_bonus: number; // Cross-dimensional signal convergence bonus
    user_role_weight?: number;
    device_criticality_weight?: number;
    network_anomaly_factor?: number;
    context_multiplier?: number;
    context_quality_score?: number;
    quality_factor?: number;
    context_adjusted_score?: number;
    raw_score: number;
    final_score: number;
}

export interface ContextSnapshot {
    scored_at: string;
    process_name?: string;
    process_path?: string;
    process_cmd_line?: string;
    user_sid?: string;
    user_name?: string;
    integrity_level?: string;
    is_elevated: boolean;
    signature_status?: string;
    parent_pid?: number;
    parent_name?: string;
    parent_path?: string;
    grandparent_name?: string;
    grandparent_path?: string;
    lineage_suspicion: string;
    ancestor_chain?: AncestorEntry[];
    burst_count: number;
    burst_window_sec: number;
    rule_id?: string;
    rule_title?: string;
    rule_severity?: string;
    rule_category?: string;
    match_count: number;
    score_breakdown: ScoreBreakdown;
    user_role_weight?: number;
    device_criticality_weight?: number;
    network_anomaly_factor?: number;
    context_multiplier?: number;
    context_quality_score?: number;
    quality_factor?: number;
    missing_context_fields?: string[];
    warnings?: string[];
    correlation?: {
        edges_added?: number;
        primary_type?: string;
        strongest_score?: number;
    };
    related_rules?: string[];
}

export type ForensicCollection = {
    command_id: string;
    agent_id: string;
    command_type: string;
    issued_at: string;
    completed_at?: string | null;
    time_range?: string;
    log_types?: string;
    summary: Record<string, any>;
};

export type ForensicEvent = {
    id: number;
    timestamp?: string | null;
    log_type: string;
    event_id?: string;
    level?: string;
    provider?: string;
    message?: string;
    raw?: any;
};

export interface Alert {
    id: string;
    timestamp: string;
    agent_id: string;
    rule_id: string;
    rule_title: string;
    severity: AlertSeverity;
    category: string;
    event_count: number;
    status: AlertStatus;
    confidence: number;
    // Sprint 3+ risk scoring
    risk_score?: number;
    risk_level?: 'low' | 'medium' | 'high' | 'critical' | string;
    false_positive_risk?: number;
    context_snapshot?: ContextSnapshot;
    score_breakdown?: ScoreBreakdown;
    matched_fields?: Record<string, string>;
    mitre_techniques?: string[];
    mitre_tactics?: string[];
    event_data?: Record<string, unknown>;
    tags?: Record<string, string>;
    notes?: string;
    assigned_to?: string;
    acknowledged_at?: string;
    resolved_at?: string;
    created_at: string;
    updated_at: string;
    // Analyst-friendly enrichment (computed by server)
    human_summary?: string;
    source_hostname?: string;
    // Raw event payload that triggered the alert. Returned only by the
    // by-id endpoint (/api/v1/sigma/alerts/{id}). Shape mirrors the agent
    // event envelope plus Kafka metadata.
    context_data?: {
        event_id?: string;
        event_type?: string;
        timestamp?: string;
        agent_id?: string;
        batch_id?: string;
        ip_address?: string;
        executable?: string;
        command_line?: string;
        name?: string;
        pid?: number;
        ppid?: number;
        integrity_level?: string;
        is_elevated?: boolean;
        signature_status?: string;
        signature_issuer?: string;
        user_name?: string;
        user_sid?: string;
        severity?: string;
        context_quality_score?: number;
        source?: {
            agent_version?: string;
            hostname?: string;
            ip_address?: string;
            os_type?: string;
            os_version?: string;
        };
        data?: Record<string, unknown>;
        _kafka_topic?: string;
        _kafka_partition?: number;
        _kafka_offset?: number;
        _kafka_time?: string;
        _kafka_key?: string;
        [k: string]: unknown;
    };
    // Correlated raw event UUIDs (populated for aggregated alerts)
    event_ids?: string[];
    // Aggregation / promotion metadata (server-side correlation engine)
    match_count?: number;
    related_rules?: string[];
    combined_confidence?: number;
    severity_promoted?: boolean;
    original_severity?: string;
}

export interface Rule {
    id: string;
    title: string;
    description: string;
    severity: string;
    category: string;
    product: string;
    enabled: boolean;
    status: string;
    tags?: string[];
    mitre_attack?: {
        tactics: string[];
        techniques: string[];
    };
    created_at: string;
    updated_at: string;
}

export interface AlertStats {
    total_alerts: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    by_rule?: Record<string, number>;
    by_agent?: Record<string, number>;
    by_tactic?: Record<string, number>;
    last_24h: number;
    last_7d: number;
    avg_confidence: number;
}

export interface RuleStats {
    total_rules: number;
    enabled_rules: number;
    disabled_rules: number;
    by_severity: Record<string, number>;
}

export interface Agent {
    id: string;
    hostname: string;
    status: AgentStatus;
    os_type: 'windows' | 'linux' | 'macos';
    os_version: string;
    agent_version: string;
    last_seen: string;
    health_score: number;
    events_delivered: number;
    events_collected?: number;
    events_dropped?: number;
    ip_addresses?: string[];
    is_isolated?: boolean;
    cpu_count?: number;
    memory_mb?: number;
    cpu_usage?: number;
    memory_used_mb?: number;
    queue_depth?: number;
    current_cert_id?: string;
    cert_expires_at?: string;
    tags?: Record<string, string>;
    metadata?: Record<string, string>;
    installed_date?: string;
    created_at: string;
    updated_at: string;
    sysmon_installed?: boolean;
    sysmon_running?: boolean;
    criticality?: 'low' | 'medium' | 'high' | 'critical' | string;
    business_unit?: string;
    environment?: string;
}

// Filter policy for dynamic agent-side event filtering
export interface FilterPolicy {
    exclude_processes?: string[];
    exclude_ips?: string[];
    exclude_event_ids?: number[];
    trusted_hashes?: string[];
    exclude_registry?: string[];
    exclude_paths?: string[];
    include_paths?: string[];
    rate_limit?: {
        enabled: boolean;
        default_max_eps: number;
        critical_bypass: boolean;
        per_event_type?: Record<string, number>;
    };
}

export interface AgentStats {
    total: number;
    online: number;
    offline: number;
    degraded: number;
    pending: number;
    suspended: number;
    by_os_type: Record<string, number>;
    by_version: Record<string, number>;
    avg_health: number;
}

export interface Command {
    id: string;
    agent_id: string;
    command_type: CommandType;
    parameters: Record<string, string>;
    status: CommandStatus;
    result?: Record<string, unknown>;
    error_message?: string;
    exit_code?: number;
    issued_at: string;
    issued_by: string;
    sent_at?: string;
    acknowledged_at?: string;
    started_at?: string;
    completed_at?: string;
    timeout_seconds: number;
}

export interface CommandRequest {
    command_type: CommandType;
    parameters: Record<string, string>;
    timeout?: number;
    /** Alias used by some test plans / tools; prefer `timeout` from the dashboard. */
    timeout_seconds?: number;
    /** Mandatory justification for a custom command (command_type 'custom'); audited. */
    reason?: string;
    /**
     * Run a stored script from the response script library. The server loads the
     * command line itself and ignores command_type/parameters from the client.
     */
    script_id?: string;
}

/** A stored script in the dashboard-managed response script library. */
export interface ResponseScript {
    id: string;
    name: string;
    description: string;
    cmd: string;
    timeout_seconds: number;
    enabled: boolean;
    created_by: string;
    updated_by: string;
    created_at: string;
    updated_at: string;
}

export interface ResponseScriptInput {
    name: string;
    description: string;
    cmd: string;
    timeout_seconds: number;
    enabled: boolean;
}

/** Which command features are enabled for the current user. */
export interface CommandCapabilities {
    custom_commands_enabled: boolean;
    custom_commands_available: boolean;
    /** Older servers omit the script library fields. */
    script_library_available?: boolean;
    script_library_manage?: boolean;
    script_library_executables?: string[];
    /** Whether manual commands currently require an out-of-band OTP. */
    command_approval_enabled?: boolean;
}

export interface AuditLog {
    id: string;
    user_id: string;
    username: string;
    action: string;
    resource_type: string;
    resource_id?: string;
    old_value?: Record<string, unknown>;
    new_value?: Record<string, unknown>;
    details?: string;
    result: 'success' | 'failure';
    error_message?: string;
    ip_address?: string;
    user_agent?: string;
    timestamp: string;
}

export interface TimelineDataPoint {
    timestamp: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
}

export interface User {
    id: string;
    username: string;
    email?: string;
    full_name?: string;
    role: 'admin' | 'security' | 'analyst' | 'operations' | 'viewer';
    status: 'active' | 'inactive' | 'locked';
    /** Whether the account requires email OTP on every login. */
    mfa_enabled?: boolean;
    last_login?: string;
    created_at?: string;
    updated_at?: string;
}

/** Describes a pending MFA challenge issued by POST /auth/login. */
export interface MFAChallenge {
    id: string;
    masked_email: string;
    expires_at: string;
}

/** Full shape returned by POST /auth/login — either tokens OR a challenge. */
export interface LoginResult {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    token_type?: string;
    user: User;
    mfa_required?: boolean;
    mfa_challenge?: MFAChallenge;
}

/** `GET /api/v1/users` list envelope. */
export interface UsersListResponse {
    data: User[];
    pagination: { total: number; limit: number; offset: number; has_more?: boolean };
    meta?: { request_id?: string; timestamp?: string };
}

export interface Permission {
    id: string;
    resource: string;
    action: string;
    description: string;
}

export interface Role {
    id: string;
    name: string;
    description: string;
    is_built_in: boolean;
    permissions: Permission[];
}

/** Combined load for the RBAC matrix (`GET /roles` + `GET /permissions`). */
export interface RolesPermissionsMatrixPayload {
    roles: Role[];
    permissions: Permission[];
    meta?: { request_id?: string; timestamp?: string };
}

// ============================================================================
// Sigma Engine Alert APIs
// ============================================================================

// Phase 2 — Endpoint Risk Intelligence
export interface EndpointRiskSummary {
    agent_id: string;
    total_alerts: number;
    peak_risk_score: number;
    avg_risk_score: number;
    critical_count: number; // risk_score >= 90
    high_count: number;     // risk_score 70-89
    open_count: number;
    last_alert_at: string;
}

export const alertsApi = {
    list: async (params?: {
        limit?: number;
        offset?: number;
        severity?: string;
        status?: string;
        agent_id?: string;
        rule_id?: string;
        date_from?: string;
        date_to?: string;
        search?: string;
        sort?: string;
        order?: 'asc' | 'desc';
    }) => {
        const response = await sigmaApi.get<{ alerts: Alert[]; total: number; limit?: number; offset?: number }>(
            '/api/v1/sigma/alerts',
            { params }
        );
        return response.data;
    },
    get: async (id: string) => {
        const response = await sigmaApi.get<Alert>(`/api/v1/sigma/alerts/${id}`);
        return response.data;
    },
    updateStatus: async (id: string, status: string, notes?: string) => {
        const response = await sigmaApi.patch(`/api/v1/sigma/alerts/${id}/status`, { status, notes });
        return response.data;
    },
    acknowledge: async (id: string) => {
        const response = await sigmaApi.post(`/api/v1/sigma/alerts/${id}/acknowledge`);
        return response.data;
    },
    delete: async (id: string) => {
        await sigmaApi.delete(`/api/v1/sigma/alerts/${id}`);
    },
    bulkUpdateStatus: async (ids: string[], status: string) => {
        const response = await sigmaApi.patch('/api/v1/sigma/alerts/bulk/status', { ids, status });
        return response.data;
    },
    // Phase 2: aggregated per-agent risk posture from connection-manager
    endpointRisk: async () => {
        const response = await connectionApi.get<{ data: EndpointRiskSummary[]; total: number }>(
            '/api/v1/alerts/endpoint-risk'
        );
        return response.data;
    },
};


// ============================================================================
// Sigma Engine Rules APIs
// ============================================================================

export const rulesApi = {
    list: async (params?: { limit?: number; offset?: number; enabled?: boolean; severity?: string }) => {
        const response = await sigmaApi.get<{ rules: Rule[]; total: number }>('/api/v1/sigma/rules', { params });
        return response.data;
    },
    get: async (id: string) => {
        const response = await sigmaApi.get<Rule>(`/api/v1/sigma/rules/${id}`);
        return response.data;
    },
    create: async (rule: Partial<Rule>) => {
        const response = await sigmaApi.post<Rule>('/api/v1/sigma/rules', rule);
        return response.data;
    },
    update: async (id: string, rule: Partial<Rule>) => {
        const response = await sigmaApi.put<Rule>(`/api/v1/sigma/rules/${id}`, rule);
        return response.data;
    },
    delete: async (id: string) => {
        await sigmaApi.delete(`/api/v1/sigma/rules/${id}`);
    },
    enable: async (id: string) => {
        const response = await sigmaApi.patch(`/api/v1/sigma/rules/${id}/enable`);
        return response.data;
    },
    disable: async (id: string) => {
        const response = await sigmaApi.patch(`/api/v1/sigma/rules/${id}/disable`);
        return response.data;
    },
};

// ============================================================================
// Sigma Engine Stats APIs
// ============================================================================

export const statsApi = {
    alerts: async () => {
        const response = await sigmaApi.get<AlertStats>('/api/v1/sigma/stats/alerts');
        return response.data;
    },
    rules: async () => {
        const response = await sigmaApi.get<RuleStats>('/api/v1/sigma/stats/rules');
        return response.data;
    },
    performance: async () => {
        const response = await sigmaApi.get('/api/v1/sigma/stats/performance');
        return response.data;
    },
    timeline: async (params: { from: string; to: string; granularity?: string }) => {
        const response = await sigmaApi.get<{ data: TimelineDataPoint[] }>('/api/v1/sigma/stats/timeline', { params });
        return response.data;
    },
};

// ============================================================================
// Connection Manager Agents APIs
// ============================================================================

/** Event row from connection-manager event APIs (`/agents/:id/events`, `/events/search`). */
export interface CmEventSummary {
    id: string;
    agent_id: string;
    event_type: string;
    timestamp: string;
    summary: string;
    severity?: string;
    data?: any;
}

/** Single event from `GET /api/v1/events/:id` (includes ingestion `raw`). */
export interface CmEventDetail extends CmEventSummary {
    raw: unknown;
}

/** Body for `POST /api/v1/events/search` (matches connection-manager EventSearchRequest). */
export interface EventSearchRequestBody {
    filters: { field: string; operator: string; value: unknown }[];
    logic: 'AND' | 'OR';
    time_range: { from: string; to: string };
    limit: number;
    offset: number;
}

export const eventsApi = {
    search: async (body: EventSearchRequestBody) => {
        const response = await connectionApi.post<{
            data: CmEventSummary[];
            pagination: { total: number; limit: number; offset: number; has_more?: boolean };
        }>('/api/v1/events/search', body);
        return response.data;
    },
    get: async (id: string) => {
        const response = await connectionApi.get<{ data: CmEventDetail }>(`/api/v1/events/${encodeURIComponent(id)}`);
        return response.data;
    },
};

/** Aggregated process execution row from GET /api/v1/app-control/process-analytics. */
export interface ProcessAnalyticsRow {
    name: string;
    executable: string;
    count: number;
    agent_count: number;
    hostnames?: string[];
    last_seen: string;
}

/** Aggregated software inventory row from GET /api/v1/app-control/software-inventory. */
export interface SoftwareInventoryRow {
    name: string;
    version: string;
    publisher: string;
    install_date: string;
    agent_count: number;
    hostnames?: string[];
    last_reported: string;
}

/** Aggregated bandwidth-per-application row from GET /api/v1/app-control/bandwidth-analytics. */
export interface BandwidthAnalyticsRow {
    process_name: string;
    executable: string;
    bytes_sent: number;
    bytes_received: number;
    total_bytes: number;
    connections: number;
    unique_destinations: number;
    unique_ports: number;
    agent_count: number;
    hostnames?: string[];
    last_seen: string;
}

export const appControlApi = {
    /** Server-side aggregated process analytics (SQL GROUP BY on process name). */
    getProcessAnalytics: async (hours = 24) => {
        const response = await connectionApi.get<{
            data: ProcessAnalyticsRow[];
            total_events: number;
            hours: number;
        }>(`/api/v1/app-control/process-analytics?hours=${hours}`);
        return response.data;
    },
    /** Aggregated installed software inventory from software_inventory events. */
    getSoftwareInventory: async () => {
        const response = await connectionApi.get<{
            data: SoftwareInventoryRow[];
            total: number;
        }>('/api/v1/app-control/software-inventory');
        return response.data;
    },
    /** Aggregated bandwidth consumption per application from network events. */
    getBandwidthAnalytics: async (hours = 24) => {
        const response = await connectionApi.get<{
            data: BandwidthAnalyticsRow[];
            total: number;
            hours: number;
        }>(`/api/v1/app-control/bandwidth-analytics?hours=${hours}`);
        return response.data;
    },
};

export const agentsApi = {
    list: async (params?: {
        limit?: number;
        offset?: number;
        status?: string;
        os_type?: string;
        search?: string;
        sort_by?: string;
        sort_order?: 'asc' | 'desc';
    }) => {
        const response = await connectionApi.get<{ data: Agent[]; pagination: { total: number; has_more: boolean } }>('/api/v1/agents', { params });
        return response.data;
    },
    get: async (id: string) => {
        const response = await connectionApi.get<{ data: Agent }>(`/api/v1/agents/${id}`);
        return response.data.data;
    },
    stats: async () => {
        const response = await connectionApi.get<AgentStats>('/api/v1/agents/stats');
        return response.data;
    },
    update: async (id: string, data: { tags?: Record<string, string> }) => {
        const response = await connectionApi.patch(`/api/v1/agents/${id}`, data);
        return response.data;
    },
    patchBusinessContext: async (id: string, data: {
        criticality?: 'low' | 'medium' | 'high' | 'critical';
        business_unit?: string;
        environment?: string;
        profile?: string;
        customer?: string;
        logged_in_user?: string;
    }) => {
        const response = await connectionApi.patch<{ data: Agent }>(
            `/api/v1/agents/${encodeURIComponent(id)}/business-context`,
            data
        );
        return response.data.data;
    },
    delete: async (id: string) => {
        await connectionApi.delete(`/api/v1/agents/${id}`);
    },
    health: async () => {
        const response = await connectionApi.get('/health');
        return response.data;
    },
    // Commands
    executeCommand: async (agentId: string, command: CommandRequest) => {
        const response = await connectionApi.post<{ command_id: string; status: string; issued_at: string }>(
            `/api/v1/agents/${agentId}/commands`,
            command
        );
        return response.data;
    },
    /**
     * Mint a signed, agent-bound, short-lived OFFLINE uninstall token for this
     * agent. The returned token is used on the endpoint (even while it is
     * disconnected) as:
     *   echo '<token>' | .\edr-agent.exe -uninstall -token-stdin
     * The out-of-band approval modal (when enabled) is handled automatically by
     * the connectionApi interceptor, exactly like manual commands.
     */
    generateUninstallToken: async (agentId: string, reason?: string) => {
        const response = await connectionApi.post<{
            token: string;
            agent_id: string;
            expires_at: string;
            ttl_seconds: number;
        }>(`/api/v1/agents/${agentId}/uninstall-token`, { reason: reason ?? '' });
        return response.data;
    },
    /** Which command features are enabled for the current user (e.g. custom commands). */
    commandCapabilities: async (): Promise<CommandCapabilities> => {
        const response = await connectionApi.get<CommandCapabilities>('/api/v1/commands/capabilities');
        return response.data;
    },
    getCommands: async (agentId: string, params?: { limit?: number; offset?: number; status?: string }) => {
        const response = await connectionApi.get<{
            data: CommandListItem[];
            pagination: { total: number; limit: number; offset: number; has_more: boolean };
        }>(
            `/api/v1/agents/${agentId}/commands`,
            { params }
        );
        return response.data;
    },
    getForensicCollections: async (agentId: string, params?: { limit?: number }) => {
        const response = await connectionApi.get<{ data: ForensicCollection[] }>(
            `/api/v1/agents/${encodeURIComponent(agentId)}/forensic-collections`,
            { params }
        );
        return response.data;
    },
    getForensicEvents: async (
        agentId: string,
        commandId: string,
        params: { log_type: string; limit?: number; cursor?: number }
    ) => {
        const response = await connectionApi.get<{ data: ForensicEvent[]; next_cursor?: number }>(
            `/api/v1/agents/${encodeURIComponent(agentId)}/forensic-collections/${encodeURIComponent(commandId)}/events`,
            { params }
        );
        return response.data;
    },
    /** Single command by ID (same payload as Action Center row). */
    getCommand: async (commandId: string) => {
        const response = await connectionApi.get<{ data: CommandListItem }>(`/api/v1/commands/${commandId}`);
        return response.data.data;
    },
    cancelCommand: async (agentId: string, commandId: string) => {
        const response = await connectionApi.post(`/api/v1/agents/${agentId}/commands/${commandId}/cancel`);
        return response.data;
    },
    // Push a new filter policy to an agent via the C2 command pipeline
    updateFilterPolicy: async (agentId: string, policy: FilterPolicy) => {
        const response = await connectionApi.post<{ command_id: string; status: string; issued_at: string }>(
            `/api/v1/agents/${agentId}/commands`,
            {
                command_type: 'update_filter_policy',
                parameters: { policy: JSON.stringify(policy) },
                timeout: 300,
            }
        );
        return response.data;
    },
    /** Allow/exception for process auto-response (pushes exclude_process to agent). */
    addProcessException: async (agentId: string, body: { process_name: string; reason?: string }) => {
        const response = await connectionApi.post<{ command_id: string; status?: string; issued_at?: string }>(
            `/api/v1/agents/${encodeURIComponent(agentId)}/process-exceptions`,
            body
        );
        return response.data;
    },
    /** Quarantine inventory (server-side); optional `include_resolved` / `all=1` for full history. */
    listQuarantine: async (agentId: string, params?: { include_resolved?: boolean; all?: string }) => {
        const response = await connectionApi.get<{ items: QuarantineItem[]; meta?: unknown }>(
            `/api/v1/agents/${encodeURIComponent(agentId)}/quarantine`,
            { params }
        );
        return response.data;
    },
    quarantineDecision: async (
        agentId: string,
        entryId: string,
        decision: 'acknowledge' | 'restore' | 'delete'
    ) => {
        const response = await connectionApi.post<{ status?: string; entry_id?: string }>(
            `/api/v1/agents/${encodeURIComponent(agentId)}/quarantine/${encodeURIComponent(entryId)}/decision`,
            { decision }
        );
        return response.data;
    },
    /** Returns `data: []` until connection-manager wires the event store (see GetAgentEvents TODO). */
    getAgentEvents: async (agentId: string) => {
        const response = await connectionApi.get<{
            data: CmEventSummary[];
            pagination?: { total: number; limit: number; offset: number; has_more?: boolean };
        }>(`/api/v1/agents/${agentId}/events`);
        return response.data;
    },
    getSoftwareInventory: async (agentId: string) => {
        const response = await connectionApi.get<{
            data: SoftwareInventoryRow[];
            total: number;
        }>(`/api/v1/agents/${encodeURIComponent(agentId)}/software-inventory`);
        return response.data;
    },
};

/** One row in agent quarantine inventory (connection-manager). */
export interface QuarantineItem {
    id: string;
    agent_id: string;
    event_id?: string;
    original_path: string;
    quarantine_path: string;
    sha256?: string;
    threat_name?: string;
    source: string;
    state: 'quarantined' | 'acknowledged' | 'restored' | 'deleted' | string;
    created_at: string;
    updated_at: string;
}

// ============================================================================
// Connection Manager Automation APIs
// ============================================================================

export interface ResponsePlaybook {
    id: string;
    name: string;
    description: string;
    category: string;
    severity_filter: string[];
    rule_pattern: string;
    commands: any[];
    mitre_techniques: string[];
    enabled: boolean;
    created_at?: string;
    updated_at?: string;
}

export interface AutomationRule {
    id: string;
    name: string;
    description: string;
    trigger_conditions: any;
    playbook_id: string;
    priority: number;
    auto_execute: boolean;
    cooldown_minutes: number;
    enabled: boolean;
    success_rate: number;
    last_execution?: string;
    created_at?: string;
    updated_at?: string;
}

/**
 * Response script library. Writes require an admin account; the out-of-band
 * approval modal (when enabled) is handled by the connectionApi interceptor.
 * Running a script is agentsApi.executeCommand(agentId, { script_id, ... }).
 */
export const responseScriptsApi = {
    list: async (): Promise<ResponseScript[]> => {
        const response = await connectionApi.get<{ data: ResponseScript[]; total: number }>('/api/v1/response-scripts');
        return response.data.data || [];
    },
    create: async (data: ResponseScriptInput): Promise<ResponseScript> => {
        const response = await connectionApi.post<{ data: ResponseScript }>('/api/v1/response-scripts', data);
        return response.data.data;
    },
    update: async (id: string, data: ResponseScriptInput): Promise<ResponseScript> => {
        const response = await connectionApi.put<{ data: ResponseScript }>(`/api/v1/response-scripts/${id}`, data);
        return response.data.data;
    },
    delete: async (id: string): Promise<void> => {
        await connectionApi.delete(`/api/v1/response-scripts/${id}`);
    },
};

export const automationApi = {
    listPlaybooks: async () => {
        const response = await connectionApi.get<{ data: ResponsePlaybook[], total: number }>('/api/v1/automation/playbooks');
        return { playbooks: response.data.data, total: response.data.total };
    },
    createPlaybook: async (data: { name: string, description: string, category: string, commands: any[] }) => {
        const response = await connectionApi.post<{ data: ResponsePlaybook }>('/api/v1/automation/playbooks', data);
        return response.data;
    },
    listRules: async () => {
        const response = await connectionApi.get<{ data: AutomationRule[], total: number }>('/api/v1/automation/rules');
        return { rules: response.data.data, total: response.data.total };
    },
    createRule: async (data: Partial<AutomationRule>) => {
        const response = await connectionApi.post<{ data: AutomationRule }>('/api/v1/automation/rules', data);
        return response.data;
    },
    updateRule: async (id: string, data: Partial<AutomationRule>) => {
        const response = await connectionApi.patch<{ data: AutomationRule }>(`/api/v1/automation/rules/${id}`, data);
        return response.data;
    },
    toggleRule: async (id: string, enabled: boolean) => {
        const response = await connectionApi.patch<{ data: AutomationRule }>(`/api/v1/automation/rules/${id}/toggle`, { enabled });
        return response.data;
    },
    deleteRule: async (id: string) => {
        const response = await connectionApi.delete(`/api/v1/automation/rules/${id}`);
        return response.data;
    },
    deletePlaybook: async (id: string) => {
        const response = await connectionApi.delete(`/api/v1/automation/playbooks/${id}`);
        return response.data;
    }
};

// ============================================================================
// Connection Manager Reliability APIs
// ============================================================================

export interface FallbackStoreStats {
    channel_len: number;
    channel_cap: number;
    enqueued_async: number;
    channel_full: number;
    sync_write_used: number;
    sync_write_failed_drop: number;
    db_write_failed: number;
    marshal_failed: number;
}

export interface FallbackStoreHealth {
    enabled: boolean;
    reason?: string;
    stats?: FallbackStoreStats;
}

export interface ReliabilityHealthResponse {
    fallback_store: FallbackStoreHealth;
    meta?: { request_id?: string; timestamp?: string };
}

export interface SignatureStatsResponse {
    max_version: number;
    count: number;
    sources: Record<string, number>;
    meta?: { request_id?: string; timestamp?: string };
}

export interface SignatureHashRow {
    id: number;
    sha256: string;
    name?: string;
    family?: string;
    severity?: string;
    source?: string;
    version: number;
}

export interface SignatureListResponse {
    data: SignatureHashRow[];
    total: number;
    meta?: { request_id?: string; timestamp?: string };
}

export interface BulkSignatureUpdateResult {
    processed: number;
    sent: number;
    queued: number;
    failed: number;
    skipped_offline: number;
    skipped_uninstalled: number;
    include_offline: boolean;
}

export interface ContextPolicy {
    id: number;
    name: string;
    scope_type: 'global' | 'agent' | 'user';
    scope_value: string;
    enabled: boolean;
    user_role_weight: number;
    device_criticality_weight: number;
    network_anomaly_factor: number;
    trusted_networks: string[];
    notes?: string;
    created_at?: string;
    updated_at?: string;
}

export const contextPoliciesApi = {
    list: async () => {
        const response = await connectionApi.get<{ data: ContextPolicy[]; total: number }>('/api/v1/context-policies');
        return response.data;
    },
    create: async (payload: Omit<ContextPolicy, 'id' | 'created_at' | 'updated_at'>) => {
        const response = await connectionApi.post<{ data: ContextPolicy }>('/api/v1/context-policies', payload);
        return response.data.data;
    },
    update: async (id: number, payload: Omit<ContextPolicy, 'id' | 'created_at' | 'updated_at'>) => {
        const response = await connectionApi.patch<{ data: ContextPolicy }>(`/api/v1/context-policies/${id}`, payload);
        return response.data.data;
    },
    remove: async (id: number) => {
        await connectionApi.delete(`/api/v1/context-policies/${id}`);
    },
};

/** CVE / package vulnerability row (connection-manager `vulnerability_findings`). */
export interface VulnerabilityFinding {
    id: string;
    agent_id: string;
    hostname: string;
    criticality?: 'low' | 'medium' | 'high' | 'critical' | string;
    cve: string;
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational' | string;
    cvss?: number;
    status: 'open' | 'acknowledged' | 'resolved' | 'risk_accepted' | string;
    source: string;
    package_name: string;
    installed_version: string;
    fixed_version: string;
    reference_url: string;
    kev_listed: boolean;
    kev_added_date?: string;
    kev_due_date?: string;
    exploit_available: boolean;
    priority_score: number;
    detected_at: string;
    published_at?: string;
    due_at?: string;
    created_at: string;
    updated_at: string;
    correlated_alerts_count?: number;
    active_threat_alerts_count?: number;
    last_correlated_alert_at?: string;
    edr_exploit_signal?: boolean;
}

/** Aggregated stats for dashboard widgets. */
export interface VulnerabilityStats {
    total: number;
    open_count: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
    kev_count: number;
    affected_hosts: number;
    top_packages: { package: string; count: number }[];
    top_hosts: { agent_id: string; hostname: string; count: number }[];
    overdue_count: number;
    exploitable_count: number;
    edr_signal_count?: number;
}

/** Payload row for bulk-importing scanner findings. */
export interface VulnerabilityImportInput {
    agent_id: string;
    cve: string;
    title?: string;
    description?: string;
    severity: string;
    cvss?: number;
    source?: string;
    package_name?: string;
    installed_version?: string;
    fixed_version?: string;
    reference_url?: string;
    published_at?: string;
    due_at?: string;
}

export interface VulnerabilityScannerIngestRequest {
    scanner_type: 'trivy' | 'grype';
    agent_id: string;
    report: Record<string, unknown>;
}

export type VulnerabilityListResponse = {
    data: VulnerabilityFinding[];
    pagination: { total: number; limit: number; offset: number; has_more: boolean };
    meta?: { request_id?: string; timestamp?: string };
};

/** SIEM / analytics export destination (connection-manager `siem_connectors`). */
export interface SiemConnector {
    id: string;
    name: string;
    connector_type: string;
    endpoint_url: string;
    enabled: boolean;
    status: string;
    last_test_at?: string | null;
    last_error?: string | null;
    notes: string;
    metadata?: Record<string, unknown>;
    created_at: string;
    updated_at: string;
}

export const siemConnectorsApi = {
    list: async () => {
        const response = await connectionApi.get<{ data: SiemConnector[] }>('/api/v1/siem/connectors');
        return response.data.data ?? [];
    },
    create: async (body: { name: string; connector_type: string; endpoint_url: string; enabled: boolean; notes?: string }) => {
        const response = await connectionApi.post<{ data: SiemConnector }>('/api/v1/siem/connectors', body);
        return response.data.data;
    },
    patch: async (
        id: string,
        body: Partial<{
            name: string;
            connector_type: string;
            endpoint_url: string;
            enabled: boolean;
            notes: string;
            status: string;
        }>
    ) => {
        const response = await connectionApi.patch<{ data: SiemConnector }>(
            `/api/v1/siem/connectors/${encodeURIComponent(id)}`,
            body
        );
        return response.data.data;
    },
    remove: async (id: string) => {
        await connectionApi.delete(`/api/v1/siem/connectors/${encodeURIComponent(id)}`);
    },
};

export const vulnerabilityApi = {
    listFindings: async (params?: {
        limit?: number;
        offset?: number;
        status?: string;
        severity?: string;
        agent_id?: string;
        search?: string;
        kev_only?: boolean;
        edr_signal_only?: boolean;
    }) => {
        const response = await connectionApi.get<VulnerabilityListResponse>('/api/v1/vuln/findings', { params });
        return response.data;
    },
    getFinding: async (id: string) => {
        const response = await connectionApi.get<{ data: VulnerabilityFinding }>(`/api/v1/vuln/findings/${encodeURIComponent(id)}`);
        return response.data.data;
    },
    patchFindingStatus: async (id: string, status: VulnerabilityFinding['status']) => {
        const response = await connectionApi.patch<{ data: VulnerabilityFinding }>(`/api/v1/vuln/findings/${encodeURIComponent(id)}`, {
            status,
        });
        return response.data.data;
    },
    bulkImport: async (findings: VulnerabilityImportInput[]) => {
        const response = await connectionApi.post<{
            data: { received: number; inserted: number; updated: number; skipped: number };
        }>('/api/v1/vuln/findings/bulk', { findings });
        return response.data.data;
    },
    ingestScannerReport: async (payload: VulnerabilityScannerIngestRequest) => {
        const response = await connectionApi.post<{
            data: {
                scanner_type: string;
                agent_id: string;
                parsed: number;
                inserted: number;
                updated: number;
                skipped: number;
            };
        }>('/api/v1/vuln/scanners/ingest', payload);
        return response.data.data;
    },
    syncKEV: async () => {
        const response = await connectionApi.post<{
            data: { catalog_size: number; findings_updated: number };
        }>('/api/v1/vuln/kev/sync');
        return response.data.data;
    },
    getStats: async () => {
        const response = await connectionApi.get<{ data: VulnerabilityStats }>('/api/v1/vuln/stats');
        return response.data.data;
    },
};

export const reliabilityApi = {
    health: async (): Promise<ReliabilityHealthResponse> => {
        const parsePayload = (data: unknown): ReliabilityHealthResponse => {
            const payload = data as ReliabilityHealthResponse;
            if (!payload || typeof payload !== 'object' || !('fallback_store' in payload)) {
                throw new Error('Invalid reliability payload shape (possible proxy misroute)');
            }
            return payload;
        };

        try {
            const response = await connectionApi.get<ReliabilityHealthResponse>('/api/v1/reliability');
            return parsePayload(response.data);
        } catch (primaryErr) {
            // Fallback for environments where VITE_CONNECTION_MANAGER_URL points to an
            // unreachable host from browser, while same-origin /api proxy is available.
            const token = localStorage.getItem('auth_token');
            const response = await axios.get<ReliabilityHealthResponse>('/api/v1/reliability', {
                timeout: 10000,
                headers: {
                    'Content-Type': 'application/json',
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                },
            });
            return parsePayload(response.data);
        }
    },
};

export const signaturesApi = {
    stats: async (): Promise<SignatureStatsResponse> => {
        const response = await connectionApi.get<SignatureStatsResponse>('/api/v1/signatures/stats');
        return response.data;
    },
    syncNow: async () => {
        const response = await connectionApi.post<{
            message: string;
            inserted: number;
            stats?: { count: number; max_version: number };
            meta?: { request_id?: string; timestamp?: string };
        }>('/api/v1/signatures/sync');
        return response.data;
    },
    list: async (params?: { since_version?: number; limit?: number }): Promise<SignatureListResponse> => {
        const response = await connectionApi.get<SignatureListResponse>('/api/v1/signatures', { params });
        return response.data;
    },
    pushUpdateAll: async (payload?: { include_offline?: boolean; limit?: number; timeout?: number }) => {
        const response = await connectionApi.post<{
            message: string;
            data: BulkSignatureUpdateResult;
            meta?: { request_id?: string; timestamp?: string };
        }>('/api/v1/signatures/push-update', payload ?? {});
        return response.data;
    },
    syncHistory: async (limit = 50): Promise<{
        data: Array<{ id: number; generation: number; hashes_inserted: number; synced_at: string }>;
        meta?: unknown;
    }> => {
        const response = await connectionApi.get('/api/v1/signatures/sync-history', { params: { limit } });
        return response.data;
    },
};

// ============================================================================
// Audit Logs API
// ============================================================================

export const auditApi = {
    list: async (params?: {
        limit?: number;
        offset?: number;
        user_id?: string;
        action?: string;
        resource_type?: string;
        from?: string;
        to?: string;
    }) => {
        const response = await connectionApi.get<{ data: AuditLog[]; pagination: { total: number } }>(
            '/api/v1/audit/logs',
            { params }
        );
        return response.data;
    },
    get: async (id: string) => {
        const response = await connectionApi.get<AuditLog>(`/api/v1/audit/logs/${id}`);
        return response.data;
    },
};

// ============================================================================
// Security Events API
// ============================================================================

export interface SecurityEvent {
    id: string;
    event_type: string;
    severity: 'info' | 'warning' | 'critical';
    actor_id?: string;
    actor_name: string;
    target_id?: string;
    target_type: string;
    ip_address: string;
    user_agent: string;
    description: string;
    metadata?: Record<string, unknown>;
    created_at: string;
}

export interface SecurityEventSummaryItem {
    event_type: string;
    severity: string;
    count: number;
}

export const securityEventsApi = {
    getEvents: async (params?: {
        event_type?: string;
        severity?: string;
        actor_id?: string;
        from?: string;
        to?: string;
        limit?: number;
        offset?: number;
    }) => {
        const response = await connectionApi.get<{
            data: SecurityEvent[];
            meta: { count: number; limit: number; offset: number };
        }>('/api/v1/security/events', { params });
        return response.data;
    },
    getSummary: async () => {
        const response = await connectionApi.get<{
            data: SecurityEventSummaryItem[];
            meta: { window: string };
        }>('/api/v1/security/events/summary');
        return response.data;
    },
};

// ============================================================================
// Enrollment Tokens API
// ============================================================================

export interface EnrollmentToken {
    id: string;
    token: string;
    description: string;
    is_active: boolean;
    expires_at: string | null;
    use_count: number;
    max_uses: number | null;
    created_by: string;
    created_at: string;
    revoked_at: string | null;
}

export const enrollmentTokensApi = {
    list: async () => {
        const response = await connectionApi.get<{ data: EnrollmentToken[] }>(
            '/api/v1/enrollment-tokens'
        );
        return response.data;
    },
    generate: async (data: { description: string; expires_in_hours?: number; max_uses?: number }) => {
        const response = await connectionApi.post<EnrollmentToken>(
            '/api/v1/enrollment-tokens',
            data
        );
        return response.data;
    },
    revoke: async (id: string) => {
        const response = await connectionApi.post(`/api/v1/enrollment-tokens/${id}/revoke`);
        return response.data;
    },
};

// ============================================================================
// Agent Build API (Dashboard-driven compilation)
// ============================================================================

export interface AgentBuildRequest {
    server_ip?: string;
    server_domain?: string;
    server_port?: string;
    token_id: string;
    skip_config: boolean;
    install_sysmon?: boolean;
}

/** Response from POST /api/v1/agent/build (new JSON format). */
export interface AgentBuildResponse {
    /** Plaintext enrollment token — shown ONCE. The admin must save it securely. */
    token: string;
    /** UUID baked into the binary (EmbeddedBuildID). */
    build_id: string;
    /** SHA-256 hex of the compiled binary. */
    sha256: string;
    /** Binary size in bytes. */
    size: number;
    /** Build duration string (e.g. "12.3s"). */
    duration: string;
    /** Base64-encoded .exe binary. */
    binary: string;
}

export const agentBuildApi = {
    /**
     * Build the agent binary. Returns JSON with the one-time token,
     * build metadata, and the base64-encoded .exe.
     */
    build: async (data: AgentBuildRequest): Promise<{
        blob: Blob;
        sha256: string;
        filename: string;
        token: string;
        build_id: string;
        size: number;
        duration: string;
    }> => {
        const response = await connectionApi.post<AgentBuildResponse>('/api/v1/agent/build', data, {
            timeout: 600_000, // 10 minutes — generous for cross-compilation
        });
        const r = response.data;
        // Decode base64 binary to Blob
        const binaryStr = atob(r.binary);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
            bytes[i] = binaryStr.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: 'application/octet-stream' });
        return {
            blob,
            sha256: r.sha256,
            filename: 'edr-agent.exe',
            token: r.token,
            build_id: r.build_id,
            size: r.size,
            duration: r.duration,
        };
    },

    /**
     * List only valid (usable) enrollment tokens.
     * Filters out revoked, expired, and maxed-out tokens.
     */
    listValidTokens: async (): Promise<EnrollmentToken[]> => {
        const result = await enrollmentTokensApi.list();
        const tokens = result.data ?? result;
        const now = new Date();
        return (tokens as EnrollmentToken[]).filter(t => {
            if (!t.is_active) return false;
            if (t.expires_at && new Date(t.expires_at) < now) return false;
            if (t.max_uses !== null && t.use_count >= t.max_uses) return false;
            return true;
        });
    },
};

// ============================================================================
// Agent Packages API (Patch / Upgrade)
// ============================================================================

export interface CreateAgentPackageRequest {
    server_ip?: string;
    server_domain?: string;
    server_port?: string;
    /** Base URL (scheme://host[:port]) the agent can reach; defaults to browser origin in UI */
    public_api_base_url?: string;
    /** Deprecated for upgrade flow; ignored by backend. */
    token_id?: string;
    skip_config: boolean;
    install_sysmon?: boolean;
    expires_in_seconds?: number;
    /**
     * Bind the download link (and mTLS verification) to a specific agent.
     * Required for in-place upgrades; download will be rejected for any
     * other agent identity and the package is automatically revoked after
     * the first successful download or upon expiry.
     */
    agent_id?: string;
}

export interface CreateAgentPackageResponse {
    package_id: string;
    sha256: string;
    filename: string;
    expires_at: string;
    url: string;
}

export const agentPackagesApi = {
    create: async (data: CreateAgentPackageRequest) => {
        const response = await connectionApi.post<CreateAgentPackageResponse>('/api/v1/agent/packages', data, {
            timeout: 600_000,
        });
        return response.data;
    },
};

// ============================================================================
// WebSocket for real-time alerts
// ============================================================================

export function createAlertStream(
    onMessage: (alert: Alert) => void,
    filters?: { severity?: string[]; agent_id?: string; rule_id?: string }
) {
    // Build WebSocket URL
    // VITE_WS_URL is the base (e.g. ws://host:port) — always append the stream path.
    // If not set, derive from sigmaEngineUrl or fall back to same-origin.
    let wsBase = config.wsUrl;
    let wsUrl: string;
    if (wsBase) {
        // Strip any trailing slash then add the stream endpoint
        wsUrl = wsBase.replace(/\/$/, '') + '/api/v1/sigma/alerts/stream';
    } else if (config.sigmaEngineUrl) {
        // Local dev: replace http(s) with ws(s)
        wsUrl = config.sigmaEngineUrl.replace(/^http/, 'ws') + '/api/v1/sigma/alerts/stream';
    } else {
        // Docker/nginx mode: derive from current page origin
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        wsUrl = `${proto}//${window.location.host}/api/v1/sigma/alerts/stream`;
    }

    // Append JWT as a query parameter — the browser WebSocket API cannot send
    // custom headers (no Authorization header support), so the server's
    // CombinedAuthMiddleware accepts ?token= as a fallback for WS connections.
    const jwt = localStorage.getItem('auth_token');
    if (jwt) {
        wsUrl += `?token=${encodeURIComponent(jwt)}`;
    }

    let ws: WebSocket;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 5;
    let reconnectTimeout: ReturnType<typeof setTimeout>;
    let pingInterval: ReturnType<typeof setInterval>;

    const connect = () => {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            reconnectAttempts = 0;
            console.log('WebSocket connected');

            // Subscribe with filters
            if (filters) {
                ws.send(JSON.stringify({ type: 'subscribe', filters }));
            }

            // Start heartbeat
            pingInterval = setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'ping' }));
                }
            }, 30000);
        };

        ws.onmessage = (event) => {
            // The engine sends one JSON document per frame; older engines
            // newline-joined bursts into one frame. JSON never contains a raw
            // newline, so splitting is safe and handles both.
            const frames = String(event.data).split('\n');
            for (const frame of frames) {
                if (!frame.trim()) continue;
                try {
                    const message = JSON.parse(frame);
                    if (message.type === 'alert') {
                        onMessage(message.data);
                    }
                } catch (e) {
                    console.error('Failed to parse WebSocket message:', e);
                }
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        ws.onclose = (event) => {
            console.log('WebSocket disconnected', { code: event.code, reason: event.reason, wasClean: event.wasClean });
            clearInterval(pingInterval);

            // Only give up permanently if there is no auth token — in that case
            // reconnecting cannot succeed (auth is structurally impossible).
            // Previously we treated any code-1006 first-attempt as "404 not implemented"
            // but that was wrong: 1006 (abnormal closure) also fires for transient
            // failures (container starting up, nginx not yet ready, auth rejection).
            // With the ?token= fix in place we should always retry if we have a token.
            const hasToken = !!localStorage.getItem('auth_token');
            if (!hasToken) {
                console.warn('WebSocket: no auth token found — real-time alerts disabled until login');
                return;
            }

            // Auto-reconnect with exponential backoff (cap at ~32 s)
            if (reconnectAttempts < maxReconnectAttempts) {
                const delay = Math.min(Math.pow(2, reconnectAttempts) * 1000, 32000);
                reconnectTimeout = setTimeout(() => {
                    reconnectAttempts++;
                    console.log(`WebSocket reconnecting… attempt ${reconnectAttempts}/${maxReconnectAttempts}`);
                    connect();
                }, delay);
            } else {
                console.warn('WebSocket: max reconnect attempts reached — real-time alerts paused');
            }
        };
    };

    connect();

    // Return cleanup function
    return {
        close: () => {
            clearTimeout(reconnectTimeout);
            clearInterval(pingInterval);
            ws.close();
        },
        getState: () => ws.readyState,
    };
}

// ============================================================================
// Auth API
// ============================================================================

export const authApi = {
    /**
     * Step 1 of login. When the account has MFA enabled the response will
     * carry `mfa_required: true` and `mfa_challenge`, and NO token will be
     * stored — the caller must then call `verifyMfa()` to finish signing in.
     */
    login: async (username: string, password: string): Promise<LoginResult> => {
        const response = await connectionApi.post<LoginResult>(
            '/api/v1/auth/login',
            { username, password },
        );
        if (response.data.access_token) {
            localStorage.setItem('auth_token', response.data.access_token);
            localStorage.setItem('user', JSON.stringify(response.data.user));
        }
        return response.data;
    },

    /**
     * Step 2 of login: consume the MFA challenge. On success the token pair
     * is persisted and the user is fully signed in.
     */
    verifyMfa: async (challengeId: string, code: string): Promise<LoginResult> => {
        const response = await connectionApi.post<LoginResult>(
            '/api/v1/auth/login/mfa',
            { challenge_id: challengeId, code },
        );
        if (response.data.access_token) {
            localStorage.setItem('auth_token', response.data.access_token);
            localStorage.setItem('user', JSON.stringify(response.data.user));
        }
        return response.data;
    },
    logout: async () => {
        try {
            await connectionApi.post('/api/v1/auth/logout');
        } catch (e) {
            console.warn('Backend logout failed or already disconnected', e);
        }
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user');
    },
    /** Live profile from connection-manager (`GET /api/v1/auth/me`). */
    fetchMe: async () => {
        const response = await connectionApi.get<{ data: User }>('/api/v1/auth/me');
        return response.data.data;
    },
    getCurrentUser: (): User | null => {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    },
    isAuthenticated: () => !!localStorage.getItem('auth_token'),
    hasRole: (roles: string[]) => {
        const user = authApi.getCurrentUser();
        return user ? roles.includes(user.role) : false;
    },

    // ── Permission helpers ───────────────────────────────────────────────
    // These mirror the RBAC matrix from migration 015_create_roles_permissions.
    // The backend enforces permissions server-side via RequirePermission middleware;
    // these helpers are for UI visibility (hiding buttons, nav items, routes).
    //
    // Permission Matrix (from DB seed):
    //   admin:      ALL permissions
    //   security:   alerts:*, endpoints:*, rules:r/w, responses:*, settings:r, users:r, roles:r, audit:r, tokens:r, agents:r/w
    //   analyst:    alerts:r/w, endpoints:r, rules:r, responses:r/execute, settings:r, tokens:r
    //   operations: alerts:r, endpoints:r/manage, responses:r, settings:r, tokens:r
    //   viewer:     alerts:r, endpoints:r, rules:r, settings:r, tokens:r

    // Alerts: view alerts page and details
    canViewAlerts: () => authApi.hasRole(['admin', 'security', 'analyst', 'operations', 'viewer']),
    // Alerts: update status, assign, add notes
    canWriteAlerts: () => authApi.hasRole(['admin', 'security', 'analyst']),
    // Alerts: delete alerts
    canDeleteAlerts: () => authApi.hasRole(['admin', 'security']),

    // Endpoints: view endpoint list
    canViewEndpoints: () => authApi.hasRole(['admin', 'security', 'analyst', 'operations', 'viewer']),
    // Endpoints: update tags, delete
    canManageEndpoints: () => authApi.hasRole(['admin', 'security', 'operations']),
    // Endpoints: network isolation
    canIsolateEndpoints: () => authApi.hasRole(['admin', 'security']),

    // Rules: view detection rules
    canViewRules: () => authApi.hasRole(['admin', 'security', 'analyst', 'viewer']),
    // Rules: create/edit rules
    canWriteRules: () => authApi.hasRole(['admin', 'security']),

    // Responses (Action Center): view command history
    canViewResponses: () => authApi.hasRole(['admin', 'security', 'analyst', 'operations']),
    // Responses: execute remote commands
    canExecuteCommands: () => authApi.hasRole(['admin', 'security', 'analyst']),

    // Settings: view
    canViewSettings: () => authApi.hasRole(['admin', 'security', 'analyst', 'operations', 'viewer']),
    // Settings: modify
    canWriteSettings: () => authApi.hasRole(['admin']),

    // Users: view user accounts
    canViewUsers: () => authApi.hasRole(['admin', 'security']),
    // Users: create/update
    canManageUsers: () => authApi.hasRole(['admin']),

    // Roles: view roles and permissions
    canViewRoles: () => authApi.hasRole(['admin', 'security']),
    /** Assign permissions to roles (`roles:write`) — typically admin only in seed. */
    canManageRoles: () => authApi.hasRole(['admin']),

    // Audit: view audit logs
    canViewAuditLogs: () => authApi.hasRole(['admin', 'security']),

    // Tokens: view enrollment tokens
    canViewTokens: () => authApi.hasRole(['admin', 'security', 'analyst', 'operations', 'viewer']),
    // Tokens: generate/revoke
    canManageTokens: () => authApi.hasRole(['admin', 'security']),

    // Agents: view deployment page
    canViewAgentDeploy: () => authApi.hasRole(['admin', 'security', 'operations']),
    // Agents: build and download
    canBuildAgent: () => authApi.hasRole(['admin', 'security']),

    // Endpoints: push filter policy to agent (equivalent to executing a C2 command)
    canPushPolicy: () => authApi.hasRole(['admin', 'security', 'analyst']),

    // Tokens: copy raw token value (sensitive — only roles that can manage tokens)
    canCopyTokens: () => authApi.hasRole(['admin', 'security']),

    // Stats: export data (CSV/PDF/JSON)
    canExportStats: () => authApi.hasRole(['admin', 'security', 'analyst']),
};

// ============================================================================
// Command History Types (Action Center)
// ============================================================================

export interface CommandListItem extends Command {
    agent_hostname: string;
    issued_by_user: string;
}

export interface CommandStats {
    total: number;
    pending: number;
    sent: number;
    completed: number;
    failed: number;
    timeout: number;
    cancelled: number;
}

// ============================================================================
// Commands API (Action Center)
// ============================================================================

export const commandsApi = {
    list: async (params?: {
        limit?: number;
        offset?: number;
        status?: string;
        command_type?: string;
        agent_id?: string;
        sort_by?: string;
        sort_order?: string;
    }) => {
        const response = await connectionApi.get<{
            data: CommandListItem[];
            pagination: { total: number; limit: number; offset: number; has_more: boolean };
        }>('/api/v1/commands', { params });
        return response.data;
    },
    get: async (commandId: string) => {
        const response = await connectionApi.get<{ data: CommandListItem }>(`/api/v1/commands/${commandId}`);
        return response.data.data;
    },
    stats: async () => {
        const response = await connectionApi.get<{ data: CommandStats }>('/api/v1/commands/stats');
        return response.data.data;
    },
};

// ============================================================================
// Users API (User Management)
// ============================================================================

export const usersApi = {
    list: async (params?: {
        limit?: number;
        offset?: number;
        role?: string;
        status?: string;
        search?: string;
    }) => {
        const response = await connectionApi.get<UsersListResponse>('/api/v1/users', { params });
        return response.data;
    },
    get: async (id: string) => {
        const response = await connectionApi.get<{ data: User }>(`/api/v1/users/${id}`);
        return response.data.data;
    },
    create: async (data: {
        username: string;
        email: string;
        password: string;
        full_name: string;
        role: string;
        mfa_enabled?: boolean;
    }) => {
        const response = await connectionApi.post<{ data: User }>('/api/v1/users', data);
        return response.data.data;
    },
    update: async (id: string, data: {
        email?: string;
        full_name?: string;
        role?: string;
        status?: string;
        mfa_enabled?: boolean;
    }) => {
        const response = await connectionApi.patch<{ data: User }>(`/api/v1/users/${id}`, data);
        return response.data.data;
    },
    delete: async (id: string) => {
        await connectionApi.delete(`/api/v1/users/${id}`);
    },
    changePassword: async (id: string, oldPassword: string, newPassword: string) => {
        await connectionApi.post(`/api/v1/users/${id}/password`, {
            old_password: oldPassword,
            new_password: newPassword,
        });
    },
};

// ============================================================================
// Roles & Permissions API (RBAC Management)
// ============================================================================

export const rolesApi = {
    list: async () => {
        const response = await connectionApi.get<{ data: Role[] }>('/api/v1/roles');
        return response.data.data;
    },
    /** Loads roles and permissions together; includes `meta.request_id` from the roles response when present. */
    loadMatrix: async (): Promise<RolesPermissionsMatrixPayload> => {
        const [rolesRes, permsRes] = await Promise.all([
            connectionApi.get<{ data: Role[]; meta?: { request_id?: string; timestamp?: string } }>('/api/v1/roles'),
            connectionApi.get<{ data: Permission[] }>('/api/v1/permissions'),
        ]);
        return {
            roles: rolesRes.data.data,
            permissions: permsRes.data.data,
            meta: rolesRes.data.meta,
        };
    },
    create: async (data: { name: string; description: string; permission_ids: string[] }) => {
        const response = await connectionApi.post<{ data: Role }>('/api/v1/roles', data);
        return response.data.data;
    },
    updatePermissions: async (id: string, permissionIds: string[]) => {
        await connectionApi.patch(`/api/v1/roles/${id}/permissions`, {
            permission_ids: permissionIds,
        });
    },
    delete: async (id: string) => {
        await connectionApi.delete(`/api/v1/roles/${id}`);
    },
    permissions: async () => {
        const response = await connectionApi.get<{ data: Permission[] }>('/api/v1/permissions');
        return response.data.data;
    },
};

// ============================================================================
// Post-Isolation Incident Types
// ============================================================================

export type PlaybookStepStatus = 'pending' | 'running' | 'success' | 'failed' | 'skipped';
export type PlaybookRunStatus = 'running' | 'completed' | 'partial' | 'failed' | 'false_positive';
export type IocVerdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';
export type IocType = 'hash' | 'ip' | 'domain';

export interface PostIsolationAlert {
    id: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    title: string;
    description?: string;
    rule_name?: string;
    status: string;
    risk_score: number;
    detected_at: string;
}

export interface PlaybookRun {
    id: number;
    playbook: string;
    trigger: string;
    status: PlaybookRunStatus;
    started_at: string;
    finished_at?: string;
    summary?: Record<string, unknown>;
}

export interface PlaybookStep {
    id: number;
    step_name: string;
    command_type: string;
    status: PlaybookStepStatus;
    command_id?: string;
    started_at?: string;
    finished_at?: string;
    error?: string;
}

export interface TriageSnapshot {
    id: number;
    kind: string;
    payload: Record<string, unknown>;
    created_at: string;
}

export interface IocEnrichment {
    id: number;
    ioc_type: IocType;
    ioc_value: string;
    provider: string;
    verdict: IocVerdict;
    score: number;
    fetched_at: string;
}

export interface IncidentData {
    agent_id: string;
    is_isolated: boolean;
    run?: PlaybookRun;
    steps: PlaybookStep[];
    snapshots: TriageSnapshot[];
    iocs: IocEnrichment[];
}

export interface ProcessInfo {
    pid: number;
    ppid: number;
    name: string;
    path?: string;
    sha256?: string;
    signed: boolean;
    net_conns?: string[];
}

export interface PersistenceItem {
    type: string;
    location: string;
    value: string;
    sha256?: string;
}

export interface LsassAccessEvent {
    time_created: string;
    event_id: string;
    actor_pid: string;
    actor_path?: string;
    access_mask?: string;
}

export interface TimelineFile {
    path: string;
    mtime: string;
    size_bytes: number;
    sha256?: string;
}

export interface NetConn {
    proto: string;
    local_addr: string;
    remote_addr: string;
    state: string;
    pid?: string;
}

export interface DnsEntry {
    name: string;
    type: string;
    answer?: string;
}

export interface AgentIntegrity {
    exe_path: string;
    exe_sha256: string;
    signature_valid: boolean;
    etw_healthy: boolean;
    checked_at: string;
}

// ============================================================================
// Post-Isolation Incident API
// ============================================================================

export const incidentApi = {
    getSummary: async (agentId: string): Promise<IncidentData> => {
        const response = await connectionApi.get<{ data: IncidentData }>(
            `/api/v1/agents/${agentId}/incident`
        );
        return response.data.data;
    },

    listRuns: async (agentId: string, limit = 20): Promise<PlaybookRun[]> => {
        const response = await connectionApi.get<{ data: PlaybookRun[] }>(
            `/api/v1/agents/${agentId}/playbook-runs`,
            { params: { limit } }
        );
        return response.data.data;
    },

    getRunSteps: async (runId: number): Promise<PlaybookStep[]> => {
        const response = await connectionApi.get<{ data: { steps: PlaybookStep[] } }>(
            `/api/v1/playbook-runs/${runId}`
        );
        return response.data.data.steps;
    },

    listIocs: async (agentId: string, limit = 100): Promise<IocEnrichment[]> => {
        const response = await connectionApi.get<{ data: IocEnrichment[] }>(
            `/api/v1/agents/${agentId}/iocs`,
            { params: { limit } }
        );
        return response.data.data;
    },

    listSnapshots: async (agentId: string, kind?: string): Promise<TriageSnapshot[]> => {
        const response = await connectionApi.get<{ data: TriageSnapshot[] }>(
            `/api/v1/agents/${agentId}/triage-snapshots`,
            { params: kind ? { kind } : undefined }
        );
        return response.data.data;
    },

    collectMemory: async (agentId: string, outputDir?: string): Promise<{ command_id: string }> => {
        const response = await connectionApi.post<{ command_id: string }>(
            `/api/v1/agents/${agentId}/collect-memory`,
            { confirm: true, output_dir: outputDir ?? '' }
        );
        return response.data;
    },

    listAlerts: async (agentId: string, since?: string, limit = 50): Promise<PostIsolationAlert[]> => {
        const params: Record<string, string | number> = { limit };
        if (since) params.since = since;
        const response = await connectionApi.get<{ data: PostIsolationAlert[] }>(
            `/api/v1/agents/${agentId}/post-isolation-alerts`,
            { params }
        );
        return response.data.data ?? [];
    },

    markFalsePositive: async (agentId: string): Promise<void> => {
        await connectionApi.post(`/api/v1/agents/${agentId}/incident/false-positive`);
    },

    escalate: async (agentId: string): Promise<void> => {
        await connectionApi.post(`/api/v1/agents/${agentId}/incident/escalate`);
    },
};
