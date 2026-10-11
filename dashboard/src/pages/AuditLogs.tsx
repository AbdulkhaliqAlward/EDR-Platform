import { useQuery } from '@tanstack/react-query';
import { useState, useEffect, useRef } from 'react';
import {
    Search,
    Download,
    Eye,
    User,
    Activity,
    Check,
    X,
    RefreshCw,
    Shield,
    ShieldOff,
    AlertTriangle,
    Settings,
    ChevronDown,
    Trash2,
    Filter,
    FileSpreadsheet,
    FileCode,
    FileKey,
    KeyRound,
    Lock,
    LogIn,
    LogOut,
    Package,
    Play,
    Server,
    Terminal,
    UserPlus,
    Loader2,
} from 'lucide-react';
import { auditApi, authApi, type AuditLog } from '../api/client';
import { Modal, DateRangePicker, type DateRange, SkeletonTable } from '../components';
import { usePaginatedQuery } from '../hooks/usePaginatedQuery';
import { usePageFilters } from '../hooks/usePageFilters';
import { PaginationControls } from '../components/PaginationControls';
import { collectPages } from '../api/collectPages';

// Every action string the server records (model constants and the dotted
// names used by newer handlers). Unknown actions still render generically.
const ACTION_ICONS: Record<string, { icon: typeof Activity; color: string }> = {
    user_login: { icon: LogIn, color: 'text-green-500' },
    user_logout: { icon: LogOut, color: 'text-slate-500' },
    user_login_failed: { icon: X, color: 'text-red-500' },
    auth_failed: { icon: X, color: 'text-red-500' },
    user_locked: { icon: Lock, color: 'text-red-500' },
    password_changed: { icon: KeyRound, color: 'text-amber-500' },
    user_created: { icon: UserPlus, color: 'text-green-500' },
    user_updated: { icon: RefreshCw, color: 'text-blue-500' },
    user_deleted: { icon: Trash2, color: 'text-red-500' },
    role_created: { icon: Shield, color: 'text-green-500' },
    role_updated: { icon: Shield, color: 'text-blue-500' },
    role_deleted: { icon: Shield, color: 'text-red-500' },
    execute_command: { icon: Terminal, color: 'text-orange-500' },
    isolate_network: { icon: AlertTriangle, color: 'text-red-600' },
    restore_network: { icon: Check, color: 'text-green-600' },
    'playbook.run': { icon: Play, color: 'text-indigo-500' },
    acknowledge_alert: { icon: Check, color: 'text-yellow-500' },
    resolve_alert: { icon: Shield, color: 'text-green-500' },
    alert_deleted: { icon: Trash2, color: 'text-red-500' },
    agent_registered: { icon: Server, color: 'text-green-500' },
    agent_approved: { icon: Server, color: 'text-green-500' },
    agent_suspended: { icon: Server, color: 'text-amber-500' },
    agent_deleted: { icon: Server, color: 'text-red-500' },
    'agent.delete': { icon: Server, color: 'text-red-500' },
    'agent.build': { icon: Package, color: 'text-cyan-500' },
    'agent.uninstall_token.issue': { icon: KeyRound, color: 'text-amber-500' },
    cert_issued: { icon: FileKey, color: 'text-green-500' },
    cert_renewed: { icon: FileKey, color: 'text-blue-500' },
    cert_revoked: { icon: FileKey, color: 'text-red-500' },
    token_created: { icon: KeyRound, color: 'text-green-500' },
    token_revoked: { icon: KeyRound, color: 'text-red-500' },
    token_deleted: { icon: KeyRound, color: 'text-red-500' },
    TOKEN_DELETED: { icon: KeyRound, color: 'text-red-500' },
    'response_script.create': { icon: FileCode, color: 'text-green-500' },
    'response_script.update': { icon: FileCode, color: 'text-blue-500' },
    'response_script.delete': { icon: FileCode, color: 'text-red-500' },
    'detection_exception.created': { icon: ShieldOff, color: 'text-green-500' },
    'detection_exception.updated': { icon: ShieldOff, color: 'text-blue-500' },
    'detection_exception.deleted': { icon: ShieldOff, color: 'text-red-500' },
    policy_created: { icon: Settings, color: 'text-green-500' },
    policy_updated: { icon: Settings, color: 'text-indigo-500' },
    policy_deleted: { icon: Settings, color: 'text-red-500' },
    deploy_policy: { icon: Activity, color: 'text-blue-500' },
    change_settings: { icon: Settings, color: 'text-slate-500' },
    rate_limit_triggered: { icon: AlertTriangle, color: 'text-amber-500' },
};

/** Friendly names for actions whose raw string reads poorly. */
const ACTION_LABELS: Record<string, string> = {
    user_login: 'Sign in',
    user_logout: 'Sign out',
    user_login_failed: 'Failed sign-in',
    auth_failed: 'Authentication failed',
    execute_command: 'Command executed',
    isolate_network: 'Network isolated',
    restore_network: 'Network restored',
    'playbook.run': 'Playbook run',
    'agent.build': 'Agent package built',
    'agent.uninstall_token.issue': 'Uninstall token issued',
    'agent.delete': 'Agent removed',
    TOKEN_DELETED: 'Token deleted',
};

/** Event-name filter: server-side groups (see actionGroupToDB). */
const ACTION_FILTERS: { value: string; label: string }[] = [
    { value: '', label: 'All events' },
    { value: 'login', label: 'Sign in' },
    { value: 'login_failed', label: 'Failed sign-in' },
    { value: 'logout', label: 'Sign out' },
    { value: 'create', label: 'Create (any object)' },
    { value: 'update', label: 'Update (any object)' },
    { value: 'delete', label: 'Delete (any object)' },
    { value: 'response', label: 'Response actions' },
    { value: 'isolation', label: 'Network isolation' },
    { value: 'playbook_run', label: 'Playbook runs' },
    { value: 'alerts', label: 'Alert triage' },
    { value: 'agent_lifecycle', label: 'Agent lifecycle' },
    { value: 'tokens', label: 'Enrollment tokens' },
    { value: 'access', label: 'Users & roles' },
    { value: 'exceptions', label: 'Detection exceptions' },
    { value: 'scripts', label: 'Response scripts' },
    { value: 'policy', label: 'Policies' },
    { value: 'rate_limits', label: 'Rate limiting' },
];

const RESOURCE_BADGES: Record<string, { label: string; color: string }> = {
    user: { label: 'User', color: 'bg-blue-500/10 text-blue-500 border border-blue-500/20' },
    role: { label: 'Role', color: 'bg-blue-500/10 text-blue-400 border border-blue-500/20' },
    agent: { label: 'Agent', color: 'bg-green-500/10 text-green-500 border border-green-500/20' },
    agent_binary: { label: 'Agent package', color: 'bg-green-500/10 text-green-400 border border-green-500/20' },
    certificate: { label: 'Certificate', color: 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20' },
    alert: { label: 'Alert', color: 'bg-orange-500/10 text-orange-500 border border-orange-500/20' },
    incident: { label: 'Incident', color: 'bg-orange-500/10 text-orange-400 border border-orange-500/20' },
    rule: { label: 'Rule', color: 'bg-rose-500/10 text-rose-500 border border-rose-500/20' },
    detection_exception: { label: 'Exception', color: 'bg-rose-500/10 text-rose-400 border border-rose-500/20' },
    policy: { label: 'Policy', color: 'bg-indigo-500/10 text-indigo-500 border border-indigo-500/20' },
    command: { label: 'Command', color: 'bg-cyan-500/10 text-cyan-500 border border-cyan-500/20' },
    playbook_execution: { label: 'Playbook run', color: 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' },
    response_script: { label: 'Script', color: 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' },
    automation_settings: { label: 'Automation', color: 'bg-purple-500/10 text-purple-500 border border-purple-500/20' },
    session: { label: 'Session', color: 'bg-purple-500/10 text-purple-500 border border-purple-500/20' },
    system: { label: 'System', color: 'bg-slate-500/10 text-slate-500 border border-slate-500/20' },
    settings: { label: 'Settings', color: 'bg-slate-500/10 text-slate-400 border border-slate-500/20' },
    token: { label: 'Token', color: 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20' },
};

const RESOURCE_FILTERS = Object.entries(RESOURCE_BADGES)
    .filter(([key]) => key !== 'session' && key !== 'system')
    .map(([value, b]) => ({ value, label: b.label }));

function formatAction(action: string): string {
    if (ACTION_LABELS[action]) return ACTION_LABELS[action];
    const words = action.toLowerCase().split(/[_.]+/).filter(Boolean);
    return words.map((word, i) => (i === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word)).join(' ');
}

function fmtCellValue(v: Record<string, unknown> | undefined | null): string {
    if (!v || typeof v !== 'object' || Object.keys(v).length === 0) return '—';
    try {
        const s = JSON.stringify(v);
        return s.length > 96 ? `${s.slice(0, 93)}…` : s;
    } catch {
        return '—';
    }
}

function affectedObjectLabel(log: AuditLog): string {
    const id = log.resource_id?.trim();
    if (id) return id;
    return log.resource_type || '—';
}

/** Standard log creation timestamp */
function formatLogDate(iso: string): string {
    try {
        const d = new Date(iso);
        return d.toLocaleString(undefined, {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true,
        });
    } catch {
        return iso;
    }
}

function AuditDetailModal({ log, isOpen, onClose }: { log: AuditLog | null; isOpen: boolean; onClose: () => void }) {
    if (!log) return null;

    const iconConfig = ACTION_ICONS[log.action] || { icon: Activity, color: 'text-slate-500' };
    const Icon = iconConfig.icon;

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Audit Log Details" size="lg">
            <div className="space-y-4 animate-slide-up-fade">
                <div className="flex items-center gap-4 p-4 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
                    <div
                        className={`p-3 rounded-lg ${log.result === 'success' ? 'bg-green-100 dark:bg-green-900/30' : 'bg-red-100 dark:bg-red-900/30'}`}
                    >
                        <Icon className={`w-6 h-6 ${iconConfig.color}`} />
                    </div>
                    <div className="flex-1">
                        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">{formatAction(log.action)}</h3>
                        <p className="text-sm text-slate-500">{formatLogDate(log.timestamp)}</p>
                    </div>
                    <span
                        className={`px-2.5 py-1 text-xs font-semibold rounded-md border ${
                            log.result === 'success'
                                ? 'bg-green-500/10 text-green-500 border-green-500/20'
                                : 'bg-rose-500/10 text-rose-500 border-rose-500/20'
                        }`}
                    >
                        {log.result}
                    </span>
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="text-xs text-slate-500 uppercase tracking-wider">User</label>
                        <p className="font-medium text-slate-900 dark:text-white">{log.username}</p>
                        <p className="text-xs text-slate-500">{log.user_id}</p>
                    </div>
                    <div>
                        <label className="text-xs text-slate-500 uppercase tracking-wider">Resource</label>
                        <p className="font-medium text-slate-900 dark:text-white">{log.resource_type}</p>
                        <p className="text-xs text-slate-500 font-mono">{log.resource_id || 'N/A'}</p>
                    </div>
                    <div>
                        <label className="text-xs text-slate-500 uppercase tracking-wider">IP Address</label>
                        <p className="font-mono text-slate-900 dark:text-white">{log.ip_address || 'N/A'}</p>
                    </div>
                    <div>
                        <label className="text-xs text-slate-500 uppercase tracking-wider">Log ID</label>
                        <p className="font-mono text-xs text-slate-600 dark:text-slate-400">{log.id}</p>
                    </div>
                </div>

                {log.user_agent && (
                    <div>
                        <label className="text-xs text-slate-500 uppercase tracking-wider">User Agent</label>
                        <p className="text-sm text-slate-600 dark:text-slate-400 font-mono break-all">{log.user_agent}</p>
                    </div>
                )}

                {log.error_message && (
                    <div className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">
                        <label className="text-xs text-red-600 uppercase tracking-wider">Error</label>
                        <p className="text-sm text-red-700 dark:text-red-300">{log.error_message}</p>
                    </div>
                )}

                {log.details && (
                    <div>
                        <label className="text-xs text-slate-500 uppercase tracking-wider">Extra info</label>
                        <p className="text-sm text-slate-700 dark:text-slate-300">{log.details}</p>
                    </div>
                )}

                {(log.old_value || log.new_value) && (
                    <div className="grid grid-cols-2 gap-4">
                        {log.old_value && (
                            <div>
                                <label className="text-xs text-slate-500 uppercase tracking-wider">Old Value</label>
                                <pre className="mt-1 p-3 text-xs bg-red-50 dark:bg-red-900/20 rounded-lg overflow-auto max-h-40 text-slate-800 dark:text-slate-200">
                                    {JSON.stringify(log.old_value, null, 2)}
                                </pre>
                            </div>
                        )}
                        {log.new_value && (
                            <div>
                                <label className="text-xs text-slate-500 uppercase tracking-wider">New Value</label>
                                <pre className="mt-1 p-3 text-xs bg-green-50 dark:bg-green-900/20 rounded-lg overflow-auto max-h-40 text-slate-800 dark:text-slate-200">
                                    {JSON.stringify(log.new_value, null, 2)}
                                </pre>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </Modal>
    );
}

function exportToCSV(logs: AuditLog[]) {
    const headers = [
        'Log creation date',
        'Staff',
        'Event name',
        'Affected object',
        'Old value',
        'New value',
        'Extra info',
        'Log ID',
        'Result',
        'IP',
    ];
    const rows = logs.map((log) => [
        new Date(log.timestamp).toISOString(),
        log.username,
        log.action,
        affectedObjectLabel(log),
        fmtCellValue(log.old_value),
        fmtCellValue(log.new_value),
        log.details || log.error_message || '',
        log.id,
        log.result,
        log.ip_address || '',
    ]);

    const csv = [headers.join(','), ...rows.map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-logs-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}


export default function AuditLogs() {
    const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
    const canViewAudit = authApi.canViewAuditLogs();
    const [defaults] = useState(() => ({ from: new Date(Date.now()-7*86400000).toISOString(), to: new Date().toISOString() }));
    const pager = usePaginatedQuery<AuditLog>({ name: 'auditLogs', defaults, fetchPage: auditApi.page, enabled: canViewAudit });
    const dateRange = { from: new Date(pager.params.from), to: new Date(pager.params.to) };
    const setDateRange = (range: DateRange) => pager.setFilters({ from: range.from?.toISOString(), to: range.to?.toISOString() });
    const [filters, setFilters] = usePageFilters(pager.params, { action: '', resource_type: '', user_id: '', search: '', staff: '', affected: '', oldVal: '', newVal: '', extra: '', session: '' }, pager.setFilters);
    const [filterPanelOpen, setFilterPanelOpen] = useState(true);
    const [exportMenuOpen, setExportMenuOpen] = useState(false);
    const [exporting, setExporting] = useState(false);
    const [exportError, setExportError] = useState<string | null>(null);
    const exportMenuRef = useRef<HTMLDivElement>(null);


    useEffect(() => {
        const fn = (e: MouseEvent) => {
            if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) setExportMenuOpen(false);
        };
        document.addEventListener('mousedown', fn);
        return () => document.removeEventListener('mousedown', fn);
    }, []);

    const { isLoading, error, isFetching, refetch } = pager;
    const logs = pager.rows;
    const filteredLogs = logs;
    // Export every log matching the current filters (not just this page),
    // walking cursor pages of 100; bounded at 10,000 rows.
    const exportAll = async () => {
        setExporting(true);
        setExportError(null);
        try {
            const base: Record<string, string> = { ...pager.params, limit: '100' };
            delete base.cursor;
            const all = await collectPages((cursor) => auditApi.page(cursor ? { ...base, cursor } : base), 10000);
            exportToCSV(all);
        } catch (e) {
            setExportError((e as Error).message || 'Export failed');
        } finally {
            setExporting(false);
        }
    };
    const detail = useQuery({ queryKey: ['audit-detail', selectedLog?.id], enabled: !!selectedLog,
        queryFn: () => auditApi.get(selectedLog!.id) });

    if (!canViewAudit) {
        return (
            <div className="card text-center py-12">
                <Shield className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">Access Denied</h3>
                <p className="text-slate-500">You don&apos;t have permission to view audit logs.</p>
                <p className="text-sm text-slate-400 mt-2">Required role: Admin or Security</p>
            </div>
        );
    }

    if (error) {
        return (
            <div className="card text-center py-12">
                <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">Failed to Load Audit Logs</h3>
                <p className="text-slate-500">Please try again later.</p><button className="btn btn-secondary" onClick={() => void refetch()}>Retry</button>
            </div>
        );
    }

    return (
        <div
            data-section-id="dashboard-audit-logs-root"
            className="flex flex-col min-h-0 w-full  gap-0"
        >
            {/* Title — compact, above Standard toolbar */}
            <div className="mb-3 shrink-0">
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Audit Logs</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Who did what, to which object, when and from where — sign-ins, response actions, configuration and agent lifecycle.
                    Entries are append-only; open a row for full before/after values.
                </p>
                {exportError && <p role="alert" className="mt-2 text-xs text-rose-600 dark:text-rose-400">{exportError}</p>}
            </div>

            {/* dm-toolbar–like strip */}
            <div
                className="flex flex-wrap items-center gap-1 px-2 py-1.5 rounded-t-lg border border-b-0 shrink-0"
                style={{
                    background: 'var(--xc-nav-bg, #0a043d)',
                    borderColor: 'var(--xc-nav-border, rgba(255,255,255,0.08))',
                }}
            >

                <div className="relative" ref={exportMenuRef}>
                    <button
                        type="button"
                        onClick={() => setExportMenuOpen((o) => !o)}
                        disabled={filteredLogs.length === 0 || exporting}
                        className="inline-flex items-center gap-2 px-2 py-1.5 rounded text-[13px] text-[var(--xc-nav-text,#c0ced6)] hover:bg-[var(--xc-nav-hover,rgb(8,3,49))] disabled:opacity-40 border border-transparent"
                    >
                        {exporting ? <Loader2 className="w-4 h-4 shrink-0 animate-spin" /> : <Download className="w-4 h-4 shrink-0" />}
                        <span>{exporting ? 'Exporting…' : 'Export'}</span>
                        <ChevronDown className={`w-3.5 h-3.5 transition-transform ${exportMenuOpen ? 'rotate-180' : ''}`} />
                    </button>
                    {exportMenuOpen && (
                        <div
                            className="absolute left-0 top-full mt-1 min-w-[200px] rounded-md border py-1 shadow-xl z-50"
                            style={{
                                background: 'var(--xc-nav-bg,#0a043d)',
                                borderColor: 'var(--xc-nav-border,rgba(255,255,255,0.08))',
                            }}
                        >
                            <button
                                type="button"
                                className="w-full text-left px-3 py-2 text-[13px] text-[var(--xc-nav-text,#c0ced6)] hover:bg-[var(--xc-nav-hover,rgb(8,3,49))] flex items-center gap-2"
                                onClick={() => {
                                    setExportMenuOpen(false);
                                    void exportAll();
                                }}
                            >
                                <FileSpreadsheet className="w-4 h-4" />
                                Export all matching to CSV
                            </button>
                        </div>
                    )}
                </div>

                <div className="ml-auto flex items-center gap-1">
                    <button
                        type="button"
                        onClick={() => refetch()}
                        disabled={isFetching}
                        title="Refresh"
                        className="inline-flex items-center justify-center p-2 rounded text-[var(--xc-nav-text,#c0ced6)] hover:bg-[var(--xc-nav-hover,rgb(8,3,49))] disabled:opacity-50"
                    >
                        <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
                    </button>
                    <button
                        type="button"
                        onClick={() => setFilterPanelOpen((v) => !v)}
                        title="Table filter"
                        className={`inline-flex items-center justify-center p-2 rounded ${
                            filterPanelOpen
                                ? 'text-[var(--xc-nav-active,#f19637)] bg-[var(--xc-nav-hover,rgb(8,3,49))]'
                                : 'text-[var(--xc-nav-text,#c0ced6)] hover:bg-[var(--xc-nav-hover,rgb(8,3,49))]'
                        }`}
                    >
                        <Filter className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* Filter panel — Platform “cover” style */}
            {filterPanelOpen && (
                <div className="border border-slate-200 dark:border-slate-700 border-t-0 rounded-b-lg bg-white dark:bg-slate-900/90 p-4 space-y-4 shadow-sm">
                    <div className="flex flex-wrap gap-4 items-end">
                        <DateRangePicker value={dateRange} onChange={setDateRange} label="Log creation date" />
                        <div className="min-w-[140px]">
                            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
                                Staff
                            </label>
                            <input
                                type="text"
                                placeholder="Staff"
                                value={filters.staff}
                                onChange={(e) => setFilters((f) => ({ ...f, staff: e.target.value }))}
                                className="w-full rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm text-slate-900 dark:text-slate-100"
                            />
                        </div>
                        <div>
                            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
                                Event name
                            </label>
                            <select
                                value={filters.action}
                                onChange={(e) => setFilters((f) => ({ ...f, action: e.target.value }))}
                                className="rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm min-w-[180px]"
                            >
                                {ACTION_FILTERS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
                                Resource
                            </label>
                            <select
                                value={filters.resource_type}
                                onChange={(e) => setFilters((f) => ({ ...f, resource_type: e.target.value }))}
                                className="rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm min-w-[140px]"
                            >
                                <option value="">All types</option>
                                {RESOURCE_FILTERS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                            </select>
                        </div>
                        <div className="flex-1 min-w-[200px]">
                            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
                                Search
                            </label>
                            <div className="relative">
                                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                <input
                                    type="text"
                                    placeholder="User, action, object, IP or details…"
                                    value={filters.search}
                                    onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
                                    className="w-full rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 pl-8 pr-2 py-1.5 text-sm"
                                />
                            </div>
                        </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2 border-t border-slate-100 dark:border-slate-800">
                        {(
                            [
                                ['affected', 'Affected object', filters.affected],
                                ['oldVal', 'Old value', filters.oldVal],
                                ['newVal', 'New value', filters.newVal],
                                ['extra', 'Extra info', filters.extra],
                                ['session', 'Log ID', filters.session],
                            ] as const
                        ).map(([key, label, val]) => (
                            <div key={key}>
                                <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">
                                    {label}
                                </label>
                                <input
                                    type="text"
                                    placeholder={label}
                                    value={val}
                                    onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.value }))}
                                    className="w-full rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm"
                                />
                            </div>
                        ))}
                    </div>
                    <p className="text-[11px] text-slate-400">
                        Column filters apply across the selected time range. Value columns show previews; open details for full values. Use date range
                        and server filters for broad queries.
                    </p>
                </div>
            )}

            {/* Table card */}
            <div className="border border-slate-200 dark:border-slate-700 rounded-b-lg overflow-hidden bg-white dark:bg-slate-900/50 flex flex-col min-h-[320px]">
                {isLoading ? (
                    <div className="p-4">
                        <SkeletonTable rows={8} columns={9} />
                    </div>
                ) : filteredLogs.length === 0 ? (
                    <div className="text-center py-16 text-slate-500">
                        <p className="italic text-sm" style={{ color: '#6E6E6E' }}>
                            No results found.
                        </p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm border-collapse items table-striped">
                            <thead>
                                <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80">
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap min-w-[150px]">
                                        Staff
                                    </th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap">
                                        Event name
                                    </th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap min-w-[120px]">
                                        Affected object
                                    </th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap max-w-[140px]">
                                        Old value
                                    </th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap max-w-[140px]">
                                        New value
                                    </th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap max-w-[160px]">
                                        Extra info
                                    </th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap font-mono text-xs">
                                        Log ID
                                    </th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap w-[180px]">
                                        Log creation date
                                    </th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 text-right w-12">
                                        {' '}
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredLogs.map((log, i) => {
                                    const iconConfig = ACTION_ICONS[log.action] || { icon: Activity, color: 'text-slate-500' };
                                    const Icon = iconConfig.icon;
                                    const resourceBadge = RESOURCE_BADGES[log.resource_type] || {
                                        label: log.resource_type,
                                        color: 'bg-slate-500/10 text-slate-500 border border-slate-500/20',
                                    };
                                    return (
                                        <tr
                                            key={log.id}
                                            className={`border-b border-slate-100 dark:border-slate-800/80 ${
                                                i % 2 === 1 ? 'bg-slate-50/80 dark:bg-slate-800/40' : ''
                                            } hover:bg-cyan-500/5 dark:hover:bg-slate-800/60`}
                                        >
                                            <td className="py-2 px-3 align-top">
                                                <div className="flex items-start gap-2 min-w-0">
                                                    <div className="w-7 h-7 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                                                        <User className="w-3.5 h-3.5 text-slate-500" />
                                                    </div>
                                                    <div className="min-w-0">
                                                        <span className="text-cyan-600 dark:text-cyan-400 font-medium truncate block">
                                                            {log.username || 'system'}
                                                        </span>
                                                        {log.ip_address && <span className="block text-[11px] font-mono text-slate-500 truncate" title="Client IP">{log.ip_address}</span>}
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="py-2 px-3 align-top">
                                                <div className="flex items-center gap-2">
                                                    <Icon className={`w-4 h-4 shrink-0 ${iconConfig.color}`} />
                                                    <span className="text-slate-800 dark:text-slate-200" title={log.action}>
                                                        {formatAction(log.action)}
                                                    </span>
                                                    {log.result && log.result !== 'success' && (
                                                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase bg-rose-500/10 text-rose-500 border border-rose-500/20">{log.result}</span>
                                                    )}
                                                </div>
                                            </td>
                                            <td className="py-2 px-3 align-top">
                                                <span
                                                    className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${resourceBadge.color}`}
                                                >
                                                    {resourceBadge.label}
                                                </span>
                                                <p
                                                    className="text-xs text-slate-600 dark:text-slate-400 font-mono mt-1 truncate max-w-[220px]"
                                                    title={log.resource_id || ''}
                                                >
                                                    {affectedObjectLabel(log)}
                                                </p>
                                            </td>
                                            <td className="py-2 px-3 align-top log-text-col text-xs font-mono text-slate-600 dark:text-slate-400 max-w-[200px] break-all">
                                                {fmtCellValue(log.old_value)}
                                            </td>
                                            <td className="py-2 px-3 align-top log-text-col text-xs font-mono text-slate-600 dark:text-slate-400 max-w-[200px] break-all">
                                                {fmtCellValue(log.new_value)}
                                            </td>
                                            <td className="py-2 px-3 align-top text-xs text-slate-600 dark:text-slate-400 max-w-[200px] break-words">
                                                {log.details || log.error_message || '—'}
                                            </td>
                                            <td className="py-2 px-3 align-top font-mono text-[11px] text-slate-500 dark:text-slate-400 max-w-[140px] truncate" title={log.id}>
                                                {log.id}
                                            </td>
                                            <td className="py-2 px-3 align-top whitespace-nowrap text-slate-700 dark:text-slate-300 text-xs">
                                                {formatLogDate(log.timestamp)}
                                            </td>
                                            <td className="py-2 px-3 align-top text-right">
                                                <button
                                                    type="button"
                                                    onClick={() => setSelectedLog(log)}
                                                    className="p-1.5 text-slate-400 hover:text-cyan-500 rounded"
                                                    title="Details"
                                                >
                                                    <Eye className="w-4 h-4" />
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}

                <PaginationControls info={pager.info} page={pager.page} count={logs.length} busy={pager.busy}
                    onNext={pager.next} onFirst={pager.first} onPrevious={pager.previous} onSize={pager.setPageSize} label="log entries" />
            </div>

            {selectedLog && !detail.data ? <Modal isOpen onClose={() => setSelectedLog(null)} title="Audit Log Details">
                {detail.isError ? <p>Could not load details. <button onClick={() => void detail.refetch()}>Retry</button></p> : <p>Loading details…</p>}
            </Modal> : <AuditDetailModal log={detail.data || null} isOpen={!!selectedLog} onClose={() => setSelectedLog(null)} />}
        </div>
    );
}

