import { useQuery } from '@tanstack/react-query';
import { useState, useEffect, useMemo } from 'react';
import {
    Shield,
    AlertTriangle,
    RefreshCw,
    Filter,
    ChevronLeft,
    ChevronRight,
    ShieldAlert,
    Info,
    LogIn,
    LogOut,
    Key,
    UserX,
    Lock,
    Server,
} from 'lucide-react';

import { securityEventsApi, authApi, type SecurityEvent, type SecurityEventSummaryItem } from '../api/client';
import { SkeletonTable } from '../components';

// ─── Event type metadata ────────────────────────────────────────────────────

const EVENT_TYPE_BADGE: Record<string, { label: string; color: string; icon: typeof Shield }> = {
    login_success:              { label: 'Login Success',        color: 'bg-teal-500/10 text-teal-600 dark:text-teal-300 border-teal-500/20',   icon: LogIn },
    login_failed:               { label: 'Login Failed',         color: 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/20', icon: UserX },
    login_locked:               { label: 'Account Locked',       color: 'bg-rose-500/10 text-rose-600 dark:text-rose-300 border-rose-500/20',   icon: Lock },
    logout:                     { label: 'Logout',               color: 'bg-slate-500/10 text-slate-600 dark:text-slate-300 border-slate-500/20', icon: LogOut },
    token_refreshed:            { label: 'Token Refreshed',      color: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-300 border-cyan-500/20',   icon: Key },
    token_reuse_detected:       { label: 'Token Reuse Detected', color: 'bg-rose-500/10 text-rose-600 dark:text-rose-300 border-rose-500/20',   icon: ShieldAlert },
    session_superseded:         { label: 'Session Superseded',   color: 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/20', icon: AlertTriangle },
    agent_enrolled:             { label: 'Agent Enrolled',       color: 'bg-teal-500/10 text-teal-600 dark:text-teal-300 border-teal-500/20',   icon: Server },
    cert_revoked:               { label: 'Cert Revoked',         color: 'bg-rose-500/10 text-rose-600 dark:text-rose-300 border-rose-500/20',   icon: ShieldAlert },
    cert_revocation_attempted:  { label: 'Cert Revoke Attempt',  color: 'bg-rose-500/10 text-rose-600 dark:text-rose-300 border-rose-500/20',   icon: ShieldAlert },
    cert_renewed:               { label: 'Cert Renewed',         color: 'bg-teal-500/10 text-teal-600 dark:text-teal-300 border-teal-500/20',   icon: Shield },
};

const SEVERITY_CONFIG: Record<string, { label: string; dot: string; text: string }> = {
    critical: { label: 'Critical', dot: 'bg-rose-500',  text: 'text-rose-600 dark:text-rose-400' },
    warning:  { label: 'Warning',  dot: 'bg-amber-400', text: 'text-amber-600 dark:text-amber-400' },
    info:     { label: 'Info',     dot: 'bg-teal-400',  text: 'text-teal-600 dark:text-teal-400' },
};

const EVENT_TYPE_OPTIONS = [
    'login_success', 'login_failed', 'login_locked', 'logout',
    'token_refreshed', 'token_reuse_detected', 'session_superseded',
    'agent_enrolled', 'cert_revoked', 'cert_revocation_attempted', 'cert_renewed',
];

const PAGE_SIZE = 50;

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatRelative(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const s = Math.floor(diff / 1000);
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
}

function formatAbsolute(iso: string): string {
    try {
        return new Date(iso).toLocaleString(undefined, {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true,
        });
    } catch { return iso; }
}

function formatEventType(t: string): string {
    return t.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

// ─── Summary widgets ─────────────────────────────────────────────────────────

function SummaryWidgets({ items }: { items: SecurityEventSummaryItem[] }) {
    const total = items.reduce((acc, i) => acc + i.count, 0);
    const critical = items.filter(i => i.severity === 'critical').reduce((acc, i) => acc + i.count, 0);
    const warning  = items.filter(i => i.severity === 'warning').reduce((acc, i) => acc + i.count, 0);

    const topEntry = useMemo(() => {
        const byType = new Map<string, number>();
        for (const i of items) byType.set(i.event_type, (byType.get(i.event_type) ?? 0) + i.count);
        let best = { type: '—', count: 0 };
        byType.forEach((count, type) => { if (count > best.count) best = { type, count }; });
        return best;
    }, [items]);

    const cards = [
        { title: 'Total Events (24h)', value: total,    color: 'border-slate-200 dark:border-slate-700', valueColor: 'text-slate-900 dark:text-white' },
        { title: 'Critical',           value: critical, color: 'border-rose-200 dark:border-rose-800/40', valueColor: 'text-rose-600 dark:text-rose-400' },
        { title: 'Warnings',           value: warning,  color: 'border-amber-200 dark:border-amber-800/40', valueColor: 'text-amber-600 dark:text-amber-400' },
        { title: 'Top Event Type',     value: topEntry.count > 0 ? formatEventType(topEntry.type) : '—', color: 'border-cyan-200 dark:border-cyan-800/40', valueColor: 'text-cyan-700 dark:text-cyan-300' },
    ];

    return (
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 mb-4">
            {cards.map((c) => (
                <div key={c.title} className={`rounded-xl border ${c.color} bg-white dark:bg-slate-800/60 px-4 py-3`}>
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">{c.title}</p>
                    <p className={`text-2xl font-bold font-mono ${c.valueColor} truncate`}>{c.value}</p>
                </div>
            ))}
        </div>
    );
}

// ─── Main page ───────────────────────────────────────────────────────────────

export default function SecurityEvents() {

    const canView = authApi.canViewAuditLogs(); // admin | security

    const [filterPanelOpen, setFilterPanelOpen] = useState(true);
    const [page, setPage] = useState(1);
    const [filters, setFilters] = useState({
        event_type: '',
        severity: '',
        from: '',
        to: '',
    });

    // Reset page on filter change
    useEffect(() => { setPage(1); }, [filters.event_type, filters.severity, filters.from, filters.to]);

    const offset = (page - 1) * PAGE_SIZE;

    const queryParams = useMemo(() => ({
        event_type: filters.event_type || undefined,
        severity:   filters.severity   || undefined,
        from:       filters.from       || undefined,
        to:         filters.to         || undefined,
        limit:  PAGE_SIZE,
        offset,
    }), [filters, offset]);

    const { data, isLoading, error, isFetching, refetch } = useQuery({
        queryKey: ['securityEvents', queryParams],
        queryFn: () => securityEventsApi.getEvents(queryParams),
        enabled: canView,
    });

    const { data: summaryData } = useQuery({
        queryKey: ['securityEventsSummary'],
        queryFn: () => securityEventsApi.getSummary(),
        enabled: canView,
    });

    const events: SecurityEvent[] = data?.data ?? [];
    const total  = data?.meta?.count ?? 0;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const fromIdx = total === 0 ? 0 : offset + 1;
    const toIdx   = Math.min(offset + events.length, total);
    const summaryItems: SecurityEventSummaryItem[] = summaryData?.data ?? [];

    const clearFilters = () => setFilters({ event_type: '', severity: '', from: '', to: '' });
    const hasFilters   = filters.event_type || filters.severity || filters.from || filters.to;

    // ── Access guard ──────────────────────────────────────────────────────────
    if (!canView) {
        return (
            <div className="card text-center py-12">
                <Shield className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">Access Denied</h3>
                <p className="text-slate-500">You don&apos;t have permission to view security events.</p>
                <p className="text-sm text-slate-400 mt-2">Required role: Admin or Security</p>
            </div>
        );
    }

    // ── Error ─────────────────────────────────────────────────────────────────
    if (error) {
        return (
            <div className="card text-center py-12">
                <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">Failed to Load Security Events</h3>
                <p className="text-slate-500 mb-4">Could not reach the backend. Check your connection.</p>
                <button
                    type="button"
                    onClick={() => refetch()}
                    className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-semibold"
                >
                    Retry
                </button>
            </div>
        );
    }

    return (
        <div className="flex flex-col min-h-0 w-full gap-0">
            {/* ── Page header ── */}
            <div className="mb-3 shrink-0">
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Security Events</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Persistent audit trail of authentication, certificate, and session security events
                </p>
            </div>

            {/* ── Summary widgets ── */}
            {summaryItems.length > 0 && <SummaryWidgets items={summaryItems} />}

            {/* ── Toolbar ── */}
            <div
                className="flex flex-wrap items-center gap-1 px-2 py-1.5 rounded-t-lg border border-b-0 shrink-0"
                style={{ background: 'var(--xc-nav-bg, #0a043d)', borderColor: 'var(--xc-nav-border, rgba(255,255,255,0.08))' }}
            >
                <span className="flex items-center gap-1.5 px-2 py-1.5 text-[13px] text-[var(--xc-nav-text,#c0ced6)]">
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                    <span className="hidden sm:inline">Security Audit Trail</span>
                </span>

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
                        onClick={() => setFilterPanelOpen(v => !v)}
                        title="Filters"
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

            {/* ── Filter panel ── */}
            {filterPanelOpen && (
                <div className="border border-slate-200 dark:border-slate-700 border-t-0 rounded-b-none bg-white dark:bg-slate-900/90 p-4 shadow-sm">
                    <div className="flex flex-wrap gap-4 items-end">
                        {/* Event Type */}
                        <div>
                            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">Event Type</label>
                            <select
                                value={filters.event_type}
                                onChange={e => setFilters(f => ({ ...f, event_type: e.target.value }))}
                                className="rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm min-w-[200px] text-slate-900 dark:text-slate-100"
                            >
                                <option value="">All event types</option>
                                {EVENT_TYPE_OPTIONS.map(t => (
                                    <option key={t} value={t}>{formatEventType(t)}</option>
                                ))}
                            </select>
                        </div>

                        {/* Severity */}
                        <div>
                            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">Severity</label>
                            <select
                                value={filters.severity}
                                onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}
                                className="rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm min-w-[140px] text-slate-900 dark:text-slate-100"
                            >
                                <option value="">All severities</option>
                                <option value="info">Info</option>
                                <option value="warning">Warning</option>
                                <option value="critical">Critical</option>
                            </select>
                        </div>

                        {/* From */}
                        <div>
                            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">From</label>
                            <input
                                type="datetime-local"
                                value={filters.from}
                                onChange={e => setFilters(f => ({ ...f, from: e.target.value }))}
                                className="rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm text-slate-900 dark:text-slate-100"
                            />
                        </div>

                        {/* To */}
                        <div>
                            <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-wide mb-1">To</label>
                            <input
                                type="datetime-local"
                                value={filters.to}
                                onChange={e => setFilters(f => ({ ...f, to: e.target.value }))}
                                className="rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm text-slate-900 dark:text-slate-100"
                            />
                        </div>

                        {hasFilters && (
                            <button
                                type="button"
                                onClick={clearFilters}
                                className="px-3 py-1.5 rounded-md border border-slate-200 dark:border-slate-600 text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                            >
                                Clear filters
                            </button>
                        )}
                    </div>
                </div>
            )}

            {/* ── Table card ── */}
            <div className="border border-slate-200 dark:border-slate-700 border-t-0 rounded-b-lg overflow-hidden bg-white dark:bg-slate-900/50 flex flex-col min-h-[320px]">
                {isLoading ? (
                    <div className="p-4">
                        <SkeletonTable rows={8} columns={7} />
                    </div>
                ) : events.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-20 text-slate-500 gap-3">
                        <Shield className="w-10 h-10 text-slate-300 dark:text-slate-600" />
                        <p className="text-sm italic">No security events match your filters.</p>
                        {hasFilters && (
                            <button
                                type="button"
                                onClick={clearFilters}
                                className="text-xs text-cyan-600 dark:text-cyan-400 hover:underline"
                            >
                                Clear filters
                            </button>
                        )}
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm border-collapse">
                            <thead>
                                <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80">
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap w-[140px]">Time</th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap">Event Type</th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap">Severity</th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap">Actor</th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap">Target</th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400 whitespace-nowrap">IP Address</th>
                                    <th className="py-2.5 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate-600 dark:text-slate-400">Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                {events.map((ev, i) => {
                                    const badge    = EVENT_TYPE_BADGE[ev.event_type] ?? { label: formatEventType(ev.event_type), color: 'bg-slate-500/10 text-slate-600 dark:text-slate-300 border-slate-500/20', icon: Info };
                                    const BadgeIcon = badge.icon;
                                    const sev      = SEVERITY_CONFIG[ev.severity] ?? SEVERITY_CONFIG.info;
                                    const actorLabel = ev.actor_name && ev.actor_name !== '' ? ev.actor_name : (ev.actor_id ? ev.actor_id.slice(0, 12) + '…' : '—');
                                    const targetLabel = [ev.target_type, ev.target_id ? ev.target_id.slice(0, 8) + '…' : ''].filter(Boolean).join(' · ') || '—';

                                    return (
                                        <tr
                                            key={ev.id}
                                            className={`border-b border-slate-100 dark:border-slate-800/80 ${i % 2 === 1 ? 'bg-slate-50/80 dark:bg-slate-800/40' : ''} hover:bg-cyan-500/5 dark:hover:bg-slate-800/60`}
                                        >
                                            {/* Time */}
                                            <td className="py-2 px-3 align-top whitespace-nowrap" title={formatAbsolute(ev.created_at)}>
                                                <span className="text-xs text-slate-700 dark:text-slate-300">{formatRelative(ev.created_at)}</span>
                                            </td>

                                            {/* Event Type badge */}
                                            <td className="py-2 px-3 align-top">
                                                <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${badge.color}`}>
                                                    <BadgeIcon className="w-3 h-3 shrink-0" />
                                                    {badge.label}
                                                </span>
                                            </td>

                                            {/* Severity */}
                                            <td className="py-2 px-3 align-top">
                                                <span className={`flex items-center gap-1.5 text-xs font-semibold ${sev.text}`}>
                                                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${sev.dot}`} />
                                                    {sev.label}
                                                </span>
                                            </td>

                                            {/* Actor */}
                                            <td className="py-2 px-3 align-top">
                                                <span className="text-cyan-600 dark:text-cyan-400 font-medium text-xs">{actorLabel}</span>
                                            </td>

                                            {/* Target */}
                                            <td className="py-2 px-3 align-top font-mono text-[11px] text-slate-500 dark:text-slate-400">
                                                {targetLabel}
                                            </td>

                                            {/* IP */}
                                            <td className="py-2 px-3 align-top font-mono text-xs text-slate-600 dark:text-slate-400 whitespace-nowrap">
                                                {ev.ip_address || '—'}
                                            </td>

                                            {/* Description */}
                                            <td className="py-2 px-3 align-top text-xs text-slate-600 dark:text-slate-400 max-w-[320px]">
                                                {ev.description || '—'}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}

                {/* Pagination */}
                {!isLoading && total > 0 && (
                    <div className="flex flex-wrap items-center justify-between gap-3 px-3 py-2 border-t border-slate-200 dark:border-slate-700 bg-slate-50/80 dark:bg-slate-900/60 text-[12px] text-slate-500 shrink-0">
                        <span>
                            Showing <span className="font-semibold text-slate-700 dark:text-slate-300">{fromIdx}–{toIdx}</span> of{' '}
                            <span className="font-semibold text-slate-700 dark:text-slate-300">{total}</span> events
                        </span>
                        <div className="flex items-center gap-2">
                            <button
                                type="button"
                                disabled={page <= 1}
                                onClick={() => setPage(p => Math.max(1, p - 1))}
                                className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-200 dark:border-slate-600 disabled:opacity-40 text-xs"
                            >
                                <ChevronLeft className="w-3.5 h-3.5" /> Previous
                            </button>
                            <span className="tabular-nums">Page {page} / {totalPages}</span>
                            <button
                                type="button"
                                disabled={page >= totalPages}
                                onClick={() => setPage(p => p + 1)}
                                className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-200 dark:border-slate-600 disabled:opacity-40 text-xs"
                            >
                                Next <ChevronRight className="w-3.5 h-3.5" />
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
