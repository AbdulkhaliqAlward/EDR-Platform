import { useQuery } from '@tanstack/react-query';
import React, { useState, useMemo } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
    Cpu, AlertTriangle, TrendingUp, Shield, Search,
    ChevronRight, Activity, Clock, Zap,
    Monitor, RefreshCw
} from 'lucide-react';
import { alertsApi, type EndpointRiskSummary } from '../api/client';
import { SkeletonKPICards, SkeletonChart } from '../components';
import { PaginationControls } from '../components/PaginationControls';
import { useClientPagination } from '../hooks/useClientPagination';

// =========================================================================
// Risk score helpers
// =========================================================================

function getRiskTier(score: number): { label: string; color: string; bg: string; glow: string; barColor: string } {
    if (score >= 90) return {
        label: 'CRITICAL',
        color: 'text-rose-400',
        bg: 'bg-rose-500/10 border-rose-500/30',
        glow: 'shadow-[0_0_20px_rgba(244,63,94,0.25)]',
        barColor: 'bg-rose-500',
    };
    if (score >= 70) return {
        label: 'HIGH',
        color: 'text-orange-400',
        bg: 'bg-orange-500/10 border-orange-500/30',
        glow: 'shadow-[0_0_16px_rgba(249,115,22,0.2)]',
        barColor: 'bg-orange-500',
    };
    if (score >= 40) return {
        label: 'MEDIUM',
        color: 'text-amber-400',
        bg: 'bg-amber-500/10 border-amber-500/30',
        glow: '',
        barColor: 'bg-amber-500',
    };
    return {
        label: 'LOW',
        color: 'text-emerald-400',
        bg: 'bg-emerald-500/10 border-emerald-500/30',
        glow: '',
        barColor: 'bg-emerald-500',
    };
}

function formatRelativeTime(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
}

// =========================================================================
// KPI Card
// =========================================================================

const KPICard = React.memo(function KPICard({
    label, value, sub, icon: Icon, accent
}: {
    label: string; value: string | number; sub?: string;
    icon: typeof Shield; accent: string;
}) {
    return (
        <div className={`relative overflow-hidden rounded-xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur-md p-5 shadow-sm transition-all hover:shadow-md group ${accent}`}>
            <div className="absolute -top-8 -right-8 w-28 h-28 rounded-full blur-3xl opacity-20 group-hover:opacity-35 transition-opacity pointer-events-none bg-current" />
            <div className="relative z-10 flex items-start gap-4">
                <div className={`p-3 rounded-lg ${accent} shrink-0`}>
                    <Icon className="w-5 h-5" />
                </div>
                <div>
                    <p className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1">{label}</p>
                    <p className="text-2xl font-bold text-slate-900 dark:text-white">{value}</p>
                    {sub && <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{sub}</p>}
                </div>
            </div>
        </div>
    );
});

// =========================================================================
// Risk Score Arc (mini radial visual)
// =========================================================================

const RiskArc = React.memo(function RiskArc({ score }: { score: number }) {
    const tier = getRiskTier(score);
    const r = 22;
    const circ = 2 * Math.PI * r;
    const filled = (score / 100) * circ;

    return (
        <div className="relative flex items-center justify-center w-16 h-16 shrink-0">
            <svg className="absolute inset-0 w-16 h-16 -rotate-90" viewBox="0 0 56 56">
                <circle cx="28" cy="28" r={r} stroke="rgba(100,116,139,0.15)" strokeWidth="5" fill="none" />
                <circle
                    cx="28" cy="28" r={r}
                    stroke={score >= 90 ? '#f43f5e' : score >= 70 ? '#f97316' : score >= 40 ? '#f59e0b' : '#10b981'}
                    strokeWidth="5" fill="none"
                    strokeDasharray={`${filled} ${circ}`}
                    strokeLinecap="round"
                    style={{ transition: 'stroke-dasharray 0.6s ease' }}
                />
            </svg>
            <div className="flex flex-col items-center">
                <span className={`text-sm font-bold leading-none ${tier.color}`}>{score}</span>
                <span className="text-[9px] text-slate-500 font-semibold leading-none mt-0.5">/ 100</span>
            </div>
        </div>
    );
});

// =========================================================================
// Endpoint Risk Card
// =========================================================================

type MergedEndpoint = EndpointRiskSummary;

const EndpointRiskCard = React.memo(function EndpointRiskCard({ ep, rank }: { ep: MergedEndpoint; rank: number }) {
    const tier = getRiskTier(ep.peak_risk_score);

    return (
        <Link to={`/management/devices/${encodeURIComponent(ep.agent_id)}`} aria-label={`Open endpoint ${ep.hostname || ep.agent_id}`}
            className={`group relative flex items-center gap-3 sm:gap-4 p-3 sm:p-4 rounded-xl border bg-white dark:bg-slate-800/60 hover:shadow-lg transition-all duration-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ${tier.glow} border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-600`}>
            {/* Rank badge */}
            <div className="hidden sm:flex shrink-0 w-8 h-8 rounded-full bg-slate-100 dark:bg-slate-900/60 items-center justify-center">
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400">{rank}</span>
            </div>

            {/* Risk arc */}
            <RiskArc score={ep.peak_risk_score} />

            {/* Main info */}
            <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                    <Monitor className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    <span className="text-sm font-bold text-slate-900 dark:text-slate-100 truncate">
                        {ep.hostname || ep.agent_id.slice(0, 8) + '…'}
                    </span>
                    <span className={`px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider rounded border ${tier.bg} ${tier.color}`}>
                        {tier.label}
                    </span>
                    {ep.device_criticality && ep.device_criticality !== 'normal' && (
                        <span className="px-1.5 py-0.5 text-[9px] font-semibold rounded-full bg-violet-500/10 text-violet-400 border border-violet-500/20">
                            device:{ep.device_criticality}
                        </span>
                    )}
                    {ep.role_risk && ep.role_risk !== 'normal' && (
                        <span className="px-1.5 py-0.5 text-[9px] font-semibold rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                            role:{ep.role_risk}
                        </span>
                    )}
                    {ep.network_anomaly && ep.network_anomaly !== 'none' && (
                        <span className="px-1.5 py-0.5 text-[9px] font-semibold rounded-full bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20">
                            net:{ep.network_anomaly}
                        </span>
                    )}
                    {ep.agent_status && (
                        <span className={`ml-auto px-1.5 py-0.5 text-[9px] font-semibold rounded-full ${ep.agent_status === 'online'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                            }`}>
                            {ep.agent_status}
                        </span>
                    )}
                </div>

                {/* Stat pills */}
                <div className="flex flex-wrap items-center gap-2 text-xs">
                    {ep.critical_count > 0 && (
                        <span className="flex items-center gap-1 px-2 py-0.5 bg-rose-500/10 text-rose-400 rounded-full border border-rose-500/20 font-semibold">
                            <span className="w-1.5 h-1.5 bg-rose-400 rounded-full animate-pulse" />
                            {ep.critical_count} critical
                        </span>
                    )}
                    {ep.high_count > 0 && (
                        <span className="flex items-center gap-1 px-2 py-0.5 bg-orange-500/10 text-orange-400 rounded-full border border-orange-500/20 font-semibold">
                            {ep.high_count} high
                        </span>
                    )}
                    {(ep.medium_count ?? 0) > 0 && (
                        <span className="flex items-center gap-1 px-2 py-0.5 bg-amber-500/10 text-amber-500 rounded-full border border-amber-500/20 font-semibold">
                            {ep.medium_count} medium
                        </span>
                    )}
                    <span className="flex items-center gap-1 px-2 py-0.5 bg-slate-100 dark:bg-slate-900/60 text-slate-500 rounded-full border border-slate-200 dark:border-slate-700">
                        <AlertTriangle className="w-3 h-3" />
                        {ep.open_count} open
                    </span>
                    <span className="flex items-center gap-1 px-2 py-0.5 bg-slate-100 dark:bg-slate-900/60 text-slate-500 rounded-full border border-slate-200 dark:border-slate-700">
                        <Clock className="w-3 h-3" />
                        {formatRelativeTime(ep.last_alert_at)}
                    </span>
                </div>
            </div>

            {/* Risk bar column */}
            <div className="hidden sm:flex shrink-0 flex-col items-end gap-1.5 w-24">
                <div className="flex items-baseline gap-1">
                    <span className={`text-xs font-bold ${tier.color}`}>avg</span>
                    <span className={`text-sm font-bold ${tier.color}`}>{ep.avg_risk_score.toFixed(0)}</span>
                </div>
                <div className="w-24 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                    <div
                        className={`h-full rounded-full transition-all duration-700 ${tier.barColor}`}
                        style={{ width: `${ep.avg_risk_score}%` }}
                    />
                </div>
                <span className="text-[10px] text-slate-400">{ep.total_alerts} active alert{ep.total_alerts === 1 ? '' : 's'}</span>
            </div>

            <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300 shrink-0 transition-colors" />
        </Link>
    );
});

// =========================================================================
// Distribution bar chart (inline, no recharts dep)
// =========================================================================

function RiskDistributionBar({ summaries }: { summaries: EndpointRiskSummary[] }) {
    const counts = useMemo(() => {
        const c = { critical: 0, high: 0, medium: 0, low: 0 };
        summaries.forEach(s => {
            if (s.peak_risk_score >= 90) c.critical++;
            else if (s.peak_risk_score >= 70) c.high++;
            else if (s.peak_risk_score >= 40) c.medium++;
            else c.low++;
        });
        return c;
    }, [summaries]);

    const total = summaries.length || 1;
    const bars = [
        { label: 'Critical', count: counts.critical, color: 'bg-rose-500', text: 'text-rose-400' },
        { label: 'High', count: counts.high, color: 'bg-orange-500', text: 'text-orange-400' },
        { label: 'Medium', count: counts.medium, color: 'bg-amber-500', text: 'text-amber-400' },
        { label: 'Low / Clean', count: counts.low, color: 'bg-emerald-500', text: 'text-emerald-400' },
    ];

    return (
        <div className="relative bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-6 shadow-sm">
            <h3 className="text-sm font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-4">Risk Distribution</h3>
            <div className="flex h-2 rounded-full overflow-hidden gap-0.5 mb-4">
                {bars.map(b => b.count > 0 && (
                    <div
                        key={b.label}
                        className={`${b.color} rounded-full transition-all duration-700`}
                        style={{ width: `${(b.count / total) * 100}%` }}
                        title={`${b.label}: ${b.count}`}
                    />
                ))}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {bars.map(b => (
                    <div key={b.label} className="text-center">
                        <div className={`text-2xl font-bold ${b.text}`}>{b.count}</div>
                        <div className="text-xs text-slate-500 mt-0.5">{b.label}</div>
                    </div>
                ))}
            </div>
        </div>
    );
}

// =========================================================================
// Empty state
// =========================================================================

function EmptyState() {
    return (
        <div className="flex flex-col items-center justify-center py-24 text-center">
            <div className="w-20 h-20 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-6 shadow-inner">
                <Shield className="w-10 h-10 text-slate-400" />
            </div>
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">No Risk Data Yet</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 max-w-sm">
                Once the Sigma engine detects and scores alerts, each endpoint's risk posture will appear here ranked by peak risk score.
            </p>
        </div>
    );
}

// =========================================================================
// Main Page
// =========================================================================

const WINDOWS = [
    { days: 1, label: '24 hours' },
    { days: 7, label: '7 days' },
    { days: 30, label: '30 days' },
    { days: 90, label: '90 days' },
] as const;
type Tier = 'all' | 'critical' | 'high' | 'medium' | 'low';
const tierOf = (score: number): Exclude<Tier, 'all'> => score >= 90 ? 'critical' : score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';

export default function EndpointRisk() {
    const [params, setParams] = useSearchParams();
    const windowDays = WINDOWS.some(w => String(w.days) === params.get('window')) ? Number(params.get('window')) : 7;
    const tierParam = params.get('tier') as Tier | null;
    const tierFilter: Tier = tierParam && ['critical', 'high', 'medium', 'low'].includes(tierParam) ? tierParam : 'all';
    const [search, setSearch] = useState(params.get('q') || '');
    const setParam = (key: string, value: string | null) => setParams(old => {
        const next = new URLSearchParams(old);
        if (value) next.set(key, value); else next.delete(key);
        next.delete('page');
        return next;
    }, { replace: true });

    // The server returns only existing, non-deleted endpoints with their
    // identity, so no client-side merging (which conflated different machines
    // sharing a hostname) and no capped agent list is needed.
    const { data: riskData, isLoading: riskLoading, isError, refetch, isFetching } = useQuery({
        queryKey: ['endpointRisk', windowDays],
        queryFn: () => alertsApi.endpointRisk(windowDays),
        refetchInterval: 30000,
        refetchIntervalInBackground: false,
    });
    const endpoints: MergedEndpoint[] = useMemo(() => riskData?.data ?? [], [riskData]);

    const term = search.trim().toLowerCase();
    const filtered = useMemo(() => endpoints.filter(ep =>
        (!term || (ep.hostname || '').toLowerCase().includes(term) || ep.agent_id.toLowerCase().includes(term)) &&
        (tierFilter === 'all' || tierOf(ep.peak_risk_score) === tierFilter)), [endpoints, term, tierFilter]);
    const pager = useClientPagination(filtered, { resetKey: `${windowDays}|${tierFilter}|${term}` });

    // KPIs use exactly the same rows as the list.
    const kpis = useMemo(() => ({
        total: endpoints.length,
        critical: endpoints.filter(d => d.peak_risk_score >= 90).length,
        highRisk: endpoints.filter(d => d.peak_risk_score >= 70).length,
        totalOpen: endpoints.reduce((acc, d) => acc + d.open_count, 0),
    }), [endpoints]);

    if (riskLoading) {
        return (
            <div className="space-y-6">
                <div className="h-9 w-72 bg-slate-200 dark:bg-slate-700 rounded animate-pulse" />
                <SkeletonKPICards count={4} />
                <SkeletonChart height={200} />
            </div>
        );
    }

    const tierButtons = [
        { key: 'all', label: 'All' },
        { key: 'critical', label: 'Critical', color: 'text-rose-500' },
        { key: 'high', label: 'High', color: 'text-orange-500' },
        { key: 'medium', label: 'Medium', color: 'text-amber-500' },
        { key: 'low', label: 'Low', color: 'text-emerald-500' },
    ] as const;
    const windowLabel = WINDOWS.find(w => w.days === windowDays)?.label ?? `${windowDays} days`;

    return (
        <div className="relative space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
                <div>
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">SOC</div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">Endpoint Risk</h1>
                </div>
                <div className="flex items-center gap-2">
                    <label className="text-xs text-slate-500 flex items-center gap-2">Activity window
                        <select aria-label="Activity window" value={windowDays} onChange={e => setParam('window', e.target.value)}
                            className="rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1.5 text-sm text-slate-800 dark:text-slate-100">
                            {WINDOWS.map(w => <option key={w.days} value={w.days}>Last {w.label}</option>)}
                        </select>
                    </label>
                    <button onClick={() => refetch()} disabled={isFetching}
                        className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors shadow-sm">
                        <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} /> Refresh
                    </button>
                </div>
            </div>

            {isError && (
                <div role="alert" className="flex items-center gap-2 rounded-xl border border-rose-200 dark:border-rose-900 bg-rose-50 dark:bg-rose-950/30 p-3 text-sm text-rose-700 dark:text-rose-400">
                    <AlertTriangle className="w-4 h-4 shrink-0" /> Unable to load endpoint risk. <button type="button" className="underline" onClick={() => refetch()}>Retry</button>
                </div>
            )}

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <KPICard label="Endpoints at risk" value={kpis.total} sub={`active alerts in ${windowLabel}`} icon={Monitor}
                    accent="bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20" />
                <KPICard label="Critical" value={kpis.critical} sub="peak score ≥ 90" icon={Zap}
                    accent="bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20" />
                <KPICard label="High or above" value={kpis.highRisk} sub="peak score ≥ 70" icon={TrendingUp}
                    accent="bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20" />
                <KPICard label="Untriaged alerts" value={kpis.totalOpen} sub="status open, all listed endpoints" icon={Activity}
                    accent="bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20" />
            </div>

            {endpoints.length > 0 && <RiskDistributionBar summaries={endpoints} />}

            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                <div className="relative w-full sm:w-72">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <input type="search" aria-label="Search endpoints" placeholder="Search by hostname or agent ID…" value={search}
                        onChange={e => { setSearch(e.target.value); setParam('q', e.target.value.trim() || null); }}
                        className="w-full pl-9 pr-4 py-2.5 text-sm bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/50" />
                </div>
                <div className="flex items-center gap-2 flex-wrap" role="group" aria-label="Risk tier">
                    {tierButtons.map(btn => (
                        <button key={btn.key} type="button" aria-pressed={tierFilter === btn.key} onClick={() => setParam('tier', btn.key === 'all' ? null : btn.key)}
                            className={`px-3 py-1.5 text-xs font-semibold rounded-lg border transition-all ${tierFilter === btn.key
                                ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 border-transparent'
                                : 'bg-white dark:bg-slate-800/60 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:border-slate-300'}`}>
                            {'color' in btn && <span className={`${btn.color} mr-1`}>●</span>}{btn.label}
                        </button>
                    ))}
                </div>
                <div className="sm:ml-auto text-xs text-slate-400 font-medium">{filtered.length} endpoint{filtered.length !== 1 ? 's' : ''}</div>
            </div>

            {filtered.length === 0 ? (
                endpoints.length === 0 ? <EmptyState /> : <div className="text-center py-16 text-slate-500 text-sm">No endpoints match your current filters.</div>
            ) : (
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/40 dark:bg-slate-900/30">
                    <div className="space-y-2 p-2">
                        {pager.pageRows.map((ep, i) => (
                            <EndpointRiskCard key={ep.agent_id} ep={ep} rank={(pager.page - 1) * pager.controls.info.limit + i + 1} />
                        ))}
                    </div>
                    <PaginationControls {...pager.controls} label="endpoints" />
                </div>
            )}

            {endpoints.length > 0 && (
                <div className="flex items-center gap-x-6 gap-y-2 justify-center pb-6 text-xs text-slate-500 flex-wrap">
                    <span className="font-semibold uppercase tracking-wider">Score tiers:</span>
                    <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-rose-500" />Critical ≥90</span>
                    <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-orange-500" />High 70–89</span>
                    <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-amber-500" />Medium 40–69</span>
                    <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-emerald-500" />Low &lt;40</span>
                    <span className="flex items-center gap-2"><Cpu className="w-3.5 h-3.5" />Same thresholds as the detection engine's risk levels</span>
                </div>
            )}
        </div>
    );
}
