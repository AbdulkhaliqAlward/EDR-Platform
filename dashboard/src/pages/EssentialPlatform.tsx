import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
    Shield,
    Server,
    Activity,
    Terminal,
    Search,
    Lock,
    RefreshCw,
    AlertCircle,
    CheckCircle2,
    AlertTriangle,
    Radio,
    ArrowUpRight,
} from 'lucide-react';
import { agentsApi, reliabilityApi, type ReliabilityHealthResponse } from '../api/client';
import { formatDateTime } from '../utils/agentDisplay';
import InsightHero from '../components/InsightHero';

function reliabilityHeadline(data: ReliabilityHealthResponse | null): {
    text: string;
    tone: 'good' | 'warn' | 'bad' | 'neutral';
} {
    const fb = data?.fallback_store;
    if (!fb) return { text: 'Reliability payload unavailable', tone: 'neutral' };
    if (!fb.enabled) {
        return { text: fb.reason?.trim() || 'Fallback store disabled', tone: 'neutral' };
    }
    const st = fb.stats;
    if (!st) return { text: 'Fallback active — statistics not yet reported', tone: 'neutral' };
    if (st.sync_write_failed_drop > 0) {
        return { text: `Ingestion drops: ${st.sync_write_failed_drop}`, tone: 'bad' };
    }
    if (st.channel_full > 0 || st.db_write_failed > 0) {
        return { text: 'Pipeline under pressure (queue or DB writes)', tone: 'warn' };
    }
    return { text: 'Ingestion path reporting healthy', tone: 'good' };
}

export default function EssentialPlatform() {
    // user removed as it's not used in UI anymore

    useEffect(() => {
        document.title = 'Essential Platform | MITRAS';
    }, []);

    const snapshotQ = useQuery({
        queryKey: ['essential-platform', 'snapshot'],
        queryFn: async () => {
            const [agentsRes, relRes] = await Promise.allSettled([agentsApi.stats(), reliabilityApi.health()]);
            return {
                agents: agentsRes.status === 'fulfilled' ? agentsRes.value : null,
                agentsErr: agentsRes.status === 'rejected' ? String((agentsRes.reason as Error)?.message || agentsRes.reason) : null,
                reliability: relRes.status === 'fulfilled' ? relRes.value : null,
                reliabilityErr: relRes.status === 'rejected' ? String((relRes.reason as Error)?.message || relRes.reason) : null,
            };
        },
        staleTime: 20_000,
        refetchOnWindowFocus: true,
    });

    const loading = snapshotQ.isLoading;
    const fetching = snapshotQ.isFetching;
    const agents = snapshotQ.data?.agents;
    const rel = snapshotQ.data?.reliability;
    const relHead = reliabilityHeadline(rel ?? null);
    const metaTs = rel?.meta?.timestamp;
    const metaRid = rel?.meta?.request_id;

    const toneRing: Record<typeof relHead.tone, string> = {
        good: 'border-emerald-300/80 dark:border-emerald-500/30 bg-emerald-50/80 dark:bg-emerald-500/10',
        warn: 'border-amber-300/80 dark:border-amber-500/30 bg-amber-50/80 dark:bg-amber-500/10',
        bad: 'border-red-300/80 dark:border-red-500/30 bg-red-50/80 dark:bg-red-500/10',
        neutral: 'border-slate-200 dark:border-slate-600 bg-slate-50/80 dark:bg-slate-800/40',
    };

    const ToneIcon =
        relHead.tone === 'good' ? CheckCircle2 : relHead.tone === 'bad' ? AlertCircle : relHead.tone === 'warn' ? AlertTriangle : Radio;

    return (
        <div className="relative flex flex-col min-h-[calc(100vh-10rem)] w-full p-4 sm:p-6 lg:p-8 bg-slate-200 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900 rounded-2xl border border-slate-300/50 dark:border-slate-700/50">
            <div className="w-full space-y-6 max-w-none mx-auto">
                {/* Live snapshot — API-backed */}
                <section
                    aria-labelledby="live-snapshot-heading"
                    className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/90 dark:bg-slate-900/60 backdrop-blur p-5 sm:p-6 md:p-8 shadow-sm"
                >
                    <InsightHero
                        titleId="live-snapshot-heading"
                        variant="light"
                        accent="cyan"
                        icon={Activity}
                        eyebrow="Essential platform"
                        title="Live deployment snapshot"
                        className="!rounded-xl border-0 shadow-none bg-transparent px-0 py-0 sm:py-1"
                        lead={
                            <>
                                <p>
                                    This dashboard provides a real-time, consolidated view of your active deployment and infrastructure health. Use this snapshot to instantly monitor overall system performance, operational status, and platform reliability before diving into detailed security posture analytics.
                                </p>
                            </>
                        }
                        actions={
                            <button
                                type="button"
                                onClick={() => snapshotQ.refetch()}
                                className="inline-flex items-center gap-2 self-start px-3 py-2 rounded-xl border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                                title="Refresh snapshot"
                            >
                                <RefreshCw className={`w-4 h-4 ${fetching ? 'animate-spin' : ''}`} />
                                Refresh
                            </button>
                        }
                    />

                    {loading ? (
                        <div className="mt-5 flex items-center gap-2 text-slate-500 dark:text-slate-400 text-sm py-8 justify-center">
                            <RefreshCw className="w-5 h-5 animate-spin" /> Loading live metrics…
                        </div>
                    ) : (
                        <div className="mt-5 grid grid-cols-2 lg:grid-cols-4 gap-3">
                            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-950/30 p-4">
                                <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Agents (total)</p>
                                <p className="mt-1 text-2xl font-bold tabular-nums text-slate-900 dark:text-white">
                                    {agents != null ? agents.total : snapshotQ.data?.agentsErr ? '—' : '0'}
                                </p>
                                {snapshotQ.data?.agentsErr && (
                                    <p className="mt-2 text-[11px] text-amber-600 dark:text-amber-400">{snapshotQ.data.agentsErr}</p>
                                )}
                            </div>
                            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-950/30 p-4">
                                <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Online</p>
                                <p className="mt-1 text-2xl font-bold tabular-nums text-emerald-700 dark:text-emerald-400">
                                    {agents?.online ?? '—'}
                                </p>
                            </div>
                            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-950/30 p-4">
                                <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Offline</p>
                                <p className="mt-1 text-2xl font-bold tabular-nums text-slate-700 dark:text-slate-300">
                                    {agents?.offline ?? '—'}
                                </p>
                            </div>
                            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-950/30 p-4">
                                <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Avg health</p>
                                <p className="mt-1 text-2xl font-bold tabular-nums text-slate-900 dark:text-white">
                                    {agents != null ? `${Math.round(agents.avg_health)}%` : '—'}
                                </p>
                            </div>
                        </div>
                    )}

                    {!loading && (
                        <div className={`mt-4 flex flex-col sm:flex-row sm:items-center gap-3 rounded-xl border p-4 ${toneRing[relHead.tone]}`}>
                            <ToneIcon
                                className={`w-5 h-5 shrink-0 ${
                                    relHead.tone === 'good'
                                        ? 'text-emerald-600 dark:text-emerald-400'
                                        : relHead.tone === 'bad'
                                          ? 'text-red-600 dark:text-red-400'
                                          : relHead.tone === 'warn'
                                            ? 'text-amber-600 dark:text-amber-400'
                                            : 'text-slate-500'
                                }`}
                            />
                            <div className="min-w-0 flex-1">
                                <p className="text-sm font-semibold text-slate-900 dark:text-white">Pipeline / fallback store</p>
                                <p className="text-sm text-slate-600 dark:text-slate-300">{relHead.text}</p>
                                {snapshotQ.data?.reliabilityErr && (
                                    <p className="text-xs text-amber-700 dark:text-amber-400 mt-1">{snapshotQ.data.reliabilityErr}</p>
                                )}
                                {(metaTs || metaRid) && (
                                    <p className="text-[11px] text-slate-500 dark:text-slate-500 mt-2 font-mono">
                                        {metaTs && <>Snapshot: {formatDateTime(metaTs)}</>}
                                        {metaTs && metaRid && ' · '}
                                        {metaRid && <>req {metaRid}</>}
                                    </p>
                                )}
                            </div>
                            <Link
                                to="/system/reliability-health"
                                className="inline-flex items-center gap-1 text-sm font-medium text-cyan-700 dark:text-cyan-300 hover:underline shrink-0"
                            >
                                Full reliability view <ArrowUpRight className="w-4 h-4" />
                            </Link>
                        </div>
                    )}
                </section>

                {/* Product overview — static documentation, intentionally not KPI charts */}
                <div className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-6 sm:p-8">
                    <div className="flex items-start gap-3">
                        <div className="p-2 rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300">
                            <Shield className="w-6 h-6" />
                        </div>
                        <div className="flex-1">
                            <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white tracking-tight">
                                Essential Platform
                            </h2>
                            <p className="text-xs font-medium text-slate-500 dark:text-slate-400 mt-2 uppercase tracking-wide">
                                Orientation — not a duplicate of SOC dashboards
                            </p>
                            <p className="text-sm text-slate-600 dark:text-slate-300 mt-3 leading-relaxed">
                                This route is the <strong className="font-medium text-slate-800 dark:text-slate-200">entry narrative</strong>{' '}
                                for what the product is and where to work next. Operational charts, alert triage, and drill-down analytics live
                                under <strong className="font-medium">Dashboards</strong> and <strong className="font-medium">SOC</strong> — not
                                here. The live strip above is only a compact pulse from the same APIs used elsewhere.
                            </p>
                            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3 text-sm text-slate-600 dark:text-slate-300">
                                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-950/20 p-4">
                                    <div className="font-semibold text-slate-900 dark:text-white">What problems it solves</div>
                                    <ul className="mt-2 space-y-1 list-disc list-inside marker:text-cyan-600">
                                        <li>Centralized visibility across endpoints (status, health, alerts).</li>
                                        <li>Faster investigations with searchable telemetry and payload detail.</li>
                                        <li>Auditable response actions through the command pipeline.</li>
                                    </ul>
                                </div>
                                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-950/20 p-4">
                                    <div className="font-semibold text-slate-900 dark:text-white">Key capabilities</div>
                                    <ul className="mt-2 space-y-1 list-disc list-inside marker:text-cyan-600">
                                        <li>Detection and alerting (Sigma rules engine).</li>
                                        <li>Device management and endpoint views.</li>
                                        <li>Remote response (containment, forensics, blocking).</li>
                                        <li>Governance (audit, RBAC, enrollment tokens).</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-5 space-y-2">
                        <div className="flex items-center gap-2 text-slate-800 dark:text-slate-100 font-semibold">
                            <Server className="w-4 h-4 text-cyan-500" /> Core services (architecture)
                        </div>
                        <ul className="text-sm text-slate-600 dark:text-slate-300 space-y-1 list-disc list-inside">
                            <li>
                                <strong className="font-medium">Connection Manager</strong> — agents, commands, audit, events, enrollment.
                            </li>
                            <li>
                                <strong className="font-medium">Sigma Engine</strong> — detections, rules, alert statistics.
                            </li>
                            <li>
                                <strong className="font-medium">Dashboard</strong> — analyst UI you are using now.
                            </li>
                        </ul>
                    </div>

                    <div className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-5 space-y-2">
                        <div className="flex items-center gap-2 text-slate-800 dark:text-slate-100 font-semibold">
                            <Activity className="w-4 h-4 text-cyan-500" /> Typical workflows
                        </div>
                        <ul className="text-sm text-slate-600 dark:text-slate-300 space-y-1 list-disc list-inside">
                            <li>Monitor posture and fleet health in dashboards.</li>
                            <li>Triage alerts and search telemetry from SOC.</li>
                            <li>Execute responses from Command Center when permitted.</li>
                            <li>Adjust policies, tokens, and roles under System / Management.</li>
                        </ul>
                    </div>
                </div>

                <div className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-5 space-y-3">
                    <div className="flex items-center gap-2 text-slate-800 dark:text-slate-100 font-semibold">
                        <Lock className="w-4 h-4 text-cyan-500" /> Permissions
                    </div>
                    <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                        Routes are guarded server-side (e.g. <code className="text-xs font-mono">alerts:read</code>,{' '}
                        <code className="text-xs font-mono">responses:execute</code>). The UI mirrors those checks; missing data above usually
                        means the API returned an error — use Refresh or check Reliability Health.
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Link
                        to="/dashboards/service"
                        className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-5 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors group"
                    >
                        <div className="flex items-center justify-between gap-2 font-semibold text-slate-900 dark:text-white">
                            <span className="flex items-center gap-2">
                                <Shield className="w-4 h-4 text-cyan-500" /> Security Posture
                            </span>
                            <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
                        </div>
                        <p className="text-sm text-slate-600 dark:text-slate-300 mt-2">
                            Operational dashboards — threat pulse, charts, live KPIs (not the overview above).
                        </p>
                    </Link>
                    <Link
                        to="/dashboards/endpoint"
                        className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-5 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors group"
                    >
                        <div className="flex items-center justify-between gap-2 font-semibold text-slate-900 dark:text-white">
                            <span className="flex items-center gap-2">
                                <Activity className="w-4 h-4 text-cyan-500" /> Endpoint summary
                            </span>
                            <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
                        </div>
                        <p className="text-sm text-slate-600 dark:text-slate-300 mt-2">Fleet health, risk context, top endpoints.</p>
                    </Link>
                    <Link
                        to="/events"
                        className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-5 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors group"
                    >
                        <div className="flex items-center justify-between gap-2 font-semibold text-slate-900 dark:text-white">
                            <span className="flex items-center gap-2">
                                <Search className="w-4 h-4 text-cyan-500" /> Telemetry search
                            </span>
                            <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 shrink-0" />
                        </div>
                        <p className="text-sm text-slate-600 dark:text-slate-300 mt-2">Search stored events and open payloads.</p>
                    </Link>
                </div>

                <div className="rounded-2xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-5">
                    <div className="flex items-center justify-between flex-wrap gap-3">
                        <div className="flex items-center gap-2 font-semibold text-slate-900 dark:text-white">
                            <Terminal className="w-4 h-4 text-cyan-500" /> Next steps
                        </div>
                        <div className="flex flex-wrap gap-3 text-sm">
                            <Link className="text-cyan-700 dark:text-cyan-300 hover:underline font-medium" to="/management/devices">
                                Fleet (devices) →
                            </Link>
                            <Link className="text-cyan-700 dark:text-cyan-300 hover:underline font-medium" to="/responses">
                                Command center →
                            </Link>
                            <Link className="text-cyan-700 dark:text-cyan-300 hover:underline font-medium" to="/alerts">
                                Alerts (triage) →
                            </Link>
                            <Link className="text-cyan-700 dark:text-cyan-300 hover:underline font-medium" to="/settings/system">
                                Dashboard preferences →
                            </Link>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
