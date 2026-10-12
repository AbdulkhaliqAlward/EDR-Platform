import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
    Shield,
    Activity,
    Terminal,
    Search,
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
                        eyebrow="Essential Platform"
                        title="Live deployment snapshot"
                        className="!rounded-xl border-0 shadow-none bg-transparent px-0 py-0 sm:py-1"
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
