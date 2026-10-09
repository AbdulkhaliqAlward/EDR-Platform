import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    Activity,
    AlertTriangle,
    BarChart3,
    Database,
    HardDrive,
    Layers,
    RefreshCw,
    Route,
    Server,
    Wifi,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { reliabilityApi } from '../../api/client';
import axios from 'axios';
import InsightHero from '../../components/InsightHero';

function MetricCard({
    title,
    value,
    subtitle,
    tone = 'neutral',
    icon: Icon,
}: {
    title: string;
    value: string | number;
    subtitle?: string;
    tone?: 'neutral' | 'good' | 'warn' | 'bad';
    icon: React.ElementType;
}) {
    const toneStyles: Record<string, string> = {
        neutral: 'border-slate-200 dark:border-slate-700',
        good: 'border-emerald-200 dark:border-emerald-500/20',
        warn: 'border-amber-200 dark:border-amber-500/20',
        bad: 'border-red-200 dark:border-red-500/20',
    };

    const iconBg: Record<string, string> = {
        neutral: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300',
        good: 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',
        warn: 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400',
        bad: 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400',
    };

    return (
        <div className={`bg-white dark:bg-slate-800 border ${toneStyles[tone]} rounded-xl p-5 shadow-sm`}>
            <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                    <p className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        {title}
                    </p>
                    <p className="mt-2 text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white font-mono tabular-nums break-all">
                        {value}
                    </p>
                    {subtitle && (
                        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                            {subtitle}
                        </p>
                    )}
                </div>
                <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${iconBg[tone]}`}>
                    <Icon size={18} />
                </div>
            </div>
        </div>
    );
}

export default function ReliabilityHealth() {
    useEffect(() => {
        document.title = 'Reliability Health — System | MITRAS';
    }, []);

    const { data, isLoading, isFetching, refetch, error, dataUpdatedAt } = useQuery({
        queryKey: ['reliability-health', 'system'],
        queryFn: reliabilityApi.health,
        refetchInterval: 8_000,
        staleTime: 4_000,
    });

    const errorHint = (() => {
        if (!error || !axios.isAxiosError(error)) return null;
        if (error.response?.status === 401) {
            return 'Authentication failed for reliability endpoint (401). Please log in again.';
        }
        if (error.response?.status === 403) {
            return 'Access denied for reliability endpoint (403).';
        }
        if (error.response?.status === 404) {
            return 'Reliability endpoint not routed (404). Check dashboard proxy.';
        }
        if (error.code === 'ECONNABORTED') {
            return 'Reliability request timed out.';
        }
        return null;
    })();

    const fb = data?.fallback_store;
    const hasFB = !!fb?.enabled && !!fb?.stats && typeof fb.stats.channel_cap === 'number';
    const stats = fb?.stats;

    const channelUsagePct =
        hasFB && stats!.channel_cap > 0 ? Math.round((stats!.channel_len / stats!.channel_cap) * 100) : 0;

    const drops = hasFB ? stats!.sync_write_failed_drop : 0;
    const channelFull = hasFB ? stats!.channel_full : 0;
    const dbWriteFailed = hasFB ? stats!.db_write_failed : 0;

    const headlineTone: 'good' | 'warn' | 'bad' | 'neutral' =
        !hasFB ? 'neutral' : drops > 0 ? 'bad' : channelFull > 0 || dbWriteFailed > 0 ? 'warn' : 'good';

    const metaTs = data?.meta?.timestamp;
    const metaRid = data?.meta?.request_id;

    return (
        <div className="space-y-6 md:space-y-8 w-full min-w-0 animate-slide-up-fade">
            <InsightHero
                
                accent="teal"
                icon={Server}
                eyebrow="Data plane durability"
                title="Reliability health"
                segments={[
                    {
                        heading: 'Live API snapshot',
                        children: (
                            <>
                                Pulled from <code className="text-[11px] text-teal-200/95 bg-white/10 px-1 rounded">GET /api/v1/reliability</code> — event-ingestion{' '}
                                <strong className="text-white">fallback queue &amp; counters</strong> inside connection-manager (async writer, sync escape hatch, DB writes).
                            </>
                        ),
                    },
                    {
                        heading: 'How to read counters',
                        children: (
                            <>
                                Values are <strong className="text-white">cumulative since process start</strong> — useful for backlog pressure and drop diagnosis, not a historical time series.
                            </>
                        ),
                    },
                    {
                        heading: 'Scope boundaries',
                        children: (
                            <>
                                This is <strong className="text-white">not</strong> endpoint fleet health and <strong className="text-white">not</strong> Sigma alert volume — use Devices and Stats for those lenses.
                            </>
                        ),
                    },
                ]}
            />

            <div className="grid gap-3 md:grid-cols-3">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <BarChart3 className="w-4 h-4 text-cyan-500" />
                        vs Service Summary
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/dashboards/service">
                            Service Summary
                        </Link>{' '}
                        mixes commands, Sigma totals, and a <strong>compact</strong> reliability line. Here you get the <strong>full fallback matrix</strong> only.
                    </p>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <Wifi className="w-4 h-4 text-sky-500" />
                        vs Fleet connectivity
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/management/network">
                            Fleet connectivity
                        </Link>{' '}
                        focuses on <strong>agents</strong> (queues per host, IPs). Reliability health is <strong>server-side ingestion plumbing</strong>.
                    </p>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <Layers className="w-4 h-4 text-violet-500" />
                        vs Stats / KPIs
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/stats">
                            Stats
                        </Link>{' '}
                        summarizes alert/rule trends. Reliability health is <strong>ingestion plumbing only</strong> — use it when investigating telemetry loss or backlog pressure.
                    </p>
                </div>
            </div>

            <div className="flex flex-wrap items-start justify-between gap-4">
                <div />
                <button
                    type="button"
                    onClick={() => refetch()}
                    className="flex items-center gap-2 px-3.5 py-2 text-sm rounded-lg font-medium transition-colors bg-slate-900 text-white hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100"
                >
                    <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
                    Refresh
                </button>
            </div>

            {(metaTs || metaRid) && (
                <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/90 dark:bg-slate-900/40 px-4 py-2 text-[11px] font-mono text-slate-600 dark:text-slate-400 flex flex-wrap gap-x-6 gap-y-1">
                    {metaTs && (
                        <span>
                            <span className="text-slate-400 uppercase mr-2">Server time</span>
                            {metaTs}
                        </span>
                    )}
                    {metaRid && (
                        <span>
                            <span className="text-slate-400 uppercase mr-2">Request ID</span>
                            {metaRid}
                        </span>
                    )}
                </div>
            )}

            <div className={`rounded-xl border p-4 text-sm ${
                headlineTone === 'good'
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-800 dark:bg-emerald-500/10 dark:border-emerald-500/20 dark:text-emerald-300'
                    : headlineTone === 'bad'
                        ? 'bg-red-50 border-red-200 text-red-800 dark:bg-red-500/10 dark:border-red-500/20 dark:text-red-300'
                        : headlineTone === 'warn'
                            ? 'bg-amber-50 border-amber-200 text-amber-800 dark:bg-amber-500/10 dark:border-amber-500/20 dark:text-amber-300'
                            : 'bg-slate-100 border-slate-300 text-slate-700 dark:bg-slate-800/60 dark:border-slate-700 dark:text-slate-300'
            }`}>
                <div className="flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
                    <div className="min-w-0 flex-1">
                        <div className="font-semibold">
                            {headlineTone === 'good'
                                ? 'Healthy'
                                : headlineTone === 'bad'
                                    ? 'Data loss risk detected'
                                    : headlineTone === 'warn'
                                        ? 'Degraded — fallback pressure observed'
                                        : 'Telemetry unavailable'}
                        </div>
                        <div className="mt-1 opacity-90">
                            {hasFB
                                ? `Fallback channel ${stats!.channel_len}/${stats!.channel_cap} (${channelUsagePct}%). Drops=${stats!.sync_write_failed_drop}, ChannelFull=${stats!.channel_full}, DBWriteFailed=${stats!.db_write_failed}.`
                                : fb?.reason || 'Fallback store stats not available.'}
                        </div>
                        {hasFB && stats!.channel_cap > 0 && (
                            <div className="mt-3">
                                <div className="flex justify-between text-[11px] font-medium opacity-90 mb-1">
                                    <span>Async queue fill</span>
                                    <span>{channelUsagePct}%</span>
                                </div>
                                <div className="h-2 rounded-full bg-black/10 dark:bg-white/10 overflow-hidden">
                                    <div
                                        className={`h-full rounded-full transition-all duration-300 ${
                                            channelUsagePct >= 90 ? 'bg-red-500' : channelUsagePct >= 60 ? 'bg-amber-400' : 'bg-teal-400'
                                        }`}
                                        style={{ width: `${Math.min(100, channelUsagePct)}%` }}
                                    />
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {isLoading ? (
                <div className="flex items-center justify-center py-16 text-sm text-slate-500 dark:text-slate-400">
                    <div className="w-10 h-10 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin mr-3" />
                    Loading reliability health…
                </div>
            ) : error ? (
                <div className="rounded-xl border border-red-200 bg-red-50 text-red-800 dark:bg-red-500/10 dark:border-red-500/20 dark:text-red-300 p-4 text-sm">
                    Failed to load reliability health. Ensure your session is valid and connection-manager is reachable.
                    {errorHint ? <div className="mt-2 opacity-90">{errorHint}</div> : null}
                </div>
            ) : (
                <>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <MetricCard
                            title="Fallback queue usage"
                            value={hasFB ? `${stats!.channel_len}/${stats!.channel_cap}` : '—'}
                            subtitle={hasFB ? `${channelUsagePct}% used` : 'DB fallback disabled / unavailable'}
                            tone={hasFB && channelUsagePct >= 90 ? 'bad' : hasFB && channelUsagePct >= 60 ? 'warn' : 'neutral'}
                            icon={HardDrive}
                        />
                        <MetricCard
                            title="Channel full events"
                            value={hasFB ? stats!.channel_full : '—'}
                            subtitle="Async queue saturated (sync write attempted)"
                            tone={hasFB && stats!.channel_full > 0 ? 'warn' : 'neutral'}
                            icon={Activity}
                        />
                        <MetricCard
                            title="Sync fallback used"
                            value={hasFB ? stats!.sync_write_used : '—'}
                            subtitle="Batches persisted synchronously (bounded timeout)"
                            tone={hasFB && stats!.sync_write_used > 0 ? 'warn' : 'neutral'}
                            icon={Database}
                        />
                        <MetricCard
                            title="Drops (sync write failed)"
                            value={hasFB ? stats!.sync_write_failed_drop : '—'}
                            subtitle="Definitive loss on fallback path"
                            tone={hasFB && stats!.sync_write_failed_drop > 0 ? 'bad' : 'neutral'}
                            icon={AlertTriangle}
                        />
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <MetricCard
                            title="Async enqueued"
                            value={hasFB ? stats!.enqueued_async : '—'}
                            subtitle="Batches accepted into async fallback writer"
                            tone="neutral"
                            icon={HardDrive}
                        />
                        <MetricCard
                            title="DB write failed"
                            value={hasFB ? stats!.db_write_failed : '—'}
                            subtitle="INSERT failures (async or sync)"
                            tone={hasFB && stats!.db_write_failed > 0 ? 'warn' : 'neutral'}
                            icon={Database}
                        />
                        <MetricCard
                            title="Metadata marshal failed"
                            value={hasFB ? stats!.marshal_failed : '—'}
                            subtitle="Payload metadata serialization failures"
                            tone={hasFB && stats!.marshal_failed > 0 ? 'warn' : 'neutral'}
                            icon={Activity}
                        />
                    </div>
                </>
            )}

            <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/80 dark:bg-slate-800/60 p-4 text-sm text-slate-600 dark:text-slate-300 space-y-2">
                <div className="flex items-center gap-2 font-semibold text-slate-800 dark:text-slate-100">
                    <Route className="w-4 h-4 text-teal-500 shrink-0" />
                    How to read this page
                </div>
                <ul className="list-disc pl-5 space-y-1 text-[13px] leading-relaxed">
                    <li>
                        <strong className="text-slate-800 dark:text-slate-100">Non-zero drops</strong> ({' '}
                        <code className="text-[11px]">sync_write_failed_drop</code>) mean investigate immediately — bounded sync path could not persist.
                    </li>
                    <li>
                        <strong className="text-slate-800 dark:text-slate-100">Channel full</strong> usually tracks bursts or downstream slowdown; sync path absorbs some load until drops rise.
                    </li>
                    <li>
                        Un replayed batches may still exist in Postgres fallback table; replay worker pushes back to Kafka when available (server-side).
                    </li>
                </ul>
            </div>

            <div className="flex flex-wrap gap-x-6 gap-y-1 text-[12px] text-slate-500 dark:text-slate-400">
                <span>
                    Client last refresh:{' '}
                    <span className="font-mono text-slate-700 dark:text-slate-300">
                        {dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleString() : '—'}
                    </span>
                </span>
                <span>Poll interval ~8s · counters cumulative since service start</span>
            </div>
        </div>
    );
}
