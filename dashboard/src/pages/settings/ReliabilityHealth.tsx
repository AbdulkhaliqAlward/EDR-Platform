import { useEffect, useState, type ElementType, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import {
    AlertOctagon, ArrowRight, CheckCircle2, Database, FileWarning, HardDrive, Layers,
    RefreshCw, RotateCcw, Server, ShieldAlert, Workflow,
} from 'lucide-react';

import { reliabilityApi, type FallbackStoreStats } from '../../api/client';
import PageHeader from '../../components/PageHeader';

const POLL_MS = 8_000;
const HISTORY_POINTS = 45; // ~6 minutes of polls kept in memory for the activity chart

type Tone = 'good' | 'info' | 'warn' | 'bad' | 'neutral';

const TONE = {
    good: { text: 'text-emerald-600 dark:text-emerald-400', soft: 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300', ring: 'ring-emerald-500/25', bar: '#10b981', dot: 'bg-emerald-500' },
    info: { text: 'text-cyan-600 dark:text-cyan-400', soft: 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-300', ring: 'ring-cyan-500/25', bar: '#06b6d4', dot: 'bg-cyan-500' },
    warn: { text: 'text-amber-600 dark:text-amber-400', soft: 'bg-amber-500/10 text-amber-700 dark:text-amber-300', ring: 'ring-amber-500/30', bar: '#f59e0b', dot: 'bg-amber-500' },
    bad: { text: 'text-rose-600 dark:text-rose-400', soft: 'bg-rose-500/10 text-rose-700 dark:text-rose-300', ring: 'ring-rose-500/30', bar: '#f43f5e', dot: 'bg-rose-500' },
    neutral: { text: 'text-slate-500 dark:text-slate-400', soft: 'bg-slate-500/10 text-slate-600 dark:text-slate-300', ring: 'ring-slate-500/20', bar: '#94a3b8', dot: 'bg-slate-400' },
} as const;

type Sample = { at: number; stats: FallbackStoreStats };

const fmt = (n: number) => n.toLocaleString();

function deltaOf(history: Sample[], key: keyof FallbackStoreStats): number {
    if (history.length < 2) return 0;
    const d = history[history.length - 1].stats[key] - history[history.length - 2].stats[key];
    return d > 0 ? d : 0; // counters reset on service restart
}

// ── Status model ─────────────────────────────────────────────────────────────
// Ingestion acknowledges a batch only after it is committed to Kafka or to the
// PostgreSQL fallback table. A failed fallback write is therefore NOT data loss
// (the agent resends the batch); only sync_write_failed_drop is definitive loss.
function statusOf(s: FallbackStoreStats | undefined, queuePct: number) {
    if (!s) return { tone: 'neutral' as Tone, label: 'Telemetry unavailable', detail: '' };
    if (s.sync_write_failed_drop > 0) {
        return { tone: 'bad' as Tone, label: 'Data loss recorded', detail: `${fmt(s.sync_write_failed_drop)} batch(es) could not be persisted on any path and were dropped.` };
    }
    if (queuePct >= 90) {
        return { tone: 'bad' as Tone, label: 'Fallback writer saturated', detail: `The async writer queue is ${queuePct}% full.` };
    }
    const failed = s.db_write_failed + s.marshal_failed;
    if (failed > 0) {
        return { tone: 'warn' as Tone, label: 'Fallback writes failing', detail: `${fmt(failed)} fallback write(s) failed. Those batches were not acknowledged, so agents retried them — no loss on this path.` };
    }
    if (s.sync_write_used > 0 || s.enqueued_async > 0 || s.channel_full > 0) {
        return { tone: 'info' as Tone, label: 'Healthy — fallback was used', detail: `Kafka was unavailable at times; ${fmt(s.sync_write_used + s.enqueued_async)} batch(es) were diverted to PostgreSQL for replay.` };
    }
    return { tone: 'good' as Tone, label: 'Healthy', detail: 'All event batches went through the primary Kafka pipeline. No fallback activity.' };
}

// ── Pieces ───────────────────────────────────────────────────────────────────
function Gauge({ pct, tone, len, cap }: { pct: number; tone: Tone; len: number; cap: number }) {
    const r = 46, c = 2 * Math.PI * r;
    const shown = Math.min(100, Math.max(0, pct));
    return (
        <div className="relative w-36 h-36 shrink-0" role="img" aria-label={`Async writer queue ${shown}% full`}>
            <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                <circle cx="60" cy="60" r={r} fill="none" strokeWidth="10" className="stroke-slate-200 dark:stroke-slate-700/70" />
                <circle cx="60" cy="60" r={r} fill="none" strokeWidth="10" strokeLinecap="round" stroke={TONE[tone].bar}
                    strokeDasharray={c} strokeDashoffset={c - (c * shown) / 100} style={{ transition: 'stroke-dashoffset 400ms ease' }} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                <span className="text-2xl font-bold tabular-nums text-slate-900 dark:text-white">{shown}%</span>
                <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">{fmt(len)} / {fmt(cap)}</span>
                <span className="mt-0.5 text-[10px] uppercase tracking-wider text-slate-400">queue</span>
            </div>
        </div>
    );
}

function Stage({ step, icon: Icon, title, value, caption, tone, last }: {
    step: number; icon: ElementType; title: string; value: string; caption: string; tone: Tone; last?: boolean;
}) {
    return (
        <div className="relative flex-1 min-w-0">
            <div className={`h-full rounded-xl border border-slate-200 dark:border-slate-700/70 bg-white dark:bg-slate-900/40 p-4 ring-1 ring-inset ${TONE[tone].ring}`}>
                <div className="flex items-center gap-2.5">
                    <span className={`w-8 h-8 rounded-lg flex items-center justify-center ${TONE[tone].soft}`}><Icon className="w-4 h-4" /></span>
                    <div className="min-w-0">
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Step {step}</div>
                        <div className="text-sm font-semibold text-slate-800 dark:text-slate-100 truncate">{title}</div>
                    </div>
                </div>
                <div className={`mt-3 text-xl font-bold tabular-nums ${TONE[tone].text}`}>{value}</div>
                <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400 leading-snug">{caption}</div>
            </div>
            {!last && (
                <ArrowRight className="hidden lg:block absolute top-1/2 -right-[19px] -translate-y-1/2 w-4 h-4 text-slate-300 dark:text-slate-600 z-10" aria-hidden="true" />
            )}
        </div>
    );
}

function Counter({ icon: Icon, label, value, hint, tone, delta }: {
    icon: ElementType; label: string; value: number | undefined; hint: string; tone: Tone; delta: number;
}) {
    return (
        <div className="group rounded-xl border border-slate-200 dark:border-slate-700/70 bg-white dark:bg-slate-800/60 p-4 transition-shadow hover:shadow-md">
            <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${TONE[tone].dot}`} />
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 truncate">{label}</span>
                </div>
                <Icon className="w-4 h-4 shrink-0 text-slate-300 dark:text-slate-600 group-hover:text-slate-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold tabular-nums text-slate-900 dark:text-white">{value === undefined ? '—' : fmt(value)}</span>
                {delta > 0 && <span className={`text-[11px] font-semibold px-1.5 py-0.5 rounded ${TONE[tone === 'neutral' ? 'info' : tone].soft}`}>+{fmt(delta)}</span>}
            </div>
            <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 leading-snug">{hint}</div>
        </div>
    );
}

function Section({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
    return (
        <section className="rounded-2xl border border-slate-200/90 dark:border-slate-700/70 bg-slate-50/60 dark:bg-slate-900/30 p-4 sm:p-5">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
                <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">{title}</h2>
                {aside}
            </div>
            {children}
        </section>
    );
}

/** Per-poll fallback writes (bars) and failures (rose) over this session. */
function ActivityChart({ history }: { history: Sample[] }) {
    const points = history.slice(1).map((s, i) => {
        const prev = history[i].stats;
        const pos = (n: number) => (n > 0 ? n : 0);
        return {
            at: s.at,
            writes: pos(s.stats.sync_write_used - prev.sync_write_used) + pos(s.stats.enqueued_async - prev.enqueued_async),
            failures: pos(s.stats.db_write_failed - prev.db_write_failed) + pos(s.stats.marshal_failed - prev.marshal_failed) + pos(s.stats.sync_write_failed_drop - prev.sync_write_failed_drop),
        };
    });
    if (points.length < 2) {
        return <div className="h-56 flex items-center justify-center text-xs text-slate-400">Collecting samples… (one every {POLL_MS / 1000}s)</div>;
    }
    const max = Math.max(1, ...points.map((p) => p.writes + p.failures));
    const total = points.reduce((a, p) => a + p.writes, 0);
    const totalFail = points.reduce((a, p) => a + p.failures, 0);
    return (
        <div>
            <div className="flex items-end gap-[3px] h-56 border-b border-slate-200 dark:border-slate-700/70" role="img" aria-label={`${total} fallback writes and ${totalFail} failures in the last ${points.length} polls`}>
                {Array.from({ length: HISTORY_POINTS - 1 - points.length }, (_, i) => <div key={`empty-${i}`} className="flex-1 min-w-[3px]" />)}
                {points.map((p) => {
                    const h = ((p.writes + p.failures) / max) * 100;
                    const fh = p.writes + p.failures === 0 ? 0 : (p.failures / (p.writes + p.failures)) * 100;
                    return (
                        <div key={p.at} className="flex-1 min-w-[3px] h-full flex flex-col justify-end"
                            title={`${new Date(p.at).toLocaleTimeString()} — ${p.writes} write(s), ${p.failures} failure(s)`}>
                            {h === 0 ? (
                                <div className="h-[3px] rounded-sm bg-emerald-500/40" />
                            ) : (
                                <div className="rounded-sm overflow-hidden flex flex-col" style={{ height: `${Math.max(6, h)}%` }}>
                                    <div className="bg-rose-500" style={{ height: `${fh}%` }} />
                                    <div className="flex-1 bg-cyan-500" />
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-[11px] text-slate-500 dark:text-slate-400">
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm bg-cyan-500" />Fallback writes <b className="tabular-nums text-slate-700 dark:text-slate-200">{fmt(total)}</b></span>
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm bg-rose-500" />Failures <b className="tabular-nums text-slate-700 dark:text-slate-200">{fmt(totalFail)}</b></span>
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-[3px] rounded-sm bg-emerald-500/60" />Primary path only</span>
                <span className="ml-auto">Last {points.length} polls</span>
            </div>
        </div>
    );
}

// ── Page ─────────────────────────────────────────────────────────────────────
export default function ReliabilityHealth() {
    useEffect(() => {
        document.title = 'Reliability Health — System | MITRAS';
    }, []);

    const { data, isLoading, isFetching, refetch, error, dataUpdatedAt } = useQuery({
        queryKey: ['reliability-health', 'system'],
        queryFn: reliabilityApi.health,
        refetchInterval: POLL_MS,
        staleTime: 4_000,
    });

    // Client-side history of counter snapshots (deltas between polls).
    // Recorded during render (guarded by the fetch time), not in an effect.
    const [history, setHistory] = useState<Sample[]>([]);
    const [recordedAt, setRecordedAt] = useState(0);
    const stats = data?.fallback_store?.enabled ? data.fallback_store.stats : undefined;
    if (stats && dataUpdatedAt && dataUpdatedAt !== recordedAt) {
        setRecordedAt(dataUpdatedAt);
        setHistory([...history, { at: dataUpdatedAt, stats }].slice(-HISTORY_POINTS));
    }

    // "Updated Xs ago" ticker.
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        const id = window.setInterval(() => setNow(Date.now()), 1000);
        return () => window.clearInterval(id);
    }, []);

    const errorHint = (() => {
        if (!error || !axios.isAxiosError(error)) return null;
        if (error.response?.status === 401) return 'Authentication failed (401). Please sign in again.';
        if (error.response?.status === 403) return 'Access denied (403).';
        if (error.response?.status === 404) return 'Reliability endpoint not routed (404). Check the dashboard proxy.';
        if (error.code === 'ECONNABORTED') return 'The request timed out.';
        return null;
    })();

    const fb = data?.fallback_store;
    const queuePct = stats && stats.channel_cap > 0 ? Math.round((stats.channel_len / stats.channel_cap) * 100) : 0;
    const status = statusOf(stats, queuePct);
    const queueTone: Tone = !stats ? 'neutral' : queuePct >= 90 ? 'bad' : queuePct >= 60 ? 'warn' : 'good';
    const diverted = stats ? stats.sync_write_used + stats.enqueued_async : 0;
    const rejected = stats ? stats.db_write_failed + stats.marshal_failed : 0;
    // Ingestion uses the synchronous path: each attempt either commits or fails.
    const committed = stats ? Math.max(0, stats.sync_write_used - rejected) : 0;
    const ago = dataUpdatedAt ? Math.max(0, Math.round((now - dataUpdatedAt) / 1000)) : null;
    const StatusIcon = status.tone === 'bad' ? AlertOctagon : status.tone === 'warn' ? ShieldAlert : status.tone === 'neutral' ? FileWarning : CheckCircle2;

    return (
        <div className="space-y-6 w-full min-w-0 animate-slide-up-fade">
            <PageHeader
                icon={Server}
                eyebrow="System"
                title="Reliability health"
                actions={
                    <>
                        <span className="inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/50 px-3 py-2 text-xs text-slate-600 dark:text-slate-300">
                            <span className="relative flex w-2 h-2">
                                {!error && <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60 animate-ping" />}
                                <span className={`relative inline-flex w-2 h-2 rounded-full ${error ? 'bg-rose-500' : 'bg-emerald-500'}`} />
                            </span>
                            {error ? 'Disconnected' : ago === null ? 'Connecting…' : `Live · updated ${ago}s ago`}
                        </span>
                        <button
                            type="button"
                            onClick={() => refetch()}
                            disabled={isFetching}
                            className="inline-flex items-center gap-2 px-3.5 py-2 text-sm rounded-lg font-medium transition-colors bg-slate-900 text-white hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100 disabled:opacity-70"
                        >
                            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
                            Refresh
                        </button>
                    </>
                }
            />

            {isLoading ? (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4" aria-busy="true">
                    {[0, 1, 2].map((i) => <div key={i} className="h-40 rounded-2xl bg-slate-200/60 dark:bg-slate-800/60 animate-pulse" />)}
                </div>
            ) : error ? (
                <div className="rounded-2xl border border-rose-200 dark:border-rose-500/25 bg-rose-50 dark:bg-rose-500/10 p-5 flex items-start gap-3 text-sm text-rose-800 dark:text-rose-300">
                    <AlertOctagon className="w-5 h-5 shrink-0 mt-0.5" />
                    <div>
                        <div className="font-semibold">Failed to load reliability health</div>
                        <div className="mt-1 opacity-90">{errorHint ?? 'Check that your session is valid and the connection manager is reachable.'}</div>
                    </div>
                </div>
            ) : (
                <>
                    {/* ── Status overview ── */}
                    <section className="rounded-2xl border border-slate-200/90 dark:border-slate-700/70 bg-white dark:bg-slate-800/60 overflow-hidden">
                        <div className="h-1" style={{ background: TONE[status.tone].bar }} />
                        <div className="p-5 sm:p-6 flex flex-col md:flex-row md:items-center gap-6">
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-3">
                                    <span className={`w-11 h-11 rounded-xl flex items-center justify-center ${TONE[status.tone].soft}`}>
                                        <StatusIcon className="w-6 h-6" />
                                    </span>
                                    <div className="min-w-0">
                                        <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Ingestion pipeline</div>
                                        <div className={`text-xl font-bold ${TONE[status.tone].text}`}>{status.label}</div>
                                    </div>
                                </div>
                                <p className="mt-3 text-sm text-slate-600 dark:text-slate-300 max-w-2xl">
                                    {stats ? status.detail : fb?.reason || 'Fallback store statistics are not available.'}
                                </p>
                                <div className="mt-4 flex flex-wrap gap-2 text-[11px]">
                                    <Pill tone={stats && stats.sync_write_failed_drop > 0 ? 'bad' : 'good'} label="Data loss" value={stats ? fmt(stats.sync_write_failed_drop) : '—'} />
                                    <Pill tone={rejected > 0 ? 'warn' : 'good'} label="Retried by agents" value={stats ? fmt(rejected) : '—'} />
                                    <Pill tone={diverted > 0 ? 'info' : 'good'} label="Diverted to fallback" value={stats ? fmt(diverted) : '—'} />
                                    <Pill tone="neutral" label="Counters" value="since service start" />
                                </div>
                            </div>
                            {stats && <Gauge pct={queuePct} tone={queueTone} len={stats.channel_len} cap={stats.channel_cap} />}
                        </div>
                    </section>

                    {/* ── Batch path ── */}
                    <Section title="Event batch path">
                        <div className="flex flex-col lg:flex-row gap-3 lg:gap-6">
                            <Stage step={1} icon={Workflow} title="Kafka (primary)" tone={diverted > 0 ? 'info' : 'good'}
                                value={diverted > 0 ? `${fmt(diverted)} diverted` : 'All batches'}
                                caption={diverted > 0 ? 'Batches redirected because Kafka was unavailable' : 'No batch needed the fallback path'} />
                            <Stage step={2} icon={Database} title="PostgreSQL fallback" tone={!stats ? 'neutral' : rejected > 0 ? 'warn' : diverted > 0 ? 'info' : 'good'}
                                value={stats ? `${fmt(committed)} committed` : '—'}
                                caption={stats ? `${fmt(stats.sync_write_used)} write attempt(s); committed batches are replayed to Kafka` : 'Committed batches are replayed to Kafka'} />
                            <Stage step={3} icon={RotateCcw} title="Agent retry" tone={rejected > 0 ? 'warn' : 'good'}
                                value={stats ? fmt(rejected) : '—'}
                                caption="Failed writes are not acknowledged, so the agent resends them" />
                            <Stage step={4} icon={AlertOctagon} title="Dropped" tone={stats && stats.sync_write_failed_drop > 0 ? 'bad' : 'good'} last
                                value={stats ? fmt(stats.sync_write_failed_drop) : '—'}
                                caption="Definitive loss — persisted on no path" />
                        </div>
                    </Section>

                    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] gap-6">
                        {/* ── Counters ── */}
                        <Section title="Counters" aside={<span className="text-[11px] text-slate-400">+N = change since the previous poll</span>}>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <Counter icon={Database} label="Fallback write attempts" value={stats?.sync_write_used} delta={deltaOf(history, 'sync_write_used')}
                                    tone={stats && stats.sync_write_used > 0 ? 'info' : 'good'} hint="Synchronous PostgreSQL writes while Kafka was unavailable" />
                                <Counter icon={HardDrive} label="Async enqueued" value={stats?.enqueued_async} delta={deltaOf(history, 'enqueued_async')}
                                    tone={stats && stats.enqueued_async > 0 ? 'info' : 'good'} hint="Batches accepted by the background fallback writer" />
                                <Counter icon={Layers} label="Queue full events" value={stats?.channel_full} delta={deltaOf(history, 'channel_full')}
                                    tone={stats && stats.channel_full > 0 ? 'warn' : 'good'} hint="Background queue saturated; a direct write was attempted" />
                                <Counter icon={FileWarning} label="DB write failed" value={stats?.db_write_failed} delta={deltaOf(history, 'db_write_failed')}
                                    tone={stats && stats.db_write_failed > 0 ? 'warn' : 'good'} hint="INSERT failures into the fallback table" />
                                <Counter icon={FileWarning} label="Metadata errors" value={stats?.marshal_failed} delta={deltaOf(history, 'marshal_failed')}
                                    tone={stats && stats.marshal_failed > 0 ? 'warn' : 'good'} hint="Batch metadata could not be serialized" />
                                <Counter icon={AlertOctagon} label="Dropped batches" value={stats?.sync_write_failed_drop} delta={deltaOf(history, 'sync_write_failed_drop')}
                                    tone={stats && stats.sync_write_failed_drop > 0 ? 'bad' : 'good'} hint="Queue full and the direct write failed" />
                            </div>
                        </Section>

                        {/* ── Live activity ── */}
                        <Section title="Live activity" aside={<span className="text-[11px] text-slate-400">this browser session</span>}>
                            <ActivityChart history={history} />
                        </Section>
                    </div>
                </>
            )}

            <div className="flex flex-wrap gap-x-6 gap-y-1 text-[11px] font-mono text-slate-400 dark:text-slate-500">
                {data?.meta?.timestamp && <span>server time {data.meta.timestamp}</span>}
                {data?.meta?.request_id && <span>request {data.meta.request_id}</span>}
                <span>poll every {POLL_MS / 1000}s</span>
            </div>
        </div>
    );
}

function Pill({ tone, label, value }: { tone: Tone; label: string; value: string }) {
    return (
        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-medium ${TONE[tone].soft}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${TONE[tone].dot}`} />
            {label}: <span className="font-semibold tabular-nums">{value}</span>
        </span>
    );
}
