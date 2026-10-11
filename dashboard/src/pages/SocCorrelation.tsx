import { useMemo, useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
    Activity,
    AlertTriangle,
    Bell,
    GitBranch,
    Layers,
    Link as LinkIcon,
    Radio,
    Shield,
    Terminal,
    Zap,
} from 'lucide-react';
import {
    Bar,
    BarChart,
    CartesianGrid,
    Cell,
    Legend,
    Pie,
    PieChart,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from 'recharts';
import { alertsApi, agentsApi, commandsApi, eventsApi, type Alert, type CmEventSummary, type CommandListItem } from '../api/client';
import { DateRangePicker, type DateRange } from '../components/DateRangePicker';
import StatCard from '../components/StatCard';
import InsightHero from '../components/InsightHero';
import EmptyState from '../components/EmptyState';

function isoOrNull(d: Date | null): string | null {
    if (!d) return null;
    return d.toISOString();
}

function last24hRange(): DateRange {
    return { from: new Date(Date.now() - 24 * 60 * 60 * 1000), to: new Date() };
}

function safeHostnameLabel(hostname?: string) {
    return hostname && hostname.trim().length > 0 ? hostname.trim() : 'Unknown host';
}

function formatEventSubtitle(e: CmEventSummary): string {
    if (!e.data) return e.summary?.slice(0, 120) || '—';
    try {
        const d = e.data;
        if (e.event_type === 'process') {
            const exe = d.name || d.executable || 'Unknown Process';
            const cmd = d.command_line ? ` — ${d.command_line}` : '';
            return `${exe}${cmd}`.slice(0, 180);
        }
        if (e.event_type === 'image_load') {
            const name = d.name || 'Unknown DLL';
            const proc = d.process_name && d.process_name !== 'unknown' ? ` by ${d.process_name}` : '';
            return `Loaded: ${name}${proc}`.slice(0, 180);
        }
        if (e.event_type === 'file') {
            const path = d.path || d.directory || 'Unknown Path';
            return `File: ${path}`.slice(0, 180);
        }
        if (e.event_type === 'network') {
            const proto = d.protocol || 'IP';
            const dst = d.destination_ip ? `${d.destination_ip}:${d.destination_port || '*'}` : 'Unknown Dest';
            return `${proto} connection to ${dst}`.slice(0, 180);
        }
        return e.summary?.slice(0, 120) || '—';
    } catch {
        return e.summary?.slice(0, 120) || '—';
    }
}

type FusionKind = 'alert' | 'command' | 'event';

type FusionTimelineRow = {
    kind: FusionKind;
    ts: number;
    id: string;
    title: string;
    subtitle: string;
    accent: string;
    tags?: { label: string; color?: string }[];
};

const TOOLTIP_STYLE = {
    backgroundColor: 'rgba(15, 23, 42, 0.92)',
    backdropFilter: 'blur(8px)',
    border: '1px solid rgba(51, 65, 85, 0.85)',
    borderRadius: '12px',
    color: 'white',
    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.45)',
};

const SEVERITY_PIE_COLORS: Record<string, string> = {
    critical: '#f43f5e',
    high: '#fb923c',
    medium: '#facc15',
    low: '#818cf8',
    informational: '#22d3ee',
};

const CHART_COLORS = {
    alerts: '#f97316',
    commands: '#06b6d4',
    events: '#34d399',
};

/** Evenly split [from, to] into `bucketCount` intervals; count items by timestamp ms. */
function buildActivityBuckets(
    from: Date,
    to: Date,
    bucketCount: number,
    alerts: Alert[],
    commands: CommandListItem[],
    events: CmEventSummary[]
): { label: string; alerts: number; commands: number; events: number }[] {
    const t0 = from.getTime();
    const t1 = to.getTime();
    const span = Math.max(1, t1 - t0);
    const n = Math.max(4, Math.min(32, bucketCount));
    const step = span / n;
    const buckets = Array.from({ length: n }, (_, i) => ({
        label: new Date(t0 + (i + 0.5) * step).toLocaleString(undefined, {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        }),
        alerts: 0,
        commands: 0,
        events: 0,
        start: t0 + i * step,
        end: t0 + (i + 1) * step,
    }));

    const bump = (ts: number, key: 'alerts' | 'commands' | 'events') => {
        if (ts < t0 || ts > t1) return;
        const idx = Math.min(n - 1, Math.max(0, Math.floor((ts - t0) / step)));
        buckets[idx][key] += 1;
    };

    for (const a of alerts) {
        bump(new Date(a.timestamp).getTime(), 'alerts');
    }
    for (const c of commands) {
        bump(new Date(c.issued_at).getTime(), 'commands');
    }
    for (const e of events) {
        bump(new Date(e.timestamp).getTime(), 'events');
    }

    return buckets.map(({ label, alerts: al, commands: co, events: ev }) => ({ label, alerts: al, commands: co, events: ev }));
}

function fusionAccent(kind: FusionKind): string {
    switch (kind) {
        case 'alert':
            return 'border-l-amber-500 bg-amber-500/5';
        case 'command':
            return 'border-l-cyan-500 bg-cyan-500/5';
        default:
            return 'border-l-emerald-500 bg-emerald-500/5';
    }
}

function kindLabel(kind: FusionKind): string {
    switch (kind) {
        case 'alert':
            return 'Alert';
        case 'command':
            return 'Command';
        default:
            return 'Telemetry';
    }
}

export default function SocCorrelation() {
    const [agentId, setAgentId] = useState<string>('');
    const [range, setRange] = useState<DateRange>(() => last24hRange());
    const [fusionPage, setFusionPage] = useState(0);
    const [rawAlertsPage, setRawAlertsPage] = useState(0);

    useEffect(() => {
        setFusionPage(0);
        setRawAlertsPage(0);
    }, [agentId, range]);

    const fromIso = isoOrNull(range.from);
    const toIso = isoOrNull(range.to);

    const agentsQ = useQuery({
        queryKey: ['agents', 'list', 'correlation'],
        queryFn: async () => {
            const out: Awaited<ReturnType<typeof agentsApi.list>>['data'] = [];
            let offset = 0;
            const limit = 500;
            for (let i = 0; i < 10; i++) {
                const r = await agentsApi.list({ limit, offset, sort_by: 'hostname', sort_order: 'asc' });
                out.push(...(r.data ?? []));
                if (!r.pagination?.has_more) break;
                offset += limit;
            }
            return out;
        },
        staleTime: 30_000,
    });

    const selectedAgent = useMemo(() => {
        if (!agentId) return null;
        return (agentsQ.data ?? []).find((a) => a.id === agentId) ?? null;
    }, [agentId, agentsQ.data]);

    const alertsQ = useQuery({
        queryKey: ['correlation', 'alerts', agentId, fromIso, toIso],
        queryFn: async () => {
            if (!agentId || !fromIso || !toIso) return { alerts: [] as Alert[], total: 0 };
            return alertsApi.list({
                limit: 500,
                offset: 0,
                agent_id: agentId,
                date_from: fromIso,
                date_to: toIso,
                sort: 'timestamp',
                order: 'desc',
            });
        },
        enabled: !!agentId && !!fromIso && !!toIso,
        staleTime: 20_000,
        retry: 1,
    });

    const commandsQ = useQuery({
        queryKey: ['correlation', 'commands', agentId, fromIso, toIso],
        queryFn: async () => {
            if (!agentId) return { data: [] as CommandListItem[], pagination: { total: 0, limit: 0, offset: 0, has_more: false } };
            return commandsApi.list({limit: 100,agent_id: agentId,sort_by: 'issued_at',sort_order: 'desc',from:fromIso || undefined,to:toIso || undefined});
        },
        enabled: !!agentId,
        staleTime: 20_000,
        retry: 1,
    });

    const eventsQ = useQuery({
        queryKey: ['correlation', 'events', agentId, fromIso, toIso],
        queryFn: async () => {
            if (!agentId || !fromIso || !toIso) return { rows: [] as CmEventSummary[], total: 0 };
            const r = await eventsApi.search({
                filters: [{ field: 'agent_id', operator: 'eq', value: agentId }],
                logic: 'AND',
                time_range: { from: fromIso, to: toIso },
                limit: 500,
                offset: 0,
            });
            return { rows: r.data ?? [], total: r.pagination?.total ?? (r.data?.length ?? 0) };
        },
        enabled: !!agentId && !!fromIso && !!toIso,
        staleTime: 20_000,
        retry: 1,
    });

    const alerts = alertsQ.data?.alerts ?? [];
    const commands = commandsQ.data?.data ?? [];
    const eventRows = eventsQ.data?.rows ?? [];

    const eventTypeCounts = useMemo(() => {
        const map = new Map<string, number>();
        for (const r of eventRows) {
            map.set(r.event_type, (map.get(r.event_type) ?? 0) + 1);
        }
        return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    }, [eventRows]);

    const openAlerts = useMemo(() => alerts.filter((a) => a.status === 'open').length, [alerts]);

    const severityPieData = useMemo(() => {
        const map = new Map<string, number>();
        for (const a of alerts) {
            map.set(a.severity, (map.get(a.severity) ?? 0) + 1);
        }
        return [...map.entries()].map(([name, value]) => ({ name, value }));
    }, [alerts]);

    const commandTypeData = useMemo(() => {
        const map = new Map<string, number>();
        for (const c of commands) {
            const t = c.command_type || 'unknown';
            map.set(t, (map.get(t) ?? 0) + 1);
        }
        return [...map.entries()]
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10);
    }, [commands]);

    const mitreTechniqueData = useMemo(() => {
        const map = new Map<string, number>();
        for (const a of alerts) {
            for (const t of a.mitre_techniques ?? []) {
                const id = t.trim();
                if (!id) continue;
                map.set(id, (map.get(id) ?? 0) + 1);
            }
        }
        return [...map.entries()]
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 12);
    }, [alerts]);

    const activityChartData = useMemo(() => {
        if (!range.from || !range.to) return [];
        const hours = Math.max(1, (range.to.getTime() - range.from.getTime()) / 3600000);
        const buckets = Math.round(Math.min(32, Math.max(6, hours)));
        return buildActivityBuckets(range.from, range.to, buckets, alerts, commands, eventRows);
    }, [range.from, range.to, alerts, commands, eventRows]);

    const fusionTimeline = useMemo((): FusionTimelineRow[] => {
        const rows: FusionTimelineRow[] = [];
        for (const a of alerts) {
            rows.push({
                kind: 'alert',
                ts: new Date(a.timestamp).getTime(),
                id: a.id,
                title: a.rule_title || a.rule_id || 'Alert',
                subtitle: `Mitre: ${(a.mitre_techniques || []).join(', ') || 'N/A'}`,
                accent: fusionAccent('alert'),
                tags: [
                    { label: a.severity.toUpperCase(), color: 'bg-amber-500/10 text-amber-600 dark:text-amber-500 border border-amber-500/20' },
                    { label: a.status.toUpperCase(), color: a.status === 'open' ? 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20' : 'bg-slate-500/10 text-slate-500 border border-slate-500/20' }
                ]
            });
        }
        for (const c of commands) {
            rows.push({
                kind: 'command',
                ts: new Date(c.issued_at).getTime(),
                id: c.id,
                title: c.command_type.replace(/_/g, ' '),
                subtitle: `Issued by ${c.issued_by_user || 'system'}`,
                accent: fusionAccent('command'),
                tags: [
                    { label: c.status.toUpperCase(), color: c.status === 'completed' ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-500 border border-emerald-500/20' : 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-500 border border-cyan-500/20' }
                ]
            });
        }
        for (const e of eventRows) {
            const tags = [];
            if (e.severity && e.severity !== 'low' && e.severity !== 'informational') {
                 tags.push({ label: e.severity.toUpperCase(), color: 'bg-rose-500/10 text-rose-600 dark:text-rose-500 border border-rose-500/20' });
            }
            if (e.data?.pid) {
                 tags.push({ label: `PID: ${e.data.pid}`, color: 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border border-slate-500/20' });
            }
            if (e.data?.action) {
                 tags.push({ label: String(e.data.action), color: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20' });
            }

            rows.push({
                kind: 'event',
                ts: new Date(e.timestamp).getTime(),
                id: e.id,
                title: e.event_type.toUpperCase(),
                subtitle: formatEventSubtitle(e),
                accent: fusionAccent('event'),
                tags
            });
        }
        return rows.sort((a, b) => b.ts - a.ts).slice(0, 120);
    }, [alerts, commands, eventRows]);

    const rangeHours = useMemo(() => {
        if (!range.from || !range.to) return 0;
        return Math.max(0, (range.to.getTime() - range.from.getTime()) / 3600000);
    }, [range.from, range.to]);

    const activityChartEmpty =
        activityChartData.length === 0 || activityChartData.every((d) => d.alerts + d.commands + d.events === 0);

    return (
        <div className="space-y-6 animate-slide-up-fade w-full min-w-0">
            <InsightHero
                
                accent="cyan"
                icon={GitBranch}
                eyebrow="SOC correlation workspace"
                title="Temporal fusion"
                lead={
                    <>
                        Align <strong className="text-white">Sigma detections</strong>, <strong className="text-white">C2 command history</strong>, and{' '}
                        <strong className="text-white">connection-manager telemetry</strong> on one clock for a single host. Built for investigation storyboards — not a replacement for
                        the full Alerts grid or Telemetry Search table.
                    </>
                }
                actions={
                    <div className="flex flex-wrap gap-2 text-xs">
                        <Link
                            to="/alerts"
                            className="inline-flex items-center gap-1.5 rounded-lg bg-white/10 hover:bg-white/15 px-3 py-2 border border-white/15 transition-colors text-white"
                        >
                            <Bell className="w-3.5 h-3.5" /> Alerts workspace
                        </Link>
                        <Link
                            to="/events"
                            className="inline-flex items-center gap-1.5 rounded-lg bg-white/10 hover:bg-white/15 px-3 py-2 border border-white/15 transition-colors text-white"
                        >
                            <Radio className="w-3.5 h-3.5" /> Telemetry search
                        </Link>
                        <Link
                            to="/responses"
                            className="inline-flex items-center gap-1.5 rounded-lg bg-white/10 hover:bg-white/15 px-3 py-2 border border-white/15 transition-colors text-white"
                        >
                            <Terminal className="w-3.5 h-3.5" /> Command center
                        </Link>
                    </div>
                }
            />

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm shadow-sm p-4 space-y-2">
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Endpoint</label>
                    <select
                        value={agentId}
                        onChange={(e) => setAgentId(e.target.value)}
                        className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-700 text-sm text-slate-900 dark:text-white"
                    >
                        <option value="">Select endpoint…</option>
                        {(agentsQ.data ?? []).map((a) => (
                            <option key={a.id} value={a.id}>
                                {safeHostnameLabel(a.hostname)} — {a.id.slice(0, 8)}…
                            </option>
                        ))}
                    </select>
                    {selectedAgent && (
                        <div className="text-xs text-slate-500 dark:text-slate-400 flex flex-wrap gap-x-3 gap-y-1">
                            <span>{selectedAgent.os_type}</span>
                            <span>{selectedAgent.os_version}</span>
                            <span>agent {selectedAgent.agent_version}</span>
                        </div>
                    )}
                </div>

                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm shadow-sm p-4 space-y-2">
                    <DateRangePicker label="Correlation window" value={range} onChange={setRange} />
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                        ~{rangeHours.toFixed(1)}h window · narrower ranges keep charts readable; data caps at 500 rows per stream.
                    </div>
                </div>

                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm shadow-sm p-4 space-y-2">
                    <div className="text-sm font-semibold text-slate-900 dark:text-white">Pivot</div>
                    <div className="flex flex-wrap gap-2 text-sm">
                        <Link
                            className="inline-flex items-center gap-1 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-700 text-white font-semibold text-sm disabled:opacity-40"
                            to={agentId ? `/management/devices/${encodeURIComponent(agentId)}` : '#'}
                            onClick={(e) => {
                                if (!agentId) e.preventDefault();
                            }}
                        >
                            <LinkIcon className="w-4 h-4" />
                            Device profile
                        </Link>
                    </div>
                    {!agentId && <div className="text-xs text-slate-500 dark:text-slate-400">Select an endpoint to enable pivots.</div>}
                </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard title="Alerts (loaded)" value={agentId ? String(alerts.length) : '—'} icon={AlertTriangle} color="amber" />
                <StatCard title="Open alerts" value={agentId ? String(openAlerts) : '—'} icon={Shield} color="red" />
                <StatCard title="Commands (window)" value={agentId ? String(commands.length) : '—'} icon={Terminal} color="cyan" />
                <StatCard title="Telemetry (loaded)" value={agentId ? String(eventRows.length) : '—'} icon={Activity} color="emerald" />
            </div>

            {!agentId ? (
                <EmptyState
                    title="Select an endpoint"
                    description="Choose a host and time window to fuse Sigma alerts, operator commands, and raw telemetry on one timeline with charts."
                />
            ) : (
                <>
                    <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                        <div className="xl:col-span-2 rounded-xl border border-slate-200/80 dark:border-slate-700/50 bg-white/80 dark:bg-slate-900/40 backdrop-blur-md p-5 shadow-sm min-h-[320px] flex flex-col">
                            <div className="flex items-center justify-between gap-2 mb-4">
                                <div>
                                    <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                        <Layers className="w-4 h-4 text-cyan-500" />
                                        Activity fusion (stacked)
                                    </h3>
                                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                                        Counts per time bucket — same clock, three evidence channels.
                                    </p>
                                </div>
                            </div>
                            <div className="flex-1 min-h-[260px]">
                                {activityChartEmpty ? (
                                    <div className="h-full flex items-center justify-center text-sm text-slate-500 dark:text-slate-400">
                                        No overlapping activity in this window.
                                    </div>
                                ) : (
                                    <ResponsiveContainer width="100%" height="100%">
                                        <BarChart data={activityChartData} margin={{ top: 8, right: 8, left: -8, bottom: 0 }}>
                                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.25} vertical={false} />
                                            <XAxis dataKey="label" tick={{ fontSize: 9, fill: '#94a3b8' }} interval="preserveStartEnd" />
                                            <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} allowDecimals={false} />
                                            <Tooltip contentStyle={TOOLTIP_STYLE} />
                                            <Legend wrapperStyle={{ fontSize: '12px' }} />
                                            <Bar dataKey="alerts" stackId="a" fill={CHART_COLORS.alerts} name="Alerts" radius={[0, 0, 0, 0]} />
                                            <Bar dataKey="commands" stackId="a" fill={CHART_COLORS.commands} name="Commands" radius={[0, 0, 0, 0]} />
                                            <Bar dataKey="events" stackId="a" fill={CHART_COLORS.events} name="Telemetry" radius={[4, 4, 0, 0]} />
                                        </BarChart>
                                    </ResponsiveContainer>
                                )}
                            </div>
                        </div>

                        <div className="rounded-xl border border-slate-200/80 dark:border-slate-700/50 bg-white/80 dark:bg-slate-900/40 backdrop-blur-md p-5 shadow-sm flex flex-col min-h-[320px]">
                            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-1 flex items-center gap-2">
                                <Zap className="w-4 h-4 text-amber-500" />
                                Alert severity mix
                            </h3>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">Sigma alerts in the selected window.</p>
                            <div className="flex-1 min-h-[220px]">
                                {severityPieData.length === 0 ? (
                                    <div className="h-full flex items-center justify-center text-sm text-slate-500 dark:text-slate-400">
                                        No alerts in range.
                                    </div>
                                ) : (
                                    <ResponsiveContainer width="100%" height="100%">
                                        <PieChart>
                                            <Pie data={severityPieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={52} outerRadius={78} paddingAngle={2}>
                                                {severityPieData.map((entry, index) => (
                                                    <Cell
                                                        key={`cell-${index}`}
                                                        fill={SEVERITY_PIE_COLORS[entry.name] || `hsl(${(index * 47) % 360}, 70%, 55%)`}
                                                    />
                                                ))}
                                            </Pie>
                                            <Tooltip contentStyle={TOOLTIP_STYLE} />
                                            <Legend verticalAlign="bottom" height={28} wrapperStyle={{ fontSize: '11px' }} />
                                        </PieChart>
                                    </ResponsiveContainer>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <div className="rounded-xl border border-slate-200/80 dark:border-slate-700/50 bg-white/80 dark:bg-slate-900/40 backdrop-blur-md p-5 shadow-sm min-h-[300px] flex flex-col">
                            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-1 flex items-center gap-2">
                                <Terminal className="w-4 h-4 text-cyan-500" />
                                Operator commands by type
                            </h3>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">C2 commands issued in the window (connection-manager).</p>
                            <div className="flex-1 min-h-[220px]">
                                {commandTypeData.length === 0 ? (
                                    <div className="h-full flex items-center justify-center text-sm text-slate-500 dark:text-slate-400">
                                        No commands in range.
                                    </div>
                                ) : (
                                    <ResponsiveContainer width="100%" height="100%">
                                        <BarChart data={commandTypeData} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 4 }}>
                                            <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                                            <YAxis
                                                type="category"
                                                dataKey="name"
                                                width={120}
                                                tick={{ fontSize: 10, fill: '#94a3b8' }}
                                                tickFormatter={(v: string) => (v.length > 18 ? `${v.slice(0, 16)}…` : v.replace(/_/g, ' '))}
                                            />
                                            <Tooltip contentStyle={TOOLTIP_STYLE} />
                                            <Bar dataKey="count" fill={CHART_COLORS.commands} radius={[0, 6, 6, 0]} barSize={18} name="Count" />
                                        </BarChart>
                                    </ResponsiveContainer>
                                )}
                            </div>
                        </div>

                        <div className="rounded-xl border border-slate-200/80 dark:border-slate-700/50 bg-white/80 dark:bg-slate-900/40 backdrop-blur-md p-5 shadow-sm min-h-[300px] flex flex-col">
                            <h3 className="text-base font-bold text-slate-900 dark:text-white mb-1 flex items-center gap-2">
                                <Shield className="w-4 h-4 text-violet-400" />
                                MITRE techniques (from alerts)
                            </h3>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">Technique IDs referenced on alert payloads in this window.</p>
                            <div className="flex-1 min-h-[220px]">
                                {mitreTechniqueData.length === 0 ? (
                                    <div className="h-full flex items-center justify-center text-sm text-slate-500 dark:text-slate-400">
                                        No MITRE tags on loaded alerts.
                                    </div>
                                ) : (
                                    <ResponsiveContainer width="100%" height="100%">
                                        <BarChart data={mitreTechniqueData} layout="vertical" margin={{ top: 4, right: 12, left: 4, bottom: 4 }}>
                                            <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                                            <YAxis type="category" dataKey="name" width={100} tick={{ fontSize: 10, fill: '#94a3b8' }} />
                                            <Tooltip contentStyle={TOOLTIP_STYLE} />
                                            <Bar dataKey="count" fill="#a78bfa" radius={[0, 6, 6, 0]} barSize={16} name="Refs" />
                                        </BarChart>
                                    </ResponsiveContainer>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="rounded-xl border border-slate-200/80 dark:border-slate-700/50 bg-white/80 dark:bg-slate-900/40 backdrop-blur-md p-5 shadow-sm">
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-4">
                            <div>
                                <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                    <GitBranch className="w-4 h-4 text-emerald-400" />
                                    Unified fusion timeline
                                </h3>
                                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                                    Newest first — up to 120 entries across alerts, commands, and telemetry.
                                </p>
                            </div>
                            <div className="flex flex-wrap gap-3 text-[10px] uppercase font-semibold tracking-wide text-slate-500">
                                <span className="flex items-center gap-1">
                                    <span className="w-2 h-2 rounded-full bg-amber-500" /> Alert
                                </span>
                                <span className="flex items-center gap-1">
                                    <span className="w-2 h-2 rounded-full bg-cyan-500" /> Command
                                </span>
                                <span className="flex items-center gap-1">
                                    <span className="w-2 h-2 rounded-full bg-emerald-500" /> Telemetry
                                </span>
                            </div>
                        </div>
                        <div className="max-h-[420px] overflow-y-auto rounded-lg border border-slate-200 dark:border-slate-700/60 divide-y divide-slate-100 dark:divide-slate-800">
                            {fusionTimeline.length === 0 ? (
                                <div className="p-8 text-center text-sm text-slate-500 dark:text-slate-400">Nothing to show for this window.</div>
                            ) : (
                                <>
                                    {fusionTimeline.slice(fusionPage * 10, (fusionPage + 1) * 10).map((row) => (
                                        <div key={`${row.kind}-${row.id}`} className={`flex gap-3 px-3 py-2.5 border-l-4 ${row.accent}`}>
                                            <div className="w-36 shrink-0 text-[11px] font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">
                                                {new Date(row.ts).toLocaleString()}
                                            </div>
                                            <div className="w-20 shrink-0 flex flex-col items-start gap-1">
                                                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300">
                                                    {kindLabel(row.kind)}
                                                </span>
                                            </div>
                                            <div className="min-w-0 flex-1">
                                                <div className="flex flex-wrap items-center gap-2 mb-0.5">
                                                    <div className="text-sm font-semibold text-slate-900 dark:text-white truncate">{row.title}</div>
                                                    {row.tags?.map((t, idx) => (
                                                        <span key={idx} className={`text-[9px] px-1.5 py-0.5 rounded uppercase tracking-wide font-medium ${t.color || 'bg-slate-100 text-slate-600'}`}>
                                                            {t.label}
                                                        </span>
                                                    ))}
                                                </div>
                                                <div className="text-xs text-slate-600 dark:text-slate-400 font-mono leading-relaxed line-clamp-2" title={row.subtitle}>{row.subtitle}</div>
                                            </div>
                                        </div>
                                    ))}
                                    {fusionTimeline.length > 10 && (
                                        <div className="flex items-center justify-between px-4 py-3 bg-slate-50/50 dark:bg-slate-800/50">
                                            <div className="text-xs text-slate-500 dark:text-slate-400">
                                                Showing {fusionPage * 10 + 1} to {Math.min((fusionPage + 1) * 10, fusionTimeline.length)} of {fusionTimeline.length} entries
                                            </div>
                                            <div className="flex gap-2">
                                                <button
                                                    onClick={() => setFusionPage(p => Math.max(0, p - 1))}
                                                    disabled={fusionPage === 0}
                                                    className="px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors"
                                                >
                                                    Prev
                                                </button>
                                                <button
                                                    onClick={() => setFusionPage(p => Math.min(Math.ceil(fusionTimeline.length / 10) - 1, p + 1))}
                                                    disabled={(fusionPage + 1) * 10 >= fusionTimeline.length}
                                                    className="px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-50 disabled:cursor-not-allowed hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors"
                                                >
                                                    Next
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    </div>

                    <details className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 shadow-sm group">
                        <summary className="cursor-pointer list-none px-4 py-3 flex items-center justify-between gap-2 text-sm font-semibold text-slate-900 dark:text-white">
                            <span className="flex items-center gap-2">
                                <Radio className="w-4 h-4 text-cyan-500" />
                                Raw stream previews
                            </span>
                            <span className="text-xs font-normal text-slate-500">Expand for tabular detail</span>
                        </summary>
                        <div className="px-4 pb-4 grid grid-cols-1 lg:grid-cols-2 gap-4 border-t border-slate-200 dark:border-slate-700/60 pt-4">
                            <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700/60">
                                <table className="min-w-full text-left text-xs">
                                    <thead className="bg-slate-50 dark:bg-slate-800/80 text-slate-500 uppercase">
                                        <tr>
                                            <th className="px-2 py-2">Time</th>
                                            <th className="px-2 py-2">Sev</th>
                                            <th className="px-2 py-2">Rule</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {alerts.slice(rawAlertsPage * 10, (rawAlertsPage + 1) * 10).map((a) => (
                                            <tr key={a.id} className="border-t border-slate-100 dark:border-slate-800">
                                                <td className="px-2 py-1.5 whitespace-nowrap">{new Date(a.timestamp).toLocaleString()}</td>
                                                <td className="px-2 py-1.5 font-mono">{a.severity}</td>
                                                <td className="px-2 py-1.5">{a.rule_title}</td>
                                            </tr>
                                        ))}
                                        {alerts.length === 0 && (
                                            <tr>
                                                <td colSpan={3} className="px-2 py-6 text-center text-slate-500">
                                                    No alerts.
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                                {alerts.length > 10 && (
                                    <div className="flex items-center justify-between px-3 py-2 border-t border-slate-200 dark:border-slate-700/60 bg-slate-50/50 dark:bg-slate-800/50">
                                        <div className="text-[10px] text-slate-500">
                                            Showing {rawAlertsPage * 10 + 1} to {Math.min((rawAlertsPage + 1) * 10, alerts.length)} of {alerts.length}
                                        </div>
                                        <div className="flex gap-1">
                                            <button
                                                onClick={() => setRawAlertsPage(p => Math.max(0, p - 1))}
                                                disabled={rawAlertsPage === 0}
                                                className="px-2 py-1 text-[10px] font-medium rounded border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-50 hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors"
                                            >
                                                Prev
                                            </button>
                                            <button
                                                onClick={() => setRawAlertsPage(p => Math.min(Math.ceil(alerts.length / 10) - 1, p + 1))}
                                                disabled={(rawAlertsPage + 1) * 10 >= alerts.length}
                                                className="px-2 py-1 text-[10px] font-medium rounded border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-50 hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors"
                                            >
                                                Next
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>
                            <div>
                                <div className="text-xs font-semibold text-slate-600 dark:text-slate-300 mb-2">Telemetry by type</div>
                                <div className="space-y-2">
                                    {eventTypeCounts.length === 0 ? (
                                        <div className="text-xs text-slate-500 py-6 text-center">No telemetry.</div>
                                    ) : (
                                        eventTypeCounts.map(([t, n]) => (
                                            <div key={t} className="flex items-center gap-2">
                                                <div className="w-36 text-[11px] font-mono text-slate-700 dark:text-slate-300 truncate" title={t}>
                                                    {t}
                                                </div>
                                                <div className="flex-1 h-2 rounded bg-slate-100 dark:bg-slate-800 overflow-hidden">
                                                    <div
                                                        className="h-2 bg-emerald-500"
                                                        style={{
                                                            width: `${Math.min(100, Math.round((n / (eventTypeCounts[0]?.[1] ?? 1)) * 100))}%`,
                                                        }}
                                                    />
                                                </div>
                                                <div className="w-8 text-right text-[11px] text-slate-500 font-mono">{n}</div>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </div>
                        </div>
                    </details>
                </>
            )}
        </div>
    );
}
