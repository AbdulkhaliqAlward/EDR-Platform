import React, { useState, useMemo, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, Navigate } from 'react-router-dom';
import { parityApi } from '../../api/parity/parityApi';
import * as mocks from '../../api/parity/mocks';
import { GenericParityView } from '../../components/parity/GenericParityView';
import StatCard from '../../components/StatCard';
import InsightHero from '../../components/InsightHero';
import {
    Activity,
    AlertTriangle,
    BarChart3,
    ChevronDown,
    ChevronLeft,
    ChevronRight,
    ChevronUp,
    ClipboardList,
    Clock,
    Database,
    Fingerprint,
    KeyRound,
    Layers,
    ListChecks,
    Radio,
    Search,
    Server,
    Shield,
    Terminal,
    TrendingUp,
    Wifi,
} from 'lucide-react';
import {
    PieChart,
    Pie,
    Cell,
    Tooltip,
    ResponsiveContainer,
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
} from 'recharts';
import {
    agentsApi,
    alertsApi,
    commandsApi,
    reliabilityApi,
    statsApi,
    type Agent,
} from '../../api/client';
import {
    formatDate,
    formatRelativeTime,
    getEffectiveStatus,
    isDecommissioned,

} from '../../utils/agentDisplay';

const CHART_TOOLTIP: React.CSSProperties = {
    background: 'rgba(15,23,42,0.95)',
    border: '1px solid rgba(30,48,72,0.8)',
    borderRadius: '10px',
    color: 'white',
    fontSize: '12px',
};
const OS_COLORS: Record<string, string> = { windows: '#38bdf8', linux: '#a855f7', macos: '#10b981' };
const OS_FALLBACK = '#64748b';

const COMPLIANCE_AGENT_PAGE = 1000;
const COMPLIANCE_MAX_PAGES = 100;

/** Full sorted fleet for compliance (paginated Agents Search API until has_more is false). */
async function fetchEntireAgentFleetForCompliance(): Promise<{ agents: Agent[]; truncated: boolean }> {
    const all: Agent[] = [];
    let offset = 0;
    let truncated = false;
    for (let p = 0; p < COMPLIANCE_MAX_PAGES; p++) {
        const res = await agentsApi.list({
            limit: COMPLIANCE_AGENT_PAGE,
            offset,
            sort_by: 'hostname',
            sort_order: 'asc',
        });
        all.push(...res.data);
        if (!res.pagination?.has_more) {
            return { agents: all, truncated: false };
        }
        offset += COMPLIANCE_AGENT_PAGE;
        if (p === COMPLIANCE_MAX_PAGES - 1) {
            truncated = true;
        }
    }
    return { agents: all, truncated };
}


type ComplianceReasonCode =
    | 'offline'
    | 'health'
    | 'isolated'
    | 'no_cert'
    | 'cert_expired'
    | 'cert_expiring';

type ComplianceStatus = 'compliant' | 'non-compliant' | 'pending_remediation';
type ComplianceSeverity = 'Critical' | 'High' | 'Medium' | 'Low';

interface ComplianceCheck {
    id: string; // e.g., POL-001
    category: 'Policy' | 'Security';
    name: string;
    passed: boolean;
    reason?: string;
    severity?: ComplianceSeverity;
    code: ComplianceReasonCode;
}

function evalEndpointCompliance(a: Agent): {
    status: ComplianceStatus;
    checks: ComplianceCheck[];
    reasons: string[];
    codes: ComplianceReasonCode[];
} {
    const checks: ComplianceCheck[] = [];
    const reasons: string[] = [];
    const codes: ComplianceReasonCode[] = [];
    let status: ComplianceStatus = 'compliant';
    let hasNonCompliant = false;
    let hasPending = false;

    // Policy Compliance
    const eff = getEffectiveStatus(a);
    if (eff !== 'online' && eff !== 'degraded') {
        checks.push({ id: 'POL-001', category: 'Policy', name: 'Agent Connectivity', passed: false, reason: 'Agent not online (effective status)', code: 'offline', severity: 'Critical' });
        reasons.push('Agent not online (effective status)');
        codes.push('offline');
        hasNonCompliant = true;
    } else {
        checks.push({ id: 'POL-001', category: 'Policy', name: 'Agent Connectivity', passed: true, code: 'offline' });
    }

    if (!a.current_cert_id) {
        checks.push({ id: 'POL-002', category: 'Policy', name: 'mTLS Certificate Presence', passed: false, reason: 'Missing active mTLS certificate', code: 'no_cert', severity: 'Critical' });
        reasons.push('Missing active mTLS certificate');
        codes.push('no_cert');
        hasNonCompliant = true;
    } else {
        checks.push({ id: 'POL-002', category: 'Policy', name: 'mTLS Certificate Presence', passed: true, code: 'no_cert' });
    }

    const certExpiry = a.cert_expires_at ? new Date(a.cert_expires_at) : null;
    if (certExpiry && !Number.isNaN(certExpiry.getTime())) {
        const t = certExpiry.getTime();
        if (t < Date.now()) {
            checks.push({ id: 'POL-003', category: 'Policy', name: 'mTLS Certificate Validity', passed: false, reason: 'mTLS certificate expired', code: 'cert_expired', severity: 'Critical' });
            reasons.push('mTLS certificate expired');
            codes.push('cert_expired');
            hasNonCompliant = true;
        } else if (t < Date.now() + 14 * 24 * 60 * 60 * 1000) {
            checks.push({ id: 'POL-003', category: 'Policy', name: 'mTLS Certificate Validity', passed: false, reason: 'mTLS certificate expires within 14 days', code: 'cert_expiring', severity: 'Medium' });
            reasons.push('mTLS certificate expires within 14 days');
            codes.push('cert_expiring');
            hasNonCompliant = true;
        } else {
            checks.push({ id: 'POL-003', category: 'Policy', name: 'mTLS Certificate Validity', passed: true, code: 'cert_expiring' });
        }
    } else if (a.current_cert_id) {
        checks.push({ id: 'POL-003', category: 'Policy', name: 'mTLS Certificate Validity', passed: true, code: 'cert_expiring' });
    }

    // Security Posture
    if ((a.health_score ?? 0) < 80) {
        checks.push({ id: 'SEC-001', category: 'Security', name: 'Minimum Health Score', passed: false, reason: 'Health score below 80%', code: 'health', severity: 'High' });
        reasons.push('Health score below 80%');
        codes.push('health');
        hasNonCompliant = true;
    } else {
        checks.push({ id: 'SEC-001', category: 'Security', name: 'Minimum Health Score', passed: true, code: 'health' });
    }

    // Isolate is now Pending_Remediation
    if (a.is_isolated) {
        checks.push({ id: 'SEC-002', category: 'Security', name: 'Network Isolation Status', passed: false, reason: 'Host is network-isolated', code: 'isolated', severity: 'Low' });
        reasons.push('Host is network-isolated (Pending Remediation)');
        codes.push('isolated');
        hasPending = true;
    } else {
        checks.push({ id: 'SEC-002', category: 'Security', name: 'Network Isolation Status', passed: true, code: 'isolated' });
    }

    if (hasNonCompliant) {
        status = 'non-compliant';
    } else if (hasPending) {
        status = 'pending_remediation';
    }

    return { status, checks, reasons, codes };
}

/** Live data from connection-manager + sigma (self-hosted). */
export function DashboardServicePage() {
    useEffect(() => { document.title = 'Service Summary \u2014 MITRAS'; }, []);

    const cmdQ = useQuery({ queryKey: ['commands-stats'], queryFn: () => commandsApi.stats(), staleTime: 30_000 });
    const alertQ = useQuery({ queryKey: ['sigma-stats-alerts'], queryFn: () => statsApi.alerts(), staleTime: 30_000 });
    const relQ = useQuery({
        queryKey: ['reliability-health'],
        queryFn: () => reliabilityApi.health(),
        staleTime: 60_000,
        retry: 1,
    });

    if (cmdQ.isLoading || alertQ.isLoading) {
        return (
            <div className="space-y-4 animate-pulse">
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    {[...Array(4)].map((_, i) => <div key={i} className="h-24 rounded-xl bg-slate-200 dark:bg-slate-800" />)}
                </div>
                <div className="grid grid-cols-3 gap-4">
                    {[...Array(3)].map((_, i) => <div key={i} className="h-24 rounded-xl bg-slate-200 dark:bg-slate-800" />)}
                </div>
            </div>
        );
    }

    const cmd = cmdQ.data;
    const al = alertQ.data;

    const relReason = relQ.data?.fallback_store?.reason;
    const relEnabled = relQ.data?.fallback_store?.enabled === true;

    return (
        <div className="space-y-5 animate-slide-up-fade">
            <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Service Summary</h2>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                    Live metrics from command operations, sigma alert engine, and reliability health.
                </p>
            </div>

            {(cmdQ.isError || alertQ.isError) && (
                <div className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 px-4 py-3 text-sm text-amber-900 dark:text-amber-200">
                    Some service metrics could not be loaded. Check API connectivity and roles.
                </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                    title="Commands (total)"
                    value={cmd ? String(cmd.total) : '—'}
                    icon={Terminal}
                    color="cyan"
                />
                <StatCard
                    title="Commands completed"
                    value={cmd ? String(cmd.completed) : '—'}
                    icon={Activity}
                    color="emerald"
                />
                <StatCard
                    title="Commands failed / timeout"
                    value={cmd ? `${cmd.failed} / ${cmd.timeout}` : '—'}
                    icon={AlertTriangle}
                    color="amber"
                />
                <StatCard
                    title="Sigma alerts (total)"
                    value={al ? String(al.total_alerts) : '—'}
                    icon={Shield}
                />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                <StatCard
                    title="Alerts (last 24h)"
                    value={al ? String(al.last_24h) : '—'}
                    icon={Clock}
                    color="cyan"
                />
                <StatCard
                    title="Open (status)"
                    value={al ? String(al.by_status?.open ?? 0) : '—'}
                    icon={AlertTriangle}
                    color="red"
                />
                <StatCard
                    title="Reliability fallback store"
                    value={relQ.isLoading ? '…' : relEnabled ? 'On' : 'Off'}
                    icon={Database}
                    color={relEnabled ? 'amber' : 'emerald'}
                />
            </div>

            {relReason && (
                <p className="text-xs text-slate-500 dark:text-slate-400">{relReason}</p>
            )}

            <div className="flex flex-wrap gap-3 text-sm">
                <Link to="/responses" className="text-cyan-600 dark:text-cyan-400 hover:underline font-medium">
                    Command Center →
                </Link>
                <Link to="/stats" className="text-cyan-600 dark:text-cyan-400 hover:underline font-medium">
                    Statistics →
                </Link>
            </div>
        </div>
    );
}

const ENDPOINT_DASHBOARD_AGENT_LIMIT = 500;

/** Executive endpoint fleet dashboard — registry stats + sampled live connectivity + risk excerpt. */
export function DashboardEndpointPage() {
    useEffect(() => { document.title = 'Endpoint Summary — MITRAS'; }, []);

    const statsQ = useQuery({ queryKey: ['agents-stats'], queryFn: () => agentsApi.stats(), staleTime: 30_000, refetchInterval: 30_000 });
    const riskQ = useQuery({ queryKey: ['endpoint-risk'], queryFn: () => alertsApi.endpointRisk(), staleTime: 60_000, refetchInterval: 60_000, retry: 1 });
    const agentsQ = useQuery({
        queryKey: ['agents', 'endpoint-dashboard', ENDPOINT_DASHBOARD_AGENT_LIMIT],
        queryFn: () => agentsApi.list({ limit: ENDPOINT_DASHBOARD_AGENT_LIMIT, offset: 0, sort_by: 'hostname', sort_order: 'asc' }),
        staleTime: 30_000,
        refetchInterval: 45_000,
    });

    const agentMap = useMemo<Record<string, string>>(() => {
        const m: Record<string, string> = {};
        (agentsQ.data?.data ?? []).forEach((a) => {
            m[a.id] = a.hostname;
        });
        return m;
    }, [agentsQ.data]);

    const riskRows = riskQ.data?.data ?? [];
    const sortedRisk = useMemo(
        () =>
            [...riskRows]
                .sort((a, b) => b.peak_risk_score - a.peak_risk_score || b.open_count - a.open_count || b.total_alerts - a.total_alerts)
                .slice(0, 10),
        [riskRows]
    );

    const sampleAgents = agentsQ.data?.data ?? [];
    const liveSample = useMemo(() => {
        let effOnline = 0;
        let effDegraded = 0;
        let effOffline = 0;
        let stale = 0;
        let isolated = 0;
        let qSum = 0;
        let dropSum = 0;
        for (const a of sampleAgents) {
            const e = getEffectiveStatus(a);
            if (e === 'online') {
                effOnline += 1;
            } else if (e === 'degraded') {
                effDegraded += 1;
            } else {
                effOffline += 1;
            }
            if ((a.status === 'online' || a.status === 'degraded') && e === 'offline') {
                stale += 1;
            }
            if (a.is_isolated) {
                isolated += 1;
            }
            qSum += a.queue_depth ?? 0;
            dropSum += a.events_dropped ?? 0;
        }
        const n = sampleAgents.length || 1;
        return { effOnline, effDegraded, effOffline, stale, isolated, qSum, dropSum, n };
    }, [sampleAgents]);

    const dominantVersion = useMemo(() => {
        const s = statsQ.data;
        if (!s?.by_version) return '';
        const ent = Object.entries(s.by_version).sort((a, b) => b[1] - a[1]);
        return ent[0]?.[0] ?? '';
    }, [statsQ.data]);

    const versionDriftHosts = useMemo(() => {
        if (!dominantVersion) return [];
        return sampleAgents.filter((a) => a.agent_version && a.agent_version !== dominantVersion).slice(0, 8);
    }, [sampleAgents, dominantVersion]);

    if (statsQ.isLoading) {
        return (
            <div className="space-y-4 animate-pulse">
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    {[...Array(4)].map((_, i) => (
                        <div key={i} className="h-28 rounded-xl bg-slate-200 dark:bg-slate-800" />
                    ))}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="h-56 rounded-xl bg-slate-200 dark:bg-slate-800" />
                    <div className="h-56 rounded-xl bg-slate-200 dark:bg-slate-800" />
                </div>
            </div>
        );
    }

    if (statsQ.isError || !statsQ.data) {
        return (
            <div className="rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50/80 dark:bg-rose-950/20 p-6 text-sm text-rose-900 dark:text-rose-200">
                Could not load agent statistics. Open{' '}
                <Link className="font-semibold underline" to="/management/devices">
                    Device Management
                </Link>{' '}
                and try again. If the issue persists, contact your system administrator.
            </div>
        );
    }

    const s = statsQ.data;
    const withOpenAlerts = riskRows.filter((r) => r.open_count > 0).length;

    const osData = Object.entries(s.by_os_type ?? {})
        .filter(([, v]) => v > 0)
        .map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), value: v, key: k }));
    const osTotal = osData.reduce((a, d) => a + d.value, 0) || 1;

    const versionData = Object.entries(s.by_version ?? {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([k, v]) => ({ version: k.length > 12 ? k.slice(0, 12) + '…' : k, count: v }));

    const connectivityCompare = [
        { name: 'Registry online', value: s.online, fill: '#22d3ee' },
        { name: 'Live online (sample)', value: liveSample.effOnline, fill: '#34d399' },
    ];

    return (
        <div className="space-y-6 animate-slide-up-fade w-full min-w-0">
            <InsightHero
                
                accent="emerald"
                icon={BarChart3}
                eyebrow="Fleet Overview"
                title="Endpoint Summary"
                lead={
                    <>
                        A high-level overview of your entire fleet: <strong className="text-white">total registered endpoints</strong>,{' '}
                        <strong className="text-white">real-time connectivity status</strong>, operating system distribution,{' '}
                        and the <strong className="text-white">highest-risk devices</strong> requiring immediate attention.
                    </>
                }
            />

            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <Layers className="w-4 h-4 text-cyan-500" />
                        Security Posture
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/dashboards/service">
                            Security Posture
                        </Link>{' '}
                        provides an overall security health view including detection rules, alerts, and system reliability.
                    </p>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <TrendingUp className="w-4 h-4 text-amber-500" />
                        Risk Analysis
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/endpoint-risk">
                            Endpoint Risk
                        </Link>{' '}
                        shows the complete risk ranking for all devices. This page shows the <strong>top 10 highest-risk endpoints</strong>.
                    </p>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <Shield className="w-4 h-4 text-violet-500" />
                        Compliance
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/dashboards/endpoint-compliance">
                            Endpoint Compliance
                        </Link>{' '}
                        evaluates each device against security policies. This dashboard focuses on fleet health and version drift.
                    </p>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <Wifi className="w-4 h-4 text-sky-500" />
                        Network Health
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/management/network">
                            Fleet Connectivity
                        </Link>{' '}
                        provides detailed network monitoring per device. This page shows a condensed connectivity overview.
                    </p>
                </div>
            </div>

            {riskQ.isError && (
                <div className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 px-4 py-2.5 text-xs text-amber-900 dark:text-amber-200">
                    Risk data is temporarily unavailable. Please check your connection and permissions.
                </div>
            )}

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard title="Total Endpoints" value={String(s.total)} icon={Server} subtext={`${s.pending} pending · ${s.suspended} suspended`} />
                <StatCard title="Online Endpoints" value={String(s.online)} icon={Activity} color="emerald" subtext={`Avg health ${Math.round(s.avg_health)}%`} />
                <StatCard title="Offline / Degraded" value={`${s.offline} / ${s.degraded}`} icon={AlertTriangle} color="amber" />
                <StatCard title="Hosts with Active Alerts" value={String(withOpenAlerts)} icon={Shield} color="red" subtext={`${riskRows.length} devices monitored`} />
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <StatCard
                    title="Currently Online"
                    value={agentsQ.isLoading ? '…' : String(liveSample.effOnline)}
                    icon={Fingerprint}
                    color="emerald"
                    subtext="Based on live heartbeat data"
                />
                <StatCard
                    title="Stale Connection"
                    value={agentsQ.isLoading ? '…' : String(liveSample.stale)}
                    icon={Radio}
                    color="amber"
                    subtext="Registered but not responding"
                />
                <StatCard title="Isolated Devices" value={agentsQ.isLoading ? '…' : String(liveSample.isolated)} icon={AlertTriangle} color="red" />
                <StatCard
                    title="Telemetry pressure"
                    value={agentsQ.isLoading ? '…' : `${liveSample.dropSum} drops`}
                    icon={Activity}
                    color="cyan"
                    subtext={`Σ queue ${liveSample.qSum} · sample only`}
                />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm p-5 shadow-sm lg:col-span-1">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-2">
                        <Radio className="w-3.5 h-3.5 text-cyan-500" />
                        Registry vs live online
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mb-3">
                        Compares DB registry online count to effective-online count on the same {liveSample.n}-host slice (sorted A→Z).
                    </p>
                    {agentsQ.isLoading ? (
                        <div className="h-36 rounded-lg bg-slate-100 dark:bg-slate-800 animate-pulse" />
                    ) : (
                        <ResponsiveContainer width="100%" height={160}>
                            <BarChart data={connectivityCompare} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" vertical={false} />
                                <XAxis dataKey="name" tick={{ fontSize: 9, fill: '#94a3b8' }} interval={0} angle={-12} textAnchor="end" height={52} />
                                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: '#94a3b8' }} />
                                <Tooltip contentStyle={CHART_TOOLTIP} />
                                <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={48}>
                                    {connectivityCompare.map((e, i) => (
                                        <Cell key={i} fill={e.fill} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </div>

                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm p-5 shadow-sm lg:col-span-1">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3 flex items-center gap-2">
                        <Server className="w-3.5 h-3.5 text-cyan-500" /> OS Distribution
                    </h3>
                    {osData.length === 0 ? (
                        <div className="flex items-center justify-center h-36 text-slate-500 text-sm">No OS data</div>
                    ) : (
                        <div className="flex flex-col items-center gap-2">
                            <ResponsiveContainer width="100%" height={140}>
                                <PieChart>
                                    <Pie data={osData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={38} outerRadius={60} paddingAngle={3} strokeWidth={0}>
                                        {osData.map((e) => (
                                            <Cell key={e.key} fill={OS_COLORS[e.key] || OS_FALLBACK} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={CHART_TOOLTIP}
                                        formatter={(v: number | undefined) => [`${v ?? 0} agents`, '']}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                            <div className="flex flex-wrap justify-center gap-3">
                                {osData.map((d) => (
                                    <span key={d.key} className="flex items-center gap-1.5 text-[11px] font-medium text-slate-500 dark:text-slate-400">
                                        <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: OS_COLORS[d.key] || OS_FALLBACK }} />
                                        {d.name} ({Math.round((d.value / osTotal) * 100)}%)
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                </div>

                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm p-5 shadow-sm lg:col-span-1">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3 flex items-center gap-2">
                        <Activity className="w-3.5 h-3.5 text-emerald-500" /> Agent Versions
                    </h3>
                    {versionData.length === 0 ? (
                        <div className="flex items-center justify-center h-36 text-slate-500 text-sm">No version data</div>
                    ) : (
                        <ResponsiveContainer width="100%" height={150}>
                            <BarChart data={versionData} layout="vertical" margin={{ left: 0, right: 16, top: 4, bottom: 4 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" horizontal={false} />
                                <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                                <YAxis type="category" dataKey="version" tick={{ fontSize: 10, fill: '#94a3b8' }} width={90} axisLine={false} tickLine={false} />
                                <Tooltip contentStyle={CHART_TOOLTIP} />
                                <Bar dataKey="count" fill="#22d3ee" radius={[0, 4, 4, 0]} maxBarSize={18} name="Agents" />
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </div>
            </div>

            {dominantVersion && versionDriftHosts.length > 0 && (
                <div className="rounded-xl border border-amber-200/80 dark:border-amber-900/40 bg-amber-50/60 dark:bg-amber-950/20 p-4 shadow-sm">
                    <h3 className="text-sm font-bold text-amber-950 dark:text-amber-100">Version drift (sample)</h3>
                    <p className="text-xs text-amber-900/80 dark:text-amber-200/90 mt-1">
                        Most common agent version in the fleet: <code className="text-[11px]">{dominantVersion}</code>. The following hosts in the first {liveSample.n} rows differ — schedule updates via{' '}
                        <Link className="font-semibold underline" to="/management/agent-deploy">
                            Agent Deployment
                        </Link>
                        .
                    </p>
                    <ul className="mt-2 flex flex-wrap gap-2 text-xs">
                        {versionDriftHosts.map((a) => (
                            <li key={a.id}>
                                <Link className="text-cyan-700 dark:text-cyan-300 hover:underline font-medium" to={`/management/devices/${encodeURIComponent(a.id)}`}>
                                    {a.hostname}
                                </Link>
                                <span className="text-slate-600 dark:text-slate-400"> ({a.agent_version})</span>
                            </li>
                        ))}
                    </ul>
                </div>
            )}

            {sortedRisk.length > 0 && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm p-5 shadow-sm">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-500" /> Highest Risk Endpoints
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mb-3">Top 10 endpoints ranked by highest risk score. View the full analysis in the Endpoint Risk page.</p>
                    <div className="overflow-x-auto">
                        <table className="min-w-full text-sm">
                            <thead>
                                <tr className="text-xs uppercase text-slate-400 border-b border-slate-200 dark:border-slate-700">
                                    <th className="text-left py-2 pr-3 font-semibold">Endpoint</th>
                                    <th className="text-right py-2 px-3 font-semibold">Peak</th>
                                    <th className="text-right py-2 px-3 font-semibold">Open</th>
                                    <th className="text-right py-2 px-3 font-semibold">Avg</th>
                                    <th className="text-right py-2 pl-3 font-semibold">Critical</th>
                                </tr>
                            </thead>
                            <tbody>
                                {sortedRisk.map((r) => (
                                    <tr key={r.agent_id} className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors">
                                        <td className="py-2 pr-3">
                                            <Link
                                                className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline"
                                                to={`/management/devices/${encodeURIComponent(r.agent_id)}`}
                                            >
                                                {agentMap[r.agent_id] || r.agent_id.slice(0, 12) + '…'}
                                            </Link>
                                        </td>
                                        <td className="text-right py-2 px-3 font-mono text-slate-600 dark:text-slate-300">{Math.round(r.peak_risk_score)}</td>
                                        <td className="text-right py-2 px-3 font-mono text-slate-600 dark:text-slate-300">{r.open_count}</td>
                                        <td className="text-right py-2 px-3 font-mono text-slate-600 dark:text-slate-300">{Math.round(r.avg_risk_score)}</td>
                                        <td className="text-right py-2 pl-3">
                                            {r.critical_count > 0 ? (
                                                <span className="text-xs font-bold text-rose-500 bg-rose-500/10 px-1.5 py-0.5 rounded">{r.critical_count}</span>
                                            ) : (
                                                <span className="text-xs text-slate-400">0</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <div className="mt-3 flex flex-wrap justify-end gap-3 text-xs">
                        <Link to="/endpoint-risk" className="text-cyan-600 dark:text-cyan-400 hover:underline font-medium">
                            Full Endpoint Risk board →
                        </Link>
                        <Link to="/management/devices" className="text-cyan-600 dark:text-cyan-400 hover:underline font-medium">
                            Devices →
                        </Link>
                    </div>
                </div>
            )}

            <div className="flex flex-wrap gap-3 text-sm">
                <Link to="/dashboards/service" className="text-cyan-600 dark:text-cyan-400 hover:underline font-medium">
                    Service Summary →
                </Link>
                <Link to="/stats" className="text-cyan-600 dark:text-cyan-400 hover:underline font-medium">
                    Statistics →
                </Link>
                <Link to="/management/network" className="text-cyan-600 dark:text-cyan-400 hover:underline font-medium">
                    Fleet connectivity →
                </Link>
            </div>
        </div>
    );
}


/** Cloud SaaS dashboards are out of scope for this deployment — use Endpoint summary. */
export function DashboardCloudPage() {
    return <Navigate to="/dashboards/endpoint" replace />;
}

export function DashboardAuditRedirect() {
    return <Navigate to="/audit" replace />;
}



export function DashboardEndpointCompliancePage() {
    useEffect(() => { document.title = 'Endpoint Compliance | MITRAS'; }, []);

    const statsQ = useQuery({
        queryKey: ['agents', 'stats', 'compliance-context'],
        queryFn: () => agentsApi.stats(),
        staleTime: 60_000,
        refetchInterval: 120_000,
        retry: 1,
    });

    const fleetQ = useQuery({
        queryKey: ['agents', 'compliance', 'fleet'],
        queryFn: fetchEntireAgentFleetForCompliance,
        staleTime: 60_000,
        refetchInterval: 120_000,
        retry: 1,
    });

    const [searchTerm, setSearchTerm] = useState('');
    const [statusFilter, setStatusFilter] = useState<'all' | 'compliant' | 'non-compliant' | 'pending'>('all');
    const [sortCol, setSortCol] = useState<'hostname' | 'health' | 'status' | 'cert'>('hostname');
    const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
    const [page, setPage] = useState(0);
    const PAGE_SIZE = 20;

    const allRows = fleetQ.data?.agents ?? [];
    const decommissioned = useMemo(() => allRows.filter(isDecommissioned), [allRows]);
    const activeRows = useMemo(() => allRows.filter((a) => !isDecommissioned(a)), [allRows]);

    const evaluatedActive = useMemo(
        () =>
            activeRows.map((a) => {
                const eff = getEffectiveStatus(a);
                const { status, checks, reasons, codes } = evalEndpointCompliance(a);
                return { agent: a, eff, status, checks, reasons, codes };
            }),
        [activeRows]
    );

    const compliantCount = evaluatedActive.filter((e) => e.status === 'compliant').length;
    const pendingCount = evaluatedActive.filter((e) => e.status === 'pending_remediation').length;
    const nonCompliantCount = evaluatedActive.filter((e) => e.status === 'non-compliant').length;

    const violationBars = useMemo(() => {
        const labels: { code: ComplianceReasonCode; label: string; fill: string; severity: ComplianceSeverity }[] = [
            { code: 'offline', label: 'Not online', fill: '#ef4444', severity: 'Critical' },
            { code: 'health', label: 'Health < 80%', fill: '#f97316', severity: 'High' },
            { code: 'isolated', label: 'Isolated (Pending)', fill: '#eab308', severity: 'Medium' },
            { code: 'no_cert', label: 'No mTLS cert', fill: '#a855f7', severity: 'Critical' },
            { code: 'cert_expired', label: 'Cert expired', fill: '#dc2626', severity: 'Critical' },
            { code: 'cert_expiring', label: 'Cert ≤14d', fill: '#f59e0b', severity: 'Medium' },
        ];
        return labels
            .map((L) => ({
                ...L,
                count: evaluatedActive.filter((e) => e.status !== 'compliant' && e.codes.includes(L.code)).length,
            }))
            .filter((d) => d.count > 0);
    }, [evaluatedActive]);

    const filtered = useMemo(() => {
        const certTs = (a: Agent) => {
            if (!a.cert_expires_at) return 0;
            const t = new Date(a.cert_expires_at).getTime();
            return Number.isNaN(t) ? 0 : t;
        };
        return evaluatedActive
            .filter((e) => {
                if (statusFilter === 'compliant' && e.status !== 'compliant') return false;
                if (statusFilter === 'non-compliant' && e.status !== 'non-compliant') return false;
                if (statusFilter === 'pending' && e.status !== 'pending_remediation') return false;
                if (searchTerm && !e.agent.hostname.toLowerCase().includes(searchTerm.toLowerCase())) return false;
                return true;
            })
            .sort((a, b) => {
                let cmp = 0;
                if (sortCol === 'hostname') cmp = a.agent.hostname.localeCompare(b.agent.hostname);
                else if (sortCol === 'health') cmp = (a.agent.health_score ?? 0) - (b.agent.health_score ?? 0);
                else if (sortCol === 'status') {
                    const weight = { 'compliant': 0, 'pending_remediation': 1, 'non-compliant': 2 };
                    cmp = weight[a.status] - weight[b.status];
                }
                else if (sortCol === 'cert') cmp = certTs(a.agent) - certTs(b.agent);
                return sortDir === 'asc' ? cmp : -cmp;
            });
    }, [evaluatedActive, searchTerm, sortCol, sortDir, statusFilter]);

    const denom = evaluatedActive.length || 1;
    const pctCompliant = Math.round((compliantCount / denom) * 100);

    // @ts-ignore
    const _pieData = [
        { name: 'Compliant', value: compliantCount, color: '#10b981' },
        { name: 'Pending Remediation', value: pendingCount, color: '#eab308' },
        { name: 'Non-compliant', value: nonCompliantCount, color: '#ef4444' },
    ].filter((d) => d.value > 0);



    if (fleetQ.isLoading) {
        return (
            <div className="space-y-4 animate-pulse">
                <div className="h-24 rounded-2xl bg-slate-200 dark:bg-slate-800" />
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    {[...Array(4)].map((_, i) => (
                        <div key={i} className="h-28 rounded-xl bg-slate-200 dark:bg-slate-800" />
                    ))}
                </div>
                <div className="h-64 rounded-xl bg-slate-200 dark:bg-slate-800" />
            </div>
        );
    }

    if (fleetQ.isError || !fleetQ.data) {
        return (
            <div className="rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50/80 dark:bg-rose-950/20 p-6 text-sm text-rose-900 dark:text-rose-200">
                Could not load agents for compliance. Check system connectivity and <code className="text-xs">endpoints:read</code> permissions.
            </div>
        );
    }

    const registryTotal = statsQ.data?.total ?? allRows.length;
    const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    const safePage = Math.min(page, totalPages - 1);
    const pageRows = filtered.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

    const toggleSort = (col: typeof sortCol) => {
        if (sortCol === col) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
        else {
            setSortCol(col);
            setSortDir('asc');
        }
        setPage(0);
    };

    const SortIcon = ({ col }: { col: typeof sortCol }) => {
        if (sortCol !== col) return null;
        return sortDir === 'asc' ? <ChevronUp className="w-3 h-3 inline" /> : <ChevronDown className="w-3 h-3 inline" />;
    };

    return (
        <div className="space-y-6 animate-slide-up-fade w-full min-w-0">
            <InsightHero
                
                accent="indigo"
                icon={ListChecks}
                eyebrow="Security Compliance"
                title="Endpoint Compliance"
                lead={
                    <>
                        Evaluates each <strong className="text-white">active device</strong> against security policies including connectivity status, certificate validity, 
                        and system health. Devices under <strong className="text-white">network isolation</strong> are classified as{' '}
                        <strong className="text-white">Pending Remediation</strong> for targeted follow-up.
                    </>
                }
            />

            <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                <StatCard title="Total Endpoints" value={String(registryTotal)} icon={Database} subtext="All registered devices" />
                <StatCard title="Active Endpoints" value={String(evaluatedActive.length)} icon={Fingerprint} subtext={`${decommissioned.length} decommissioned excluded`} />
                <StatCard title="Compliant" value={String(compliantCount)} icon={Shield} color="emerald" subtext={`${pctCompliant}% of active`} />
                <StatCard title="Pending Remediation" value={String(pendingCount)} icon={AlertTriangle} color="amber" subtext="Isolated devices" />
                <StatCard title="Non-compliant" value={String(nonCompliantCount)} icon={Activity}  subtext="Critical failures" />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm p-4 shadow-sm flex flex-col items-center justify-center min-h-[180px]">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-4">Compliance Rate</h3>
                    <div className="relative w-28 h-28">
                        <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                            <circle cx="18" cy="18" r="15.9" fill="none" stroke="currentColor" className="text-slate-200 dark:text-slate-700" strokeWidth="3" />
                            <circle cx="18" cy="18" r="15.9" fill="none" stroke={pctCompliant >= 80 ? '#10b981' : pctCompliant >= 50 ? '#eab308' : '#ef4444'} strokeWidth="3" strokeDasharray={`${pctCompliant} ${100 - pctCompliant}`} strokeLinecap="round" />
                        </svg>
                        <div className="absolute inset-0 flex items-center justify-center">
                            <span className="text-2xl font-bold text-slate-800 dark:text-slate-100">{pctCompliant}%</span>
                        </div>
                    </div>
                    <p className="text-xs text-slate-500 mt-3 text-center">{compliantCount} of {evaluatedActive.length} active devices are compliant</p>
                </div>

                <div className="lg:col-span-2 rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm p-4 shadow-sm">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center gap-2">
                        <Activity className="w-3.5 h-3.5 text-cyan-500" />
                        Violation mix & Severity (Impact Analysis)
                    </h3>
                    {violationBars.length === 0 ? (
                        <div className="flex items-center justify-center h-32 text-sm text-slate-500">No open violations — fleet is compliant.</div>
                    ) : (
                        <ResponsiveContainer width="100%" height={140}>
                            <BarChart data={violationBars} layout="vertical" margin={{ left: 4, right: 16, top: 4, bottom: 4 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(100,116,139,0.15)" horizontal={false} />
                                <XAxis type="number" allowDecimals={false} tick={{ fontSize: 10, fill: '#94a3b8' }} />
                                <YAxis type="category" dataKey="label" width={130} tick={{ fontSize: 10, fill: '#94a3b8' }} />
                                <Tooltip
                                    contentStyle={CHART_TOOLTIP}
                                    formatter={(v: number | undefined, _n: string | undefined, props: any) => [`${v} hosts (${props?.payload?.severity ?? 'Unknown'})`, 'Count']}
                                />
                                <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={22} name="Hosts">
                                    {violationBars.map((e, i) => (
                                        <Cell key={i} fill={e.fill} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </div>
            </div>

            <div className="flex flex-wrap items-center gap-3">
                <div className="relative flex-1 min-w-[200px] max-w-sm">
                    <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                        type="text"
                        placeholder="Search hostname…"
                        value={searchTerm}
                        onChange={(e) => {
                            setSearchTerm(e.target.value);
                            setPage(0);
                        }}
                        className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white placeholder:text-slate-400"
                    />
                </div>
                <select
                    value={statusFilter}
                    onChange={(e) => {
                        setStatusFilter(e.target.value as any);
                        setPage(0);
                    }}
                    className="px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white"
                >
                    <option value="all">All active</option>
                    <option value="compliant">Compliant</option>
                    <option value="pending">Pending Remediation</option>
                    <option value="non-compliant">Non-compliant</option>
                </select>
                <span className="text-xs text-slate-500 ml-auto">
                    {filtered.length} result{filtered.length !== 1 ? 's' : ''} (active hosts only)
                </span>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm shadow-sm">
                <table className="min-w-full text-left text-sm">
                    <thead className="bg-slate-50 dark:bg-slate-900/50 text-slate-500 dark:text-slate-400 text-xs uppercase">
                        <tr>
                            <th className="px-3 py-2.5 cursor-pointer select-none" onClick={() => toggleSort('hostname')}>
                                Host <SortIcon col="hostname" />
                            </th>
                            <th className="px-3 py-2.5 cursor-pointer select-none" onClick={() => toggleSort('status')}>
                                Compliance <SortIcon col="status" />
                            </th>
                            <th className="px-3 py-2.5">Evaluated Policies</th>
                            <th className="px-3 py-2.5 cursor-pointer select-none" onClick={() => toggleSort('health')}>
                                Health <SortIcon col="health" />
                            </th>
                            <th className="px-3 py-2.5 cursor-pointer select-none" onClick={() => toggleSort('cert')}>
                                mTLS expiry <SortIcon col="cert" />
                            </th>
                            <th className="px-3 py-2.5">Last seen</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                        {pageRows.map(({ agent: a, status, checks }) => (
                            <tr
                                key={a.id}
                                className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                            >
                                <td className="px-3 py-3 align-top">
                                    <Link
                                        className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline block"
                                        to={`/management/devices/${encodeURIComponent(a.id)}`}
                                    >
                                        {a.hostname}
                                    </Link>
                                    <span className="text-[10px] text-slate-500 font-mono mt-1 block">{a.id.slice(0, 12)}...</span>
                                </td>
                                <td className="px-3 py-3 align-top">
                                    {status === 'compliant' ? (
                                        <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full inline-flex items-center gap-1">
                                            <Shield className="w-3 h-3" /> Compliant
                                        </span>
                                    ) : status === 'pending_remediation' ? (
                                        <span className="text-xs font-bold text-amber-600 dark:text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-full inline-flex items-center gap-1">
                                            <AlertTriangle className="w-3 h-3" /> Pending Remediation
                                        </span>
                                    ) : (
                                        <span className="text-xs font-bold text-rose-600 dark:text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded-full inline-flex items-center gap-1">
                                            <Activity className="w-3 h-3" /> Non-compliant
                                        </span>
                                    )}
                                </td>
                                <td className="px-3 py-3">
                                    <div className="space-y-1.5 max-w-sm">
                                        {checks.map(chk => (
                                            <div key={chk.id} className="flex items-start gap-2 text-xs">
                                                <span className={`mt-0.5 shrink-0 ${chk.passed ? 'text-emerald-500' : chk.severity === 'Critical' ? 'text-rose-500' : 'text-amber-500'}`}>
                                                    {chk.passed ? '✓' : '✗'}
                                                </span>
                                                <div>
                                                    <span className="font-semibold text-slate-700 dark:text-slate-200">{chk.id}</span>
                                                    <span className="text-slate-500 dark:text-slate-400"> — {chk.name}</span>
                                                    {!chk.passed && (
                                                        <div className="text-[10px] mt-0.5 text-slate-500">
                                                            {chk.reason} ({chk.severity})
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </td>
                                <td className="px-3 py-3 align-top">
                                    <span
                                        className={`text-xs font-mono font-semibold ${
                                            (a.health_score ?? 0) >= 80 ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'
                                        }`}
                                    >
                                        {Math.round(a.health_score ?? 0)}%
                                    </span>
                                </td>
                                <td className="px-3 py-3 align-top text-xs text-slate-600 dark:text-slate-300">
                                    <span className="inline-flex items-center gap-1">
                                        <KeyRound className="w-3 h-3 text-slate-400 shrink-0" />
                                        {a.cert_expires_at ? formatDate(a.cert_expires_at) : '—'}
                                    </span>
                                </td>
                                <td className="px-3 py-3 align-top text-xs text-slate-500">{formatRelativeTime(a.last_seen)}</td>
                            </tr>
                        ))}
                        {pageRows.length === 0 && (
                            <tr>
                                <td colSpan={6} className="px-3 py-8 text-center text-sm text-slate-500">
                                    No matching active endpoints.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
            
            {totalPages > 1 && (
                <div className="flex items-center justify-between text-xs text-slate-500">
                    <span>
                        Page {safePage + 1} of {totalPages}
                    </span>
                    <div className="flex gap-1">
                        <button
                            disabled={safePage === 0}
                            onClick={() => setPage((p) => p - 1)}
                            className="p-1.5 rounded-lg border border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30 transition-colors"
                        >
                            <ChevronLeft className="w-4 h-4" />
                        </button>
                        <button
                            disabled={safePage >= totalPages - 1}
                            onClick={() => setPage((p) => p + 1)}
                            className="p-1.5 rounded-lg border border-slate-300 dark:border-slate-600 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30 transition-colors"
                        >
                            <ChevronRight className="w-4 h-4" />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}export function DashboardCtemPage() {
    return (
        <div className="space-y-6">
            <GenericParityView
                title="CTEM exposure summary"
                missingApi="true"
                queryKey={['parity', 'ctem', 'exposure']}
                fetcher={() => parityApi.getCtemExposureSummary()}
                mock={mocks.mockCtemExposure}
            />
            <GenericParityView
                title="CTEM findings"
                missingApi="true"
                queryKey={['parity', 'ctem', 'findings']}
                fetcher={() => parityApi.getCtemFindings()}
                mock={mocks.mockCtemFindings.data}
            />
        </div>
    );
}

/** Commercial verdict cloud — not used; fleet view lives under Endpoint. */
export function DashboardVerdictCloudPage() {
    return <Navigate to="/dashboards/endpoint" replace />;
}

export function DashboardRoiPage() {
    return (
        <GenericParityView
            title="ROI dashboard"
            missingApi="true"
            queryKey={['parity', 'dashboard', 'roi']}
            fetcher={() => parityApi.getRoi()}
            mock={mocks.mockRoi}
        />
    );
}

export function DashboardReportsPage() {
    useEffect(() => { document.title = 'Reports \u2014 MITRAS'; }, []);

    // Import the new Report Generator
    const ReportGenerator = React.lazy(() => import('../../components/reports').then(m => ({ default: m.ReportGenerator })));

    return (
        <React.Suspense fallback={
            <div className="flex items-center justify-center p-12">
                <div className="animate-pulse flex flex-col items-center gap-4">
                    <div className="w-12 h-12 rounded-xl bg-slate-200 dark:bg-slate-700" />
                    <div className="w-48 h-4 rounded bg-slate-200 dark:bg-slate-700" />
                </div>
            </div>
        }>
            <ReportGenerator />
        </React.Suspense>
    );
}

// Legacy Reports Page (kept for reference)
export function _LegacyDashboardReportsPage() {
    useEffect(() => { document.title = 'Reports \u2014 MITRAS'; }, []);

    const agentsQ = useQuery({ queryKey: ['agents-stats'], queryFn: () => agentsApi.stats(), staleTime: 30_000 });
    const cmdQ = useQuery({ queryKey: ['commands-stats'], queryFn: () => commandsApi.stats(), staleTime: 30_000 });
    const alertQ = useQuery({ queryKey: ['sigma-stats-alerts'], queryFn: () => statsApi.alerts(), staleTime: 30_000 });

    const downloadJson = (name: string, payload: unknown) => {
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `${name}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
    };

    const downloadCsv = (name: string, rows: Record<string, unknown>[]) => {
        const esc = (v: unknown) => {
            const s = v === null || v === undefined ? '' : String(v);
            return `"${s.replaceAll('"', '""')}"`;
        };
        const headers = Array.from(rows.reduce((set, r) => { Object.keys(r).forEach(k => set.add(k)); return set; }, new Set<string>()));
        const lines = [headers.join(','), ...rows.map(r => headers.map(h => esc(r[h])).join(','))];
        const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `${name}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`;
        a.click();
        URL.revokeObjectURL(a.href);
    };

    const fetchAllPaged = async <T,>(
        fetchPage: (offset: number, limit: number) => Promise<{ data: T[]; pagination?: { has_more?: boolean } }>,
        opts?: { limit?: number; max?: number }
    ): Promise<T[]> => {
        const limit = opts?.limit ?? 500;
        const max = opts?.max ?? 5000;
        const maxIter = Math.ceil(max / limit) + 1;
        const out: T[] = [];
        let offset = 0;
        for (let i = 0; i < maxIter; i++) {
            const r = await fetchPage(offset, limit);
            out.push(...(r.data ?? []));
            if (!r.pagination?.has_more) break;
            offset += limit;
            if (out.length >= max) break;
        }
        return out.slice(0, max);
    };

    const [reportType, setReportType] = useState<'commands' | 'alerts' | 'devices'>('commands');
    const [agentScope, setAgentScope] = useState<string>('all');
    const [from, setFrom] = useState<string>(() => new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 16));
    const [to, setTo] = useState<string>(() => new Date().toISOString().slice(0, 16));
    const [loading, setLoading] = useState(false);
    const [err, setErr] = useState<string | null>(null);
    const [lastCount, setLastCount] = useState<number | null>(null);

    const agentsListQ = useQuery({
        queryKey: ['agents', 'list', 'reports'],
        queryFn: async () => fetchAllPaged((offset, limit) => agentsApi.list({ offset, limit, sort_by: 'hostname', sort_order: 'asc' }), { max: 2000 }),
        staleTime: 30_000, retry: 1,
    });

    const runReport = async (fmt: 'json' | 'csv') => {
        try {
            setLoading(true); setErr(null); setLastCount(null);
            const fromIso = new Date(from).toISOString();
            const toIso = new Date(to).toISOString();

            if (reportType === 'commands') {
                const rows = await fetchAllPaged(
                    (offset, limit) => commandsApi.list({ offset, limit, agent_id: agentScope === 'all' ? undefined : agentScope, sort_by: 'issued_at', sort_order: 'desc' }),
                    { max: 5000 }
                );
                const filtered = rows.filter((c: any) => { const t = new Date(c.issued_at).getTime(); return t >= new Date(fromIso).getTime() && t <= new Date(toIso).getTime(); });
                setLastCount(filtered.length);
                const mapped = filtered.map((c: any) => ({ id: c.id, agent_id: c.agent_id, agent_hostname: c.agent_hostname, command_type: c.command_type, status: c.status, issued_at: c.issued_at, issued_by_user: c.issued_by_user, exit_code: c.exit_code ?? '', error_message: c.error_message ?? '' }));
                fmt === 'json' ? downloadJson('report-commands', { from: fromIso, to: toIso, scope: agentScope, rows: mapped }) : downloadCsv('report-commands', mapped);
                return;
            }
            if (reportType === 'alerts') {
                const allAlerts = await fetchAllPaged(
                    (offset, limit) => alertsApi.list({ limit, offset, agent_id: agentScope === 'all' ? undefined : agentScope, date_from: fromIso, date_to: toIso, sort: 'timestamp', order: 'desc' }).then(r => ({ data: r.alerts ?? [], pagination: { has_more: (r.alerts?.length ?? 0) >= limit } })),
                    { max: 2000 }
                );
                setLastCount(allAlerts.length);
                const mapped = allAlerts.map((a: any) => ({ id: a.id, timestamp: a.timestamp, agent_id: a.agent_id, rule_title: a.rule_title, severity: a.severity, status: a.status, category: a.category, risk_score: a.risk_score ?? '' }));
                fmt === 'json' ? downloadJson('report-alerts', { from: fromIso, to: toIso, scope: agentScope, rows: mapped }) : downloadCsv('report-alerts', mapped);
                return;
            }
            if (reportType === 'devices') {
                const allAgents = agentsListQ.data ?? [];
                const fromT = new Date(fromIso).getTime();
                const toT = new Date(toIso).getTime();
                const filtered = allAgents.filter((a: any) => { const t = new Date(a.created_at).getTime(); return t >= fromT && t <= toT; });
                setLastCount(filtered.length);
                const mapped = filtered.map((a: any) => ({ id: a.id, hostname: a.hostname, os_type: a.os_type, os_version: a.os_version, agent_version: a.agent_version, status: a.status, created_at: a.created_at, last_seen: a.last_seen }));
                fmt === 'json' ? downloadJson('report-devices', { from: fromIso, to: toIso, rows: mapped }) : downloadCsv('report-devices', mapped);
            }
        } catch (e: any) {
            setErr(e?.message || 'Report generation failed');
        } finally { setLoading(false); }
    };

    const inputCls = "w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white";
    const labelCls = "block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1";

    return (
        <div className="space-y-6 animate-slide-up-fade w-full min-w-0">
            <InsightHero
                variant="light"
                accent="violet"
                icon={ClipboardList}
                eyebrow="Dashboards"
                title="Reports"
                segments={[
                    {
                        heading: 'Exports',
                        children: (
                            <>
                                Generate <strong className="font-semibold text-slate-800 dark:text-slate-200">browser-side downloads</strong> (JSON or CSV) from live APIs — executed
                                commands, Sigma alerts, or devices enrolled in the selected time window. Pick report type, optional endpoint scope, and range below.
                            </>
                        ),
                    },
                    {
                        heading: 'Limits & safety',
                        children: (
                            <>
                                Large extracts are <strong className="font-semibold text-slate-800 dark:text-slate-200">paged and capped</strong> so the UI stays responsive. For unconstrained
                                search, streaming triage, or audit trails, use the linked workspaces at the bottom of this page.
                            </>
                        ),
                    },
                    {
                        heading: 'Metric snapshots',
                        children: (
                            <>
                                The three summary tiles below expose read-only <strong className="font-semibold text-slate-800 dark:text-slate-200">aggregate JSON</strong> (fleet, commands,
                                alerts) for quick archival — separate from the filtered row exports above.
                            </>
                        ),
                    },
                ]}
            />

            <div className="rounded-2xl border border-slate-200/90 dark:border-slate-700/80 bg-white/95 dark:bg-slate-800/90 backdrop-blur-sm shadow-md overflow-hidden">
                <div className="px-5 py-4 sm:px-6 border-b border-slate-200 dark:border-slate-700 bg-gradient-to-r from-violet-50/80 via-white to-slate-50/80 dark:from-violet-950/30 dark:via-slate-900/80 dark:to-slate-900/60">
                    <h2 className="text-base font-semibold text-slate-900 dark:text-white tracking-tight">Report builder</h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-none leading-relaxed">
                        Choose data type, scope, and time range — then download. Generation runs in this browser against live connection-manager and Sigma endpoints.
                    </p>
                </div>
                <div className="p-5 sm:p-6 space-y-4">
                <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
                    <div>
                        <label className={labelCls}>Report type</label>
                        <select value={reportType} onChange={e => setReportType(e.target.value as any)} className={inputCls}>
                            <option value="commands">Executed commands</option>
                            <option value="alerts">Alerts</option>
                            <option value="devices">Devices (joined in range)</option>
                        </select>
                    </div>
                    <div>
                        <label className={labelCls}>Scope</label>
                        <select value={agentScope} onChange={e => setAgentScope(e.target.value)} className={inputCls}>
                            <option value="all">All endpoints</option>
                            {(agentsListQ.data ?? []).slice(0, 500).map((a: any) => (
                                <option key={a.id} value={a.id}>{a.hostname}</option>
                            ))}
                        </select>
                        {agentsListQ.isLoading && <div className="mt-1 text-xs text-slate-500">Loading endpoints\u2026</div>}
                    </div>
                    <div>
                        <label className={labelCls}>From</label>
                        <input type="datetime-local" value={from} onChange={e => setFrom(e.target.value)} className={inputCls} />
                    </div>
                    <div>
                        <label className={labelCls}>To</label>
                        <input type="datetime-local" value={to} onChange={e => setTo(e.target.value)} className={inputCls} />
                    </div>
                </div>
                {err && <div className="rounded-lg border border-rose-200 dark:border-rose-900/50 bg-rose-50/80 dark:bg-rose-950/20 px-4 py-3 text-sm text-rose-900 dark:text-rose-200">{err}</div>}
                <div className="flex flex-wrap items-center gap-2">
                    <button type="button" disabled={loading} onClick={() => runReport('json')}
                        className="px-4 py-2 rounded-lg text-sm font-semibold bg-cyan-600 hover:bg-cyan-700 text-white disabled:opacity-50 transition-colors">
                        {loading ? 'Generating\u2026' : 'Download JSON'}
                    </button>
                    <button type="button" disabled={loading} onClick={() => runReport('csv')}
                        className="px-4 py-2 rounded-lg text-sm font-semibold bg-slate-700 hover:bg-slate-800 text-white disabled:opacity-50 dark:bg-slate-600 dark:hover:bg-slate-500 transition-colors">
                        {loading ? 'Generating\u2026' : 'Download CSV'}
                    </button>
                    {loading && (
                        <div className="flex-1 max-w-xs"><div className="h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden"><div className="h-full bg-cyan-500 rounded-full animate-pulse" style={{ width: '60%' }} /></div></div>
                    )}
                    {lastCount !== null && !loading && <span className="text-xs text-slate-500 ml-auto">Last report: {lastCount} rows exported</span>}
                </div>
                </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {[
                    {
                        title: 'Fleet snapshot',
                        desc: 'Live aggregate from connection-manager agent metrics.',
                        data: agentsQ.data,
                        name: 'fleet-stats',
                        icon: Server,
                    },
                    {
                        title: 'Command operations',
                        desc: 'Queue and outcome totals from the command API.',
                        data: cmdQ.data,
                        name: 'commands-stats',
                        icon: Terminal,
                    },
                    {
                        title: 'Alert summary',
                        desc: 'Sigma engine alert statistics snapshot.',
                        data: alertQ.data,
                        name: 'sigma-alert-stats',
                        icon: AlertTriangle,
                    },
                ].map((card) => {
                    const Icon = card.icon;
                    return (
                        <div
                            key={card.name}
                            className="rounded-xl border border-slate-200/90 dark:border-slate-700/80 bg-gradient-to-br from-white to-violet-50/30 dark:from-slate-800/95 dark:to-violet-950/25 p-5 shadow-sm flex flex-col gap-4 ring-1 ring-violet-500/[0.06] dark:ring-violet-400/10"
                        >
                            <div className="flex items-start gap-3 min-w-0">
                                <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-violet-500/12 text-violet-600 dark:text-violet-400 border border-violet-500/15">
                                    <Icon className="h-5 w-5" aria-hidden />
                                </span>
                                <div className="min-w-0">
                                    <div className="font-semibold text-slate-900 dark:text-white leading-snug">{card.title}</div>
                                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">{card.desc}</div>
                                </div>
                            </div>
                            <button
                                type="button"
                                disabled={!card.data}
                                onClick={() => downloadJson(card.name, card.data)}
                                className="mt-auto w-full sm:w-auto self-start px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 text-white disabled:opacity-50 transition-colors shadow-sm"
                            >
                                Download JSON
                            </button>
                        </div>
                    );
                })}
            </div>

            <section className="rounded-2xl border border-slate-200/90 dark:border-slate-700/80 bg-slate-50/90 dark:bg-slate-900/50 px-5 py-5 sm:px-6 sm:py-6">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Full workspaces</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed max-w-3xl">
                    For complete datasets with server-side pagination, saved filters, streaming, or tamper-evident audit trails — use these routes instead of bulk export alone.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                    {[
                        { to: '/alerts', label: 'Alerts' },
                        { to: '/responses', label: 'Command Center' },
                        { to: '/events', label: 'Telemetry Search' },
                        { to: '/system/audit-logs', label: 'Audit logs' },
                    ].map((x) => (
                        <Link
                            key={x.to}
                            to={x.to}
                            className="inline-flex items-center rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-3 py-2 text-sm font-medium text-cyan-700 dark:text-cyan-300 hover:border-cyan-300 dark:hover:border-cyan-600 hover:bg-cyan-50/80 dark:hover:bg-cyan-950/30 transition-colors"
                        >
                            {x.label}
                        </Link>
                    ))}
                </div>
            </section>
        </div>
    );
}



export function DashboardNotificationsPage() {
    return (
        <div className="rounded-xl border border-dashed border-slate-300 dark:border-slate-600 p-8 text-center text-slate-500 dark:text-slate-400">
            <p className="font-medium text-slate-700 dark:text-slate-300">Notifications</p>
            <p className="text-sm mt-2">In-app notification center — coming soon.</p>
            <p className="text-sm mt-4 text-left max-w-md mx-auto text-slate-600 dark:text-slate-300">
                For now, monitor <Link className="text-cyan-600 dark:text-cyan-400 font-medium" to="/alerts">Alerts</Link>
                {' '}and <Link className="text-cyan-600 dark:text-cyan-400 font-medium" to="/">Overview</Link> live streams.
            </p>
        </div>
    );
}

