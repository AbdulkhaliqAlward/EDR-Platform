import { useNavigate, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
    AlertTriangle, Activity, Monitor, Shield, Cpu, BarChart3, ShieldAlert
} from 'lucide-react';
import { SkeletonKPICards } from '../components';
import StatCard from '../components/StatCard';
import ThreatMeter from '../components/ThreatMeter';
import InsightHero from '../components/InsightHero';
import { useDashboard } from '../hooks/useDashboard';
import { securityEventsApi, authApi } from '../api/client';
import {
    OSDonut,
    MitreQuickStats,
    AlertDrawer,
    AlertsFeed,
    ActiveIncidentQueue,
    EndpointsPulse,
    SystemActionLog,
} from '../components/dashboard';

function SecurityEventsWidget() {
    const navigate = useNavigate();
    const { data: summaryData } = useQuery({
        queryKey: ['securityEventsSummaryDash'],
        queryFn: () => securityEventsApi.getSummary(),
        staleTime: 60_000,
    });
    const items = summaryData?.data ?? [];
    const total = items.reduce((acc, i) => acc + i.count, 0);
    const critical = items.filter(i => i.severity === 'critical').reduce((acc, i) => acc + i.count, 0);
    const warning = items.filter(i => i.severity === 'warning').reduce((acc, i) => acc + i.count, 0);
    const info = total - critical - warning;

    return (
        <StatCard
            title="Security Events (24h)"
            value={total}
            icon={ShieldAlert}
            color="red"
            subtext={`${critical} critical · ${warning} warning · ${info} info`}
            onClick={() => navigate('/security/events')}
        />
    );
}

export default function Dashboard() {
    const navigate = useNavigate();
    const {
        alertStats,
        statsLoading,
        agentStats,
        agents,
        liveAlerts,
        agentMap,
        threatScore,
        sparklines,
        handleAlertClick,
        handleCloseDrawer,
        drawerAlert,
    } = useDashboard();

    if (statsLoading) {
        return (
            <div className="space-y-6 w-full min-w-0">
                <div className="rounded-2xl border border-slate-200/80 dark:border-slate-700/60 bg-gradient-to-br from-slate-100 to-slate-50 dark:from-slate-800 dark:to-slate-900 h-36 sm:h-40 animate-pulse" aria-hidden />
                <SkeletonKPICards count={4} />
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div className="lg:col-span-2 h-96 bg-slate-200 dark:bg-slate-800 rounded-xl animate-pulse" />
                    <div className="lg:col-span-1 h-96 bg-slate-200 dark:bg-slate-800 rounded-xl animate-pulse" />
                </div>
            </div>
        );
    }

    const byOs = agentStats?.by_os_type || {};

    return (
        <div className="space-y-6 pb-8 w-full min-w-0">
            <InsightHero
                variant="light"
                accent="cyan"
                icon={BarChart3}
                eyebrow="Dashboards"
                title="Security Posture"
                segments={[
                    {
                        heading: 'What this screen is',
                        children: (
                            <>
                                Executive snapshot of <strong className="font-semibold text-slate-800 dark:text-slate-200">alert pressure</strong>,{' '}
                                <strong className="font-semibold text-slate-800 dark:text-slate-200">fleet connectivity</strong>, and{' '}
                                <strong className="font-semibold text-slate-800 dark:text-slate-200">detection confidence</strong> — fed by Sigma statistics and connection-manager agent
                                APIs. Use it for at-a-glance posture before drilling into operational grids.
                            </>
                        ),
                    },
                    {
                        heading: 'Live behaviour',
                        children: (
                            <>
                                Recent alerts update via stream when available, with polling fallback. KPI cards and charts refresh on a short interval — suitable for NOC-style
                                monitoring, not long-form investigation by itself.
                            </>
                        ),
                    },
                    {
                        heading: 'Where to go deeper',
                        children: (
                            <>
                                Full triage: <Link className="text-cyan-600 dark:text-cyan-400 font-semibold hover:underline" to="/alerts">Alerts</Link>
                                {' · '}
                                Fleet ops: <Link className="text-cyan-600 dark:text-cyan-400 font-semibold hover:underline" to="/management/devices">Devices</Link>
                                {' · '}
                                Alternative summary:{' '}
                                <Link className="text-cyan-600 dark:text-cyan-400 font-semibold hover:underline" to="/dashboards/endpoint">
                                    Endpoint Summary
                                </Link>
                            </>
                        ),
                    },
                ]}
            />

            {/* ── Row 1: KPI Cards ── */}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4 animate-slide-up-fade">
                <StatCard
                    title="Alerts (24h)"
                    value={alertStats?.last_24h || 0}
                    icon={AlertTriangle}
                    color="amber"
                    sparkline={sparklines.total}
                    subtext={`${alertStats?.last_7d || 0} in 7 days · ${alertStats?.by_status?.open || 0} open`}
                    onClick={() => navigate('/alerts')}
                />
                <StatCard
                    title="Critical Threats"
                    value={alertStats?.by_severity?.critical || 0}
                    icon={Shield}
                    color="red"
                    sparkline={sparklines.critical}
                    subtext="Requires immediate triage"
                    onClick={() => navigate('/alerts?severity=critical')}
                />
                <StatCard
                    title="Active Agents"
                    value={agentStats?.online || 0}
                    icon={Monitor}
                    color="emerald"
                    subtext={`Avg health ${Math.round(agentStats?.avg_health || 0)}%`}
                    onClick={() => navigate('/management/devices')}
                />
                <StatCard
                    title="Detection Engine"
                    value={`${((alertStats?.avg_confidence || 0) * 100).toFixed(1)}%`}
                    icon={Activity}
                    color="cyan"
                    subtext="Average rule confidence"
                />
                {authApi.canViewAuditLogs() && <SecurityEventsWidget />}
            </div>

            {/* ── Row 2: Threat Meter + MITRE Bar + OS Donut ── */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="card border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/90 rounded-xl p-5 flex flex-col items-center justify-center gap-2 animate-slide-up-fade animate-delay-100">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 self-start flex items-center gap-2">
                        <Shield className="w-3.5 h-3.5 text-cyan-500" /> Threat Level
                    </h3>
                    <ThreatMeter score={threatScore} size={150} />
                </div>

                <div className="card border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/90 rounded-xl p-5 animate-slide-up-fade animate-delay-200">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-4 flex items-center gap-2">
                        <Cpu className="w-3.5 h-3.5 text-purple-500" /> MITRE ATT&CK — Top Tactics
                    </h3>
                    <MitreQuickStats alerts={liveAlerts} byTactic={alertStats?.by_tactic} />
                </div>

                <div className="card border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/90 rounded-xl p-5 animate-slide-up-fade animate-delay-300">
                    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-4 flex items-center gap-2">
                        <BarChart3 className="w-3.5 h-3.5 text-sky-500" /> OS Distribution
                    </h3>
                    <OSDonut byOsType={byOs} />
                </div>
            </div>

            {/* ── Row 3: Alerts Feed + Incident Queue + Agent Pulse ── */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 w-full">
                <div className="xl:col-span-8 flex flex-col h-[520px] min-h-0">
                    <AlertsFeed alerts={liveAlerts} agentMap={agentMap} onAlertClick={handleAlertClick} />
                </div>

                <div className="xl:col-span-4 flex flex-col gap-4 h-[520px] min-h-0">
                    <div className="flex-1 flex flex-col min-h-0">
                        <ActiveIncidentQueue alerts={liveAlerts} agentMap={agentMap} />
                    </div>
                    <div className="shrink-0">
                        <EndpointsPulse
                            stats={agentStats || null}
                            agents={agents}
                            onClick={() => navigate('/management/devices')}
                        />
                    </div>
                </div>
            </div>

            {/* ── Row 4: System Action Log ── */}
            <div className="w-full shrink-0">
                <SystemActionLog alerts={liveAlerts} agents={agents} />
            </div>

            {/* ── Alert Detail Drawer ── */}
            {drawerAlert && (
                <AlertDrawer alert={drawerAlert} agentMap={agentMap} onClose={handleCloseDrawer} />
            )}
        </div>
    );
}
