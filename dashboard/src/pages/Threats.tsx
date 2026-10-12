import PageHeader from '../components/PageHeader';
import { useQuery } from '@tanstack/react-query';
import React, { useState, useMemo } from 'react';
import { Shield, Target, TrendingUp, Eye, ChevronRight, ExternalLink, GitBranch, ArrowRight } from 'lucide-react';
import { alertsApi, type Alert } from '../api/client';
import { SkeletonKPICards, SkeletonChart } from '../components';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { useNavigate } from 'react-router-dom';

// MITRE ATT&CK Tactics
const MITRE_TACTICS = [
    { id: 'TA0043', name: 'Reconnaissance', shortName: 'Recon' },
    { id: 'TA0042', name: 'Resource Development', shortName: 'Resource' },
    { id: 'TA0001', name: 'Initial Access', shortName: 'Initial' },
    { id: 'TA0002', name: 'Execution', shortName: 'Exec' },
    { id: 'TA0003', name: 'Persistence', shortName: 'Persist' },
    { id: 'TA0004', name: 'Privilege Escalation', shortName: 'PrivEsc' },
    { id: 'TA0005', name: 'Defense Evasion', shortName: 'DefEvas' },
    { id: 'TA0006', name: 'Credential Access', shortName: 'Cred' },
    { id: 'TA0007', name: 'Discovery', shortName: 'Discov' },
    { id: 'TA0008', name: 'Lateral Movement', shortName: 'Lateral' },
    { id: 'TA0009', name: 'Collection', shortName: 'Collect' },
    { id: 'TA0011', name: 'Command and Control', shortName: 'C2' },
    { id: 'TA0010', name: 'Exfiltration', shortName: 'Exfil' },
    { id: 'TA0040', name: 'Impact', shortName: 'Impact' },
];

// 7 Kill Chain phases and their MITRE tactic name matches
const KILL_CHAIN_PHASES = [
    { phase: 'Recon',          tactics: ['reconnaissance', 'resource development'],         color: '#6366f1' },
    { phase: 'Initial Access', tactics: ['initial access'],                                  color: '#8b5cf6' },
    { phase: 'Execution',      tactics: ['execution'],                                       color: '#f59e0b' },
    { phase: 'Persistence',    tactics: ['persistence', 'privilege escalation'],             color: '#f97316' },
    { phase: 'Evasion',        tactics: ['defense evasion', 'credential access', 'discovery'], color: '#ef4444' },
    { phase: 'C2 / Lateral',   tactics: ['lateral movement', 'command and control', 'collection'], color: '#dc2626' },
    { phase: 'Impact',         tactics: ['exfiltration', 'impact'],                         color: '#7f1d1d' },
];

// Kill Chain Swimlane
const KillChainSwimlane = React.memo(function KillChainSwimlane({
    tacticCounts, onPhaseClick
}: { tacticCounts: Record<string, number>; onPhaseClick: (tactic: string) => void }) {
    // aggregate tactic counts per phase
    const phaseCounts = KILL_CHAIN_PHASES.map(ph => ({
        ...ph,
        count: ph.tactics.reduce((sum, t) => sum + (tacticCounts[t] || 0), 0),
    }));
    const max = Math.max(...phaseCounts.map(p => p.count), 1);

    return (
        <div className="relative bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-6 shadow-sm mb-6">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-indigo-400" /> Kill Chain Progression
            </h3>
            <div className="flex items-end gap-2 overflow-x-auto pb-2">
                {phaseCounts.map((ph, i) => {
                    const barH = ph.count === 0 ? 6 : Math.max(18, Math.round((ph.count / max) * 80));
                    return (
                        <React.Fragment key={ph.phase}>
                            <button
                                onClick={() => onPhaseClick(ph.tactics[0])}
                                className="flex flex-col items-center gap-2 flex-1 min-w-[80px] group"
                                title={`${ph.count} alerts`}
                            >
                                <span className="text-xs font-bold text-white py-1 px-2 rounded-full" style={{ backgroundColor: ph.color }}>{ph.count}</span>
                                <div className="w-full rounded-t-md transition-all group-hover:opacity-80" style={{ height: barH, backgroundColor: ph.color + (ph.count === 0 ? '33' : 'cc') }} />
                                <span className="text-[10px] font-semibold text-center text-slate-600 dark:text-slate-400 leading-tight">{ph.phase}</span>
                            </button>
                            {i < phaseCounts.length - 1 && <ArrowRight className="w-4 h-4 text-slate-300 dark:text-slate-600 shrink-0 mb-6" />}
                        </React.Fragment>
                    );
                })}
            </div>
        </div>
    );
});

// ─── Premium Threat Card (replaces plain alert row) ──────────────────────────
const PremiumThreatCard = React.memo(function PremiumThreatCard({ alert, onInvestigate }: { alert: Alert; onInvestigate: (tactic: string) => void }) {
    const sev = alert.severity as 'critical' | 'high' | 'medium' | 'low';
    const severityRing: Record<string, string> = {
        critical: 'ring-2 ring-rose-500/60',
        high:     'ring-2 ring-orange-500/60',
        medium:   'ring-2 ring-amber-400/50',
        low:      'ring-1 ring-indigo-400/40',
    };
    const severityDot: Record<string, string> = {
        critical: 'bg-rose-500',
        high:     'bg-orange-500',
        medium:   'bg-amber-400',
        low:      'bg-indigo-400',
    };
    const ringClass = severityRing[sev] || '';
    const dotClass = severityDot[sev] || 'bg-slate-400';

    return (
        <div className={`relative bg-white dark:bg-slate-800/70 rounded-xl p-4 border border-slate-200 dark:border-slate-700/50 hover:shadow-md transition-all ${ringClass}`}>
            <div className="flex items-start gap-3">
                <span className={`w-2.5 h-2.5 rounded-full shrink-0 mt-1.5 ${dotClass} shadow-[0_0_6px_currentColor]`} />
                <div className="flex-1 min-w-0">
                    <p className="font-semibold text-slate-800 dark:text-slate-100 text-sm truncate">{alert.rule_title}</p>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                        {(alert.mitre_tactics || []).slice(0, 3).map(t => (
                            <span key={t} className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-600 dark:text-purple-300 border border-purple-500/20">{t}</span>
                        ))}
                        {(alert.mitre_techniques || []).slice(0, 2).map(t => (
                            <span key={t} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-100 dark:bg-slate-900 text-slate-500 border border-slate-200 dark:border-slate-700">{t}</span>
                        ))}
                    </div>
                    <div className="flex items-center justify-between mt-2">
                        <span className="text-[11px] text-slate-400">{new Date(alert.timestamp).toLocaleString()}</span>
                        {alert.mitre_tactics?.[0] && (
                            <button
                                onClick={() => onInvestigate(alert.mitre_tactics![0])}
                                className="text-[11px] font-semibold text-indigo-500 hover:text-indigo-700 dark:text-indigo-400 flex items-center gap-1 transition-colors"
                            >
                                Investigate <ChevronRight className="w-3 h-3" />
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
});


const getHeatmapColor = (count: number, maxCount: number) => {
    if (count === 0) return 'transparent';
    const intensity = Math.min(1, count / Math.max(maxCount * 0.8, 1));
    if (intensity < 0.25) return 'rgba(59, 130, 246, 0.3)'; // Light blue
    if (intensity < 0.5) return 'rgba(234, 179, 8, 0.5)'; // Yellow
    if (intensity < 0.75) return 'rgba(249, 115, 22, 0.7)'; // Orange
    return 'rgba(239, 68, 68, 0.9)'; // Red
};

// Threat Summary Card
const ThreatSummaryCard = React.memo(function ThreatSummaryCard({
    title,
    value,
    icon: Icon,
    colorTheme,
    subtitle
}: {
    title: string;
    value: string | number;
    icon: typeof Shield;
    colorTheme: { bg: string; text: string; glow: string };
    subtitle?: string;
}) {
    return (
        <div className="relative overflow-hidden bg-white/60 dark:bg-slate-900/40 backdrop-blur-md rounded-xl border border-slate-200/80 dark:border-slate-700/50 p-5 shadow-sm transition-all hover:shadow-md group">
            <div className={`absolute -top-10 -right-10 w-32 h-32 rounded-full blur-3xl opacity-20 pointer-events-none transition-opacity group-hover:opacity-40 ${colorTheme.glow}`} />
            <div className="flex items-center gap-4 relative z-10">
                <div className={`p-3 rounded-lg ${colorTheme.bg} ${colorTheme.text}`}>
                    <Icon className="w-6 h-6" />
                </div>
                <div>
                    <div className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">{title}</div>
                    <div className="text-2xl font-bold text-slate-900 dark:text-white">{value}</div>
                    {subtitle && <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">{subtitle}</div>}
                </div>
            </div>
        </div>
    );
});

// MITRE Matrix Heatmap
const MitreMatrixHeatmap = React.memo(function MitreMatrixHeatmap({
    tacticCounts,
    onTacticClick
}: {
    tacticCounts: Record<string, number>;
    onTacticClick: (tactic: string) => void;
}) {
    const maxCount = Math.max(...Object.values(tacticCounts), 1);

    return (
        <div className="relative bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-6 shadow-sm flex flex-col mb-6 mt-6">
            <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                    MITRE ATT&CK Matrix
                </h3>
                <a
                    href="https://attack.mitre.org/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 flex items-center gap-1.5 transition-colors bg-indigo-50 dark:bg-indigo-500/10 px-3 py-1.5 rounded-lg border border-indigo-200 dark:border-indigo-500/20"
                >
                    View Framework <ExternalLink className="w-3.5 h-3.5" />
                </a>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-3">
                {MITRE_TACTICS.map((tactic) => {
                    const matchingKey = Object.keys(tacticCounts).find(k => 
                        k.toLowerCase() === tactic.name.toLowerCase() || 
                        k.toLowerCase() === tactic.id.toLowerCase()
                    );
                    const count = matchingKey ? tacticCounts[matchingKey] : 0;
                    const bgColor = getHeatmapColor(count, maxCount);

                    return (
                        <button
                            key={tactic.id}
                            onClick={() => onTacticClick(tactic.name)}
                            className={`relative p-4 rounded-xl border transition-all duration-300 ${count > 0
                                    ? 'hover:-translate-y-1 hover:shadow-lg cursor-pointer border-transparent'
                                    : 'border-slate-200 dark:border-slate-700/50 cursor-default opacity-60 hover:opacity-100'
                                }`}
                            style={{ backgroundColor: bgColor || 'rgba(148, 163, 184, 0.05)' }}
                            disabled={count === 0}
                        >
                            <div className="text-center">
                                <p className={`text-xs font-semibold uppercase tracking-wider mb-1 ${count > 0 ? 'text-slate-900 dark:text-white' : 'text-slate-500 dark:text-slate-400'}`}>
                                    {tactic.shortName}
                                </p>
                                <p className={`text-2xl font-bold font-mono ${count > 0 ? 'text-slate-900 dark:text-white' : 'text-slate-400 dark:text-slate-600'}`}>
                                    {count}
                                </p>
                            </div>
                            {count > maxCount * 0.75 && (
                                <div className="absolute top-2 right-2 w-2 h-2 bg-rose-500 rounded-full shadow-[0_0_8px_rgba(244,63,94,0.8)] animate-pulse" />
                            )}
                        </button>
                    );
                })}
            </div>

            {/* Legend */}
            <div className="flex items-center justify-center gap-6 mt-8 pt-6 border-t border-slate-200 dark:border-slate-700/50">
                <div className="flex items-center gap-3">
                    <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Heatmap Intensity:</span>
                    <div className="flex flex-wrap items-center gap-4 text-xs font-medium text-slate-600 dark:text-slate-400">
                        <div className="flex items-center gap-1.5"><div className="w-4 h-4 rounded-md shadow-sm" style={{ backgroundColor: 'rgba(59, 130, 246, 0.3)' }} /> Low</div>
                        <div className="flex items-center gap-1.5"><div className="w-4 h-4 rounded-md shadow-sm" style={{ backgroundColor: 'rgba(234, 179, 8, 0.5)' }} /> Guarded</div>
                        <div className="flex items-center gap-1.5"><div className="w-4 h-4 rounded-md shadow-sm" style={{ backgroundColor: 'rgba(249, 115, 22, 0.7)' }} /> Elevated</div>
                        <div className="flex items-center gap-1.5"><div className="w-4 h-4 rounded-md shadow-sm" style={{ backgroundColor: 'rgba(239, 68, 68, 0.9)' }} /> Critical</div>
                    </div>
                </div>
            </div>
        </div>
    );
});

// Top Techniques Chart
const TopTechniquesChart = React.memo(function TopTechniquesChart({ techniques }: { techniques: { name: string; count: number }[] }) {
    const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'];

    return (
        <div className="relative bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-6 shadow-sm flex flex-col h-[400px]">
            <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-6">
                Top Techniques Detected
            </h3>
            {techniques.length === 0 ? (
                <div className="flex-1 flex items-center justify-center text-slate-500 dark:text-slate-400 text-sm">
                    No technique data available
                </div>
            ) : (
                <div className="flex-1 min-h-0">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={techniques} layout="vertical" margin={{ top: 0, right: 0, left: 10, bottom: 0 }}>
                            <XAxis type="number" tick={{ fontSize: 11, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                            <YAxis
                                dataKey="name"
                                type="category"
                                width={180}
                                tick={{ fontSize: 11, fill: '#94a3b8', fontWeight: 500 }}
                                axisLine={false}
                                tickLine={false}
                                tickFormatter={(value) => value.length > 25 ? value.slice(0, 22) + '...' : value}
                            />
                            <Tooltip
                                cursor={{ fill: 'rgba(148, 163, 184, 0.1)' }}
                                contentStyle={{
                                    backgroundColor: 'rgba(15, 23, 42, 0.9)',
                                    backdropFilter: 'blur(8px)',
                                    border: '1px solid rgba(51, 65, 85, 0.8)',
                                    borderRadius: '12px',
                                    color: 'white',
                                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
                                }}
                            />
                            <Bar dataKey="count" radius={[0, 6, 6, 0]} barSize={24}>
                                {techniques.map((_, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            )}
        </div>
    );
});

// Main Threats Page
export default function Threats() {
    const navigate = useNavigate();
    const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
    const [viewMode, setViewMode] = useState<'matrix' | 'swimlane'>('matrix');


    // Fetch alerts with MITRE data
    const { data, isLoading } = useQuery({
        queryKey: ['alertsWithMitre'],
        queryFn: () => alertsApi.list({ limit: 100 }),
    });

    const alerts = (data?.alerts || []).filter(a =>
        (a.mitre_tactics?.length ?? 0) > 0 || (a.mitre_techniques?.length ?? 0) > 0
    );

    // Calculate tactic counts
    const tacticCounts = useMemo(() => {
        const counts: Record<string, number> = {};
        alerts.forEach((alert) => {
            alert.mitre_tactics?.forEach((tactic) => {
                counts[tactic] = (counts[tactic] || 0) + 1;
            });
        });
        return counts;
    }, [alerts]);

    // Calculate technique counts
    const { techniqueCounts, topTechniques } = useMemo(() => {
        const tc: Record<string, number> = {};
        alerts.forEach((alert) => {
            alert.mitre_techniques?.forEach((tech) => {
                tc[tech] = (tc[tech] || 0) + 1;
            });
        });
        const top = Object.entries(tc)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 8)
            .map(([name, count]) => ({ name, count }));
        return { techniqueCounts: tc, topTechniques: top };
    }, [alerts]);

    // Calculate summary stats
    const { totalTactics, mostCommonTactic, totalTechniques, threatLevel } = useMemo(() => ({
        totalTactics: Object.keys(tacticCounts).length,
        mostCommonTactic: Object.entries(tacticCounts).sort(([, a], [, b]) => b - a)[0],
        totalTechniques: Object.keys(techniqueCounts).length,
        threatLevel: alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length,
    }), [alerts, tacticCounts, techniqueCounts]);

    if (isLoading) {
        return (
            <div className="space-y-6">
                <div className="h-9 w-64 bg-slate-200 dark:bg-slate-700 rounded animate-pulse" />
                <SkeletonKPICards count={4} />
                <SkeletonChart height={300} />
            </div>
        );
    }

    return (
        <div className="relative flex flex-col min-h-[calc(100vh-5rem)] lg:min-h-[calc(100vh-3.5rem)] -mx-4 sm:-mx-6 lg:-mx-8 -my-4 sm:-my-6 lg:-my-8 p-4 sm:p-6 lg:p-8 bg-slate-200 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900 transition-colors">
            {/* Ambient Glow */}
            <div className="absolute top-0 right-0 w-[600px] h-[600px] pointer-events-none mix-blend-screen" style={{ background: 'radial-gradient(circle, rgba(244,63,94,0.05) 0%, transparent 70%)' }} />
            <div className="absolute bottom-0 left-0 w-[600px] h-[600px] pointer-events-none mix-blend-screen" style={{ background: 'radial-gradient(circle, rgba(99,102,241,0.05) 0%, transparent 70%)' }} />

            <div className="relative  w-full space-y-6">
                <PageHeader eyebrow="SOC" title="ATT&amp;CK Analytics" icon={Shield} actions={<>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => setViewMode('matrix')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${viewMode==='matrix'? 'bg-indigo-600 text-white shadow-sm':'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'}`}
                        >
                            MITRE Matrix
                        </button>
                        <button
                            onClick={() => setViewMode('swimlane')}
                            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${viewMode==='swimlane'? 'bg-indigo-600 text-white shadow-sm':'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-700'}`}
                        >
                            Kill Chain
                        </button>
                        <button
                            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg transition-colors shadow-sm shadow-indigo-500/20 ml-2"
                            onClick={() => window.open('https://attack.mitre.org/','_blank')}
                        >
                            <Shield className="w-4 h-4" />
                            Explore Framework
                            <ExternalLink className="w-3.5 h-3.5 ml-1 opacity-70" />
                        </button>
                    </div>
                </>} />

                {/* Summary Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <ThreatSummaryCard
                        title="Tactics Triggered"
                        value={totalTactics}
                        icon={Target}
                        colorTheme={{ bg: 'bg-rose-500/10 dark:bg-rose-500/20', text: 'text-rose-600 dark:text-rose-400', glow: 'bg-rose-500' }}
                        subtitle={`across ${MITRE_TACTICS.length} stages`}
                    />
                    <ThreatSummaryCard
                        title="Top Attacker Goal"
                        value={mostCommonTactic ? mostCommonTactic[0] : 'None'}
                        icon={Shield}
                        colorTheme={{ bg: 'bg-orange-500/10 dark:bg-orange-500/20', text: 'text-orange-600 dark:text-orange-400', glow: 'bg-orange-500' }}
                        subtitle={mostCommonTactic ? `${mostCommonTactic[1]} alert mappings` : 'No vectors identified'}
                    />
                    <ThreatSummaryCard
                        title="Techniques Matched"
                        value={totalTechniques}
                        icon={Eye}
                        colorTheme={{ bg: 'bg-blue-500/10 dark:bg-blue-500/20', text: 'text-blue-600 dark:text-blue-400', glow: 'bg-blue-500' }}
                        subtitle="Distinct behavioral signatures"
                    />
                    <ThreatSummaryCard
                        title="Critical Posture"
                        value={threatLevel}
                        icon={TrendingUp}
                        colorTheme={
                            threatLevel > 10
                                ? { bg: 'bg-rose-500/10 dark:bg-rose-500/20', text: 'text-rose-600 dark:text-rose-400', glow: 'bg-rose-500' }
                                : { bg: 'bg-emerald-500/10 dark:bg-emerald-500/20', text: 'text-emerald-600 dark:text-emerald-400', glow: 'bg-emerald-500' }
                        }
                        subtitle={threatLevel > 10 ? 'Requires immediate attention' : 'Controlled exposure footprint'}
                    />
                </div>

                {/* MITRE View — Matrix or Kill Chain */}
                {viewMode === 'swimlane' ? (
                    <KillChainSwimlane
                        tacticCounts={tacticCounts}
                        onPhaseClick={(tactic) => setSelectedTactic(tactic === selectedTactic ? null : tactic)}
                    />
                ) : (
                    <MitreMatrixHeatmap
                        tacticCounts={tacticCounts}
                        onTacticClick={(tactic) => setSelectedTactic(tactic === selectedTactic ? null : tactic)}
                    />
                )}

                {/* Charts and Alerts */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pb-8">
                    <TopTechniquesChart techniques={topTechniques} />
                    {/* Premium Threat Cards */}
                    <div className="relative bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl shadow-sm flex flex-col h-[420px] overflow-hidden">
                        <div className="p-5 pb-3 border-b border-slate-200 dark:border-slate-700/50 flex items-center justify-between shrink-0 bg-slate-50/50 dark:bg-slate-800/30">
                            <h3 className="text-base font-bold text-slate-900 dark:text-white">{selectedTactic ? `Threats: ${selectedTactic}` : 'Recent Threat Alerts'}</h3>
                            {selectedTactic && <button onClick={() => setSelectedTactic(null)} className="text-xs text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors">Clear</button>}
                        </div>
                        <div className="flex-1 overflow-auto custom-scrollbar p-3 space-y-2">
                            {(selectedTactic
                                ? alerts.filter(a => a.mitre_tactics?.some(t => t.toLowerCase().includes(selectedTactic.toLowerCase())))
                                : alerts.slice(0, 12)
                            ).map(alert => (
                                <PremiumThreatCard
                                    key={alert.id}
                                    alert={alert}
                                    onInvestigate={(tactic) => navigate(`/alerts?tactic=${encodeURIComponent(tactic)}`)}
                                />
                            ))}
                            {alerts.length === 0 && (
                                <div className="h-full flex items-center justify-center text-slate-400 text-sm">No threat alerts found</div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

