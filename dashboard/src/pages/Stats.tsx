import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useState, useMemo } from 'react';
import {
    PieChart, Pie, Cell,
    AreaChart, Area,
    BarChart, Bar, CartesianGrid,
    XAxis, YAxis,
    Tooltip, ResponsiveContainer
} from 'recharts';

import { Download, TrendingUp, Activity, Shield, AlertTriangle, Target, ChevronDown, Server } from 'lucide-react';
import { statsApi, authApi, agentsApi } from '../api/client';




const COLORS = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#22c55e'];

const STATUS_COLORS = {
    open: '#ef4444',
    in_progress: '#f59e0b',
    acknowledged: '#f59e0b',
    resolved: '#22c55e',
};

const DATE_RANGES = [
    { label: 'Last 24 Hours', value: '24h' },
    { label: 'Last 7 Days', value: '7d' },
    { label: 'Last 30 Days', value: '30d' },
    { label: 'Custom', value: 'custom' },
];

function AlertStatusOverview({ data }: { data: Record<string, number> }) {
    const statusItems = [
        { key: 'open', label: 'Open', color: STATUS_COLORS.open },
        { key: 'in_progress', label: 'In Progress', color: STATUS_COLORS.in_progress },
        { key: 'resolved', label: 'Resolved', color: STATUS_COLORS.resolved },
    ];

    const total = Object.values(data).reduce((a, b) => a + b, 0);

    return (
        <div className="card border border-slate-200 dark:border-slate-700/60 shadow-lg dark:shadow-cyan-900/10 bg-white dark:bg-slate-800/90 backdrop-blur-sm rounded-xl h-full flex flex-col">
            <div className="flex items-center justify-between mb-6 relative z-10">
                <h3 className="text-lg font-bold text-slate-800 dark:text-white flex items-center gap-2">
                    <Activity className="w-5 h-5 text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]" />
                    Alert Status Overview
                </h3>
            </div>
            
            <div className="flex-1 flex flex-col justify-center gap-8 border border-slate-200 dark:border-slate-700/40 rounded-xl p-6 bg-slate-50/30 dark:bg-slate-900/40">
                <div className="grid grid-cols-3 gap-4 text-center">
                    {statusItems.map((item) => {
                        const count = data[item.key] || 0;
                        return (
                            <div key={item.key} className="flex flex-col items-center">
                                <p className="text-4xl font-bold font-mono" style={{ color: item.color, textShadow: `0 0 10px ${item.color}40` }}>
                                    {count}
                                </p>
                                <p className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mt-2">{item.label}</p>
                                <p className="text-[10px] text-slate-400 mt-0.5">
                                    {total > 0 ? ((count / total) * 100).toFixed(0) : 0}%
                                </p>
                            </div>
                        );
                    })}
                </div>

                <div className="w-full h-3 bg-slate-200 dark:bg-slate-700/50 rounded-full overflow-hidden flex shadow-inner">
                    {statusItems.map((item) => {
                        const count = data[item.key] || 0;
                        const percentage = total > 0 ? (count / total) * 100 : 0;
                        return (
                            <div
                                key={item.key}
                                className="h-full transition-all duration-1000 ease-out"
                                style={{ width: `${percentage}%`, backgroundColor: item.color }}
                            >
                                <div className="w-full h-full bg-white/20"></div>
                            </div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}

export default function Stats() {
    const navigate = useNavigate();
    const canExport = authApi.canExportStats();
    const [dateRange, setDateRange] = useState('7d');
    const [customFrom, setCustomFrom] = useState('');
    const [customTo, setCustomTo] = useState('');
    const [exportFormat, setExportFormat] = useState('csv');

    // Fetch stats
    const { data: alertStats, isLoading: alertsLoading } = useQuery({
        queryKey: ['alertStats'],
        queryFn: statsApi.alerts,
        refetchInterval: 10000,
    });

    const { data: ruleStats, isLoading: rulesLoading } = useQuery({
        queryKey: ['ruleStats'],
        queryFn: statsApi.rules,
        refetchInterval: 30000,
    });

    const { data: perfStats } = useQuery({
        queryKey: ['performanceStats'],
        queryFn: statsApi.performance,
        refetchInterval: 10000,
    });

    // Compute date range for timeline
    const getDateRange = () => {
        const now = new Date();
        if (dateRange === 'custom') {
            const from = customFrom ? new Date(customFrom).toISOString() : new Date(now.getTime() - 720 * 60 * 60 * 1000).toISOString();
            const to = customTo ? new Date(customTo).toISOString() : now.toISOString();
            const diffHours = (new Date(to).getTime() - new Date(from).getTime()) / (1000 * 60 * 60);
            return { from, to, granularity: diffHours <= 48 ? '1h' : '1d' };
        }
        
        const hours = dateRange === '24h' ? 24 : dateRange === '7d' ? 168 : 720;
        const from = new Date(now.getTime() - hours * 60 * 60 * 1000).toISOString();
        return { from, to: now.toISOString(), granularity: dateRange === '24h' ? '1h' : '1d' };
    };

    const { data: timelineData } = useQuery({
        queryKey: ['statsTimeline', dateRange, customFrom, customTo],
        queryFn: () => statsApi.timeline(getDateRange()),
        refetchInterval: 15000,
    });


    const { data: heatmapData } = useQuery({
        queryKey: ['statsHeatmap30d'],
        queryFn: () => {
            const to = new Date().toISOString();
            const from = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
            return statsApi.timeline({ from, to, granularity: '1d' });
        },
        refetchInterval: 60000,
    });

    // Agent list for top targeted endpoints hostname resolution
    const { data: agentListForStats } = useQuery({
        queryKey: ['agentsForStats'],
        queryFn: () => agentsApi.list({ limit: 200 }),
        refetchInterval: 60000,
    });



    // Transform severity data for pie chart
    const severityData = alertStats?.by_severity
        ? Object.entries(alertStats.by_severity).map(([name, value]) => ({
            name: name.charAt(0).toUpperCase() + name.slice(1),
            value,
        }))
        : [];



    // Top rules from alert frequency mapping
    const topRules = alertStats?.by_rule
        ? Object.entries(alertStats.by_rule)
            .map(([name, count]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), count: count as number }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 5)
        : [];

    // Agent hostname map
    const agentMapForStats = useMemo(() => {
        const m: Record<string, string> = {};
        (agentListForStats?.data || []).forEach(a => { m[a.id] = a.hostname; });
        return m;
    }, [agentListForStats]);

    // Heatmap cells (last 30 days)
    const heatmapCells = useMemo(() => {
        const map: Record<string, number> = {};
        (heatmapData?.data || []).forEach(p => {
            const day = new Date(p.timestamp).toISOString().slice(0, 10);
            map[day] = (p.critical || 0) + (p.high || 0) + (p.medium || 0) + (p.low || 0) + (p.informational || 0);
        });
        const cells: { date: string; count: number; label: string }[] = [];
        for (let i = 29; i >= 0; i--) {
            const d = new Date(Date.now() - i * 86400000);
            const key = d.toISOString().slice(0, 10);
            cells.push({ date: key, count: map[key] || 0, label: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) });
        }
        return cells;
    }, [heatmapData]);



    // Top targeted endpoints from by_agent
    const topEndpoints = useMemo(() => {
        const byAgent = alertStats?.by_agent || {};
        return Object.entries(byAgent)
            .sort(([, a], [, b]) => (b as number) - (a as number))
            .slice(0, 5)
            .map(([id, count]) => ({ id, hostname: agentMapForStats[id] || id.slice(0, 12) + '...', count: count as number }));
    }, [alertStats, agentMapForStats]);

    // Area chart multi-series data
    const areaChartData = useMemo(() => {
        return (timelineData?.data || []).map(p => ({
            name: new Date(p.timestamp).toLocaleDateString('en-US', dateRange === '24h' ? { hour: '2-digit' } : { month: 'short', day: 'numeric' }),
            critical: p.critical || 0,
            high: p.high || 0,
            medium: p.medium || 0,
        }));
    }, [timelineData, dateRange]);

    if (alertsLoading || rulesLoading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
            </div>
        );
    }

    return (
        <div>
            <div className="flex justify-between items-center mb-8">
                <div className="flex flex-col">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">SOC</div>
                    <h1 className="text-xl font-bold text-slate-900 dark:text-white">Statistics</h1>
                </div>

                {/* Export Controls */}
                <div className="flex items-center gap-4">
                    <div className="relative">
                        <select
                            value={dateRange}
                            onChange={(e) => setDateRange(e.target.value)}
                            className="appearance-none bg-slate-900/60 border border-slate-700 text-slate-200 rounded-lg pl-4 pr-10 py-2 hover:bg-slate-800 focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 focus:outline-none transition-all cursor-pointer font-medium text-sm w-40"
                        >
                            {DATE_RANGES.map((range) => (
                                <option key={range.value} value={range.value}>
                                    {range.label}
                                </option>
                            ))}
                        </select>
                        <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-slate-400">
                            <ChevronDown className="w-4 h-4" />
                        </div>
                    </div>

                    {dateRange === 'custom' && (
                        <div className="flex items-center gap-2">
                            <input 
                                type="date" 
                                value={customFrom}
                                onChange={(e) => setCustomFrom(e.target.value)}
                                className="bg-slate-900/60 border border-slate-700 text-slate-200 rounded-lg px-3 py-2 hover:bg-slate-800 focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 focus:outline-none transition-all text-sm w-36"
                            />
                            <span className="text-slate-500">to</span>
                            <input 
                                type="date" 
                                value={customTo}
                                onChange={(e) => setCustomTo(e.target.value)}
                                className="bg-slate-900/60 border border-slate-700 text-slate-200 rounded-lg px-3 py-2 hover:bg-slate-800 focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 focus:outline-none transition-all text-sm w-36"
                            />
                        </div>
                    )}

                    {canExport && (
                        <>
                            <div className="relative">
                                <select
                                    value={exportFormat}
                                    onChange={(e) => setExportFormat(e.target.value)}
                                    className="appearance-none bg-slate-900/60 border border-slate-700 text-slate-200 rounded-lg pl-4 pr-10 py-2 hover:bg-slate-800 focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 focus:outline-none transition-all cursor-pointer font-medium text-sm w-28"
                                >
                                    <option value="csv">CSV</option>
                                    <option value="pdf">PDF</option>
                                    <option value="json">JSON</option>
                                </select>
                                <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-slate-400">
                                    <ChevronDown className="w-4 h-4" />
                                </div>
                            </div>

                            <button onClick={() => console.log(`Export: format=${exportFormat}, range=${dateRange}`)} className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-md hover:shadow-cyan-500/25 transition-all rounded-lg px-5 py-2 text-sm font-semibold flex items-center gap-2">
                                <Download className="w-4 h-4" />
                                Export
                            </button>
                        </>
                    )}
                </div>
            </div>

            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-sm dark:shadow-slate-900/20 rounded-xl">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-red-100 dark:bg-red-900 rounded-lg">
                            <AlertTriangle className="w-5 h-5 text-red-600" />
                        </div>
                        <div>
                            <p className="text-sm text-slate-500">Total Alerts</p>
                            <p className="text-2xl font-bold">{alertStats?.total_alerts || 0}</p>
                        </div>
                    </div>
                </div>

                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-sm dark:shadow-slate-900/20 rounded-xl">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
                            <Shield className="w-5 h-5 text-blue-600" />
                        </div>
                        <div>
                            <p className="text-sm text-slate-500">Active Rules</p>
                            <p className="text-2xl font-bold">{ruleStats?.enabled_rules || 0}</p>
                        </div>
                    </div>
                </div>

                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-sm dark:shadow-slate-900/20 rounded-xl">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-green-100 dark:bg-green-900 rounded-lg">
                            <Activity className="w-5 h-5 text-green-600" />
                        </div>
                        <div>
                            <p className="text-sm text-slate-500">Events/Sec</p>
                            <p className="text-2xl font-bold">{perfStats?.events_per_second?.toFixed(1) || 0}</p>
                        </div>
                    </div>
                </div>

                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-sm dark:shadow-slate-900/20 rounded-xl">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-purple-100 dark:bg-purple-900 rounded-lg">
                            <TrendingUp className="w-5 h-5 text-purple-600" />
                        </div>
                        <div>
                            <p className="text-sm text-slate-500">Avg Risk (normalized)</p>
                            <p className="text-2xl font-bold">{((alertStats?.avg_confidence || 0) * 100).toFixed(1)}%</p>
                        </div>
                    </div>
                </div>

                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-sm dark:shadow-slate-900/20 rounded-xl">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-cyan-100 dark:bg-cyan-900 rounded-lg">
                            <Target className="w-5 h-5 text-cyan-600" />
                        </div>
                        <div>
                            <p className="text-sm text-slate-500">Unique Rules Fired</p>
                            <p className="text-2xl font-bold">{Object.keys(alertStats?.by_rule || {}).length || 0}</p>

                        </div>
                    </div>
                </div>


                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-sm dark:shadow-slate-900/20 rounded-xl">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-indigo-100 dark:bg-indigo-900 rounded-lg">
                            <Shield className="w-5 h-5 text-indigo-600" />
                        </div>
                        <div>
                            <p className="text-sm text-slate-500">MITRE Tactics Seen</p>
                            <p className="text-2xl font-bold">{Object.keys(alertStats?.by_tactic || {}).length || 0}</p>
                        </div>
                    </div>
                </div>

            </div>

            {/* Charts Row — Area Chart + Donut */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                {/* Multi-Series Area Chart */}
                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-lg bg-white dark:bg-slate-800/90 backdrop-blur-sm rounded-xl">
                    <div className="flex justify-between items-center mb-4">
                        <h3 className="text-base font-bold text-slate-800 dark:text-white flex items-center gap-2">
                            <Activity className="w-4 h-4 text-cyan-400" />
                            Alert Trend <span className="text-sm font-normal text-slate-500">({dateRange})</span>
                        </h3>
                        <div className="flex gap-3 text-[11px] font-medium">
                            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-500" />Critical</span>
                            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-400" />High</span>
                            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-400" />Medium</span>
                        </div>
                    </div>
                    {areaChartData.length === 0 ? (
                        <div className="h-[220px] flex items-center justify-center text-slate-500 text-sm">No timeline data</div>
                    ) : (
                        <ResponsiveContainer width="100%" height={220}>
                            <AreaChart data={areaChartData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5} />
                                        <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                                    </linearGradient>
                                    <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#f97316" stopOpacity={0.4} />
                                        <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                                    </linearGradient>
                                    <linearGradient id="gradMedium" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                                <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                                <Tooltip
                                    contentStyle={{ background: 'rgba(15,23,42,0.95)', border: '1px solid rgba(30,48,72,0.8)', borderRadius: '10px', color: 'white', fontSize: '12px' }}
                                />
                                <Area type="monotone" dataKey="medium" stackId="1" stroke="#f59e0b" strokeWidth={1.5} fill="url(#gradMedium)" />
                                <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" strokeWidth={1.5} fill="url(#gradHigh)" />
                                <Area type="monotone" dataKey="critical" stackId="1" stroke="#f43f5e" strokeWidth={2} fill="url(#gradCritical)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    )}
                </div>

                {/* Severity Donut */}
                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-sm rounded-xl">
                    <h3 className="text-base font-bold text-slate-800 dark:text-white mb-4 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-rose-400" /> Severity Distribution
                    </h3>
                    <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                            <Pie
                                data={severityData}
                                cx="50%" cy="50%"
                                innerRadius={55} outerRadius={85}
                                paddingAngle={3}
                                dataKey="value"
                                labelLine={false}
                                label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}
                            >
                                {severityData.map((_, i) => (
                                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                                ))}
                            </Pie>
                            <Tooltip contentStyle={{ background: 'rgba(15,23,42,0.95)', border: '1px solid rgba(30,48,72,0.8)', borderRadius: '10px', color: 'white', fontSize: '12px' }} />
                        </PieChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Heatmap + Top Endpoints Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                {/* Alert Volume Bar Chart */}
                <div className="lg:col-span-2 card border border-slate-200 dark:border-slate-700/60 shadow-lg bg-white dark:bg-slate-800/90 rounded-xl">
                    <h3 className="text-base font-bold text-slate-800 dark:text-white mb-4 flex items-center gap-2">
                        <Activity className="w-4 h-4 text-cyan-400" /> 30-Day Alert Volume
                    </h3>
                    {heatmapCells.length === 0 ? (
                        <div className="h-[200px] flex items-center justify-center text-slate-500 text-sm">No volume data</div>
                    ) : (
                        <ResponsiveContainer width="100%" height={200}>
                            <BarChart data={heatmapCells} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(148,163,184,0.1)" />
                                <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                                <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} axisLine={false} tickLine={false} />
                                <Tooltip
                                    contentStyle={{ background: 'rgba(15,23,42,0.95)', border: '1px solid rgba(30,48,72,0.8)', borderRadius: '10px', color: 'white', fontSize: '12px' }}
                                    cursor={{ fill: 'rgba(148,163,184,0.1)' }}
                                />
                                <Bar dataKey="count" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </div>

                {/* Top Targeted Endpoints */}
                <div className="card border border-slate-200 dark:border-slate-700/60 shadow-lg bg-white dark:bg-slate-800/90 rounded-xl">
                    <h3 className="text-base font-bold text-slate-800 dark:text-white mb-4 flex items-center gap-2">
                        <Server className="w-4 h-4 text-rose-400" /> Top Targeted Endpoints
                    </h3>
                    {topEndpoints.length === 0 ? (
                        <div className="flex items-center justify-center h-28 text-slate-400 text-sm">No endpoint alert data</div>
                    ) : (
                        <div className="space-y-3">
                            {topEndpoints.map((ep, i) => {
                                const maxCount = topEndpoints[0]?.count || 1;
                                return (
                                    <div key={ep.id}>
                                        <div className="flex justify-between items-center mb-1">
                                            <div className="flex items-center gap-2">
                                                <span className="text-[10px] font-bold font-mono text-slate-400 w-4">#{i+1}</span>
                                                <span className="text-xs font-semibold text-slate-700 dark:text-slate-200 font-mono truncate max-w-[120px]" title={ep.hostname}>{ep.hostname}</span>
                                            </div>
                                            <span className="text-xs font-bold text-rose-500 dark:text-rose-400 font-mono">{ep.count}</span>
                                        </div>
                                        <div className="h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                                            <div
                                                className="h-full rounded-full transition-all duration-700"
                                                style={{ width: `${(ep.count / maxCount) * 100}%`, background: 'linear-gradient(to right, #f43f5e, #f97316)' }}
                                            />
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>

            {/* Main Data Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                {/* Top Rules - Modern SaaS Redesign */}
                <div className="lg:col-span-2 card relative overflow-hidden border border-slate-200 dark:border-slate-700/60 shadow-lg dark:shadow-cyan-900/10 bg-white dark:bg-slate-800/90 backdrop-blur-sm rounded-xl h-full flex flex-col">
                    {/* Subtle background glow */}
                    <div className="absolute top-0 right-0 w-64 h-64 -z-10 mix-blend-screen pointer-events-none" style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.05) 0%, transparent 70%)' }}></div>

                    <div className="flex items-center justify-between mb-6 relative z-10 shrink-0">
                        <h3 className="text-lg font-bold text-slate-800 dark:text-white flex items-center gap-2">
                            <Target className="w-5 h-5 text-cyan-400 drop-shadow-[0_0_5px_rgba(34,211,238,0.5)]" />
                            Top Triggered Rules
                        </h3>
                    </div>
                    
                    <div className="flex-1 border border-slate-200 dark:border-slate-700/40 rounded-xl p-6 bg-slate-50/30 dark:bg-slate-900/40 relative z-10 box-border flex flex-col justify-center">
                        <div className="space-y-6">
                            {topRules.length === 0 ? (
                                <div className="flex items-center justify-center h-40 text-slate-500">No rule data available.</div>
                            ) : (
                                topRules.map((rule, idx) => {
                                    const maxCount = Math.max(...topRules.map(r => r.count), 1);
                                    const percentage = (rule.count / maxCount) * 100;
                                    return (
                                        <div key={idx} className="relative group">
                                            <div className="flex justify-between items-end mb-2">
                                                <div className="flex items-center gap-2">
                                                    <span className="text-sm font-semibold text-slate-700 dark:text-slate-200 group-hover:text-cyan-400 transition-colors drop-shadow-sm">
                                                        {rule.name}
                                                    </span>
                                                </div>
                                                <span className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-1.5 drop-shadow-sm">
                                                    {rule.count}
                                                    <span className="text-xs font-normal text-slate-500 dark:text-slate-400">alerts</span>
                                                </span>
                                            </div>
                                            <div className="h-2.5 w-full bg-slate-200 dark:bg-slate-800/80 rounded-full overflow-hidden shadow-inner flex border border-slate-300 dark:border-slate-700/50 relative">
                                                <div 
                                                    className="h-full bg-gradient-to-r from-blue-600 to-cyan-400 rounded-full relative transition-all duration-1000 ease-out flex items-center justify-end"
                                                    style={{ width: `${percentage}%` }}
                                                >
                                                    {/* Glowing continuous Hover Pulse */}
                                                    <div className="absolute top-0 bottom-0 left-0 right-0 bg-white/20 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                                                    
                                                    {/* Glowing Leading Edge */}
                                                    <div className="w-4 h-full bg-white opacity-40 blur-[2px] rounded-full mr-0.5 shadow-[0_0_8px_rgba(255,255,255,0.8)]"></div>
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })
                            )}
                        </div>
                    </div>
                </div>

                <div className="lg:col-span-1 h-full">
                    <AlertStatusOverview data={alertStats?.by_status || {}} />
                </div>
            </div>

            {/* Performance Metrics */}
            <div className="card border border-slate-200 dark:border-slate-700/60 shadow-sm dark:shadow-slate-900/20 bg-white dark:bg-slate-800 rounded-xl">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold text-slate-800 dark:text-white">Performance & Reliability</h3>
                    <div className="flex items-center gap-3">
                        <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                            Sigma Engine
                        </span>
                        <button
                            onClick={() => navigate('/settings/reliability')}
                            className="text-[11px] font-semibold px-2.5 py-1 rounded-md border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-900/40 transition-colors"
                        >
                            View Ingestion Reliability
                        </button>
                    </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="flex flex-col items-center justify-center p-6 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-100 dark:border-slate-700/60 transition-all hover:shadow-md hover:border-blue-500/30">
                        <p className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Avg Latency</p>
                        <p className="text-2xl font-bold text-slate-900 dark:text-white">{perfStats?.avg_event_latency_ms?.toFixed(2) || 0}<span className="text-sm font-medium text-slate-400 ml-1">ms</span></p>
                    </div>
                    <div className="flex flex-col items-center justify-center p-6 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-100 dark:border-slate-700/60 transition-all hover:shadow-md hover:border-blue-500/30">
                        <p className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Rule Match Time</p>
                        <p className="text-2xl font-bold text-slate-900 dark:text-white">{perfStats?.avg_rule_matching_ms?.toFixed(2) || 0}<span className="text-sm font-medium text-slate-400 ml-1">ms</span></p>
                    </div>
                    <div className="flex flex-col items-center justify-center p-6 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-100 dark:border-slate-700/60 transition-all hover:shadow-md hover:border-blue-500/30">
                        <p className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">DB Query Time</p>
                        <p className="text-2xl font-bold text-slate-900 dark:text-white">{perfStats?.avg_database_query_ms?.toFixed(2) || 0}<span className="text-sm font-medium text-slate-400 ml-1">ms</span></p>
                    </div>
                    <div className="flex flex-col items-center justify-center p-6 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-100 dark:border-slate-700/60 transition-all hover:shadow-md hover:border-rose-500/30">
                        <p className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Error Rate</p>
                        <p className="text-2xl font-bold text-slate-900 dark:text-white">{((perfStats?.error_rate || 0) * 100).toFixed(3)}<span className="text-sm font-medium text-slate-400 ml-1">%</span></p>
                    </div>

                    <div className="flex flex-col items-center justify-center p-6 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-100 dark:border-slate-700/60 transition-all hover:shadow-md hover:border-amber-500/30">
                        <p className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Alert Fallback Used</p>
                        <p className="text-2xl font-bold text-slate-900 dark:text-white font-mono">
                            {perfStats?.alert_fallback_used ?? 0}
                        </p>
                        <p className="text-[11px] text-slate-400 mt-1 text-center">
                            Fallback delivery when internal channel saturated
                        </p>
                    </div>

                    <div className="flex flex-col items-center justify-center p-6 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-100 dark:border-slate-700/60 transition-all hover:shadow-md hover:border-red-500/30">
                        <p className="text-sm font-medium text-slate-500 dark:text-slate-400 mb-1">Alerts Dropped</p>
                        <p className="text-2xl font-bold text-slate-900 dark:text-white font-mono">
                            {perfStats?.alerts_dropped ?? 0}
                        </p>
                        <p className="text-[11px] text-slate-400 mt-1 text-center">
                            Non‑zero indicates potential alert data loss
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
}

