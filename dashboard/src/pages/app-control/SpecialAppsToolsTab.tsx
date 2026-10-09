import React, { useEffect, useMemo, useState } from 'react';
import {
    Terminal, KeyRound, Wrench, Cog, AlertTriangle,
    RefreshCw, Search, ChevronDown, ChevronRight,
    Package, Shield,
} from 'lucide-react';
import { useProcessAnalytics } from './useProcessAnalytics';
import { type ProcessCategory, type ProcessAggRow } from './types';
import { isHighAttention } from './classifyProcess';
import HostsCell from './HostsCell';

// ────────────────────────────────────────────────────────────────────────────
// Special Applications & Tools Tab
//
// Maps to WatchGuard "Special Applications & Tools" tab:
//   - Scripting Applications Executed (+ by Machine and User)
//   - Remote Access Applications Executed (+ by Machine and User)
//   - Admin Tools Executed (+ by Machine and User)
//   - System Tools Executed (+ by Machine and User)
//   - System Internal Tools (+ by Machine and User)
//   - Unwanted Freeware Applications (+ by Machine and User)
//
// Uses the same process-analytics data as the ProcessAnalyticsTab,
// but organises it into per-category drill-down sections.
// ────────────────────────────────────────────────────────────────────────────

/** Configuration for each special-apps section. */
interface SectionConfig {
    id: string;
    category: ProcessCategory;
    label: string;
    description: string;
    icon: React.ElementType;
    accent: string;
    dotColor: string;
}

const SECTIONS: SectionConfig[] = [
    {
        id: 'scripting',
        category: 'scripting',
        label: 'Scripting Applications',
        description: 'Script interpreters and engines — PowerShell, CMD, Python, WSH, Node.js',
        icon: Terminal,
        accent: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
        dotColor: 'bg-amber-500',
    },
    {
        id: 'remote_access',
        category: 'remote_access',
        label: 'Remote Access Applications',
        description: 'RDP, SSH, TeamViewer, AnyDesk, PsExec, and other remote tools',
        icon: KeyRound,
        accent: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20',
        dotColor: 'bg-rose-500',
    },
    {
        id: 'admin',
        category: 'admin',
        label: 'Admin & Recon Tools',
        description: 'System admin tools — regedit, net, sc, certutil, whoami, schtasks',
        icon: Wrench,
        accent: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
        dotColor: 'bg-orange-500',
    },
    {
        id: 'system',
        category: 'system',
        label: 'System Services & Internal Tools',
        description: 'Core OS processes — svchost, csrss, lsass, dwm, explorer, and others',
        icon: Cog,
        accent: 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20',
        dotColor: 'bg-slate-400',
    },
    {
        id: 'security',
        category: 'security',
        label: 'Security Tools',
        description: 'Security solutions — Sysmon, MITRAS Agent, Trivy, Windows Defender',
        icon: Shield,
        accent: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20',
        dotColor: 'bg-emerald-500',
    },
    {
        id: 'unknown',
        category: 'unknown',
        label: 'Uncategorised / Freeware',
        description: 'Applications not in the known classification set — may include freeware, unrecognised, or third-party tools',
        icon: Package,
        accent: 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20',
        dotColor: 'bg-indigo-500',
    },
];

// ─── Collapsible section ─────────────────────────────────────────────────────

function ToolSection({ config, rows }: { config: SectionConfig; rows: ProcessAggRow[] }) {
    const [expanded, setExpanded] = useState(
        // Auto-expand high-attention categories
        config.category === 'scripting' || config.category === 'remote_access' || config.category === 'admin'
    );
    const [page, setPage] = useState(1);
    const pageSize = 10;

    const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
    useEffect(() => {
        if (page > totalPages) setPage(totalPages);
    }, [page, totalPages]);
    useEffect(() => {
        // reset when collapsing/expanding or data changes
        setPage(1);
    }, [expanded, rows.length]);
    const pageRows = useMemo(() => {
        const start = (page - 1) * pageSize;
        return rows.slice(start, start + pageSize);
    }, [rows, page]);

    const totalExecs = rows.reduce((s, r) => s + r.count, 0);
    const uniqueHosts = new Set(rows.flatMap(r => r.hostnames)).size;
    const Icon = config.icon;

    return (
        <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900/60 overflow-hidden shadow-sm transition-all">
            {/* Header (click to expand) */}
            <button
                onClick={() => setExpanded(e => !e)}
                className="w-full px-4 py-3.5 flex items-center gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors text-left"
            >
                <div className={`p-2 rounded-lg shrink-0 ${config.accent}`}>
                    <Icon className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                        <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">{config.label}</h3>
                        {isHighAttention(config.category) && (
                            <span className="px-1.5 py-0.5 text-[9px] font-bold uppercase rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/25">
                                attention
                            </span>
                        )}
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{config.description}</p>
                </div>
                <div className="flex items-center gap-4 shrink-0">
                    <div className="text-right">
                        <p className="text-xs font-bold text-slate-700 dark:text-slate-300">{rows.length} <span className="font-normal text-slate-400">exe</span></p>
                        <p className="text-[10px] text-slate-400">{totalExecs.toLocaleString()} exec</p>
                    </div>
                    <div className="text-right">
                        <p className="text-xs font-bold text-slate-700 dark:text-slate-300">{uniqueHosts} <span className="font-normal text-slate-400">hosts</span></p>
                    </div>
                    {expanded
                        ? <ChevronDown className="w-4 h-4 text-slate-400" />
                        : <ChevronRight className="w-4 h-4 text-slate-400" />}
                </div>
            </button>

            {/* Expanded content */}
            {expanded && (
                <div className="border-t border-slate-200 dark:border-slate-700">
                    {rows.length === 0 ? (
                        <div className="px-4 py-8 text-center text-xs text-slate-400">
                            No {config.label.toLowerCase()} detected in the last 24 hours.
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-sm border-collapse">
                                <thead>
                                    <tr className="bg-slate-50/80 dark:bg-slate-800/40">
                                        <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Process</th>
                                        <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 text-right">Executions</th>
                                        <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 text-center">Hosts</th>
                                        <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Last Seen</th>
                                        <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Path</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {pageRows.map((row, i) => (
                                        <tr
                                            key={row.name}
                                            className={`border-t border-slate-100 dark:border-slate-800/60 transition-colors hover:bg-cyan-500/5 dark:hover:bg-slate-800/40 ${
                                                i % 2 === 1 ? 'bg-slate-50/40 dark:bg-slate-800/20' : ''
                                            }`}
                                        >
                                            <td className="px-4 py-2">
                                                <div className="flex items-center gap-2">
                                                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${config.dotColor}`} />
                                                    <span className="font-mono text-xs font-semibold text-slate-900 dark:text-white">{row.name}</span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-2 tabular-nums text-right font-semibold text-slate-700 dark:text-slate-300 text-xs">
                                                {row.count.toLocaleString()}
                                            </td>
                                            <td className="px-4 py-2 tabular-nums text-center text-slate-600 dark:text-slate-400 text-xs">
                                                <HostsCell hostnames={row.hostnames} fallbackCount={0} />
                                            </td>
                                            <td className="px-4 py-2 text-xs text-slate-500 whitespace-nowrap">
                                                {new Date(row.lastSeen).toLocaleString()}
                                            </td>
                                            <td className="px-4 py-2 text-xs text-slate-400 max-w-[280px] truncate font-mono" title={row.executable}>
                                                {row.executable || '—'}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                            <div className="flex items-center justify-between px-4 py-2 border-t border-slate-200 dark:border-slate-700 text-[11px] text-slate-500">
                                <span>
                                    Page {page} / {totalPages} · Showing {pageRows.length} of {rows.length}
                                </span>
                                <div className="flex items-center gap-2">
                                    <button
                                        type="button"
                                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                                        disabled={page <= 1}
                                        className="px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-600 disabled:opacity-50"
                                    >
                                        Prev
                                    </button>
                                    <button
                                        type="button"
                                        onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                                        disabled={page >= totalPages}
                                        className="px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-600 disabled:opacity-50"
                                    >
                                        Next
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// ─── Summary KPI card ────────────────────────────────────────────────────────

function SummaryKPI({ label, value, sub, icon: Icon, accent }: {
    label: string; value: string | number; sub?: string;
    icon: React.ElementType; accent: string;
}) {
    return (
        <div className={`rounded-xl border p-4 flex items-center gap-3 ${accent} bg-white/60 dark:bg-slate-900/40 backdrop-blur-md shadow-sm`}>
            <div className={`p-2 rounded-lg ${accent}`}>
                <Icon className="w-4 h-4" />
            </div>
            <div>
                <p className="text-[11px] font-bold uppercase tracking-widest text-slate-500 dark:text-slate-400">{label}</p>
                <p className="text-xl font-extrabold text-slate-900 dark:text-white leading-none mt-0.5">{value}</p>
                {sub && <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">{sub}</p>}
            </div>
        </div>
    );
}

// ─── Main component ──────────────────────────────────────────────────────────

export default function SpecialAppsToolsTab() {
    const { rows, isLoading, isError, refetch, isFetching } = useProcessAnalytics();
    const [search, setSearch] = useState('');

    // Group rows by category
    const grouped = useMemo(() => {
        const map = new Map<ProcessCategory, ProcessAggRow[]>();
        for (const section of SECTIONS) {
            map.set(section.category, []);
        }
        for (const row of rows) {
            const existing = map.get(row.category);
            if (existing) {
                existing.push(row);
            } else {
                // Put in 'unknown' bucket
                map.get('unknown')?.push(row);
            }
        }
        return map;
    }, [rows]);

    // KPI totals
    const kpis = useMemo(() => {
        const scripting = grouped.get('scripting') ?? [];
        const remote = grouped.get('remote_access') ?? [];
        const admin = grouped.get('admin') ?? [];
        const security = grouped.get('security') ?? [];
        return {
            scriptingExecs: scripting.reduce((s, r) => s + r.count, 0),
            remoteExecs: remote.reduce((s, r) => s + r.count, 0),
            adminExecs: admin.reduce((s, r) => s + r.count, 0),
            securityExecs: security.reduce((s, r) => s + r.count, 0),
            totalHighAttention: rows.filter(r => isHighAttention(r.category)).length,
        };
    }, [rows, grouped]);

    // Apply search filter across all sections
    const filteredGrouped = useMemo(() => {
        if (!search.trim()) return grouped;
        const q = search.toLowerCase();
        const filtered = new Map<ProcessCategory, ProcessAggRow[]>();
        for (const [cat, catRows] of grouped) {
            filtered.set(cat, catRows.filter(r =>
                r.name.includes(q) ||
                r.executable.toLowerCase().includes(q)
            ));
        }
        return filtered;
    }, [grouped, search]);

    // Loading
    if (isLoading) {
        return (
            <div className="flex items-center justify-center py-20 text-slate-500 gap-2">
                <RefreshCw className="w-5 h-5 animate-spin" /> Loading special applications…
            </div>
        );
    }

    // Error
    if (isError) {
        return (
            <div className="rounded-xl border border-rose-200 dark:border-rose-900/50 p-6 text-center space-y-2">
                <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
                <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">Failed to load process data</p>
                <button onClick={refetch} className="mt-2 px-4 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 text-white hover:bg-slate-700 transition-colors">
                    Retry
                </button>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* KPI summary row */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <SummaryKPI label="Scripting" value={kpis.scriptingExecs.toLocaleString()}
                    sub={`${(grouped.get('scripting') ?? []).length} unique`}
                    icon={Terminal} accent="bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20" />
                <SummaryKPI label="Remote Access" value={kpis.remoteExecs.toLocaleString()}
                    sub={`${(grouped.get('remote_access') ?? []).length} unique`}
                    icon={KeyRound} accent="bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20" />
                <SummaryKPI label="Admin Tools" value={kpis.adminExecs.toLocaleString()}
                    sub={`${(grouped.get('admin') ?? []).length} unique`}
                    icon={Wrench} accent="bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20" />
                <SummaryKPI label="Security" value={kpis.securityExecs.toLocaleString()}
                    sub={`${(grouped.get('security') ?? []).length} unique`}
                    icon={Shield} accent="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20" />
                <SummaryKPI label="Attention-Worthy" value={kpis.totalHighAttention}
                    sub="Unique executables"
                    icon={AlertTriangle} accent="bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20" />
            </div>

            {/* Search bar */}
            <div className="flex items-center gap-3">
                <div className="relative w-full sm:w-72">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                    <input
                        type="text"
                        placeholder="Filter across all categories…"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        className="w-full pl-9 pr-4 py-2 text-sm bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-violet-500/40"
                    />
                </div>
                <button
                    onClick={refetch}
                    disabled={isFetching}
                    className="flex items-center gap-2 px-3 py-2 bg-slate-800 dark:bg-slate-700 hover:bg-slate-700 dark:hover:bg-slate-600 disabled:opacity-50 text-white text-xs font-medium rounded-lg transition-colors shadow-sm ml-auto"
                >
                    <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin' : ''}`} />
                    Refresh
                </button>
            </div>

            {/* Section panels */}
            <div className="space-y-4">
                {SECTIONS.map(section => {
                    const sectionRows = filteredGrouped.get(section.category) ?? [];
                    return (
                        <ToolSection
                            key={section.id}
                            config={section}
                            rows={sectionRows}
                        />
                    );
                })}
            </div>
        </div>
    );
}
