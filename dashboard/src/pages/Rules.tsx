import { usePaginatedQuery } from '../hooks/usePaginatedQuery';
import { usePageSearch } from '../hooks/usePageSearch';
import { PaginationControls } from '../components/PaginationControls';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, useMemo } from 'react';
import {
    Plus, Search, Edit, Trash2, Shield, ChevronDown,
    Activity, CheckCircle, XCircle, Zap, Target
} from 'lucide-react';
import { rulesApi, statsApi, authApi, type Rule } from '../api/client';
import { RuleEditorModal } from './rules/RuleEditorModal';

// ── iOS-style toggle switch ──────────────────────────────────────────────────
function ToggleSwitch({
    checked,
    onChange,
    disabled = false,
    pending = false,
}: {
    checked: boolean;
    onChange: () => void;
    disabled?: boolean;
    pending?: boolean;
}) {
    return (
        <button
            type="button"
            onClick={onChange}
            disabled={disabled || pending}
            className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-all duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500/50 ${ checked ? 'bg-emerald-500' : 'bg-slate-300 dark:bg-slate-600' } ${ disabled || pending ? 'opacity-50 cursor-not-allowed' : '' }`}
            title={checked ? 'Disable rule' : 'Enable rule'}
        >
            <span className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-sm ring-0 transition-transform duration-200 ${ checked ? 'translate-x-4' : 'translate-x-0' }`}>
                {pending && (
                    <span className="absolute inset-0 flex items-center justify-center">
                        <span className="w-2.5 h-2.5 border border-slate-400 border-t-transparent rounded-full animate-spin" />
                    </span>
                )}
            </span>
        </button>
    );
}

// ── Alert-fire mini-bar for a rule ───────────────────────────────────────────
function AlertFireBar({ count, max }: { count: number; max: number }) {
    const pct = max === 0 ? 0 : Math.max(4, Math.round((count / max) * 100));
    const color = count === 0 ? 'bg-slate-200 dark:bg-slate-700' :
                  count > max * 0.6 ? 'bg-rose-500' :
                  count > max * 0.3 ? 'bg-amber-400' : 'bg-emerald-500';
    return (
        <div className="flex items-center gap-2 min-w-[80px]">
            <div className="flex-1 h-1.5 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
            </div>
            <span className="text-[11px] font-mono font-semibold text-slate-500 dark:text-slate-400 w-5 text-right">
                {count > 999 ? '999+' : count}
            </span>
        </div>
    );
}

// ── Severity color maps ───────────────────────────────────────────────────────
const SEV_BADGE: Record<string, string> = {
    critical: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20',
    high:     'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
    medium:   'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
    low:      'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
};

const SEV_BAR: Record<string, string> = {
    critical: 'bg-rose-500',
    high:     'bg-orange-500',
    medium:   'bg-amber-400',
    low:      'bg-blue-400',
};

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Rules() {
    const queryClient = useQueryClient();
    const canWrite = authApi.canWriteRules();
    const pager = usePaginatedQuery<Rule>({ name: 'rules', defaults: { sort: 'title', order: 'asc' }, fetchPage: rulesApi.page });
    const [searchTerm, setSearchTerm] = usePageSearch(pager.params, pager.setFilters);
    const isLoading = pager.isLoading;
    const [showModal, setShowModal] = useState(false);
    const [editingRule, setEditingRule] = useState<Rule | null>(null);
    const enabledFilter = pager.params.enabled === 'true' ? true : pager.params.enabled === 'false' ? false : undefined;
    const setEnabledFilter = (value: boolean | undefined) => pager.setFilters({ enabled: value === undefined ? '' : String(value) });
    const sortBySeverity = pager.params.sort === 'severity';
    const setSortBySeverity = (value: boolean) => pager.setFilters({ sort: value ? 'severity' : 'title', order: 'asc' });
    const [pendingId, setPendingId] = useState<string | null>(null);

    // Fetch rule stats (enabled/disabled/by_severity)
    const { data: ruleStats } = useQuery({
        queryKey: ['ruleStats'],
        queryFn: statsApi.rules,
        refetchInterval: 30000,
    });

    // Fetch alert stats — gives us by_rule counts for the sparklines
    const { data: alertStats } = useQuery({
        queryKey: ['alertStatsForRules'],
        queryFn: statsApi.alerts,
        refetchInterval: 30000,
    });

    const byRule = useMemo(() => alertStats?.by_rule || {}, [alertStats?.by_rule]);
    const maxFires = useMemo(() => Math.max(1, ...Object.values(byRule) as number[]), [byRule]);

    // Enable/Disable mutations
    const enableMutation = useMutation({
        mutationFn: (id: string) => rulesApi.enable(id),
        onSettled: () => {
            setPendingId(null);
            queryClient.invalidateQueries({ queryKey: ['rules'] });
            queryClient.invalidateQueries({ queryKey: ['ruleStats'] });
        },
    });

    const disableMutation = useMutation({
        mutationFn: (id: string) => rulesApi.disable(id),
        onSettled: () => {
            setPendingId(null);
            queryClient.invalidateQueries({ queryKey: ['rules'] });
            queryClient.invalidateQueries({ queryKey: ['ruleStats'] });
        },
    });

    const deleteMutation = useMutation({
        mutationFn: (id: string) => rulesApi.delete(id),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['rules'] });
            queryClient.invalidateQueries({ queryKey: ['ruleStats'] });
        },
    });

    const handleToggle = (rule: Rule) => {
        setPendingId(rule.id);
        if (rule.enabled) {
            disableMutation.mutate(rule.id);
        } else {
            enableMutation.mutate(rule.id);
        }
    };

    const filteredRules = pager.rows;

    // Totals
    const totalRules    = ruleStats?.total_rules    ?? pager.data?.total?.value        ?? 0;
    const enabledRules  = ruleStats?.enabled_rules  ?? 0;
    const disabledRules = ruleStats?.disabled_rules ?? 0;
    const bySeverity    = ruleStats?.by_severity    ?? {};
    const sevTotal      = Object.values(bySeverity).reduce((n: number, v) => n + (v as number), 0) || 1;

    return (
        <div className="relative flex flex-col min-h-[calc(100vh-2rem)] lg:min-h-[calc(100vh-1rem)] h-full -mx-4 sm:-mx-6 lg:-mx-8 -my-4 sm:-my-6 lg:-my-8 p-4 sm:p-6 lg:p-8 bg-slate-200 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900 transition-colors overflow-hidden">
            {/* Ambient glow */}
            <div className="absolute top-0 right-0 w-[500px] h-[500px] pointer-events-none mix-blend-screen" style={{ background: 'radial-gradient(circle, rgba(99,102,241,0.08) 0%, transparent 70%)' }} />
            <div className="absolute bottom-0 left-0 w-[400px] h-[400px] pointer-events-none mix-blend-screen" style={{ background: 'radial-gradient(circle, rgba(16,185,129,0.06) 0%, transparent 70%)' }} />

            <div className="relative flex-1 flex flex-col min-h-0 space-y-5  w-full">

                {/* ── Header ── */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 shrink-0">
                    <div>
                        <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-slate-900 to-slate-600 dark:from-white dark:to-slate-300 tracking-tight">
                            Detection Rules
                        </h2>
                        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                            Manage Sigma &amp; behavioral detection signatures
                        </p>
                    </div>
                    {canWrite && (
                        <button
                            onClick={() => { setEditingRule(null); setShowModal(true); }}
                            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-xl transition-colors shadow-md shadow-indigo-500/20"
                        >
                            <Plus className="w-4 h-4" />
                            Create Rule
                        </button>
                    )}
                </div>

                {/* ── KPI Cards ── */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 shrink-0">
                    {/* Total */}
                    <div className="relative overflow-hidden bg-white/70 dark:bg-slate-900/50 backdrop-blur-md rounded-2xl border border-slate-200/80 dark:border-slate-700/50 p-5 shadow-sm hover:shadow-md transition-all group">
                        <div className="flex items-center gap-4">
                            <div className="p-3 rounded-xl bg-indigo-500/10 dark:bg-indigo-500/20 text-indigo-600 dark:text-indigo-400">
                                <Shield className="w-6 h-6" />
                            </div>
                            <div className="flex-1 min-w-0">
                                <div className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Total Rules</div>
                                <div className="text-2xl font-extrabold text-slate-900 dark:text-white">{totalRules}</div>
                            </div>
                        </div>
                        {/* Severity breakdown mini-bars */}
                        <div className="mt-4 space-y-1">
                            {['critical','high','medium','low'].map(sev => {
                                const cnt = (bySeverity[sev] as number) || 0;
                                const pct = Math.round((cnt / sevTotal) * 100);
                                return (
                                    <div key={sev} className="flex items-center gap-2 text-[10px]">
                                        <span className="w-12 text-slate-400 uppercase font-bold">{sev}</span>
                                        <div className="flex-1 h-1 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                                            <div className={`h-full rounded-full ${SEV_BAR[sev] || 'bg-slate-400'}`} style={{ width: `${pct}%` }} />
                                        </div>
                                        <span className="w-5 text-right text-slate-500 font-semibold">{cnt}</span>
                                    </div>
                                );
                            })}
                        </div>
                        <div className="absolute top-0 right-0 w-20 h-20 bg-indigo-500/5 rounded-full -translate-y-6 translate-x-6" />
                    </div>

                    {/* Active */}
                    <div className="relative overflow-hidden bg-white/70 dark:bg-slate-900/50 backdrop-blur-md rounded-2xl border border-slate-200/80 dark:border-slate-700/50 p-5 shadow-sm hover:shadow-md transition-all group">
                        <div className="flex items-center gap-4">
                            <div className="p-3 rounded-xl bg-emerald-500/10 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400">
                                <CheckCircle className="w-6 h-6" />
                            </div>
                            <div>
                                <div className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Active Signatures</div>
                                <div className="text-2xl font-extrabold text-slate-900 dark:text-white">{enabledRules}</div>
                            </div>
                        </div>
                        <div className="mt-4 flex items-center gap-2">
                            <div className="flex-1 h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                                <div className="h-full bg-emerald-500 rounded-full transition-all" style={{ width: `${totalRules ? Math.round((enabledRules / totalRules) * 100) : 0}%` }} />
                            </div>
                            <span className="text-xs font-bold text-emerald-600 dark:text-emerald-400">
                                {totalRules ? Math.round((enabledRules / totalRules) * 100) : 0}%
                            </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">of all signatures are active</p>
                        <div className="absolute top-0 right-0 w-20 h-20 bg-emerald-500/5 rounded-full -translate-y-6 translate-x-6" />
                    </div>

                    {/* Disabled */}
                    <div className="relative overflow-hidden bg-white/70 dark:bg-slate-900/50 backdrop-blur-md rounded-2xl border border-slate-200/80 dark:border-slate-700/50 p-5 shadow-sm hover:shadow-md transition-all group">
                        <div className="flex items-center gap-4">
                            <div className="p-3 rounded-xl bg-slate-500/10 dark:bg-slate-500/20 text-slate-600 dark:text-slate-400">
                                <XCircle className="w-6 h-6" />
                            </div>
                            <div>
                                <div className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Disabled Rules</div>
                                <div className="text-2xl font-extrabold text-slate-900 dark:text-white">{disabledRules}</div>
                            </div>
                        </div>
                        <div className="mt-4">
                            <p className="text-[11px] text-slate-400">
                                {disabledRules === 0
                                    ? '✅ All rules are active'
                                    : `${disabledRules} signature${disabledRules > 1 ? 's' : ''} not contributing to detection`}
                            </p>
                        </div>
                        <div className="absolute top-0 right-0 w-20 h-20 bg-slate-500/5 rounded-full -translate-y-6 translate-x-6" />
                    </div>
                </div>

                {/* ── Filter Bar ── */}
                <div className="relative z-20 shrink-0 bg-white/70 dark:bg-slate-900/50 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-4 shadow-sm">
                    <div className="flex flex-wrap gap-3 items-end">
                        {/* Search */}
                        <div className="flex-1 min-w-[200px] relative">
                            <label className="block text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Search</label>
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                <input
                                    type="text"
                                    placeholder="Title, ID, or category…"
                                    value={searchTerm}
                                    onChange={(e) => setSearchTerm(e.target.value)}
                                    className="w-full bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 rounded-lg pl-9 pr-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all"
                                />
                            </div>
                        </div>

                        {/* Status filter */}
                        <div className="w-44 relative">
                            <label className="block text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5">Status</label>
                            <div className="relative">
                                <select
                                    value={enabledFilter === undefined ? '' : enabledFilter.toString()}
                                    onChange={(e) => {
                                        const val = e.target.value;
                                        setEnabledFilter(val === '' ? undefined : val === 'true');
                                    }}
                                    className="appearance-none w-full bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 rounded-lg pl-3 pr-8 py-2 text-sm focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all cursor-pointer"
                                >
                                    <option value="">All Rules</option>
                                    <option value="true">Active Only</option>
                                    <option value="false">Disabled Only</option>
                                </select>
                                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                            </div>
                        </div>

                        {/* Sort toggle */}
                        <div className="flex items-end gap-2 pb-0.5">
                            <button
                                onClick={() => setSortBySeverity(!sortBySeverity)}
                                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold border transition-all ${ sortBySeverity ? 'bg-indigo-600 text-white border-indigo-600 shadow-sm' : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:border-indigo-400' }`}
                            >
                                <Target className="w-3.5 h-3.5" />
                                Sort by Severity
                            </button>
                        </div>
                    </div>
                </div>

                {/* ── Data Table ── */}
                <div className="relative flex-1 flex flex-col min-h-0 bg-white dark:bg-slate-800/70 rounded-2xl border border-slate-200 dark:border-slate-700/60 shadow-sm overflow-hidden">
                    <div className="flex-1 overflow-auto custom-scrollbar">
                        {pager.isError ? (<div role="alert" className="p-6">Could not load rules. <button className="underline" onClick={() => void pager.refetch()}>Retry</button></div>) : isLoading ? (
                            <div className="p-6 space-y-3">
                                {[...Array(6)].map((_, i) => (
                                    <div key={i} className="h-14 bg-slate-100 dark:bg-slate-800 rounded-xl animate-pulse" style={{ opacity: 1 - i * 0.12 }} />
                                ))}
                            </div>
                        ) : filteredRules.length === 0 ? (
                            <div className="text-center py-20 flex flex-col items-center justify-center">
                                <Activity className="w-12 h-12 text-slate-400 dark:text-slate-600 mb-4" />
                                <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mb-1">No signatures found</h3>
                                <p className="text-slate-500 dark:text-slate-400 text-sm">Try adjusting your filters or search.</p>
                            </div>
                        ) : (
                            <table className="w-full text-left border-collapse text-sm">
                                <thead className="sticky top-0 z-10 bg-slate-100/90 dark:bg-slate-800 border-b-2 border-slate-200 dark:border-slate-700/80 backdrop-blur-sm">
                                    <tr>
                                        <th className="px-5 py-3.5 text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-bold w-8">
                                            {/* Toggle col */}
                                        </th>
                                        <th className="px-4 py-3.5 text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-bold w-[36%]">Signature</th>
                                        <th className="px-4 py-3.5 text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-bold">Severity</th>
                                        <th className="px-4 py-3.5 text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-bold">MITRE / Category</th>
                                        <th className="px-4 py-3.5 text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-bold">Alerts Fired</th>
                                        {canWrite && <th className="px-4 py-3.5 text-right text-[10px] uppercase tracking-wider text-slate-500 dark:text-slate-400 font-bold">Actions</th>}
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
                                    {filteredRules.map((rule) => {
                                        const fires = (byRule[rule.id] as number) || (byRule[rule.title] as number) || 0;
                                        const isPending = pendingId === rule.id;
                                        return (
                                            <tr key={rule.id} className={`group transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/40 ${ !rule.enabled ? 'opacity-60' : '' }`}>

                                                {/* Toggle switch */}
                                                <td className="px-5 py-3.5">
                                                    {canWrite ? (
                                                        <ToggleSwitch
                                                            checked={rule.enabled}
                                                            onChange={() => handleToggle(rule)}
                                                            pending={isPending}
                                                        />
                                                    ) : (
                                                        <span className={`w-2 h-2 rounded-full inline-block ${ rule.enabled ? 'bg-emerald-500' : 'bg-slate-400' }`} />
                                                    )}
                                                </td>

                                                {/* Signature name + description */}
                                                <td className="px-4 py-3.5">
                                                    <div className="font-semibold text-slate-900 dark:text-slate-100 truncate max-w-xs">
                                                        {rule.title}
                                                    </div>
                                                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate max-w-xs" title={rule.description}>
                                                        {rule.description || <span className="italic">No description</span>}
                                                    </div>
                                                    <div className="font-mono text-[10px] text-slate-400 mt-0.5 truncate">
                                                        {rule.id.length > 28 ? rule.id.slice(0, 28) + '…' : rule.id}
                                                    </div>
                                                </td>

                                                {/* Severity badge */}
                                                <td className="px-4 py-3.5">
                                                    <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-bold border ${ SEV_BADGE[rule.severity] || SEV_BADGE.low }`}>
                                                        {(rule.severity || 'low').toUpperCase()}
                                                    </span>
                                                </td>

                                                {/* MITRE tactics + category */}
                                                <td className="px-4 py-3.5">
                                                    <div className="flex flex-wrap gap-1">
                                                        {(rule.mitre_attack?.tactics || []).slice(0, 2).map(t => (
                                                            <span key={t} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-600 dark:text-purple-300 border border-purple-500/20">
                                                                {t}
                                                            </span>
                                                        ))}
                                                        {(rule.mitre_attack?.techniques || []).slice(0, 1).map(t => (
                                                            <span key={t} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-100 dark:bg-slate-900 text-slate-500 border border-slate-200 dark:border-slate-700">
                                                                {t}
                                                            </span>
                                                        ))}
                                                        {rule.category && (
                                                            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] bg-slate-100 dark:bg-slate-900/60 text-slate-500 dark:text-slate-400 font-medium">
                                                                {rule.category}
                                                            </span>
                                                        )}
                                                    </div>
                                                </td>

                                                {/* Alert fire mini-bar */}
                                                <td className="px-4 py-3.5">
                                                    <div className="flex items-center gap-1.5">
                                                        {fires > 0 && <Zap className="w-3 h-3 text-amber-500 shrink-0" />}
                                                        <AlertFireBar count={fires} max={maxFires} />
                                                    </div>
                                                </td>

                                                {/* Actions */}
                                                {canWrite && (
                                                    <td className="px-4 py-3.5 text-right">
                                                        <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                                            <button
                                                                onClick={() => { setEditingRule(rule); setShowModal(true); }}
                                                                className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-400 hover:text-indigo-600 dark:hover:text-indigo-400 transition-colors"
                                                                title="Edit Rule"
                                                            >
                                                                <Edit className="w-3.5 h-3.5" />
                                                            </button>
                                                            <div className="w-px h-4 bg-slate-200 dark:bg-slate-700" />
                                                            <button
                                                                onClick={() => {
                                                                    if (confirm('Delete this rule? This action cannot be undone.')) {
                                                                        deleteMutation.mutate(rule.id);
                                                                    }
                                                                }}
                                                                className="p-1.5 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-500/10 text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                                                                title="Delete Rule"
                                                            >
                                                                <Trash2 className="w-3.5 h-3.5" />
                                                            </button>
                                                        </div>
                                                    </td>
                                                )}
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        )}
                    </div>

                    <PaginationControls info={pager.info} page={pager.page} count={pager.rows.length} busy={pager.busy}
                        onNext={pager.next} onFirst={pager.first} onPrevious={pager.previous} onSize={pager.setPageSize} />
                    {/* Footer */}
                    <div className="shrink-0 px-5 py-3 bg-slate-50/60 dark:bg-slate-900/40 border-t border-slate-200 dark:border-slate-800/60 text-xs text-slate-500 dark:text-slate-400 flex justify-between items-center">
                        <span>
                            On this page: <span className="font-semibold text-slate-700 dark:text-slate-200">{filteredRules.length}</span> · Fleet: <span className="font-semibold text-slate-700 dark:text-slate-200">{totalRules}</span> signatures
                        </span>
                        <span className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-emerald-500" />
                            <span>{enabledRules} active</span>
                            <span className="mx-1.5 text-slate-300 dark:text-slate-600">·</span>
                            <span className="w-2 h-2 rounded-full bg-slate-400" />
                            <span>{disabledRules} disabled</span>
                        </span>
                    </div>
                </div>
            </div>

            {/* ── Create/Edit rule editor ── */}
            {showModal && (
                <RuleEditorModal key={editingRule?.id ?? 'new'} rule={editingRule} onClose={() => setShowModal(false)} />
            )}
        </div>
    );
}

