import { useQuery, useMutation } from '@tanstack/react-query';
import React, { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import {
    Zap, CheckCircle2, Clock, XCircle, AlertTriangle,
    ChevronDown, ChevronRight, RefreshCw, Terminal,
    Monitor, Search, X, Activity, ShieldAlert
} from 'lucide-react';
import { authApi, commandsApi, eventsApi, agentsApi, type CommandListItem, type CommandStats, type CmEventSummary } from '../api/client';
import { useToast, type ToastType } from '../components';
import { usePageFilters } from '../hooks/usePageFilters';
import { usePaginatedQuery } from '../hooks/usePaginatedQuery';
import { PaginationControls } from '../components/PaginationControls';

const STATUS_CONFIG: Record<string, { label: string; color: string; bg: string; icon: React.ElementType }> = {
    pending: { label: 'Pending', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', icon: Clock },
    sent: { label: 'Sent', color: '#3b82f6', bg: 'rgba(59,130,246,0.12)', icon: Zap },
    completed: { label: 'Completed', color: '#22c55e', bg: 'rgba(34,197,94,0.12)', icon: CheckCircle2 },
    failed: { label: 'Failed', color: '#ef4444', bg: 'rgba(239,68,68,0.12)', icon: XCircle },
    timeout: { label: 'Timeout', color: '#f97316', bg: 'rgba(249,115,22,0.12)', icon: AlertTriangle },
    cancelled: { label: 'Cancelled', color: '#6b7280', bg: 'rgba(107,114,128,0.12)', icon: XCircle },
};

function StatusBadge({ status }: { status: string }) {
    const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
    const Icon = cfg.icon;
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: '6px',
            padding: '4px 10px', borderRadius: '9999px', fontSize: '12px', fontWeight: 600,
            color: cfg.color, backgroundColor: cfg.bg,
        }}>
            <Icon style={{ width: 14, height: 14 }} />
            {cfg.label}
        </span>
    );
}


// ------------------------


function formatDuration(ms: number) {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
}

function commandCenterResultOutput(item: CommandListItem): React.ReactNode {
    const t = item.command_type;
    if (t !== 'collect_logs' && t !== 'collect_forensics') {
        return (
            <pre className="bg-slate-900 p-3 rounded-md text-slate-100 whitespace-pre-wrap break-words overflow-y-auto max-h-[28rem] text-xs">
                {typeof item.result === 'object' ? JSON.stringify(item.result, null, 2) : String(item.result)}
            </pre>
        );
    }
    const st = String(item.status || '').toLowerCase();
    const forensicsTo = `/management/devices/${encodeURIComponent(item.agent_id)}?tab=forensics&command_id=${encodeURIComponent(item.id)}`;
    const forensicsLink = (
        <Link to={forensicsTo} className="text-cyan-300 font-semibold hover:underline">
            Forensic Logs
        </Link>
    );
    if (st === 'failed' || st === 'timeout' || st === 'cancelled') {
        return (
            <div className="space-y-2 text-xs">
                <pre className="bg-slate-900 p-3 rounded-md text-slate-100 whitespace-pre-wrap break-words overflow-y-auto max-h-[14rem]">
                    {typeof item.result === 'object' ? JSON.stringify(item.result, null, 2) : String(item.result)}
                </pre>
                <p className="text-slate-400">Successful runs are browsable under {forensicsLink}.</p>
            </div>
        );
    }
    const done = st === 'completed';
    return (
        <div className="text-slate-200 text-xs space-y-2">
            <p>
                {done
                    ? <>Full log output is not shown here. Open {forensicsLink} on the device to browse events.</>
                    : <>When this command completes, browse logs on the {forensicsLink} tab.</>}
            </p>
            <p className="font-mono text-[11px] text-slate-500 break-all">{forensicsTo}</p>
        </div>
    );
}

// KPI Card Component
const KPICard = React.memo(function KPICard({ title: label, value, icon: Icon, color, subtitle }: {
    title: string; value: number; icon: React.ElementType; color: string; subtitle?: string;
}) {
    return (
        <div className="relative overflow-hidden bg-white/60 dark:bg-slate-900/40 backdrop-blur-md rounded-xl border border-slate-200/80 dark:border-slate-700/50 p-5 shadow-sm transition-all hover:shadow-md group">
            <div className="flex items-center gap-4 relative z-10">
                <div className={`p-3 rounded-lg ${color}`}>
                    <Icon className="w-6 h-6" />
                </div>
                <div>
                    <div className="text-sm font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">{label}</div>
                    <div className="text-2xl font-bold text-slate-900 dark:text-white">{value.toLocaleString()}</div>
                    {subtitle && <div className="text-xs text-slate-500 dark:text-slate-500 mt-1">{subtitle}</div>}
                </div>
            </div>
        </div>
    );
});

// Command Stream Row Component
const CommandRow = React.memo(function CommandRow({ command }: { command: CommandListItem }) {
    const [expanded, setExpanded] = useState(false);
    const detail = useQuery({ queryKey: ['command-detail', command.id], queryFn: () => commandsApi.get(command.id), enabled: expanded });
    const item = detail.data ?? command;

    const issuedDate = new Date(item.issued_at);
    const completedDate = item.completed_at ? new Date(item.completed_at) : null;
    const duration = completedDate ? completedDate.getTime() - issuedDate.getTime() : null;

    const getCommandStyles = (type: string) => {
        switch (type) {
            case 'kill_process': return { icon: XCircle, color: 'text-rose-600 dark:text-rose-400', bg: 'bg-rose-500/10 dark:bg-rose-500/20' };
            case 'quarantine_file': return { icon: AlertTriangle, color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-500/10 dark:bg-orange-500/20' };
            case 'collect_logs': return { icon: Monitor, color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-500/10 dark:bg-blue-500/20' };
            case 'update_policy': return { icon: CheckCircle2, color: 'text-indigo-600 dark:text-indigo-400', bg: 'bg-indigo-500/10 dark:bg-indigo-500/20' };
            case 'restart_agent': return { icon: RefreshCw, color: 'text-amber-600 dark:text-amber-400', bg: 'bg-amber-500/10 dark:bg-amber-500/20' };
            case 'restart_machine': return { icon: RefreshCw, color: 'text-rose-600 dark:text-rose-400', bg: 'bg-rose-500/10 dark:bg-rose-500/20' };
            case 'shutdown_machine': return { icon: XCircle, color: 'text-red-600 dark:text-red-400', bg: 'bg-red-500/10 dark:bg-red-500/20' };
            case 'isolate_network': return { icon: Zap, color: 'text-red-600 dark:text-red-400', bg: 'bg-red-500/10 dark:bg-red-500/20' };
            case 'restore_network': return { icon: Zap, color: 'text-emerald-600 dark:text-emerald-400', bg: 'bg-emerald-500/10 dark:bg-emerald-500/20' };
            case 'scan_file': return { icon: Search, color: 'text-purple-600 dark:text-purple-400', bg: 'bg-purple-500/10 dark:bg-purple-500/20' };
            case 'scan_memory': return { icon: Search, color: 'text-cyan-600 dark:text-cyan-400', bg: 'bg-cyan-500/10 dark:bg-cyan-500/20' };
            default: return { icon: Terminal, color: 'text-slate-600 dark:text-slate-400', bg: 'bg-slate-500/10 dark:bg-slate-500/20' };
        }
    };

    const { icon: Icon, color, bg } = getCommandStyles(item.command_type);

    return (
        <div
            className="p-4 rounded-xl border transition-all duration-200 group relative bg-slate-50/50 dark:bg-slate-800/40 border-slate-200/80 dark:border-slate-700/50 hover:bg-white dark:hover:bg-slate-800/60 hover:border-slate-300 dark:hover:border-slate-600/50"
            style={{ contentVisibility: 'auto', containIntrinsicSize: '180px' } }
        >
            {/* Status Indicator Bar */}
            <div className={`absolute left-0 top-0 bottom-0 w-1 rounded-l-xl ${
                item.status === 'completed' ? 'bg-emerald-500' :
                item.status === 'failed' ? 'bg-rose-500' :
                item.status === 'timeout' ? 'bg-orange-500' :
                'bg-blue-500 animate-pulse'
            }`} />

            <div className="grid grid-cols-1 lg:grid-cols-[2fr_1.5fr_1.5fr_auto] items-center w-full gap-4 lg:gap-6">
                {/* 1. Command Primary Info */}
                <div className="flex items-center gap-4 min-w-0">
                    <div className={`p-3 rounded-xl shrink-0 ${bg} ${color} flex items-center justify-center`}>
                        <Icon className="w-5 h-5" />
                    </div>
                    <div className="flex flex-col justify-center min-w-0 gap-1.5 py-0.5">
                        <div className="flex items-center flex-wrap gap-2.5">
                            <span className="font-bold text-slate-900 dark:text-slate-100 uppercase tracking-widest text-xs leading-none">
                                {item.command_type.replace(/_/g, ' ')}
                            </span>
                            <StatusBadge status={item.status} />
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="h-5 px-2 flex items-center justify-center rounded text-[10px] font-mono bg-slate-100 dark:bg-slate-900/60 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-800/60 transition-colors">
                                ID: {item.id.substring(0, 8)}
                            </span>
                        </div>
                    </div>
                </div>

                {/* 2. Target Info */}
                <div className="flex flex-col min-w-0 gap-1.5 justify-center">
                    <div className="flex items-center gap-2 text-slate-600 dark:text-slate-300 text-xs font-semibold">
                        <Monitor className="w-4 h-4 text-slate-400" />
                        <Link
                            to={`/management/devices/${item.agent_id}`}
                            className="truncate text-cyan-700 dark:text-cyan-400 hover:underline"
                            title="Open device detail"
                        >
                            {item.agent_hostname || 'Unknown Host'}
                        </Link>
                    </div>
                    <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 text-[11px] font-mono" title="Agent ID">
                        <span className="font-bold text-slate-400">{'>_'}</span>
                        <span className="truncate">{item.agent_id}</span>
                    </div>
                </div>

                {/* 3. Time & Duration Info */}
                <div className="flex flex-row lg:flex-col justify-start lg:justify-center items-center lg:items-start min-w-0 gap-3 lg:gap-2">
                    <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 text-xs font-medium bg-slate-100 dark:bg-slate-800/40 px-2.5 py-1 rounded-md w-fit">
                        <Activity className="w-3.5 h-3.5 opacity-70" />
                        <span>{duration !== null ? formatDuration(duration) : '—'}</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 text-[11px] font-medium px-2 py-0.5">
                        <Clock className="w-3.5 h-3.5 opacity-70" />
                        <span>{new Date(item.issued_at).toLocaleString()}</span>
                    </div>
                </div>

                {/* 4. Action */}
                <div className="flex items-center justify-end shrink-0 ml-auto lg:ml-0">
                    <button
                        onClick={() => setExpanded(!expanded)}
                        className="p-1.5 rounded-full hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors focus:outline-none focus:ring-2 focus:ring-slate-300 dark:focus:ring-slate-600"
                        title={expanded ? 'Collapse Details' : 'Expand Details'}
                    >
                        {expanded
                            ? <ChevronDown className="w-5 h-5 text-slate-500 dark:text-slate-400" />
                            : <ChevronRight className="w-5 h-5 text-slate-500 dark:text-slate-400" />
                        }
                    </button>
                </div>
            </div>

            {expanded && (
                <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700/50 pl-2">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                            <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Command ID</div>
                            <code className="block bg-slate-100 dark:bg-slate-900/60 p-2 rounded-md text-slate-700 dark:text-slate-200 break-all">{item.id}</code>
                        </div>
                        <div>
                            <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Agent ID</div>
                            <code className="block bg-slate-100 dark:bg-slate-900/60 p-2 rounded-md text-slate-700 dark:text-slate-200 break-all">{item.agent_id}</code>
                        </div>
                    </div>

                    {detail.isLoading && <p role="status">Loading command details...</p>}
                    {detail.isError && <p role="alert">Unable to load command details. <button className="btn btn-secondary" onClick={() => detail.refetch()}>Retry</button></p>}
                    <div className="mt-4">
                        <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Parameters</div>
                        <pre className="bg-slate-100 dark:bg-slate-900/60 p-3 rounded-md text-slate-700 dark:text-slate-200 whitespace-pre-wrap break-words overflow-y-auto max-h-80 text-xs">
                            {JSON.stringify(item.parameters || {}, null, 2)}
                        </pre>
                    </div>

                    {(item.command_type === 'collect_logs' || item.command_type === 'collect_forensics') && (
                        <div className="mt-4 flex justify-end">
                            <Link
                                to={`/management/devices/${encodeURIComponent(item.agent_id)}?tab=forensics&command_id=${encodeURIComponent(item.id)}`}
                                className="px-3 py-2 text-sm font-semibold rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-800 dark:text-cyan-300 hover:bg-cyan-500/20 transition-colors"
                                title="Open Forensic Logs tab for this collection"
                            >
                                Open Forensic Logs
                            </Link>
                        </div>
                    )}

                    {item.result && (
                        <div className="mt-4">
                            <div className="text-xs font-semibold text-emerald-600 dark:text-emerald-400 uppercase tracking-wider mb-1 flex items-center gap-1">
                                <Terminal className="w-3.5 h-3.5" /> Result Output
                            </div>
                            {commandCenterResultOutput(item)}
                        </div>
                    )}

                    {item.error_message && (
                        <div className="mt-4">
                            <div className="text-xs font-semibold text-rose-600 dark:text-rose-400 uppercase tracking-wider mb-1">Error</div>
                            <pre className="bg-slate-500/10 dark:bg-rose-500/20 p-3 rounded-md text-rose-700 dark:text-rose-300 whitespace-pre-wrap break-words overflow-y-auto max-h-[28rem] text-xs">
                                {item.error_message}
                            </pre>
                        </div>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 text-sm text-slate-600 dark:text-slate-400">
                        <div>
                            <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Issued At</div>
                            <div>{new Date(item.issued_at).toLocaleString()}</div>
                        </div>
                        {item.sent_at && (
                            <div>
                                <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Sent At</div>
                                <div>{new Date(item.sent_at).toLocaleString()}</div>
                            </div>
                        )}
                        {item.completed_at && (
                            <div>
                                <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Completed At</div>
                                <div>{new Date(item.completed_at).toLocaleString()}</div>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
});

export default function ActionCenter() {
    const navigate = useNavigate();
    const { showToast } = useToast();
    const [searchParams] = useSearchParams();
    const [activeTab, setActiveTab] = useState<'commands' | 'auto-proc'>('commands');
    const pager = usePaginatedQuery<CommandListItem>({ name: 'commands', namespace: 'commands', refreshFirstPage: 30_000, defaults: { agent_id: searchParams.get('agent_id') || '', sort: 'issued_at', order: 'desc' }, fetchPage: commandsApi.page });
    const [filters, setFilters] = usePageFilters(pager.params, { status: '', command_type: '', agent_id: '' }, pager.setFilters);
    const debouncedAgentId = filters.agent_id;

    const { data: stats } = useQuery<CommandStats>({
        queryKey: ['command-stats'],
        queryFn: () => commandsApi.stats(),
        refetchInterval: 30000,
    });

    const { isLoading: commandsLoading, isFetching, isError, dataUpdatedAt } = pager;
    const commands = pager.rows;
    const handleRefresh = () => { pager.reset(); void pager.refetch(); };
    const lastUpdated = dataUpdatedAt;

    return (
        <div className="relative flex flex-col min-h-[calc(100vh-2rem)] lg:min-h-[calc(100vh-1rem)] h-full -mx-4 sm:-mx-6 lg:-mx-8 -my-4 sm:-my-6 lg:-my-8 p-4 sm:p-6 lg:p-8 bg-slate-200 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900 transition-colors overflow-hidden">
            {/* Background ambient glow setup */}
            <div className="absolute top-0 right-0 w-[500px] h-[500px] pointer-events-none mix-blend-screen" style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.08) 0%, transparent 70%)' }} />

            <div className="relative flex-1 flex flex-col min-h-0 space-y-4 lg:space-y-6  w-full">
                                {/* Header Section */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 shrink-0">
                    <div>
                        <h2 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-slate-900 to-slate-600 dark:from-white dark:to-slate-300">
                            Command Center
                        </h2>
                        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                            Command history and autonomous response events across all agents.
                        </p>
                    </div>
                    {/* Action Bar */}
                    <div className="flex flex-wrap items-center gap-3">
                        {isError && (
                            <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 bg-rose-50 dark:bg-rose-500/10 px-3 py-1.5 rounded-lg border border-rose-200 dark:border-rose-500/20 text-sm font-medium">
                                <AlertTriangle className="w-4 h-4" />
                                <span>Sync failed</span>
                            </div>
                        )}
                        <span className="text-sm text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                            {isFetching && !commandsLoading && <RefreshCw className="w-4 h-4 animate-spin text-cyan-500" />}
                            Last updated: {new Date(lastUpdated).toLocaleTimeString()}
                        </span>
                        {activeTab === 'commands' && authApi.canExecuteCommands() && (
                            <button
                                type="button"
                                onClick={() => {
                                    const aid = debouncedAgentId?.trim();
                                    if (aid) {
                                        navigate(`/management/devices/${aid}?tab=response`);
                                    } else {
                                        showToast('Enter an Agent ID in Search Endpoints, or open Device Management and pick a host.', 'info');
                                    }
                                }}
                                className="px-3 py-2 text-sm font-semibold rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-800 dark:text-cyan-300 hover:bg-cyan-500/20 transition-colors"
                            >
                                New command
                            </button>
                        )}
                        <button
                            onClick={handleRefresh}
                            className="p-2 border border-slate-200 dark:border-slate-700 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition-colors bg-white/60 dark:bg-slate-900/60 backdrop-blur"
                            title="Refresh Now"
                        >
                            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
                        </button>
                    </div>
                </div>

                {/* Sub-tabs */}
                <div className="flex gap-1 bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-1.5 shrink-0 w-fit">
                    <button
                        type="button"
                        onClick={() => setActiveTab('commands')}
                        className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-all duration-200 ${
                            activeTab === 'commands'
                                ? 'bg-gradient-to-r from-cyan-500 to-indigo-600 text-white shadow-md'
                                : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800'
                        }`}
                    >
                        <Terminal className="w-3.5 h-3.5" /> Manual Commands
                    </button>
                    <button
                        type="button"
                        onClick={() => setActiveTab('auto-proc')}
                        className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg transition-all duration-200 ${
                            activeTab === 'auto-proc'
                                ? 'bg-gradient-to-r from-cyan-500 to-indigo-600 text-white shadow-md'
                                : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800'
                        }`}
                    >
                        <ShieldAlert className="w-3.5 h-3.5" /> Auto-Proc Termination
                    </button>
                </div>

                {/* Stats KPIs */}
                {activeTab === 'commands' && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 shrink-0">
                        <KPICard title="Total Commands" value={stats?.total || 0} icon={Terminal} color="bg-blue-500/10 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-500/20" />
                        <KPICard title="Pending" value={stats?.pending || 0} icon={Clock} color="bg-amber-500/10 dark:bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/20" />
                        <KPICard title="Completed" value={stats?.completed || 0} icon={CheckCircle2} color="bg-emerald-500/10 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20" />
                        <KPICard title="Failed" value={stats?.failed || 0} icon={XCircle} color="bg-rose-500/10 dark:bg-rose-500/20 text-rose-600 dark:text-rose-400 border border-rose-500/20" />
                    </div>
                )}

                {activeTab === 'auto-proc' && <AutoProcTerminationPanel showToast={showToast} />}

                {/* Filters Strip — only for Manual Commands tab */}
                {activeTab === 'commands' && <div className="relative z-20 shrink-0 bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-4 shadow-sm flex flex-col md:flex-row gap-4 items-end">
                    
                    <div className="w-full md:w-64 relative">
                        <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                            Search Endpoints
                        </label>
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <input
                                type="text"
                                placeholder="Filter by Agent ID..."
                                value={filters.agent_id || ''}
                                onChange={(e) => setFilters(prev => ({ ...prev, agent_id: e.target.value }))}
                                className="w-full bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700/80 text-slate-700 dark:text-slate-200 rounded-lg pl-9 pr-3 py-2 text-sm focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all hover:bg-white dark:hover:bg-slate-800"
                            />
                            {filters.agent_id && (
                                <button 
                                    onClick={() => setFilters(prev => ({ ...prev, agent_id: '' }))}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-500"
                                >
                                    <X className="w-3.5 h-3.5" />
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="w-full md:w-48 relative">
                        <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                            Type Filter
                        </label>
                        <div className="relative">
                            <select
                                value={filters.command_type || ''}
                                onChange={(e) => setFilters(prev => ({ ...prev, command_type: e.target.value }))}
                                className="appearance-none w-full bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700/80 text-slate-700 dark:text-slate-200 rounded-lg pl-3 pr-8 py-2 text-sm focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all hover:bg-white dark:hover:bg-slate-800 cursor-pointer"
                            >
                                <option value="">All Types</option>
                                <option value="remediate">Remediate</option>
                                <option value="isolate">Isolate</option>
                                <option value="scan">Scan</option>
                                <option value="restart">Restart</option>
                            </select>
                            <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                        </div>
                    </div>
                </div>}

                {/* Commands tab content */}
                {activeTab === 'commands' && (
                    <>
                    {/* Commands Stream Grid */}
                    <div className="relative flex-1 flex flex-col min-h-0 bg-white dark:bg-slate-800/70 rounded-2xl border border-slate-200 dark:border-slate-700/60 shadow-sm overflow-hidden mt-2">
                        {/* Inner Scrollable Area */}
                        <div className="flex-1 overflow-auto custom-scrollbar p-0.5 transform-gpu">
                            {commandsLoading ? (
                                <div className="p-4 space-y-4">
                                    <div className="h-20 bg-slate-200 dark:bg-slate-800 rounded-xl animate-pulse"></div>
                                    <div className="h-20 bg-slate-200 dark:bg-slate-800 rounded-xl animate-pulse opacity-75"></div>
                                    <div className="h-20 bg-slate-200 dark:bg-slate-800 rounded-xl animate-pulse opacity-50"></div>
                                </div>
                            ) : isError ? (<p role="alert" className="p-6">Unable to load commands. <button className="btn btn-secondary" onClick={() => pager.refetch()}>Retry</button></p>) : commands.length === 0 ? (
                                <div className="text-center py-20 flex flex-col items-center justify-center">
                                    <Activity className="w-12 h-12 text-slate-400 dark:text-slate-600 mb-4" />
                                    <h3 className="text-lg font-medium text-slate-900 dark:text-slate-100 mb-1">No commands found</h3>
                                    <p className="text-slate-500 dark:text-slate-400">Try adjusting your filters or search terms.</p>
                                </div>
                            ) : (
                                <div className="p-4 space-y-3">
                                    {commands.map((cmd) => (
                                        <CommandRow key={cmd.id} command={cmd} />
                                    ))}
                                </div>
                            )}
                        </div>

                        <PaginationControls info={pager.info} page={pager.page} count={commands.length} busy={pager.busy} total={pager.data?.total} onNext={pager.next} onFirst={pager.first} onPrevious={pager.previous} onSize={pager.setPageSize} />
                    </div>
                    </>
                )}
            </div>
        </div>
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-Proc Termination Panel (all agents)
// ─────────────────────────────────────────────────────────────────────────────

const AP_ACTION_BADGE: Record<string, { label: string; color: string; bg: string; icon: React.ElementType }> = {
    auto_terminated:                  { label: 'Terminated',  color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  icon: CheckCircle2 },
    auto_terminate_failed:            { label: 'Failed',      color: '#ef4444', bg: 'rgba(239,68,68,0.12)',  icon: XCircle },
    process_rule_matched_detect_only: { label: 'Detect Only', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', icon: AlertTriangle },
};

function AutoProcTerminationPanel({ showToast }: { showToast: (msg: string, type?: ToastType) => void }) {
    const [expandedId, setExpandedId] = useState<string | null>(null);
    const [allowTarget, setAllowTarget] = useState<{ agentId: string; name: string; rule: string } | null>(null);
    const [allowReason, setAllowReason] = useState('');
    const [defaults] = useState(() => ({ days: '30', from: new Date(Date.now() - 30 * 86400000).toISOString(), to: new Date().toISOString() }));
    const q = usePaginatedQuery<CmEventSummary>({ name: 'auto-proc-all', namespace: 'autoProc', defaults,
        fetchPage: (params, signal) => eventsApi.page({
            filters: [{ field: 'event_type', operator: 'equals', value: 'process' },
                { field: 'data.action', operator: 'in', value: ['auto_terminated', 'auto_terminate_failed'] }],
            logic: 'AND', time_range: { from: params.from, to: params.to },
            limit: Number(params.limit), cursor: params.cursor, sort: 'created_at', order: 'desc',
        }, signal),
    });
    const rangeDays = Number(q.params.days);
    const setRangeDays = (days: number) => q.setFilters({ days: String(days), from: new Date(Date.now() - days * 86400000).toISOString(), to: new Date().toISOString() });
    const rows = q.rows;
    const detail = useQuery({ queryKey: ['event-detail', expandedId], queryFn: () => eventsApi.get(expandedId!), enabled: !!expandedId });

    const exceptionMutation = useMutation({
        mutationFn: (body: { agentId: string; process_name: string; reason?: string }) =>
            agentsApi.addProcessException(body.agentId, { process_name: body.process_name, reason: body.reason }),
        onSuccess: () => {
            showToast('Process exception added', 'success');
            setAllowTarget(null);
            setAllowReason('');
        },
        onError: (e: Error) => showToast(e.message || 'Failed to add exception', 'error'),
    });

    const getField = (ev: CmEventSummary, field: string): string => {
        const full = detail.data?.data;
        const source = ev.id === expandedId && full?.id === ev.id ? full.raw : ev;
        const raw = source && typeof source === 'object' ? source as Record<string, unknown> : {};
        const data = raw.data as Record<string, unknown> | undefined;
        return String(data?.[field] ?? raw[field] ?? '');
    };

    const getBadge = (ev: CmEventSummary) => {
        const action = getField(ev, 'action');
        return AP_ACTION_BADGE[action] || AP_ACTION_BADGE['auto_terminate_failed'];
    };

    const filteredRows = rows; // Both action filters are applied by the server before pagination.

    // KPI stats
    const terminated = filteredRows.filter(r => getField(r, 'action') === 'auto_terminated').length;
    const failed     = filteredRows.filter(r => getField(r, 'action') === 'auto_terminate_failed').length;

    return (
        <>
        {/* KPIs */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 shrink-0">
            <KPICard title="Events on this page" value={rows.length} icon={ShieldAlert} color="bg-cyan-500/10 dark:bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20" subtitle={`Last ${rangeDays} days`} />
            <KPICard title="Terminated on page" value={terminated} icon={CheckCircle2} color="bg-emerald-500/10 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20" />
            <KPICard title="Failed on page" value={failed} icon={XCircle} color="bg-rose-500/10 dark:bg-rose-500/20 text-rose-600 dark:text-rose-400 border border-rose-500/20" />
        </div>

        {/* Time range selector */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
            <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Time range</span>
            {([7, 30, 90] as const).map((d) => (
                <button key={d} type="button" onClick={() => setRangeDays(d)}
                    className={`px-2.5 py-1 rounded-md text-xs font-medium border transition-colors ${
                        rangeDays === d
                            ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-800 dark:text-cyan-200'
                            : 'border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                    }`}
                >Last {d} days</button>
            ))}
        </div>

        {/* Table */}
        <div className="relative flex-1 flex flex-col min-h-0 bg-white dark:bg-slate-800/70 rounded-2xl border border-slate-200 dark:border-slate-700/60 shadow-sm overflow-hidden">
            <div className="flex-1 overflow-auto custom-scrollbar transform-gpu">
                {q.isLoading ? (
                    <div className="p-4 space-y-4">
                        <div className="h-16 bg-slate-200 dark:bg-slate-800 rounded-xl animate-pulse"></div>
                        <div className="h-16 bg-slate-200 dark:bg-slate-800 rounded-xl animate-pulse opacity-75"></div>
                        <div className="h-16 bg-slate-200 dark:bg-slate-800 rounded-xl animate-pulse opacity-50"></div>
                    </div>
                ) : q.isError ? (
                    <div role="alert" className="p-6">Unable to load events. <button className="btn btn-secondary" onClick={() => q.refetch()}>Retry</button></div>
                ) : filteredRows.length === 0 ? (
                    <div className="text-center py-20 flex flex-col items-center justify-center">
                        <ShieldAlert className="w-12 h-12 text-slate-400 dark:text-slate-600 mb-4" />
                        <h3 className="text-lg font-medium text-slate-900 dark:text-slate-100 mb-1">No auto-termination events</h3>
                        <p className="text-slate-500 dark:text-slate-400">Autonomous process termination events will appear here when the agent acts.</p>
                    </div>
                ) : (
                    <table className="w-full text-left text-xs">
                        <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 uppercase text-[10px] sticky top-0 z-10">
                            <tr>
                                <th className="p-3">Time</th>
                                <th className="p-3">Action</th>
                                <th className="p-3">Severity</th>
                                <th className="p-3">Agent / Host</th>
                                <th className="p-3">Process</th>
                                <th className="p-3">Rule</th>
                                <th className="p-3">User</th>
                                <th className="p-3 text-right">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredRows.map((ev) => {
                                const badge = getBadge(ev);
                                const BadgeIcon = badge.icon;
                                const isExpanded = expandedId === ev.id;
                                const processName = getField(ev, 'name') || getField(ev, 'process_name') || '—';
                                const ruleName = getField(ev, 'matched_rule_title') || getField(ev, 'matched_rule_id') || '—';
                                const userName = getField(ev, 'user_name') || '—';
                                const severity = (ev as any).severity || getField(ev, 'severity') || 'medium';
                                const sevColor = severity === 'critical' ? 'text-rose-600 dark:text-rose-400 bg-rose-500/10 border-rose-500/20'
                                    : severity === 'high' ? 'text-orange-600 dark:text-orange-400 bg-orange-500/10 border-orange-500/20'
                                    : 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/20';
                                const agentId = ev.agent_id;
                                const hostname = getField(ev, 'hostname') || agentId?.slice(0, 12) || '—';

                                return (
                                    <React.Fragment key={ev.id}>
                                        <tr
                                            className="border-t border-slate-100 dark:border-slate-800 cursor-pointer hover:bg-slate-50/90 dark:hover:bg-slate-800/40 transition-colors"
                                            onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                                        >
                                            <td className="p-3 whitespace-nowrap text-slate-600 dark:text-slate-300">{new Date(ev.timestamp).toLocaleString()}</td>
                                            <td className="p-3">
                                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '2px 8px', borderRadius: '9999px', fontSize: '10px', fontWeight: 600, color: badge.color, backgroundColor: badge.bg }}>
                                                    <BadgeIcon style={{ width: 12, height: 12 }} /> {badge.label}
                                                </span>
                                            </td>
                                            <td className="p-3">
                                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${sevColor}`}>{severity}</span>
                                            </td>
                                            <td className="p-3">
                                                <Link
                                                    to={`/management/devices/${encodeURIComponent(agentId)}?tab=auto-proc`}
                                                    className="text-cyan-600 dark:text-cyan-400 hover:underline font-medium"
                                                    onClick={(e) => e.stopPropagation()}
                                                    title={agentId}
                                                >
                                                    {hostname}
                                                </Link>
                                            </td>
                                            <td className="p-3 font-mono font-medium text-slate-800 dark:text-slate-200">{processName}</td>
                                            <td className="p-3 text-slate-600 dark:text-slate-300 max-w-[160px] truncate" title={ruleName}>{ruleName}</td>
                                            <td className="p-3 text-slate-500">{userName}</td>
                                            <td className="p-3 text-right">
                                                {getField(ev, 'action') !== 'process_rule_matched_detect_only' && (
                                                    <button
                                                        type="button"
                                                        className="px-2 py-1 rounded border border-emerald-500/40 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/10"
                                                        onClick={(e) => { e.stopPropagation(); setAllowTarget({ agentId, name: processName, rule: ruleName }); }}
                                                    >Allow</button>
                                                )}
                                            </td>
                                        </tr>
                                        {isExpanded && (
                                            <tr className="bg-slate-50/50 dark:bg-slate-900/30">
                                                <td colSpan={8} className="p-4">
                                                    {detail.isLoading && <p role="status">Loading event details...</p>}
                                                    {detail.isError && <p role="alert">Unable to load details. <button className="btn btn-secondary" onClick={() => detail.refetch()}>Retry</button></p>}
                                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">PID</span><div className="font-mono mt-0.5">{getField(ev, 'pid') || '—'}</div></div>
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">PPID</span><div className="font-mono mt-0.5">{getField(ev, 'ppid') || '—'}</div></div>
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Kill Tree</span><div className="mt-0.5">{getField(ev, 'kill_tree') === 'true' ? <span className="text-rose-600 font-bold">Yes</span> : 'No'}</div></div>
                                                        <div className="md:col-span-3"><span className="font-semibold text-slate-500 uppercase text-[10px]">Command Line</span><div className="font-mono mt-0.5 bg-slate-100 dark:bg-slate-900/60 p-2 rounded break-all max-h-24 overflow-auto">{getField(ev, 'command_line') || '—'}</div></div>
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Parent</span><div className="font-mono mt-0.5">{getField(ev, 'parent_name') || '—'}</div></div>
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Signature</span><div className="mt-0.5">{getField(ev, 'signature_status') || '—'}</div></div>
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Elevated</span><div className="mt-0.5">{getField(ev, 'is_elevated') === 'true' ? <span className="text-amber-600 font-bold">Yes</span> : 'No'}</div></div>
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Rule ID</span><div className="font-mono mt-0.5 text-slate-400">{getField(ev, 'matched_rule_id') || '—'}</div></div>
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Decision Mode</span><div className="mt-0.5">{getField(ev, 'decision_mode') || '—'}</div></div>
                                                        <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Agent ID</span><div className="font-mono mt-0.5 text-slate-400 text-[10px]">{agentId}</div></div>
                                                        {getField(ev, 'kill_output') && (
                                                            <div className="md:col-span-3"><span className="font-semibold text-slate-500 uppercase text-[10px]">Kill Output</span><pre className="font-mono mt-0.5 bg-slate-900 text-slate-100 p-2 rounded text-[10px] max-h-20 overflow-auto">{getField(ev, 'kill_output')}</pre></div>
                                                        )}
                                                        {getField(ev, 'kill_error') && (
                                                            <div className="md:col-span-3"><span className="font-semibold text-rose-500 uppercase text-[10px]">Error</span><pre className="font-mono mt-0.5 bg-rose-500/10 text-rose-700 dark:text-rose-300 p-2 rounded text-[10px]">{getField(ev, 'kill_error')}</pre></div>
                                                        )}
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </React.Fragment>
                                );
                            })}
                        </tbody>
                    </table>
                )}
            </div>

            <PaginationControls info={q.info} page={q.page} count={rows.length} busy={q.busy} onNext={q.next} onFirst={q.first} onPrevious={q.previous} onSize={q.setPageSize} />
        </div>

        {/* Allow Confirmation Dialog */}
        {allowTarget && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm" onClick={() => { setAllowTarget(null); setAllowReason(''); }}>
                <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 p-6 max-w-md w-full mx-4" onClick={(e) => e.stopPropagation()}>
                    <h3 className="text-lg font-bold text-slate-800 dark:text-slate-100 mb-3">Allow Process — Add Exception</h3>
                    <div className="space-y-3 text-sm">
                        <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/40 text-amber-800 dark:text-amber-300 text-xs flex items-start gap-2">
                            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                            <span>This process will <strong>no longer be auto-terminated</strong> on the target agent.</span>
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Process</label>
                            <code className="block bg-slate-100 dark:bg-slate-800 p-2 rounded">{allowTarget.name}</code>
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Rule</label>
                            <code className="block bg-slate-100 dark:bg-slate-800 p-2 rounded text-xs">{allowTarget.rule}</code>
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Reason (optional)</label>
                            <input className="w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-950 px-3 py-2 text-sm" value={allowReason} onChange={(e) => setAllowReason(e.target.value)} placeholder="e.g., approved automation" />
                        </div>
                    </div>
                    <div className="flex justify-end gap-2 mt-4">
                        <button type="button" className="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800" onClick={() => { setAllowTarget(null); setAllowReason(''); }}>Cancel</button>
                        <button
                            type="button"
                            className="px-4 py-2 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-700 text-white disabled:opacity-50"
                            disabled={exceptionMutation.isPending}
                            onClick={() => { if (allowTarget) exceptionMutation.mutate({ agentId: allowTarget.agentId, process_name: allowTarget.name, reason: allowReason || `Allowed from rule: ${allowTarget.rule}` }); }}
                        >
                            {exceptionMutation.isPending ? 'Adding…' : 'Confirm Allow'}
                        </button>
                    </div>
                </div>
            </div>
        )}
        </>
    );
}
