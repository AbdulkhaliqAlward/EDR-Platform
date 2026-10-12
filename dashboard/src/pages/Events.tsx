import { usePageSearch } from '../hooks/usePageSearch';
import { memo, useCallback, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, Loader2, Search } from 'lucide-react';
import { authApi, eventsApi, type CmEventSummary } from '../api/client';
import { EventDetailModal } from '../components/EventDetailModal';
import { usePaginatedQuery } from '../hooks/usePaginatedQuery';
import { PaginationControls } from '../components/PaginationControls';


const EventRow = memo(function EventRow({
    e,
    onOpen,
}: {
    e: CmEventSummary;
    onOpen: (id: string) => void;
}) {
    return (
        <tr
            key={e.id}
            role="button"
            tabIndex={0}
            className="border-t border-slate-100 dark:border-slate-800 cursor-pointer hover:bg-slate-50/80 dark:hover:bg-slate-800/40"
            onClick={() => onOpen(e.id)}
            onKeyDown={(ev) => {
                if (ev.key === 'Enter' || ev.key === ' ') {
                    ev.preventDefault();
                    onOpen(e.id);
                }
            }}
        >
            <td className="p-3 whitespace-nowrap text-xs font-mono text-slate-500">{new Date(e.timestamp).toLocaleString()}</td>
            <td className="p-3">
                <Link
                    className="text-cyan-700 dark:text-cyan-300 hover:underline font-mono text-xs"
                    to={`/management/devices/${encodeURIComponent(e.agent_id)}?tab=activity`}
                    onClick={(ev) => ev.stopPropagation()}
                >
                    {e.agent_id.slice(0, 8)}…
                </Link>
            </td>
            <td className="p-3 font-mono text-xs">{e.event_type}</td>
            <td className="p-3">{e.summary}</td>
        </tr>
    );
});

function isoHoursAgo(hours: number) {
    return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

export default function Events() {
    const canView = authApi.canViewAlerts(); // server guards events/search with alerts:read
    const q = usePaginatedQuery<CmEventSummary>({ name: 'events-search', enabled: canView,
        defaults: { from: isoHoursAgo(1), to: new Date().toISOString() },
        fetchPage: (params, signal) => {
            const filters = [];
            if (params.agent_id) filters.push({ field: 'agent_id', operator: 'equals', value: params.agent_id });
            if (params.event_type) filters.push({ field: 'event_type', operator: 'equals', value: params.event_type });
            return eventsApi.page({ filters, logic: 'AND', time_range: { from: params.from, to: params.to }, limit: Number(params.limit), cursor: params.cursor }, signal);
        },
    });
    const [agentId, setAgentId] = usePageSearch(q.params, q.setFilters, 'agent_id');
    const [eventType, setEventType] = usePageSearch(q.params, q.setFilters, 'event_type');
    const from = q.params.from, to = q.params.to;
    const setFrom = (value: string) => q.setFilters({ from: value });
    const setTo = (value: string) => q.setFilters({ to: value });
    const [detailId, setDetailId] = useState<string | null>(null);
    const openDetail = useCallback((id: string) => setDetailId(id), []);
    const rows = q.rows;

    if (!canView) {
        return (
            <div className="p-8 text-center text-slate-500">
                You do not have permission to view Events. This endpoint is guarded by <code className="text-xs">alerts:read</code>.
            </div>
        );
    }

    return (
        <div className="relative flex flex-col min-h-[calc(100vh-2rem)] -mx-4 sm:-mx-6 lg:-mx-8 -my-4 sm:-my-6 lg:-my-8 p-4 sm:p-6 lg:p-8 bg-slate-200 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900">
            <div className=" w-full space-y-4">
                <div className="flex items-start gap-3">
                    <div className="p-2 rounded-xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300">
                        <Activity className="w-6 h-6" />
                    </div>
                    <div className="flex-1">
                        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">SOC</div>
                        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Telemetry Search</h1>
                    </div>
                    <Link
                        to="/alerts"
                        className="px-3 py-2 text-sm font-semibold rounded-lg border border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-900/50 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                        Alerts (Triage)
                    </Link>
                </div>

                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur p-4 sm:p-5 space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                        <div className="md:col-span-2">
                            <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Agent ID</label>
                            <div className="relative">
                                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                                <input
                                    className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-9 py-2 text-sm"
                                    value={agentId}
                                    onChange={(e) => { setAgentId(e.target.value); }}
                                    placeholder="UUID (optional)"
                                />
                            </div>
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">Event type</label>
                            <input
                                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
                                value={eventType}
                                onChange={(e) => { setEventType(e.target.value); }}
                                placeholder="e.g. network, process, file"
                            />
                        </div>
                        <div className="flex items-end">
                            <button
                                type="button"
                                className="w-full px-3 py-2 text-sm font-semibold rounded-lg border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-800"
                                onClick={() => {
                                    q.setFilters({ agent_id: undefined, event_type: undefined, from: isoHoursAgo(1), to: new Date().toISOString() });
                                }}
                            >
                                Reset
                            </button>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div>
                            <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">From (ISO)</label>
                            <input
                                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm font-mono"
                                value={from}
                                onChange={(e) => { setFrom(e.target.value); }}
                            />
                        </div>
                        <div>
                            <label className="block text-xs font-semibold text-slate-500 uppercase mb-1">To (ISO)</label>
                            <input
                                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm font-mono"
                                value={to}
                                onChange={(e) => { setTo(e.target.value); }}
                            />
                        </div>
                    </div>

                    <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                        <div>
                            Showing <span className="font-semibold text-slate-700 dark:text-slate-200">{rows.length}</span> rows
                            {q.data?.total ? <> / {q.data.total.value.toLocaleString()}{q.data.total.capped ? '+' : ''}</> : null}
                        </div>
                        <div className="font-mono">
                            Ordered by ingestion time
                        </div>
                    </div>
                </div>

                {q.isLoading ? (
                    <div className="flex items-center justify-center py-16">
                        <Loader2 className="w-10 h-10 animate-spin text-cyan-500" />
                    </div>
                ) : q.isError ? (
                    <div className="rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50/80 dark:bg-rose-950/20 p-5 text-sm text-rose-900 dark:text-rose-200 flex items-start gap-3">
                        <AlertTriangle className="w-5 h-5 mt-0.5 shrink-0" />
                        <div>
                            Could not load events. Check the filters and retry.
                            <button type="button" className="ml-3 underline" onClick={() => void q.refetch()}>Retry</button>
                        </div>
                    </div>
                ) : rows.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-slate-300 dark:border-slate-700 p-8 text-center text-slate-500 dark:text-slate-400">
                        No results for these filters. Try another time range or clear the filters.
                    </div>
                ) : (
                    <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 backdrop-blur">
                        <table className="w-full text-left text-sm">
                            <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-300 text-xs uppercase">
                                <tr>
                                    <th className="p-3">Time</th>
                                    <th className="p-3">Agent</th>
                                    <th className="p-3">Type</th>
                                    <th className="p-3">Summary</th>
                                </tr>
                            </thead>
                            <tbody style={{ contentVisibility: 'auto', containIntrinsicSize: '600px' }}>
                                {rows.map((e) => (
                                    <EventRow key={e.id} e={e} onOpen={openDetail} />
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}

                <PaginationControls info={q.info} page={q.page} count={rows.length} busy={q.busy} total={q.data?.total} onNext={q.next} onFirst={q.first} onPrevious={q.previous} onSize={q.setPageSize} />

                <EventDetailModal eventId={detailId} onClose={() => setDetailId(null)} fetchEnabled={canView} />
            </div>
        </div>
    );
}



