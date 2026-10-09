import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronUp, Database, RefreshCw, Send, ShieldCheck, Workflow } from 'lucide-react';
import { authApi, signaturesApi } from '../../api/client';
import { useToast } from '../../components/Toast';
import InsightHero from '../../components/InsightHero';

function formatDateTime(iso: string) {
    return new Date(iso).toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
}

export default function SignaturesManagement() {
    const queryClient = useQueryClient();
    const { showToast } = useToast();
    const canWrite = authApi.canWriteSettings();
    const [includeOffline, setIncludeOffline] = useState(true);
    const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

    useEffect(() => {
        document.title = 'Signatures — System | MITRAS';
    }, []);

    const statsQuery = useQuery({
        queryKey: ['signatures', 'stats'],
        queryFn: signaturesApi.stats,
        refetchInterval: 10000,
    });

    const historyQuery = useQuery({
        queryKey: ['signatures', 'sync-history'],
        queryFn: () => signaturesApi.syncHistory(50),
        refetchInterval: 15000,
    });

    const syncMutation = useMutation({
        mutationFn: signaturesApi.syncNow,
        onSuccess: (data) => {
            showToast(data.message, data.inserted === 0 ? 'info' : 'success');
            queryClient.invalidateQueries({ queryKey: ['signatures'] });
        },
        onError: (err: any) => showToast(err?.message || 'Failed to trigger sync', 'error'),
    });

    const pushAllMutation = useMutation({
        mutationFn: () => signaturesApi.pushUpdateAll({ include_offline: includeOffline }),
        onSuccess: (res) => {
            const d = res.data;
            showToast(`Queued for fleet: sent=${d.sent}, queued=${d.queued}, failed=${d.failed}`, 'success');
            queryClient.invalidateQueries({ queryKey: ['signatures'] });
        },
        onError: (err: any) => showToast(err?.message || 'Failed to push update', 'error'),
    });

    const historyRows = useMemo(() => {
        const rows = [...(historyQuery.data?.data || [])];
        return rows.sort((a, b) => sortDir === 'asc' ? a.generation - b.generation : b.generation - a.generation);
    }, [historyQuery.data, sortDir]);

    const sourceRows = useMemo(() => {
        const src = statsQuery.data?.sources || {};
        return Object.entries(src).sort((a, b) => b[1] - a[1]);
    }, [statsQuery.data]);

    return (
        <div className="space-y-6 md:space-y-8">
            <InsightHero
                accent="emerald"
                icon={ShieldCheck}
                eyebrow="Server-managed signatures"
                title="Central malware hash feed"
                segments={[
                    {
                        heading: 'Single source of truth',
                        children: <>The connection-manager syncs and versions signatures, then all agents pull deltas from server endpoints.</>,
                    },
                    {
                        heading: 'Fleet-wide push',
                        children: <>Use one action to queue `update_signatures` to the whole fleet instead of per-device updates.</>,
                    },
                ]}
            />

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4">
                    <div className="text-xs uppercase font-semibold text-slate-500 flex items-center gap-2"><Database className="w-4 h-4" /> Total hashes</div>
                    <div className="mt-2 text-2xl font-bold">{statsQuery.data?.count ?? '—'}</div>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4">
                    <div className="text-xs uppercase font-semibold text-slate-500 flex items-center gap-2"><Workflow className="w-4 h-4" /> Signature version</div>
                    <div className="mt-2 text-2xl font-bold">{statsQuery.data?.max_version ?? '—'}</div>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4">
                    <div className="text-xs uppercase font-semibold text-slate-500 flex items-center gap-2"><RefreshCw className="w-4 h-4" /> Sources</div>
                    <div className="mt-2 text-sm space-y-1">
                        {sourceRows.length === 0 ? <div className="text-slate-500">No source data</div> : sourceRows.map(([k, v]) => (
                            <div key={k} className="flex justify-between"><span>{k}</span><span className="font-mono">{v}</span></div>
                        ))}
                    </div>
                </div>
            </div>

            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-5 space-y-4">
                <h3 className="font-semibold text-slate-900 dark:text-slate-100">Actions</h3>
                <div className="flex flex-wrap gap-3 items-center">
                    <button
                        type="button"
                        disabled={!canWrite || syncMutation.isPending}
                        onClick={() => syncMutation.mutate()}
                        className="px-3 py-2 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-700 text-white disabled:opacity-40"
                    >
                        {syncMutation.isPending ? 'Syncing…' : 'Sync signatures now'}
                    </button>
                    <label className="inline-flex items-center gap-2 text-sm">
                        <input type="checkbox" checked={includeOffline} onChange={(e) => setIncludeOffline(e.target.checked)} />
                        Include offline agents (queue for reconnect)
                    </label>
                    <button
                        type="button"
                        disabled={!canWrite || pushAllMutation.isPending}
                        onClick={() => pushAllMutation.mutate()}
                        className="px-3 py-2 rounded-lg text-sm font-semibold bg-cyan-600 hover:bg-cyan-700 text-white disabled:opacity-40 inline-flex items-center gap-2"
                    >
                        <Send className="w-4 h-4" />
                        {pushAllMutation.isPending ? 'Dispatching…' : 'Push update to all agents'}
                    </button>
                </div>
                {!canWrite && (
                    <p className="text-xs text-amber-600 dark:text-amber-400">Read-only role: you can view stats, but only admins can trigger sync or fleet dispatch.</p>
                )}
            </div>

            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-5">
                <h3 className="font-semibold text-slate-900 dark:text-slate-100 mb-3">Sync history</h3>
                {historyQuery.isLoading ? (
                    <p className="text-sm text-slate-500">Loading…</p>
                ) : historyQuery.isError ? (
                    <p className="text-sm text-rose-600 dark:text-rose-400">Failed to load sync history.</p>
                ) : (historyQuery.data?.data || []).length === 0 ? (
                    <p className="text-sm text-slate-500">No syncs recorded yet. Run a sync or wait for the automatic 6-hour cycle.</p>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-200 dark:border-slate-700">
                                    <th className="pb-2 pr-6 font-semibold">
                                        <button
                                            type="button"
                                            onClick={() => setSortDir(d => d === 'asc' ? 'desc' : 'asc')}
                                            className="inline-flex items-center gap-1 hover:text-slate-800 dark:hover:text-slate-200"
                                        >
                                            Version
                                            {sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                                        </button>
                                    </th>
                                    <th className="pb-2 pr-6 font-semibold">Hashes added</th>
                                    <th className="pb-2 font-semibold">Date &amp; time</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                                {historyRows.map((row) => (
                                    <tr key={row.id}>
                                        <td className="py-2 pr-6">
                                            <span className="inline-flex items-center px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/30 text-emerald-800 dark:text-emerald-300 font-mono text-xs font-semibold">
                                                v{row.generation}
                                            </span>
                                        </td>
                                        <td className="py-2 pr-6 font-mono">{row.hashes_inserted.toLocaleString()}</td>
                                        <td className="py-2 text-slate-500 dark:text-slate-400">{formatDateTime(row.synced_at)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}
