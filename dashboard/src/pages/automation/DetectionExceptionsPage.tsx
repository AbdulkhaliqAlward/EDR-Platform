// Detection exceptions — review and manage analyst-approved false-positive
// suppressions (scope, conditions, justification, expiry and hit counts).
import { useCallback, useEffect, useState } from 'react';
import { Plus, ShieldOff, Trash2, RefreshCw } from 'lucide-react';
import { authApi, detectionExceptionsApi, type DetectionException } from '../../api/client';
import { apiErrorMessage } from '../../api/apiError';
import { CreateExceptionModal } from '../../components/alerts/CreateExceptionModal';

function expired(ex: DetectionException) {
    return !!ex.expires_at && new Date(ex.expires_at).getTime() < Date.now();
}

export function DetectionExceptionsPage() {
    const [items, setItems] = useState<DetectionException[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [creating, setCreating] = useState(false);
    const canManage = authApi.hasRole(['admin', 'security']);

    const load = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            setItems(await detectionExceptionsApi.list());
        } catch (err) {
            setError(apiErrorMessage(err, 'Could not load detection exceptions'));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { load(); }, [load]);

    const toggle = async (ex: DetectionException) => {
        try {
            const updated = await detectionExceptionsApi.update(ex.id, { enabled: !ex.enabled });
            setItems(prev => prev.map(i => (i.id === ex.id ? updated : i)));
        } catch (err) {
            alert(apiErrorMessage(err, 'Update failed'));
        }
    };

    const remove = async (ex: DetectionException) => {
        if (!window.confirm(`Delete exception "${ex.name}"? Matching detections will raise alerts again.`)) return;
        try {
            await detectionExceptionsApi.delete(ex.id);
            setItems(prev => prev.filter(i => i.id !== ex.id));
        } catch (err) {
            alert(apiErrorMessage(err, 'Delete failed'));
        }
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-amber-100 dark:bg-amber-900/30 rounded-lg">
                        <ShieldOff className="w-6 h-6 text-amber-600 dark:text-amber-400" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Detection Exceptions</h1>
                        <p className="text-sm text-slate-500 mt-1">Known-benign activity suppressed for specific rules. Review hit counts and expiries regularly.</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <button onClick={load} className="p-2 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800" title="Refresh">
                        <RefreshCw className="w-4 h-4" />
                    </button>
                    {canManage && (
                        <button onClick={() => setCreating(true)} className="btn btn-primary flex items-center gap-2">
                            <Plus className="w-4 h-4" /> New exception
                        </button>
                    )}
                </div>
            </div>

            {!canManage && (
                <p className="text-sm text-slate-500">Read-only: creating or changing exceptions requires the administrator or security role.</p>
            )}

            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 shadow-sm overflow-x-auto">
                {loading ? (
                    <p className="p-6 text-sm text-slate-500">Loading…</p>
                ) : error ? (
                    <p className="p-6 text-sm text-rose-600 dark:text-rose-400">{error}</p>
                ) : items.length === 0 ? (
                    <p className="p-6 text-sm text-slate-500">No exceptions. Create one from an alert with “Mark as false positive”.</p>
                ) : (
                    <table className="w-full text-sm">
                        <thead className="text-xs uppercase text-slate-500 bg-slate-50 dark:bg-slate-900/40">
                            <tr>
                                <th className="text-left px-4 py-2">Exception</th>
                                <th className="text-left px-3 py-2">Scope</th>
                                <th className="text-left px-3 py-2">Conditions</th>
                                <th className="text-left px-3 py-2">Hits</th>
                                <th className="text-left px-3 py-2">Expires</th>
                                <th className="text-left px-3 py-2">State</th>
                                <th className="px-3 py-2" />
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-700/80">
                            {items.map(ex => (
                                <tr key={ex.id} className="align-top">
                                    <td className="px-4 py-3">
                                        <div className="font-semibold text-slate-800 dark:text-slate-200">{ex.name}</div>
                                        <div className="text-xs text-slate-500 mt-0.5">{ex.reason}</div>
                                        <div className="text-[10px] text-slate-400 mt-1">by {ex.created_by || '—'} · {new Date(ex.created_at).toLocaleDateString()}</div>
                                    </td>
                                    <td className="px-3 py-3 text-xs text-slate-600 dark:text-slate-300">
                                        <div>{ex.rule_id ? (ex.rule_title || ex.rule_id) : <span className="text-amber-600 dark:text-amber-400 font-semibold">All rules</span>}</div>
                                        <div className="text-slate-400">{ex.agent_id ? (ex.hostname || ex.agent_id.slice(0, 8)) : 'All endpoints'}</div>
                                    </td>
                                    <td className="px-3 py-3 text-xs font-mono text-slate-600 dark:text-slate-300 max-w-md">
                                        {ex.conditions.map((c, i) => (
                                            <div key={i} className="break-all"><span className="text-indigo-600 dark:text-indigo-400">{c.field}</span> {c.op} {c.value}</div>
                                        ))}
                                    </td>
                                    <td className="px-3 py-3 text-xs text-slate-600 dark:text-slate-300">
                                        <div className="font-semibold">{ex.hit_count}</div>
                                        {ex.last_hit_at && <div className="text-slate-400">last {new Date(ex.last_hit_at).toLocaleString()}</div>}
                                    </td>
                                    <td className="px-3 py-3 text-xs text-slate-600 dark:text-slate-300">
                                        {ex.expires_at ? new Date(ex.expires_at).toLocaleDateString() : 'Never'}
                                    </td>
                                    <td className="px-3 py-3">
                                        {expired(ex) ? (
                                            <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-100 text-slate-500 dark:bg-slate-800">expired</span>
                                        ) : (
                                            <button disabled={!canManage} onClick={() => toggle(ex)}
                                                className={`px-2 py-0.5 rounded text-xs font-semibold ${ex.enabled ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400' : 'bg-slate-100 text-slate-500 dark:bg-slate-800'} disabled:cursor-default`}>
                                                {ex.enabled ? 'active' : 'disabled'}
                                            </button>
                                        )}
                                    </td>
                                    <td className="px-3 py-3">
                                        {canManage && (
                                            <button onClick={() => remove(ex)} className="p-1.5 text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-900/20 rounded" title="Delete">
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {creating && <CreateExceptionModal isOpen={creating} onClose={() => setCreating(false)} onCreated={() => load()} />}
        </div>
    );
}

export default DetectionExceptionsPage;
