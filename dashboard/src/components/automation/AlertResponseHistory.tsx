// AlertResponseHistory — every response run for one alert (automated and
// manual), with per-step results; refreshes while a run is active.
import { useEffect, useState } from 'react';
import { Bot, CheckCircle, Circle, Loader2, MinusCircle, User, XCircle } from 'lucide-react';
import { automationApi, isExecutionFinished, type PlaybookExecution } from '../../api/client';

const statusStyle: Record<string, string> = {
    completed: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
    partial: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    failed: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400',
    cancelled: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
    running: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400',
    pending: 'bg-indigo-50 text-indigo-600 dark:bg-indigo-900/20 dark:text-indigo-300',
};

const statusLabel: Record<string, string> = {
    pending: 'queued', cancelled: 'not run (guardrail)', partial: 'partially completed',
};

const stepIcon = (s: string) => {
    switch (s) {
        case 'success': return <CheckCircle className="w-3.5 h-3.5 text-emerald-500 shrink-0" />;
        case 'failed': return <XCircle className="w-3.5 h-3.5 text-rose-500 shrink-0" />;
        case 'running': return <Loader2 className="w-3.5 h-3.5 text-indigo-500 animate-spin shrink-0" />;
        case 'skipped': return <MinusCircle className="w-3.5 h-3.5 text-slate-400 shrink-0" />;
        default: return <Circle className="w-3.5 h-3.5 text-slate-300 shrink-0" />;
    }
};

interface Props {
    alertId: string;
    /** Bump to force a reload (e.g. after starting a run). */
    refreshKey?: number;
}

export function AlertResponseHistory({ alertId, refreshKey = 0 }: Props) {
    const [runs, setRuns] = useState<PlaybookExecution[] | null>(null);
    const [error, setError] = useState(false);

    useEffect(() => {
        let cancelled = false;
        let timer: ReturnType<typeof setTimeout>;
        const load = async () => {
            try {
                const list = await automationApi.listExecutions({ alert_id: alertId, limit: 20 });
                if (cancelled) return;
                setRuns(list);
                setError(false);
                // A response can start after this panel opens, including
                // when the initial list is empty or contains only old runs.
                timer = setTimeout(load, list.some(r => !isExecutionFinished(r.status)) ? 3000 : 10000);
            } catch {
                if (!cancelled) { setError(true); timer = setTimeout(load, 10000); }
            }
        };
        load();
        return () => { cancelled = true; clearTimeout(timer); };
    }, [alertId, refreshKey]);

    if (error) return null; // role without responses:read
    if (runs === null) return <p className="text-xs text-slate-400">Loading response history…</p>;
    if (runs.length === 0) return <p className="text-xs text-slate-500">No response has been run for this alert.</p>;

    return (
        <div className="space-y-2">
            {runs.map(r => (
                <div key={r.id} className="rounded-lg border border-slate-200 dark:border-slate-700 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                        {r.trigger_source === 'automation'
                            ? <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase text-indigo-600 dark:text-indigo-400"><Bot className="w-3.5 h-3.5" /> Automated</span>
                            : <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase text-slate-500"><User className="w-3.5 h-3.5" /> {r.created_by_username || 'Manual'}</span>}
                        <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">{r.playbook_name}</span>
                        <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${statusStyle[r.status] || statusStyle.cancelled}`}>
                            {statusLabel[r.status] || r.status}
                        </span>
                        <span className="ml-auto text-[11px] text-slate-400">{new Date(r.started_at).toLocaleString()}</span>
                    </div>
                    {r.error_message && <p className="mt-1 text-xs text-rose-600 dark:text-rose-400 break-words">{r.error_message}</p>}
                    {r.steps && r.steps.length > 0 && (
                        <ul className="mt-2 space-y-1">
                            {r.steps.map(s => (
                                <li key={s.index} className="flex items-start gap-1.5 text-xs text-slate-600 dark:text-slate-300">
                                    {stepIcon(s.status)}
                                    <span className="min-w-0">
                                        <span className="font-medium">{s.label || s.type}</span>
                                        {s.status === 'failed' && s.error && <span className="text-rose-600 dark:text-rose-400"> — {s.error}</span>}
                                        {s.status === 'success' && s.output && <span className="text-slate-500"> — {s.output.length > 160 ? `${s.output.slice(0, 160)}…` : s.output}</span>}
                                    </span>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            ))}
        </div>
    );
}

export default AlertResponseHistory;
