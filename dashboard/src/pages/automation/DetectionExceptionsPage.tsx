import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Clock3, Loader2, Plus, RefreshCw, Search, ShieldCheck, ShieldOff, Trash2 } from 'lucide-react';
import { authApi, detectionExceptionsApi, type DetectionException } from '../../api/client';
import { apiErrorMessage } from '../../api/apiError';
import { ConfirmDialog } from '../../components/Modal';
import { CreateExceptionModal } from '../../components/alerts/CreateExceptionModal';

type ExceptionState = 'active' | 'disabled' | 'expired';
const stateOf = (exception: DetectionException): ExceptionState => exception.expires_at && new Date(exception.expires_at).getTime() <= Date.now() ? 'expired' : exception.enabled ? 'active' : 'disabled';
const date = (value?: string) => value ? new Date(value).toLocaleString() : 'Never';

export function DetectionExceptionsPage() {
    const [items, setItems] = useState<DetectionException[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [actionError, setActionError] = useState<string | null>(null);
    const [creating, setCreating] = useState(false);
    const [deleting, setDeleting] = useState<DetectionException | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [search, setSearch] = useState('');
    const [filter, setFilter] = useState<'all' | ExceptionState>('all');
    const [, tick] = useState(0);
    const request = useRef(0);
    const mutation = useRef(false);
    const canManage = authApi.hasRole(['admin', 'security']);

    const load = useCallback(async () => {
        const version = ++request.current;
        setLoading(true);
        setError(null);
        try {
            const rows = await detectionExceptionsApi.list();
            if (request.current === version) setItems(rows);
        } catch (err) {
            if (request.current === version) setError(apiErrorMessage(err, 'Could not load detection exceptions.'));
        } finally {
            if (request.current === version) setLoading(false);
        }
    }, []);
    useEffect(() => { const tracker = request; void load(); return () => { tracker.current++; }; }, [load]);
    // Keep expiry labels and filters accurate while the page remains open.
    useEffect(() => { const timer = window.setInterval(() => tick(value => value + 1), 30_000); return () => window.clearInterval(timer); }, []);

    const toggle = async (exception: DetectionException) => {
        if (mutation.current || !canManage || stateOf(exception) === 'expired') return;
        mutation.current = true;
        setBusy(exception.id);
        setActionError(null);
        try {
            const updated = await detectionExceptionsApi.update(exception.id, { enabled: !exception.enabled });
            setItems(previous => previous.map(item => item.id === updated.id ? updated : item));
        } catch (err) { setActionError(apiErrorMessage(err, 'Could not update the exception.')); }
        finally { mutation.current = false; setBusy(null); }
    };
    const remove = async () => {
        if (!deleting || mutation.current || !canManage) return;
        mutation.current = true;
        setBusy(deleting.id);
        setActionError(null);
        try {
            await detectionExceptionsApi.delete(deleting.id);
            setItems(previous => previous.filter(item => item.id !== deleting.id));
            setDeleting(null);
        } catch (err) { setActionError(apiErrorMessage(err, 'Could not delete the exception.')); }
        finally { mutation.current = false; setBusy(null); }
    };

    const term = search.trim().toLowerCase();
    const visible = items.filter(item => (filter === 'all' || stateOf(item) === filter) && [item.name, item.reason, item.rule_title, item.rule_id, item.hostname, item.agent_id, ...item.conditions.map(c => `${c.field} ${c.op} ${c.value}`)].join(' ').toLowerCase().includes(term));
    const active = items.filter(item => stateOf(item) === 'active').length;
    const expired = items.filter(item => stateOf(item) === 'expired').length;
    const hits = items.reduce((count, item) => count + item.hit_count, 0);

    return <div className="min-w-0 space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex min-w-0 items-start gap-3">
                <span className="rounded-xl border border-indigo-200 bg-indigo-50 p-2.5 dark:border-indigo-800 dark:bg-indigo-950/40"><ShieldOff className="h-5 w-5 text-indigo-600 dark:text-indigo-400" /></span>
                <div className="min-w-0"><h1 className="text-xl font-bold text-slate-900 dark:text-white">Detection Exceptions</h1>
                    <p className="mt-1 max-w-2xl text-sm text-slate-500">Review approved benign activity, its scope and how often detections were suppressed.</p>
                </div>
            </div>
            <div className="flex items-center gap-2">
                <button type="button" onClick={() => void load()} disabled={loading || !!busy} className="btn btn-secondary inline-flex items-center gap-2 disabled:opacity-50"><RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} /> Refresh</button>
                {canManage && <button type="button" onClick={() => setCreating(true)} className="btn btn-primary inline-flex items-center gap-2"><Plus className="h-4 w-4" /> New exception</button>}
            </div>
        </div>
        {!canManage && <p className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-500 dark:border-slate-700 dark:bg-slate-900/30">Read-only access. Managing exceptions requires the administrator or security role.</p>}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {[{ label: 'Active exceptions', value: active, Icon: ShieldCheck }, { label: 'Suppressed rule matches', value: hits.toLocaleString(), Icon: ShieldOff }, { label: 'Expired exceptions', value: expired, Icon: Clock3 }].map(({ label, value, Icon }) => <div key={label} className="flex items-center gap-3 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-800">
                <Icon className="h-5 w-5 text-slate-400" /><div><p className="text-xs text-slate-500">{label}</p><p className="mt-1 text-xl font-semibold text-slate-900 dark:text-white">{value}</p></div>
            </div>)}
        </div>
        <div className="flex flex-col gap-3 sm:flex-row">
            <div className="relative min-w-0 flex-1"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                <label htmlFor="exception-search" className="sr-only">Search exceptions</label>
                <input id="exception-search" className="input !pl-9" placeholder="Search name, rule, endpoint or condition…" value={search} onChange={event => setSearch(event.target.value)} />
            </div>
            <div className="min-w-0 sm:w-44"><label htmlFor="exception-state" className="sr-only">Filter by state</label>
                <select id="exception-state" className="input" value={filter} onChange={event => setFilter(event.target.value as typeof filter)}><option value="all">All states</option><option value="active">Active</option><option value="disabled">Disabled</option><option value="expired">Expired</option></select>
            </div>
        </div>
        {(error || actionError) && <div role="alert" className="flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700 dark:border-rose-900 dark:bg-rose-950/30 dark:text-rose-400"><AlertTriangle className="h-4 w-4 shrink-0" />{actionError || error}</div>}
        {loading && !items.length ? <div role="status" className="flex items-center justify-center gap-2 rounded-xl border border-slate-200 p-10 text-sm text-slate-500 dark:border-slate-700"><Loader2 className="h-4 w-4 animate-spin" /> Loading exceptions…</div>
            : !visible.length ? <div className="rounded-xl border border-dashed border-slate-300 bg-white p-8 text-center dark:border-slate-700 dark:bg-slate-800">
                <ShieldOff className="mx-auto mb-3 h-7 w-7 text-slate-400" />
                <p className="text-sm font-semibold text-slate-900 dark:text-white">{error && !items.length ? 'Exceptions could not be loaded' : items.length ? 'No matching exceptions' : 'No detection exceptions yet'}</p>
                <p className="mt-2 text-xs text-slate-500">{error && !items.length ? 'Use Refresh to try again.' : items.length ? 'Change the search or state filter.' : 'Create a precise exception from an alert using “False Positive…”, or choose New exception.'}</p>
            </div> : <div className="space-y-3">
                <p className="text-xs text-slate-500">Showing {visible.length} of {items.length} exceptions · Hit counts update periodically.</p>
                {visible.map(exception => {
                    const state = stateOf(exception);
                    return <article key={exception.id} aria-label={exception.name} className="min-w-0 rounded-xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-700 dark:bg-slate-800">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                            <div className="min-w-0 flex-1"><h2 className="break-words text-sm font-semibold text-slate-900 dark:text-white">{exception.name}</h2><p className="mt-1 break-words text-xs text-slate-500">{exception.reason}</p></div>
                            <div className="flex shrink-0 items-center gap-2">
                                {state === 'expired' ? <span className="rounded-md bg-amber-50 px-2.5 py-1 text-xs font-medium text-amber-700 dark:bg-amber-950/30 dark:text-amber-400">Expired</span>
                                    : <button type="button" disabled={!canManage || !!busy || loading} onClick={() => void toggle(exception)} aria-label={`${exception.enabled ? 'Disable' : 'Enable'} exception ${exception.name}`} aria-pressed={exception.enabled}
                                        className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold disabled:opacity-50 ${exception.enabled ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-400' : 'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-900'}`}>
                                        {busy === exception.id && <Loader2 className="h-3 w-3 animate-spin" />}{exception.enabled ? 'Active' : 'Disabled'}
                                    </button>}
                                {canManage && <button type="button" disabled={!!busy || loading} onClick={() => { setActionError(null); setDeleting(exception); }} aria-label={`Delete exception ${exception.name}`} className="rounded-md p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-600 disabled:opacity-50 dark:hover:bg-rose-950/40"><Trash2 className="h-4 w-4" /></button>}
                            </div>
                        </div>
                        <div className="mt-4 grid min-w-0 grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)_minmax(0,0.8fr)]">
                            <div className="min-w-0"><p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Scope</p>
                                <p className="break-words text-xs font-medium text-slate-700 dark:text-slate-200">{exception.rule_id ? exception.rule_title || exception.rule_id : 'All rules'}</p>
                                <p className="mt-1 break-words text-xs text-slate-500">{exception.agent_id ? exception.hostname || exception.agent_id : 'All endpoints'}</p>
                            </div>
                            <div className="min-w-0"><p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Conditions · all must match</p>
                                <div className="space-y-1">{exception.conditions.map((condition, index) => <p key={index} className="break-all rounded-md bg-slate-50 px-2 py-1 font-mono text-[11px] text-slate-600 dark:bg-slate-900/50 dark:text-slate-300"><span className="font-semibold text-indigo-600 dark:text-indigo-400">{condition.field}</span> {condition.op} {condition.value}</p>)}</div>
                            </div>
                            <div className="min-w-0 text-xs text-slate-500"><p><span className="font-semibold text-slate-700 dark:text-slate-200">{exception.hit_count.toLocaleString()}</span> suppressed matches</p>
                                <p className="mt-1">Last hit: {exception.last_hit_at ? date(exception.last_hit_at) : 'None'}</p><p className="mt-1">Expires: {date(exception.expires_at)}</p>
                            </div>
                        </div>
                        <p className="mt-3 break-words border-t border-slate-100 pt-3 text-[11px] text-slate-400 dark:border-slate-700">Created by {exception.created_by || '—'} · {date(exception.created_at)}</p>
                    </article>;
                })}
            </div>}
        {creating && <CreateExceptionModal isOpen onClose={() => setCreating(false)} onCreated={() => load()} />}
        {deleting && <ConfirmDialog isOpen onClose={() => { if (!mutation.current) setDeleting(null); }} onConfirm={() => void remove()} title="Delete detection exception" message={`Delete “${deleting.name}”? Future matching activity will be evaluated without this exception.`} confirmText="Delete exception" variant="danger" isLoading={!!busy} errorMessage={actionError} />}
    </div>;
}
export default DetectionExceptionsPage;
