// ResponseActivityBell — keeps the analyst informed about every automated
// response, wherever they are in the dashboard:
//   • server-side automated playbook runs (started, finished, refused by a
//     guardrail) — from GET /automation/executions?updated_since=…
//   • agent-local prevention actions (process killed / file quarantined on the
//     endpoint by its own rule pack) — from POST /events/search
// New activity raises a toast and is listed in the bell panel with a link to
// the alert's response history.
import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bell, ShieldAlert, ShieldCheck, ShieldX, Zap } from 'lucide-react';
import { automationApi, eventsApi, type PlaybookExecution } from '../../api/client';
import { useToast } from '../Toast';
import { advanceActivityWindow, beginActivityWindow, createActivityWindow } from './activityWindow';

const POLL_MS = 10_000;
const MAX_ITEMS = 30;

interface ActivityItem {
    key: string;
    at: string;
    observedAt?: string;
    kind: 'automation' | 'endpoint';
    title: string;
    detail: string;
    tone: 'running' | 'success' | 'failed' | 'warning' | 'info';
    link?: string;
}

const toneIcon = {
    running: <Zap className="w-4 h-4 text-indigo-500" />,
    success: <ShieldCheck className="w-4 h-4 text-emerald-500" />,
    failed: <ShieldX className="w-4 h-4 text-rose-500" />,
    warning: <ShieldAlert className="w-4 h-4 text-amber-500" />,
    info: <ShieldAlert className="w-4 h-4 text-slate-400" />,
};

function describeExecution(e: PlaybookExecution): ActivityItem {
    const host = e.agent_hostname || e.agent_id.slice(0, 8);
    const alert = e.alert_title ? ` — alert "${e.alert_title}"` : '';
    let tone: ActivityItem['tone'] = 'running';
    let verb = 'running';
    switch (e.status) {
        case 'pending': verb = 'queued (another response is running on this host)'; break;
        case 'running': verb = 'running'; break;
        case 'completed': tone = 'success'; verb = 'completed'; break;
        case 'partial': tone = 'warning'; verb = 'finished with failed steps'; break;
        case 'failed': tone = 'failed'; verb = 'failed'; break;
        case 'cancelled': tone = 'info'; verb = 'not run (guardrail)'; break;
    }
    return {
        key: `x:${e.id}:${e.status}`,
        at: e.updated_at || e.started_at,
        kind: 'automation',
        title: `Automated response ${verb}: ${e.playbook_name}`,
        detail: `${host}${alert}${e.error_message ? ` · ${e.error_message}` : ''}`,
        tone,
        link: e.alert_id ? `/itsm/playbooks?alert_id=${encodeURIComponent(e.alert_id)}` : '/itsm/playbooks',
    };
}

export function ResponseActivityBell() {
    const { showToast } = useToast();
    const [items, setItems] = useState<ActivityItem[]>([]);
    const [unread, setUnread] = useState(0);
    const [open, setOpen] = useState(false);
    const [disabled, setDisabled] = useState(false);
    const [initialSince] = useState(() => new Date(Date.now() - 24 * 3600_000).toISOString());
    const [initialCutoff] = useState(() => Date.now());
    const windows = useRef({ runs: createActivityWindow(initialSince), events: createActivityWindow(initialSince) });
    const polling = useRef(false);
    const seen = useRef<Set<string>>(new Set());
    const panelRef = useRef<HTMLDivElement>(null);

    const push = useCallback((list: ActivityItem[]) => {
        const fresh = list.filter(i => {
            if (seen.current.has(i.key)) return false;
            seen.current.add(i.key);
            return true;
        });
        if (fresh.length === 0) return;
        while (seen.current.size > 10000) {
            const oldest = seen.current.values().next().value;
            if (oldest === undefined) break;
            seen.current.delete(oldest);
        }
        setItems(prev => [...fresh, ...prev].sort((a, b) => b.at.localeCompare(a.at)).slice(0, MAX_ITEMS));
        const notifications = fresh.filter(i => Date.parse(i.observedAt || i.at) > initialCutoff);
        if (notifications.length > 0) {
            setUnread(n => n + notifications.length);
            notifications.slice(0, 3).forEach(i => {
                const type = i.tone === 'failed' ? 'error' : i.tone === 'success' ? 'success' : i.tone === 'warning' ? 'warning' : 'info';
                showToast(`${i.title} — ${i.detail}`, type, 8000);
            });
        }
    }, [showToast, initialCutoff]);

    const poll = useCallback(async () => {
        if (document.visibilityState !== 'visible' || disabled || polling.current) return;
        polling.current = true;
        const now = new Date(Date.now() - 2_000).toISOString();
        const w = windows.current;
        beginActivityWindow(w.runs, now);
        beginActivityWindow(w.events, now);
        const collected: ActivityItem[] = [];
        try {
            // Continue saturated windows on the next poll. A keyset cursor
            // avoids skipping older runs when another run changes status.
            for (let page = 0; page < 3; page++) {
                const runs = await automationApi.listExecutions({ updated_since: w.runs.from, updated_until: w.runs.through,
                    cursor_updated_at: w.runs.afterAt || undefined, cursor_id: w.runs.afterID || undefined, trigger: 'automation', limit: 200 });
                runs.forEach(e => collected.push(describeExecution(e)));
                advanceActivityWindow(w.runs, runs, 200, e => e.updated_at);
                if (runs.length < 200) break;
            }
        } catch (err) {
            const status = (err as { response?: { status?: number } })?.response?.status;
            if (status === 401 || status === 403) {
                setDisabled(true); // role cannot read responses: no notifier
                polling.current = false;
                return;
            }
        }
        try {
            for (let page = 0; page < 3; page++) {
              const ev = await eventsApi.preventionActivity({
                from: w.events.from, through: w.events.through, limit: 200,
                cursor_ingested_at: w.events.afterAt || undefined, cursor_id: w.events.afterID || undefined,
              });
            ev.forEach(e => {
                const d = e.data || {};
                const action = String(d.response_action || d.action || 'action');
                const name = String(d.name || d.process_name || d.path || '');
                const failed = String(d.action || '').includes('failed');
                collected.push({
                    key: `e:${e.id}`,
                    at: e.timestamp,
                    observedAt: e.ingested_at,
                    kind: 'endpoint',
                    title: `Endpoint prevention: ${action.replace(/_/g, ' ')}${name ? ` — ${name}` : ''}`,
                    detail: `${d.matched_rule_title || d.threat_name || 'local rule'} · agent ${String(e.agent_id).slice(0, 8)}`,
                    tone: failed ? 'failed' : 'warning',
                    link: `/management/devices/${encodeURIComponent(e.agent_id)}`,
                });
            });
              advanceActivityWindow(w.events, ev, 200, e => e.ingested_at);
              if (ev.length < 200) break;
            }
        } catch {
            // events API unavailable for this role: executions still notify
        }
        polling.current = false;
        push(collected);
    }, [disabled, push]);

    useEffect(() => {
        const initialPoll = setTimeout(poll, 0);
        const t = setInterval(poll, POLL_MS);
        const onVisible = () => { if (document.visibilityState === 'visible') poll(); };
        document.addEventListener('visibilitychange', onVisible);
        return () => { clearTimeout(initialPoll); clearInterval(t); document.removeEventListener('visibilitychange', onVisible); };
    }, [poll]);

    useEffect(() => {
        if (!open) return;
        const close = (e: MouseEvent) => { if (panelRef.current && !panelRef.current.contains(e.target as Node)) setOpen(false); };
        document.addEventListener('mousedown', close);
        return () => document.removeEventListener('mousedown', close);
    }, [open]);

    if (disabled) return null;

    return (
        <div className="relative" ref={panelRef}>
            <button
                type="button"
                onClick={() => { setOpen(o => !o); setUnread(0); }}
                className="relative p-2 rounded-md text-[var(--xc-nav-text)] hover:bg-[var(--xc-nav-hover)]"
                aria-label="Response activity"
                title="Automated response activity"
            >
                <Bell className="w-4 h-4" />
                {unread > 0 && (
                    <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-rose-500 text-white text-[10px] font-bold flex items-center justify-center">
                        {unread > 9 ? '9+' : unread}
                    </span>
                )}
            </button>
            {open && (
                <div className="absolute right-0 mt-2 w-96 max-h-[70vh] overflow-y-auto rounded-xl shadow-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 z-[60]">
                    <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
                        <span className="text-sm font-bold text-slate-900 dark:text-white">Response activity</span>
                        <Link to="/itsm/playbooks" onClick={() => setOpen(false)} className="text-xs text-indigo-600 dark:text-indigo-400 hover:underline">All runs</Link>
                    </div>
                    {items.length === 0 ? (
                        <p className="p-4 text-sm text-slate-500">No automated response activity in the last 24 hours.</p>
                    ) : (
                        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                            {items.map(i => (
                                <li key={i.key}>
                                    <Link to={i.link || '#'} onClick={() => setOpen(false)} className="flex gap-3 px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/60">
                                        <span className="mt-0.5 shrink-0">{toneIcon[i.tone]}</span>
                                        <span className="min-w-0">
                                            <span className="block text-sm font-medium text-slate-800 dark:text-slate-200">{i.title}</span>
                                            <span className="block text-xs text-slate-500 break-words">{i.detail}</span>
                                            <span className="block text-[10px] text-slate-400 mt-0.5">
                                                {i.kind === 'endpoint' ? 'Agent-local prevention' : 'Server automation'} · {new Date(i.at).toLocaleString()}
                                            </span>
                                        </span>
                                    </Link>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            )}
        </div>
    );
}

export default ResponseActivityBell;
