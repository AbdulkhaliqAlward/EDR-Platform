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
import { Bell, Clock, MapPin, ShieldAlert, ShieldCheck, ShieldX, Zap } from 'lucide-react';
import { agentsApi, automationApi, eventsApi, type AgentNetworkContext, type PlaybookExecution } from '../../api/client';
import { useToast } from '../Toast';
import { useServerClock } from '../../hooks/useServerClock';
import { formatAgentLocation } from '../../utils/agentLocation';
import { describeClockOffset } from '../../utils/serverTime';
import { advanceActivityWindow, beginActivityWindow, createActivityWindow } from './activityWindow';

const POLL_MS = 10_000;
const MAX_ITEMS = 30;

interface ActivityItem {
    key: string;
    /** Server-clock time (agent event times are normalised on ingestion). */
    at: string;
    observedAt?: string;
    kind: 'automation' | 'endpoint';
    title: string;
    detail: string;
    agentId?: string;
    host?: string;
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
    const alert = e.alert_title ? `Alert "${e.alert_title}"` : 'Playbook run';
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
        detail: `${alert}${e.error_message ? ` · ${e.error_message}` : ''}`,
        agentId: e.agent_id,
        host: e.agent_hostname || undefined,
        tone,
        link: e.alert_id ? `/itsm/playbooks?alert_id=${encodeURIComponent(e.alert_id)}` : '/itsm/playbooks',
    };
}

// Where an item's agent connects from + its clock note, for display/toasts.
function agentLine(i: ActivityItem, ctx?: AgentNetworkContext): { host: string; location: string; clock: string } {
    const host = i.host || ctx?.hostname || (i.agentId ? `agent ${i.agentId.slice(0, 8)}` : '');
    const off = ctx?.clock_offset_ms ?? 0;
    return {
        host,
        location: formatAgentLocation(ctx),
        clock: Math.abs(off) >= 1000 ? `Agent clock ${describeClockOffset(off)} — time shown is server time` : '',
    };
}

export function ResponseActivityBell() {
    const { showToast } = useToast();
    const { clock, now: serverNow, ready: clockReady, format, zoneLabel } = useServerClock();
    const [contexts, setContexts] = useState<Record<string, AgentNetworkContext>>({});
    const contextsRef = useRef<Record<string, AgentNetworkContext>>({});
    const contextTried = useRef<Set<string>>(new Set());
    const contextDenied = useRef(false);
    const [items, setItems] = useState<ActivityItem[]>([]);
    const [unread, setUnread] = useState(0);
    const [open, setOpen] = useState(false);
    const [disabled, setDisabled] = useState(false);
    const [initialSince] = useState(() => new Date(Date.now() - 24 * 3600_000).toISOString());
    const [initialCutoff] = useState(() => Date.now());
    const serverNowRef = useRef(serverNow);
    useEffect(() => { serverNowRef.current = serverNow; }, [serverNow]);
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
        setItems(prev => [...fresh, ...prev].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, MAX_ITEMS));
        // Server-clock comparison: the browser's own clock may be off.
        const cutoff = initialCutoff + (serverNowRef.current() - Date.now());
        const notifications = fresh.filter(i => Date.parse(i.observedAt || i.at) > cutoff);
        if (notifications.length > 0) {
            setUnread(n => n + notifications.length);
            notifications.slice(0, 3).forEach(i => {
                const type = i.tone === 'failed' ? 'error' : i.tone === 'success' ? 'success' : i.tone === 'warning' ? 'warning' : 'info';
                const a = agentLine(i, i.agentId ? contextsRef.current[i.agentId] : undefined);
                const where = [a.host, a.location].filter(Boolean).join(' — ');
                showToast(`${i.title} — ${i.detail}${where ? ` · ${where}` : ''}`, type, 8000);
            });
        }
    }, [showToast, initialCutoff]);

    // Agent locations for new items (best effort; skipped for roles that
    // cannot read endpoints).
    const loadContexts = useCallback(async (list: ActivityItem[]) => {
        if (contextDenied.current) return;
        const ids = [...new Set(list.map(i => i.agentId).filter((id): id is string => !!id && !contextTried.current.has(id)))];
        if (ids.length === 0) return;
        ids.forEach(id => contextTried.current.add(id));
        try {
            const rows = await agentsApi.networkContext(ids);
            if (rows.length === 0) return;
            const next = { ...contextsRef.current };
            rows.forEach(r => { next[r.agent_id] = r; });
            contextsRef.current = next;
            setContexts(next);
        } catch (err) {
            const status = (err as { response?: { status?: number } })?.response?.status;
            if (status === 401 || status === 403) contextDenied.current = true;
            else ids.forEach(id => contextTried.current.delete(id)); // retry next poll
        }
    }, []);

    const poll = useCallback(async () => {
        // Windows are bounded by the server clock: wait until it is known so a
        // browser clock that runs ahead cannot push a window into the future
        // (the next window would then skip the activity in between).
        if (!clockReady || document.visibilityState !== 'visible' || disabled || polling.current) return;
        polling.current = true;
        const now = new Date(serverNowRef.current() - 2_000).toISOString();
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
                    detail: `${d.matched_rule_title || d.threat_name || 'local rule'}`,
                    agentId: String(e.agent_id),
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
        await loadContexts(collected);
        polling.current = false;
        push(collected);
    }, [clockReady, disabled, push, loadContexts]);

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
                        <span className="min-w-0">
                            <span className="block text-sm font-bold text-slate-900 dark:text-white">Response activity</span>
                            <span className="block text-[10px] text-slate-400">Times in {zoneLabel} (server time)</span>
                        </span>
                        <Link to="/itsm/playbooks" onClick={() => setOpen(false)} className="text-xs text-indigo-600 dark:text-indigo-400 hover:underline">All runs</Link>
                    </div>
                    {items.length === 0 ? (
                        <p className="p-4 text-sm text-slate-500">No automated response activity in the last 24 hours.</p>
                    ) : (
                        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
                            {items.map(i => {
                                const a = agentLine(i, i.agentId ? contexts[i.agentId] : undefined);
                                return (
                                <li key={i.key}>
                                    <Link to={i.link || '#'} onClick={() => setOpen(false)} className="flex gap-3 px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/60">
                                        <span className="mt-0.5 shrink-0">{toneIcon[i.tone]}</span>
                                        <span className="min-w-0">
                                            <span className="block text-sm font-medium text-slate-800 dark:text-slate-200">{i.title}</span>
                                            <span className="block text-xs text-slate-500 break-words">{[a.host, i.detail].filter(Boolean).join(' · ')}</span>
                                            {a.location && (
                                                <span className="flex items-start gap-1 text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 break-words">
                                                    <MapPin className="w-3 h-3 mt-[1px] shrink-0" aria-hidden="true" />{a.location}
                                                </span>
                                            )}
                                            <span className="flex items-center gap-1 text-[10px] text-slate-400 mt-0.5">
                                                <Clock className="w-3 h-3 shrink-0" aria-hidden="true" />
                                                {i.kind === 'endpoint' ? 'Agent-local prevention' : 'Server automation'} · {format(i.at)}
                                            </span>
                                            {a.clock && <span className="block text-[10px] text-amber-600 dark:text-amber-400 mt-0.5">{a.clock}</span>}
                                        </span>
                                    </Link>
                                </li>
                                );
                            })}
                        </ul>
                    )}
                    {clock?.geoip?.attribution_url && Object.keys(contexts).length > 0 && (
                        // Required attribution for the DB-IP Lite database (CC BY 4.0).
                        <div className="px-4 py-2 border-t border-slate-100 dark:border-slate-800 text-[10px] text-slate-400">
                            <a href={clock.geoip.attribution_url} target="_blank" rel="noopener noreferrer" className="hover:underline">IP Geolocation by DB-IP</a>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default ResponseActivityBell;
