// PlaybookRunPanel — previews and runs a playbook on the server-side response
// engine. Parameters are bound by the server from the alert ({{alert.*}}),
// shown for review, optionally overridden, and the run is tracked by polling
// the execution record (real agent results, not a client-side simulation).
import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle, Circle, Loader2, MinusCircle, Play, Server, XCircle } from 'lucide-react';
import {
    automationApi, isExecutionFinished,
    type BoundPlaybookStep, type PlaybookExecution, type PlaybookRunPlan,
} from '../../api/client';
import { apiErrorMessage } from '../../api/apiError';

const POLL_MS = 2000;

// Identity / attribution values bound from the alert: shown, not edited
// (they protect against terminating a reused PID).
const READONLY_PARAMS = new Set(['process_path', 'process_started_at']);

const stepIcon = (status: string) => {
    switch (status) {
        case 'success': return <CheckCircle className="w-4 h-4 text-emerald-500" />;
        case 'failed': return <XCircle className="w-4 h-4 text-rose-500" />;
        case 'running': return <Loader2 className="w-4 h-4 text-indigo-500 animate-spin" />;
        case 'skipped': return <MinusCircle className="w-4 h-4 text-slate-400" />;
        default: return <Circle className="w-4 h-4 text-slate-300 dark:text-slate-600" />;
    }
};

const executionBanner: Record<string, { text: string; style: string }> = {
    completed: { text: 'Playbook completed successfully', style: 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800/50 text-emerald-700 dark:text-emerald-400' },
    partial: { text: 'Playbook finished with failed steps (continued on failure)', style: 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800/50 text-amber-700 dark:text-amber-400' },
    failed: { text: 'Playbook failed', style: 'bg-rose-50 dark:bg-rose-900/20 border-rose-200 dark:border-rose-800/50 text-rose-700 dark:text-rose-400' },
    cancelled: { text: 'Playbook cancelled', style: 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300' },
};

interface PlaybookRunPanelProps {
    playbookId: string;
    /** Sigma alert the run responds to (binds {{alert.*}} and the target endpoint). */
    alertId?: string;
    /** Target endpoint when there is no alert. */
    agentId?: string;
    /** Called when the server accepted the run. */
    onStarted?: (execution: PlaybookExecution) => void;
    /** Called once when a started run reaches a terminal status. */
    onFinished?: (execution: PlaybookExecution) => void;
}

export function PlaybookRunPanel({ playbookId, alertId, agentId, onStarted, onFinished }: PlaybookRunPanelProps) {
    const [plan, setPlan] = useState<PlaybookRunPlan | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [overrides, setOverrides] = useState<Record<number, Record<string, string>>>({});
    const [reason, setReason] = useState('');
    const [starting, setStarting] = useState(false);
    const [execution, setExecution] = useState<PlaybookExecution | null>(null);
    const [priorRuns, setPriorRuns] = useState<PlaybookExecution[]>([]);
    const [activeOnHost, setActiveOnHost] = useState<PlaybookExecution[]>([]);
    const onFinishedRef = useRef(onFinished);
    onFinishedRef.current = onFinished;

    const hasTarget = !!(alertId || agentId);

    // Bind the playbook to the alert/endpoint (preview only, nothing runs).
    useEffect(() => {
        setPlan(null);
        setError(null);
        setOverrides({});
        setExecution(null);
        if (!hasTarget) return;
        let cancelled = false;
        setLoading(true);
        automationApi.previewRun(playbookId, { alertId, agentId })
            .then(p => { if (!cancelled) setPlan(p); })
            .catch(err => {
                if (cancelled) return;
                const data = (err as { response?: { data?: { plan?: PlaybookRunPlan } } })?.response?.data;
                if (data?.plan) setPlan(data.plan);
                setError(apiErrorMessage(err, 'Could not prepare the playbook'));
            })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [playbookId, alertId, agentId, hasTarget]);

    // Coordination context: what already ran for this alert, and whether a
    // response is executing on the endpoint now (a new run will queue).
    const planAgent = plan?.agent_id;
    useEffect(() => {
        let cancelled = false;
        if (alertId) {
            automationApi.listExecutions({ alert_id: alertId, limit: 5 })
                .then(list => { if (!cancelled) setPriorRuns(list); })
                .catch(() => { /* optional context */ });
        }
        if (planAgent) {
            automationApi.listExecutions({ agent_id: planAgent, status: 'pending,running', limit: 5 })
                .then(list => { if (!cancelled) setActiveOnHost(list); })
                .catch(() => { /* optional context */ });
        }
        return () => { cancelled = true; };
    }, [alertId, planAgent]);

    // Track the run until it reaches a terminal status.
    const executionId = execution?.id;
    const finished = execution ? isExecutionFinished(execution.status) : false;
    useEffect(() => {
        if (!executionId || finished) return;
        let cancelled = false;
        let timer: ReturnType<typeof setTimeout>;
        const poll = async () => {
            try {
                const next = await automationApi.getExecution(executionId);
                if (cancelled) return;
                setExecution(next);
                if (isExecutionFinished(next.status)) {
                    onFinishedRef.current?.(next);
                    return;
                }
            } catch {
                // Transient errors: keep polling; the run continues server-side.
            }
            if (!cancelled) timer = setTimeout(poll, POLL_MS);
        };
        timer = setTimeout(poll, POLL_MS);
        return () => { cancelled = true; clearTimeout(timer); };
    }, [executionId, finished]);

    const setOverride = (index: number, key: string, value: string) => {
        setOverrides(prev => ({ ...prev, [index]: { ...(prev[index] || {}), [key]: value } }));
    };

    const start = async () => {
        if (!plan) return;
        setStarting(true);
        setError(null);
        try {
            const res = await automationApi.runPlaybook(playbookId, {
                alert_id: alertId || undefined,
                agent_id: alertId ? undefined : agentId,
                reason: reason.trim() || undefined,
                overrides: Object.keys(overrides).length > 0 ? overrides : undefined,
            });
            setPlan(res.plan);
            setExecution(res.execution);
            onStarted?.(res.execution);
        } catch (err) {
            const data = (err as { response?: { data?: { plan?: PlaybookRunPlan } } })?.response?.data;
            if (data?.plan) setPlan(data.plan);
            setError(apiErrorMessage(err, 'Could not start the playbook'));
        } finally {
            setStarting(false);
        }
    };

    if (!hasTarget) {
        return <p className="text-sm text-slate-500">Select a target endpoint to prepare this playbook.</p>;
    }
    if (loading) {
        return (
            <div className="flex items-center gap-2 text-sm text-slate-500 py-6 justify-center">
                <Loader2 className="w-4 h-4 animate-spin" /> Binding parameters to the alert…
            </div>
        );
    }

    // While/after running, show the live per-step state from the server.
    const steps: BoundPlaybookStep[] = (execution?.steps && execution.steps.length > 0) ? execution.steps : (plan?.steps || []);
    const started = !!execution;
    const hasOverrides = Object.keys(overrides).length > 0;
    const canRun = !!plan && !started && !starting && plan.agent_online && (plan.ready || hasOverrides);

    return (
        <div className="space-y-4">
            {plan && (
                <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                        <Server className="w-3.5 h-3.5" />
                        {plan.agent_hostname || plan.agent_id}
                    </span>
                    <span className={`px-2.5 py-1 rounded-md font-semibold border ${plan.agent_online
                        ? 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50'
                        : 'bg-rose-50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800/50'}`}>
                        {plan.agent_online ? 'Online' : 'Offline'}
                    </span>
                    {plan.alert_id && <span className="font-mono text-slate-400 truncate" title={plan.alert_id}>alert {plan.alert_id.slice(0, 8)}</span>}
                </div>
            )}

            {plan?.warnings && plan.warnings.length > 0 && (
                <div className="rounded-lg border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/10 p-3 text-xs text-amber-700 dark:text-amber-400 space-y-1">
                    {plan.warnings.map((w, i) => (
                        <div key={i} className="flex items-start gap-1.5"><AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />{w}</div>
                    ))}
                </div>
            )}

            {!execution && priorRuns.length > 0 && (
                <div className="rounded-lg border border-indigo-200 dark:border-indigo-800/50 bg-indigo-50 dark:bg-indigo-900/10 p-3 text-xs text-indigo-800 dark:text-indigo-300 space-y-1">
                    <div className="font-semibold">Responses already run for this alert:</div>
                    {priorRuns.map(r => (
                        <div key={r.id}>
                            {r.trigger_source === 'automation' ? 'Automated' : `Manual (${r.created_by_username || 'analyst'})`} · {r.playbook_name} · <strong>{r.status === 'pending' ? 'queued' : r.status}</strong> · {new Date(r.started_at).toLocaleString()}
                        </div>
                    ))}
                    <div className="text-indigo-600/80 dark:text-indigo-400/80">Steps whose goal is already met (e.g. the host is isolated, the process has exited) succeed without acting again.</div>
                </div>
            )}
            {!execution && activeOnHost.length > 0 && (
                <div className="rounded-lg border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/10 p-3 text-xs text-amber-800 dark:text-amber-300">
                    A response is executing on this endpoint now ({activeOnHost[0].playbook_name}). A new run is queued and starts when it finishes — runs never interleave on one host.
                </div>
            )}

            <div className="space-y-2">
                {steps.map(step => {
                    const params = step.params || {};
                    const editable = !started && step.type !== 'run_script' && step.type !== 'run_cmd';
                    return (
                        <div key={step.index} className="rounded-lg border border-slate-200 dark:border-slate-700 p-3 bg-slate-50/60 dark:bg-slate-900/40">
                            <div className="flex items-center gap-2">
                                {stepIcon(started ? step.status : (step.errors?.length ? 'failed' : 'pending'))}
                                <span className="text-xs font-bold text-slate-400">{step.index + 1}.</span>
                                <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">{step.label || step.type}</span>
                                {step.script_name && <span className="text-xs text-indigo-600 dark:text-indigo-400 font-mono truncate">{step.script_name}</span>}
                                {step.on_failure === 'continue' && <span className="ml-auto text-[10px] uppercase font-bold text-slate-400">continue on failure</span>}
                            </div>
                            {step.type === 'terminate_process' && (
                                <div className="mt-2 pl-6 flex items-center gap-2 text-xs">
                                    <span className="w-24 shrink-0 text-slate-500">Scope</span>
                                    {editable ? (
                                        <select
                                            value={overrides[step.index]?.kill_tree ?? params.kill_tree ?? 'false'}
                                            onChange={e => setOverride(step.index, 'kill_tree', e.target.value)}
                                            className="flex-1 min-w-0 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded px-2 py-1 text-slate-800 dark:text-slate-200 focus:ring-1 focus:ring-indigo-500 outline-none"
                                        >
                                            <option value="false">This process only</option>
                                            <option value="true">Process tree — the process and every process it started</option>
                                        </select>
                                    ) : (
                                        <span className="text-slate-700 dark:text-slate-300">{params.kill_tree === 'true' ? 'Process tree' : 'This process only'}</span>
                                    )}
                                </div>
                            )}
                            {Object.keys(params).filter(k => !(step.type === 'terminate_process' && k === 'kill_tree')).length > 0 && (
                                <div className="mt-2 grid grid-cols-1 gap-1.5 pl-6">
                                    {Object.entries(params).filter(([key]) => !(step.type === 'terminate_process' && key === 'kill_tree')).map(([key, value]) => (
                                        <label key={key} className="flex items-center gap-2 text-xs">
                                            <span className="w-24 shrink-0 text-slate-500 font-mono">{key}</span>
                                            {editable && !READONLY_PARAMS.has(key) ? (
                                                <input
                                                    type="text"
                                                    value={overrides[step.index]?.[key] ?? value}
                                                    onChange={e => setOverride(step.index, key, e.target.value)}
                                                    className="flex-1 min-w-0 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded px-2 py-1 font-mono text-slate-800 dark:text-slate-200 focus:ring-1 focus:ring-indigo-500 outline-none"
                                                />
                                            ) : (
                                                <span className="flex-1 min-w-0 font-mono text-slate-700 dark:text-slate-300 break-all">{value || '—'}</span>
                                            )}
                                        </label>
                                    ))}
                                </div>
                            )}
                            {!started && step.errors && step.errors.length > 0 && (
                                <ul className="mt-2 pl-6 text-xs text-rose-600 dark:text-rose-400 list-disc list-inside">
                                    {step.errors.map((e, i) => <li key={i}>{e}</li>)}
                                </ul>
                            )}
                            {started && step.error && <p className="mt-2 pl-6 text-xs text-rose-600 dark:text-rose-400 break-all">{step.error}</p>}
                            {started && step.output && (
                                <pre className="mt-2 ml-6 p-2 max-h-32 overflow-auto rounded bg-slate-900 text-[11px] text-emerald-300 whitespace-pre-wrap break-all">{step.output}</pre>
                            )}
                        </div>
                    );
                })}
            </div>

            {error && (
                <div className="rounded-lg border border-rose-200 dark:border-rose-800/50 bg-rose-50 dark:bg-rose-900/20 p-3 text-sm text-rose-700 dark:text-rose-400 flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />{error}
                </div>
            )}

            {execution && finished && (
                <div className={`rounded-lg border p-3 text-sm font-semibold ${(executionBanner[execution.status] || executionBanner.failed).style}`}>
                    {(executionBanner[execution.status] || executionBanner.failed).text}
                    {execution.error_message && <span className="block font-normal text-xs mt-1 break-all">{execution.error_message}</span>}
                </div>
            )}
            {execution && !finished && (
                <div className="flex items-center gap-2 text-sm text-indigo-600 dark:text-indigo-400">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    {execution.status === 'pending'
                        ? 'Queued — waiting for another response on this endpoint to finish'
                        : `Running on the endpoint — step ${Math.min(execution.commands_executed + 1, execution.commands_total)} of ${execution.commands_total}`}
                </div>
            )}

            {!started && plan && (
                <div className="space-y-3 pt-1">
                    <input
                        type="text"
                        value={reason}
                        onChange={e => setReason(e.target.value)}
                        maxLength={500}
                        placeholder="Reason (recorded in the audit log)"
                        className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 outline-none"
                    />
                    {!plan.agent_online && <p className="text-xs text-rose-600 dark:text-rose-400">The endpoint is offline; the playbook cannot run now.</p>}
                    {plan.agent_online && !plan.ready && !hasOverrides && (
                        <p className="text-xs text-rose-600 dark:text-rose-400">Some parameters could not be resolved from the alert. Fill them in above.</p>
                    )}
                    <button
                        type="button"
                        onClick={start}
                        disabled={!canRun}
                        className="w-full px-4 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 font-semibold flex items-center justify-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {starting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                        {starting ? 'Starting…' : `Run ${plan.steps.length} step${plan.steps.length === 1 ? '' : 's'} on ${plan.agent_hostname || 'endpoint'}`}
                    </button>
                </div>
            )}
        </div>
    );
}

export default PlaybookRunPanel;
