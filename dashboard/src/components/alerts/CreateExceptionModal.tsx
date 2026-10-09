import { useEffect, useRef, useState, useId } from 'react';
import { AlertTriangle, CheckCircle2, FileCheck2, Loader2, Monitor, Plus, ShieldOff, Trash2 } from 'lucide-react';
import { Modal } from '../Modal';
import { alertsApi, authApi, detectionExceptionsApi, type Alert } from '../../api/client';
import { apiErrorMessage } from '../../api/apiError';
import { ExceptionEndpointPicker, type ExceptionEndpoint } from './ExceptionEndpointPicker';
import {
    buildExceptionInput, candidatesFromAlert, EXCEPTION_FIELDS, EXCEPTION_OPS, MAX_CONDITIONS,
    validateExceptionDraft, type ExceptionCandidate, type ExceptionDraft,
} from './exceptionForm';

interface CreateExceptionModalProps {
    isOpen: boolean;
    onClose: () => void;
    alert?: Alert | null;
    onCreated?: (markedFalsePositive: boolean) => void | Promise<void>;
    updateAlertStatus?: boolean;
}

export function CreateExceptionModal(props: CreateExceptionModalProps) {
    // A new session resets the draft on reopen or when switching to a different alert.
    if (!props.isOpen) return null;
    return <ExceptionForm key={props.alert?.id || 'new'} {...props} />;
}

function ExceptionForm({ isOpen, onClose, alert = null, onCreated, updateAlertStatus = true }: CreateExceptionModalProps) {
    const id = useId();
    const initial = candidatesFromAlert(alert);
    const [conds, setConds] = useState<ExceptionCandidate[]>(initial.length ? initial : [{ field: 'Image', op: 'equals', value: '', use: true }]);
    const [name, setName] = useState(alert ? `FP: ${alert.rule_title}`.slice(0, 255) : '');
    const [ruleScope, setRuleScope] = useState<'rule' | 'all'>('rule');
    const [ruleId, setRuleId] = useState(alert?.rule_id || '');
    const [hostScope, setHostScope] = useState<'host' | 'all'>(alert?.agent_id ? 'host' : 'all');
    const [endpoint, setEndpoint] = useState<ExceptionEndpoint | null>(alert?.agent_id ? { id: alert.agent_id, hostname: alert.source_hostname || alert.agent_id } : null);
    const [reason, setReason] = useState('');
    const [expiryDays, setExpiryDays] = useState('90');
    const [markFP, setMarkFP] = useState(!!alert);
    const [saving, setSaving] = useState(false);
    const [created, setCreated] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const inFlight = useRef(false);
    const errorRef = useRef<HTMLParagraphElement>(null);
    useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);
    const canManage = authApi.hasRole(['admin', 'security']);
    const draft: ExceptionDraft = { name, reason, ruleScope, ruleId, hostScope, agentId: endpoint?.id || '', expiryDays, conditions: conds };
    const selectedCount = conds.filter(condition => condition.use).length;
    const allRuleIds = [...new Set([alert?.rule_id, ...(alert?.related_rule_ids || [])].filter((value): value is string => !!value))];
    const tooBroad = ruleScope === 'all' && !conds.some(c => c.use && c.value.trim() && c.op === 'equals' && ['Image', 'Hashes'].includes(c.field));
    const locked = saving || created;
    const input = 'input min-w-0 disabled:opacity-60 disabled:cursor-not-allowed';
    const label = 'mb-1.5 block text-xs font-semibold text-slate-600 dark:text-slate-300';

    const update = (index: number, patch: Partial<ExceptionCandidate>) => setConds(previous => previous.map((condition, i) => i === index ? { ...condition, ...patch } : condition));
    const save = async () => {
        if (inFlight.current || !canManage) return;
        setError(null);
        if (!created) {
            const validation = validateExceptionDraft(draft);
            if (validation) { setError(validation); return; }
        }
        inFlight.current = true;
        setSaving(true);
        let exceptionSaved = created;
        try {
            if (!exceptionSaved) {
                await detectionExceptionsApi.create(buildExceptionInput(draft, alert));
                exceptionSaved = true;
                setCreated(true);
            }
            if (markFP && alert && updateAlertStatus) {
                await alertsApi.updateStatus(alert.id, 'false_positive', `Detection exception "${name.trim()}": ${reason.trim()}`);
            }
            await onCreated?.(markFP && !!alert);
            onClose();
        } catch (err) {
            const message = apiErrorMessage(err, 'Could not save the exception.');
            setError(exceptionSaved ? `The exception was created, but the follow-up update failed. ${message} Retry finishes the update without creating another exception.` : message);
        } finally {
            inFlight.current = false;
            setSaving(false);
        }
    };

    const footer = <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs text-slate-500">{created ? 'Exception saved' : `${selectedCount} enabled condition${selectedCount === 1 ? '' : 's'}`}</span>
        <div className="flex items-center gap-2">
            <button type="button" onClick={onClose} disabled={saving} className="btn btn-secondary disabled:opacity-50">{created ? 'Close' : 'Cancel'}</button>
            <button type="submit" form={`${id}-form`} disabled={saving || !canManage} className="btn btn-primary inline-flex items-center gap-2 disabled:opacity-50">
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : created ? <CheckCircle2 className="h-4 w-4" /> : <ShieldOff className="h-4 w-4" />}
                {saving ? 'Saving…' : created ? 'Retry follow-up update' : 'Create exception'}
            </button>
        </div>
    </div>;

    return <Modal isOpen={isOpen} onClose={onClose} closeDisabled={saving} title="Create detection exception" size="xl" footer={footer} closeOnOverlayClick={false}>
        <form id={`${id}-form`} noValidate onChange={() => setError(null)} onSubmit={event => { event.preventDefault(); void save(); }} className="min-w-0 space-y-5">
            <div className="flex items-start gap-3 rounded-xl border border-indigo-200 bg-indigo-50/70 p-3 dark:border-indigo-800/50 dark:bg-indigo-950/30">
                <ShieldOff className="mt-0.5 h-5 w-5 shrink-0 text-indigo-600 dark:text-indigo-400" />
                <div className="min-w-0 text-xs leading-5 text-slate-600 dark:text-slate-300">
                    <p className="font-semibold text-slate-900 dark:text-white">Suppress only activity you have verified as benign.</p>
                    <p>Every enabled condition must match. Limit the rule, endpoint and lifetime; suppressed matches remain counted for review.</p>
                </div>
            </div>
            {!canManage && <p role="alert" className="text-sm text-amber-700 dark:text-amber-400">Creating exceptions requires the administrator or security role.</p>}
            {created && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-400">The exception is saved. Only the follow-up update remains.</p>}
            <fieldset disabled={locked || !canManage} className="min-w-0 space-y-5 disabled:opacity-80">
                <div>
                    <label htmlFor={`${id}-name`} className={label}>Name</label>
                    <input id={`${id}-name`} autoFocus className={input} value={name} maxLength={255} placeholder="e.g. Approved nightly backup" onChange={event => setName(event.target.value)} />
                </div>
                <section className="min-w-0 rounded-xl border border-slate-200 p-3 sm:p-4 dark:border-slate-700">
                    <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-white"><Monitor className="h-4 w-4 text-indigo-500" /> Scope</h3>
                    <div className="grid min-w-0 grid-cols-1 gap-4 sm:grid-cols-2">
                        <div className="min-w-0">
                            <label htmlFor={`${id}-rule-scope`} className={label}>Rule scope</label>
                            <select id={`${id}-rule-scope`} className={input} value={ruleScope} onChange={event => setRuleScope(event.target.value as 'rule' | 'all')}>
                                <option value="rule">One rule</option><option value="all">All rules</option>
                            </select>
                            {ruleScope === 'rule' && <div className="mt-3 min-w-0">
                                <label htmlFor={`${id}-rule-id`} className={label}>Sigma rule ID</label>
                                {alert ? <select id={`${id}-rule-id`} className={input} value={ruleId} onChange={event => setRuleId(event.target.value)}>
                                    {!ruleId && <option value="">Select a rule</option>}
                                    {allRuleIds.map(value => <option key={value} value={value}>{value === alert.rule_id ? alert.rule_title : value}</option>)}
                                </select> : <input id={`${id}-rule-id`} className={`${input} font-mono`} value={ruleId} maxLength={255} placeholder="Enter the rule ID" onChange={event => setRuleId(event.target.value)} />}
                            </div>}
                            {ruleScope === 'all' && <p className="mt-2 text-xs text-amber-700 dark:text-amber-400">Requires an exact Image or Hashes condition.</p>}
                        </div>
                        <div className="min-w-0">
                            <label htmlFor={`${id}-endpoint-scope`} className={label}>Endpoint scope</label>
                            <select id={`${id}-endpoint-scope`} className={input} value={hostScope} onChange={event => setHostScope(event.target.value as 'host' | 'all')}>
                                <option value="host">Specific endpoint</option><option value="all">All endpoints</option>
                            </select>
                            {hostScope === 'host' ? <ExceptionEndpointPicker id={`${id}-endpoint`} selected={endpoint} onChange={setEndpoint} disabled={locked || !canManage} />
                                : <p className="mt-2 text-xs text-slate-500">Applies to every endpoint when all conditions match.</p>}
                        </div>
                    </div>
                </section>
                <section className="min-w-0 rounded-xl border border-slate-200 p-3 sm:p-4 dark:border-slate-700">
                    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Conditions <span className="font-normal text-slate-500">(all must match)</span></h3>
                        <span className="rounded-md bg-slate-100 px-2 py-1 text-[11px] font-medium text-slate-500 dark:bg-slate-900">{conds.length} / {MAX_CONDITIONS}</span>
                    </div>
                    <div className="space-y-2">
                        <p className="text-xs text-slate-500">Each enabled condition needs a field, an operator and a value.</p>
                        {conds.map((condition, index) => <div key={index} data-condition-row className="grid min-w-0 grid-cols-[1.25rem_minmax(0,1fr)_2rem] items-start gap-2 rounded-lg border border-slate-200 bg-slate-50/80 p-2.5 dark:border-slate-700 dark:bg-slate-900/30">
                            <input type="checkbox" aria-label={`Enable condition ${index + 1}`} checked={condition.use} onChange={event => update(index, { use: event.target.checked })} className="mt-7 h-3.5 w-3.5 accent-indigo-600" />
                            <div className={`grid min-w-0 grid-cols-2 gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,0.8fr)_minmax(0,1.6fr)] ${condition.use ? '' : 'opacity-50'}`}>
                                <div className="min-w-0"><label htmlFor={`${id}-field-${index}`} className={label}>Field</label>
                                    <select id={`${id}-field-${index}`} className={input} value={condition.field} onChange={event => update(index, { field: event.target.value })}>
                                        {EXCEPTION_FIELDS.map(field => <option key={field} value={field}>{field}</option>)}
                                    </select>
                                </div>
                                <div className="min-w-0"><label htmlFor={`${id}-op-${index}`} className={label}>Operator</label>
                                    <select id={`${id}-op-${index}`} className={input} value={condition.op} onChange={event => update(index, { op: event.target.value as ExceptionCandidate['op'] })}>
                                        {EXCEPTION_OPS.map(op => <option key={op} value={op}>{({ equals: 'Equals', startswith: 'Starts with', endswith: 'Ends with', contains: 'Contains' })[op]}</option>)}
                                    </select>
                                </div>
                                <div className="col-span-2 min-w-0 sm:col-span-1"><label htmlFor={`${id}-value-${index}`} className={label}>Value</label>
                                    <input id={`${id}-value-${index}`} className={`${input} font-mono !text-xs`} value={condition.value} maxLength={1024} placeholder="Exact value or text to match" onChange={event => update(index, { value: event.target.value })} />
                                </div>
                            </div>
                            <button type="button" aria-label={`Remove condition ${index + 1}`} onClick={() => setConds(previous => previous.filter((_, i) => i !== index))} className="mt-5 rounded-md p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-600 dark:hover:bg-rose-950/40"><Trash2 className="h-4 w-4" /></button>
                        </div>)}
                    </div>
                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                        <button type="button" disabled={conds.length >= MAX_CONDITIONS} onClick={() => setConds(previous => [...previous, { field: 'CommandLine', op: 'contains', value: '', use: true }])} className="inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-600 disabled:opacity-40 dark:text-indigo-400"><Plus className="h-3.5 w-3.5" /> Add condition</button>
                        <span className="text-[11px] text-slate-500">Unchecked conditions are excluded.</span>
                    </div>
                    {tooBroad && <p className="mt-3 flex items-start gap-1.5 text-xs text-amber-700 dark:text-amber-400"><AlertTriangle className="h-3.5 w-3.5 shrink-0" /> Add an exact Image or Hashes match, or select one rule.</p>}
                </section>
                <section className="grid min-w-0 grid-cols-1 gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,0.55fr)]">
                    <div className="min-w-0"><label htmlFor={`${id}-reason`} className={label}>Justification (audited)</label>
                        <textarea id={`${id}-reason`} className={`${input} min-h-24 resize-y`} value={reason} maxLength={1000} onChange={event => setReason(event.target.value)} placeholder="Explain why this activity is benign and reference the approval or change ticket." />
                    </div>
                    <div className="min-w-0"><label htmlFor={`${id}-expiry`} className={label}>Expires</label>
                        <select id={`${id}-expiry`} className={input} value={expiryDays} onChange={event => setExpiryDays(event.target.value)}>
                            <option value="7">In 7 days</option><option value="30">In 30 days</option><option value="90">In 90 days</option><option value="365">In 1 year</option><option value="0">Never</option>
                        </select>
                        <p className="mt-2 text-xs leading-5 text-slate-500">{expiryDays === '0' ? 'No automatic expiry. Review this exception regularly.' : 'Suppression stops automatically when the exception expires.'}</p>
                    </div>
                </section>
                {alert && <label className="flex items-start gap-2 rounded-lg bg-slate-50 p-3 text-xs text-slate-700 dark:bg-slate-900/50 dark:text-slate-300">
                    <input type="checkbox" checked={markFP} onChange={event => setMarkFP(event.target.checked)} className="mt-0.5 accent-indigo-600" />
                    <FileCheck2 className="h-4 w-4 shrink-0 text-slate-400" /> Also mark this alert as a false positive
                </label>}
            </fieldset>
            {error && <p ref={errorRef} tabIndex={-1} role="alert" className="break-words rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700 dark:border-rose-900 dark:bg-rose-950/30 dark:text-rose-400">{error}</p>}
        </form>
    </Modal>;
}

export default CreateExceptionModal;
