// CreateExceptionModal — turns a false positive into a precise, reviewable
// detection exception (rule-scoped by default, optionally host-scoped, with a
// justification and an expiry). Pre-filled from the alert's own evidence.
import { useMemo, useState } from 'react';
import { AlertTriangle, Loader2, Plus, ShieldOff, Trash2 } from 'lucide-react';
import { Modal } from '../Modal';
import {
    alertsApi, detectionExceptionsApi,
    type Alert, type ExceptionCondition,
} from '../../api/client';
import { apiErrorMessage } from '../../api/apiError';

const EXCEPTION_FIELDS = [
    'Image', 'ParentImage', 'CommandLine', 'ParentCommandLine', 'OriginalFileName', 'Hashes', 'User',
    'IntegrityLevel', 'Company', 'Product', 'Description', 'CurrentDirectory', 'TargetFilename', 'ImageLoaded',
    'TargetObject', 'Details', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'QueryName', 'PipeName',
    'SourceImage', 'TargetImage', 'ScriptBlockText', 'Path',
] as const;

const OPS: ExceptionCondition['op'][] = ['equals', 'startswith', 'endswith', 'contains'];

interface Candidate extends ExceptionCondition {
    use: boolean;
}

/** Evidence → suggested conditions (exact image/parent by default). */
function candidatesFromAlert(alert: Alert | null): Candidate[] {
    if (!alert) return [];
    const ctx = (alert.context_data ?? {}) as Record<string, unknown>;
    const d = ((ctx.data ?? {}) as Record<string, unknown>);
    const pick = (...keys: string[]) => {
        for (const k of keys) {
            const v = d[k] ?? ctx[k];
            if (typeof v === 'string' && v.trim()) return v.trim();
        }
        return '';
    };
    const out: Candidate[] = [];
    const add = (field: string, op: ExceptionCondition['op'], value: string, use: boolean) => {
        if (value) out.push({ field, op, value, use });
    };
    const image = pick('executable', 'process_path');
    add('Image', 'equals', image.includes('\\') ? image : '', true);
    add('ParentImage', 'equals', pick('parent_executable'), true);
    add('CommandLine', 'equals', pick('command_line'), false);
    add('Hashes', 'contains', pick('sha256') ? `SHA256=${pick('sha256').toUpperCase()}` : '', false);
    add('User', 'equals', pick('user_name'), false);
    add('TargetFilename', 'equals', pick('target_filename'), false);
    add('DestinationHostname', 'equals', pick('destination_hostname'), false);
    add('QueryName', 'equals', pick('query_name'), false);
    add('TargetObject', 'equals', pick('target_object', 'key_path'), false);
    return out;
}

interface CreateExceptionModalProps {
    isOpen: boolean;
    onClose: () => void;
    /** Pre-fill from this alert (rule, host, evidence). */
    alert?: Alert | null;
    /** markedFalsePositive: the analyst asked to close the alert as a false positive. */
    onCreated?: (markedFalsePositive: boolean) => void;
    /** When false the caller updates the alert status itself (via onCreated). */
    updateAlertStatus?: boolean;
}

export function CreateExceptionModal({ isOpen, onClose, alert = null, onCreated, updateAlertStatus = true }: CreateExceptionModalProps) {
    const initial = useMemo(() => candidatesFromAlert(alert), [alert]);
    const [conds, setConds] = useState<Candidate[]>(initial.length ? initial : [{ field: 'Image', op: 'equals', value: '', use: true }]);
    const [name, setName] = useState(alert ? `FP: ${alert.rule_title}` : '');
    const [ruleScope, setRuleScope] = useState<'rule' | 'all'>(alert ? 'rule' : 'all');
    const [ruleId, setRuleId] = useState(alert?.rule_id || '');
    const [hostScope, setHostScope] = useState<'host' | 'all'>(alert ? 'host' : 'all');
    const [reason, setReason] = useState('');
    const [expiryDays, setExpiryDays] = useState('90');
    const [markFP, setMarkFP] = useState(!!alert);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const selected = conds.filter(c => c.use && c.value.trim());
    const anchored = selected.some(c => c.op === 'equals' && (c.field === 'Image' || c.field === 'Hashes'));
    const tooBroad = ruleScope === 'all' && !anchored;

    const update = (i: number, patch: Partial<Candidate>) => setConds(prev => prev.map((c, j) => (j === i ? { ...c, ...patch } : c)));

    const save = async () => {
        setError(null);
        if (!name.trim() || !reason.trim()) {
            setError('A name and a justification are required.');
            return;
        }
        if (selected.length === 0) {
            setError('Select at least one condition.');
            return;
        }
        if (ruleScope === 'rule' && !ruleId.trim()) {
            setError('Enter the Sigma rule ID, or scope the exception to all rules.');
            return;
        }
        setSaving(true);
        try {
            const days = Number(expiryDays);
            await detectionExceptionsApi.create({
                name: name.trim(),
                rule_id: ruleScope === 'rule' ? ruleId.trim() : '',
                rule_title: ruleScope === 'rule' ? (alert?.rule_title || '') : '',
                agent_id: hostScope === 'host' && alert ? alert.agent_id : undefined,
                conditions: selected.map(({ field, op, value }) => ({ field, op, value: value.trim() })),
                reason: reason.trim(),
                expires_at: days > 0 ? new Date(Date.now() + days * 86_400_000).toISOString() : undefined,
                source_alert_id: alert?.id,
            });
            if (markFP && alert && updateAlertStatus) {
                await alertsApi.updateStatus(alert.id, 'false_positive', `Detection exception "${name.trim()}": ${reason.trim()}`);
            }
            onCreated?.(markFP && !!alert);
            onClose();
        } catch (err) {
            setError(apiErrorMessage(err, 'Could not create the exception'));
        } finally {
            setSaving(false);
        }
    };

    const footer = (
        <div className="flex items-center justify-end gap-3">
            <button type="button" onClick={onClose} disabled={saving} className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg">
                Cancel
            </button>
            <button type="button" onClick={save} disabled={saving || tooBroad}
                className="px-4 py-2 text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg flex items-center gap-2 disabled:opacity-50">
                {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldOff className="w-4 h-4" />}
                Create exception
            </button>
        </div>
    );

    const input = 'w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 outline-none';

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Create detection exception" size="lg" footer={footer} closeOnOverlayClick={false}>
            <div className="space-y-4">
                <p className="text-xs text-slate-500">
                    Matches of the rule are hidden only when the event satisfies <strong>every</strong> selected condition.
                    Prefer exact paths; keep the exception scoped to one rule and, when possible, one endpoint.
                    Suppressed matches are counted so the exception can be reviewed.
                </p>

                <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Name</label>
                    <input className={input} value={name} maxLength={255} onChange={e => setName(e.target.value)} />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Rule scope</label>
                        <select className={input} value={ruleScope} onChange={e => setRuleScope(e.target.value as 'rule' | 'all')}>
                            <option value="rule">{alert ? `Only "${alert.rule_title}"` : 'One rule'}</option>
                            <option value="all">All rules (requires exact Image or hash)</option>
                        </select>
                        {ruleScope === 'rule' && !alert && (
                            <input className={`${input} mt-2 font-mono`} placeholder="Sigma rule ID" value={ruleId} onChange={e => setRuleId(e.target.value)} />
                        )}
                    </div>
                    <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Endpoint scope</label>
                        <select className={input} value={hostScope} onChange={e => setHostScope(e.target.value as 'host' | 'all')} disabled={!alert}>
                            {alert && <option value="host">Only this endpoint</option>}
                            <option value="all">All endpoints</option>
                        </select>
                    </div>
                </div>

                <div>
                    <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Conditions (all must match)</label>
                    <div className="space-y-2">
                        {conds.map((c, i) => (
                            <div key={i} className="flex items-center gap-2">
                                <input type="checkbox" checked={c.use} onChange={e => update(i, { use: e.target.checked })} />
                                <select className={`${input} w-40 shrink-0`} value={c.field} onChange={e => update(i, { field: e.target.value })}>
                                    {EXCEPTION_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
                                </select>
                                <select className={`${input} w-32 shrink-0`} value={c.op} onChange={e => update(i, { op: e.target.value as ExceptionCondition['op'] })}>
                                    {OPS.map(o => <option key={o} value={o}>{o}</option>)}
                                </select>
                                <input className={`${input} font-mono text-xs`} value={c.value} onChange={e => update(i, { value: e.target.value })} />
                                <button type="button" onClick={() => setConds(prev => prev.filter((_, j) => j !== i))} className="p-1.5 text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-900/20 rounded" title="Remove">
                                    <Trash2 className="w-4 h-4" />
                                </button>
                            </div>
                        ))}
                    </div>
                    <button type="button" onClick={() => setConds(prev => [...prev, { field: 'CommandLine', op: 'contains', value: '', use: true }])}
                        className="mt-2 text-xs text-indigo-600 dark:text-indigo-400 flex items-center gap-1 hover:underline">
                        <Plus className="w-3.5 h-3.5" /> Add condition
                    </button>
                    {tooBroad && (
                        <p className="mt-2 text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1">
                            <AlertTriangle className="w-3.5 h-3.5" /> An exception for all rules must include an exact Image path or file hash (equals).
                        </p>
                    )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="sm:col-span-2">
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Justification (audited)</label>
                        <textarea className={`${input} h-20`} value={reason} maxLength={1000} onChange={e => setReason(e.target.value)}
                            placeholder="Why this activity is benign (e.g. nightly backup agent, approved by IT change #123)" />
                    </div>
                    <div>
                        <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1">Expires</label>
                        <select className={input} value={expiryDays} onChange={e => setExpiryDays(e.target.value)}>
                            <option value="7">In 7 days</option>
                            <option value="30">In 30 days</option>
                            <option value="90">In 90 days</option>
                            <option value="365">In 1 year</option>
                            <option value="0">Never (review regularly)</option>
                        </select>
                    </div>
                </div>

                {alert && (
                    <label className="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
                        <input type="checkbox" checked={markFP} onChange={e => setMarkFP(e.target.checked)} />
                        Also mark this alert as a false positive
                    </label>
                )}

                {error && <p className="text-sm text-rose-600 dark:text-rose-400">{error}</p>}
            </div>
        </Modal>
    );
}

export default CreateExceptionModal;
