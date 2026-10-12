import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle, FlaskConical, Loader2, Save, XCircle } from 'lucide-react';
import { Modal } from '../../components';
import { rulesApi, type Rule, type RuleValidation } from '../../api/client';
import { apiErrorMessage } from '../../api/apiError';
import { RULE_TEMPLATES, templateWithId } from './ruleTemplates';

const SEV_BADGE: Record<string, string> = {
    critical: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20',
    high: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
    medium: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
    low: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
};

const VALIDATE_DELAY_MS = 450;

interface Props {
    /** Rule being edited; null creates a new rule. */
    rule: Rule | null;
    onClose: () => void;
}

/**
 * Sigma rule editor. The YAML is the single source of truth: the server
 * derives title, level, status, tags and logsource from it, validates and
 * compiles it, refuses content the running detector would never load, stores
 * it and hot-loads it into the detection engine.
 */
export function RuleEditorModal({ rule, onClose }: Props) {
    const queryClient = useQueryClient();
    const editing = rule !== null;
    const [templateKey, setTemplateKey] = useState(RULE_TEMPLATES[0].key);
    const [content, setContent] = useState(() => (editing ? '' : templateWithId(RULE_TEMPLATES[0])));
    const [pristine, setPristine] = useState(content);
    const [sample, setSample] = useState(() => JSON.stringify(RULE_TEMPLATES[0].sample, null, 2));
    const [validation, setValidation] = useState<RuleValidation | null>(null);
    const [validatedContent, setValidatedContent] = useState<string | null>(null);
    const [validating, setValidating] = useState(false);
    const [validateError, setValidateError] = useState<string | null>(null);
    const [testResult, setTestResult] = useState<{ content: string; result?: RuleValidation; error?: string } | null>(null);
    const [testing, setTesting] = useState(false);
    const abortRef = useRef<AbortController | null>(null);

    // Edit mode: load the stored YAML.
    const detail = useQuery({
        queryKey: ['rule', rule?.id],
        queryFn: () => rulesApi.get(rule!.id),
        enabled: editing,
        staleTime: 0,
    });
    const loadedFor = useRef<string | null>(null);
    useEffect(() => {
        if (!editing || !detail.data || loadedFor.current === detail.data.id) return;
        loadedFor.current = detail.data.id;
        const yaml = detail.data.content ?? '';
        setContent(yaml);
        setPristine(yaml);
    }, [editing, detail.data]);

    // Debounced server-side validation of the current YAML (nothing is stored).
    useEffect(() => {
        if (!content.trim()) {
            setValidation(null);
            setValidatedContent(null);
            return;
        }
        const timer = window.setTimeout(() => {
            abortRef.current?.abort();
            const ctrl = new AbortController();
            abortRef.current = ctrl;
            setValidating(true);
            rulesApi.validate(content, { id: rule?.id, signal: ctrl.signal })
                .then((res) => { setValidation(res); setValidatedContent(content); setValidateError(null); })
                .catch((err) => { if (!ctrl.signal.aborted) setValidateError(apiErrorMessage(err, 'Validation request failed')); })
                .finally(() => { if (abortRef.current === ctrl) setValidating(false); });
        }, VALIDATE_DELAY_MS);
        return () => window.clearTimeout(timer);
    }, [content, rule?.id]);
    useEffect(() => () => abortRef.current?.abort(), []);

    const dirty = content !== pristine;
    const current = validatedContent === content ? validation : null;
    const enabledRule = rule?.enabled ?? true;
    // Server rules: create refuses a duplicate id or an inactive rule; update
    // refuses an inactive rule only while the rule is enabled.
    const blockReason = !content.trim() ? 'Rule YAML is empty'
        : !current ? (validating ? 'Validating…' : 'Waiting for validation')
        : !current.valid ? 'Fix the validation error first'
        : !editing && current.exists ? 'A rule with this id already exists — change the id'
        : enabledRule && !current.will_activate ? 'This rule would not be loaded by the detector'
        : editing && !dirty ? 'No changes to save'
        : null;

    const save = useMutation({
        mutationFn: () => (editing ? rulesApi.update(rule!.id, content) : rulesApi.create(content)),
        onSuccess: (saved) => {
            queryClient.invalidateQueries({ queryKey: ['rules'] });
            queryClient.invalidateQueries({ queryKey: ['ruleStats'] });
            queryClient.invalidateQueries({ queryKey: ['rule', saved.id] });
            onClose();
        },
    });

    const runTest = async () => {
        let event: Record<string, unknown>;
        try {
            const parsed: unknown = JSON.parse(sample);
            if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('must be a JSON object');
            event = parsed as Record<string, unknown>;
        } catch (err) {
            setTestResult({ content, error: `Sample event is not valid JSON: ${(err as Error).message}` });
            return;
        }
        setTesting(true);
        try {
            const result = await rulesApi.validate(content, { event, id: rule?.id });
            setTestResult({ content, result });
        } catch (err) {
            setTestResult({ content, error: apiErrorMessage(err, 'Test request failed') });
        } finally {
            setTesting(false);
        }
    };
    const shownTest = testResult && testResult.content === content ? testResult : null;

    const applyTemplate = (key: string) => {
        const tpl = RULE_TEMPLATES.find((t) => t.key === key);
        if (!tpl) return;
        if (dirty && !confirm('Replace the current YAML with this template?')) return;
        const yaml = templateWithId(tpl);
        setTemplateKey(key);
        setContent(yaml);
        setPristine(yaml);
        setSample(JSON.stringify(tpl.sample, null, 2));
    };

    const close = () => {
        if (save.isPending) return;
        if (dirty && !confirm('Discard unsaved changes?')) return;
        onClose();
    };

    const footer = (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="text-xs min-h-[1rem]">
                {save.isError ? (
                    <span className="text-rose-600 dark:text-rose-400">{apiErrorMessage(save.error, 'Saving the rule failed')}</span>
                ) : blockReason ? (
                    <span className="text-slate-500 dark:text-slate-400">{blockReason}</span>
                ) : (
                    <span className="text-emerald-600 dark:text-emerald-400">
                        Ready — the rule is {enabledRule ? 'loaded into the detector' : 'stored (disabled)'} as soon as it is saved
                    </span>
                )}
            </div>
            <div className="flex justify-end gap-3">
                <button type="button" onClick={close} disabled={save.isPending}
                    className="px-4 py-2 border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-sm font-medium rounded-xl transition-colors disabled:opacity-50">
                    Cancel
                </button>
                <button type="button" onClick={() => save.mutate()} disabled={!!blockReason || save.isPending}
                    className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-xl transition-colors shadow-sm shadow-indigo-500/20 disabled:opacity-50 disabled:cursor-not-allowed">
                    {save.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                    {editing ? 'Save changes' : 'Create rule'}
                </button>
            </div>
        </div>
    );

    return (
        <Modal isOpen onClose={close} title={editing ? `Edit rule — ${rule!.title}` : 'Create detection rule'}
            size="full" closeOnOverlayClick={false} closeDisabled={save.isPending} footer={footer}>
            <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_340px] gap-5">
                {/* ── YAML editor ── */}
                <div className="flex flex-col gap-3 min-w-0">
                    {!editing && (
                        <label className="flex flex-col sm:flex-row sm:items-center gap-2 text-sm">
                            <span className="font-medium text-slate-700 dark:text-slate-300 shrink-0">Start from template</span>
                            <select value={templateKey} onChange={(e) => applyTemplate(e.target.value)}
                                className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 text-sm">
                                {RULE_TEMPLATES.map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}
                            </select>
                        </label>
                    )}
                    {editing && detail.isLoading ? (
                        <div className="h-[420px] flex items-center justify-center text-sm text-slate-500"><Loader2 className="w-4 h-4 animate-spin mr-2" />Loading rule…</div>
                    ) : editing && detail.isError ? (
                        <div className="p-4 rounded-xl border border-rose-200 dark:border-rose-500/30 bg-rose-50 dark:bg-rose-500/10 text-sm text-rose-700 dark:text-rose-300">
                            {apiErrorMessage(detail.error, 'Could not load the rule')}
                        </div>
                    ) : (
                        <textarea
                            aria-label="Sigma rule YAML"
                            value={content}
                            onChange={(e) => setContent(e.target.value)}
                            spellCheck={false}
                            autoCapitalize="off"
                            autoCorrect="off"
                            className="w-full h-[420px] xl:h-[52vh] resize-y p-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-950 text-slate-100 font-mono text-[12.5px] leading-relaxed focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
                        />
                    )}
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                        Sigma YAML. Title, level, status, tags and logsource are read from the YAML. Rules must be
                        level <b>medium</b> or higher, status <b>test</b> or <b>stable</b>, and product <b>windows</b> to be loaded by the detector.
                    </p>
                </div>

                {/* ── Validation, metadata and test ── */}
                <div className="flex flex-col gap-4 min-w-0">
                    <ValidationPanel validation={current} validating={validating} error={validateError} editing={editing} enabledRule={enabledRule} />

                    <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4 flex flex-col gap-2">
                        <div className="flex items-center justify-between gap-2">
                            <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">Test with a sample event</span>
                            <button type="button" onClick={runTest} disabled={testing || !current?.valid}
                                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 disabled:opacity-50">
                                {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />}
                                Run test
                            </button>
                        </div>
                        <textarea aria-label="Sample event JSON" value={sample} onChange={(e) => setSample(e.target.value)} spellCheck={false}
                            className="w-full h-40 resize-y p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-800 dark:text-slate-200 font-mono text-[11.5px]" />
                        <p className="text-[11px] text-slate-500 dark:text-slate-400">
                            Agent telemetry shape: <code>event_type</code> (process, file, registry, network, dns, image_load, powershell, eventlog) and <code>data</code> fields.
                        </p>
                        {shownTest?.error && <p className="text-xs text-rose-600 dark:text-rose-400">{shownTest.error}</p>}
                        {shownTest?.result && (
                            shownTest.result.error ? (
                                <p className="text-xs text-rose-600 dark:text-rose-400">{shownTest.result.error}</p>
                            ) : shownTest.result.matched ? (
                                <p className="flex items-center gap-1.5 text-xs font-semibold text-emerald-600 dark:text-emerald-400"><CheckCircle className="w-3.5 h-3.5" />The rule matches this event</p>
                            ) : (
                                <p className="flex items-center gap-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300"><XCircle className="w-3.5 h-3.5" />No match for this event</p>
                            )
                        )}
                    </div>
                </div>
            </div>
        </Modal>
    );
}

function ValidationPanel({ validation, validating, error, editing, enabledRule }: {
    validation: RuleValidation | null; validating: boolean; error: string | null; editing: boolean; enabledRule: boolean;
}) {
    if (error) {
        return <Box tone="error" title="Validation unavailable">{error}</Box>;
    }
    if (!validation) {
        return (
            <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4 text-sm text-slate-500 flex items-center gap-2">
                {validating && <Loader2 className="w-4 h-4 animate-spin" />}
                {validating ? 'Validating…' : 'Edit the YAML to validate it'}
            </div>
        );
    }
    if (!validation.valid) {
        return <Box tone="error" title="Invalid rule"><span className="font-mono text-xs break-words">{validation.error}</span></Box>;
    }
    const logsource = [validation.product, validation.category, validation.service].filter(Boolean).join(' / ');
    return (
        <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4 flex flex-col gap-3 text-sm">
            {!editing && validation.exists ? (
                <Box tone="error" title="Duplicate id">A rule with id <code>{validation.id}</code> already exists.</Box>
            ) : validation.will_activate ? (
                <Box tone="ok" title="Valid — will be active">The detector compiles and loads this rule.</Box>
            ) : (
                <Box tone={enabledRule ? 'error' : 'warn'} title="Valid, but would not be loaded">
                    {validation.inactive_reason}
                </Box>
            )}
            <dl className="grid grid-cols-[88px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-xs">
                <dt className="text-slate-500">Title</dt><dd className="text-slate-800 dark:text-slate-200 font-medium break-words">{validation.title || '—'}</dd>
                <dt className="text-slate-500">Level</dt>
                <dd><span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${SEV_BADGE[validation.severity ?? ''] || 'border-slate-300 text-slate-600'}`}>{(validation.severity || '—').toUpperCase()}</span></dd>
                <dt className="text-slate-500">Status</dt><dd className="text-slate-800 dark:text-slate-200">{validation.status || '—'}</dd>
                <dt className="text-slate-500">Logsource</dt><dd className="text-slate-800 dark:text-slate-200 break-words">{logsource || '—'}</dd>
                <dt className="text-slate-500">MITRE</dt><dd className="text-slate-800 dark:text-slate-200 break-words">{[...(validation.mitre_tactics ?? []), ...(validation.mitre_techniques ?? [])].join(', ') || '—'}</dd>
                <dt className="text-slate-500">Rule id</dt><dd className="font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all">{validation.id}</dd>
            </dl>
        </div>
    );
}

function Box({ tone, title, children }: { tone: 'ok' | 'warn' | 'error'; title: string; children: ReactNode }) {
    const styles = {
        ok: 'border-emerald-200 dark:border-emerald-500/30 bg-emerald-50 dark:bg-emerald-500/10 text-emerald-800 dark:text-emerald-300',
        warn: 'border-amber-200 dark:border-amber-500/30 bg-amber-50 dark:bg-amber-500/10 text-amber-800 dark:text-amber-300',
        error: 'border-rose-200 dark:border-rose-500/30 bg-rose-50 dark:bg-rose-500/10 text-rose-800 dark:text-rose-300',
    }[tone];
    const Icon = tone === 'ok' ? CheckCircle : tone === 'warn' ? AlertTriangle : XCircle;
    return (
        <div className={`rounded-lg border p-3 text-xs ${styles}`}>
            <div className="flex items-center gap-1.5 font-semibold mb-0.5"><Icon className="w-3.5 h-3.5 shrink-0" />{title}</div>
            <div className="break-words">{children}</div>
        </div>
    );
}
