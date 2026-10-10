// AlertDetailPanel — one alert, organised for triage:
//   header   → severity (rule level), risk, status, occurrences, host, actions
//   Overview → what happened, recommended action, triggering activity, endpoint
//   Event    → every collected field (grouped, searchable, copyable) + raw JSON
//   Process  → process lineage
//   Detection→ rule, MITRE ATT&CK, matched fields, related rules, risk scoring
//   Response → playbooks, false-positive exception, response history
// Only the active tab is rendered (cheap on large events).
import { useMemo, useState, type ReactNode } from 'react';
import {
    AlertTriangle, Check, CheckCircle, ChevronDown, ChevronUp, Clock, ExternalLink, History,
    Info, Monitor, Play, RotateCcw, Settings, Shield, ShieldOff, Terminal, User, XCircle,
} from 'lucide-react';
import { Modal } from '../';
import { useNavigate } from 'react-router-dom';
import { RiskScoreBadge } from './RiskScoreBadge';
import { UEBASignalBadge } from './UEBASignalBadge';
import { LineageTree } from './ProcessLineageTree';
import { UEBAPanel } from './UEBAPanel';
import { ScoreBreakdownPanel } from './ScoreBreakdownPanel';
import { getRiskScoreStyle, json_safe, severityColors, statusColors } from './alertsUtils';
import { authApi } from '../../api/client';
import type { Alert } from '../../api/client';
import { RunPlaybookModal } from '../automation/RunPlaybookModal';
import { AlertResponseHistory } from '../automation/AlertResponseHistory';
import { AlertEvidencePanel } from './AlertEvidencePanel';
import { AlertFieldsView } from './AlertFieldsView';
import { alertEvidence, displaySnapshot } from './alertEvidence';
import { CreateExceptionModal } from './CreateExceptionModal';
import { useAutomationSettings } from '../../hooks/useAutomationSettings';

interface AlertDetailPanelProps {
    alert: Alert | null;
    isOpen: boolean;
    onClose: () => void;
    onStatusChange: (id: string, status: string, requireSuccess?: boolean) => void | Promise<void>;
    inlineMode?: boolean;
}

type TabId = 'overview' | 'event' | 'process' | 'detection' | 'response';

const TABS: { id: TabId; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'event', label: 'Event' },
    { id: 'process', label: 'Process' },
    { id: 'detection', label: 'Detection' },
    { id: 'response', label: 'Response' },
];

const RECOMMENDED: Record<string, { text: string; style: string }> = {
    critical: { text: 'Investigate immediately — potential active threat', style: 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300' },
    high: { text: 'Investigate within 1 hour', style: 'bg-orange-50 dark:bg-orange-950/30 border-orange-200 dark:border-orange-800 text-orange-700 dark:text-orange-300' },
    medium: { text: 'Review when possible — may be benign', style: 'bg-yellow-50 dark:bg-yellow-950/30 border-yellow-200 dark:border-yellow-800 text-yellow-700 dark:text-yellow-300' },
    low: { text: 'Low priority — review during routine triage', style: 'bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-800 text-green-700 dark:text-green-300' },
};

const fmt = (v?: string) => {
    if (!v) return '';
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? v : d.toLocaleString();
};

/** MITRE technique id → attack.mitre.org URL (T1059.001 → /T1059/001/). */
const mitreUrl = (t: string) => `https://attack.mitre.org/techniques/${t.toUpperCase().replace('.', '/')}/`;

function SectionLabel({ children }: { children: ReactNode }) {
    return <h3 className="text-[10px] text-slate-400 uppercase tracking-wider font-bold mb-2">{children}</h3>;
}

function FactGrid({ facts }: { facts: [string, string, boolean?][] }) {
    const shown = facts.filter(([, v]) => v);
    if (!shown.length) return null;
    return (
        <dl className="grid min-w-0 grid-cols-1 sm:grid-cols-[150px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-xs">
            {shown.map(([label, value, mono]) => (
                <div key={label} className="contents">
                    <dt className="text-slate-500">{label}</dt>
                    <dd dir="auto" className={`min-w-0 text-slate-800 dark:text-slate-200 whitespace-pre-wrap break-all ${mono ? 'font-mono' : ''}`}>{value}</dd>
                </div>
            ))}
        </dl>
    );
}

export function AlertDetailPanel({ alert, isOpen, onClose, onStatusChange, inlineMode = false }: AlertDetailPanelProps) {
    const [activeTab, setActiveTab] = useState<TabId>('overview');
    const [showRawJson, setShowRawJson] = useState(false);
    const [runPlaybookOpen, setRunPlaybookOpen] = useState(false);
    const [exceptionOpen, setExceptionOpen] = useState(false);
    const [historyKey, setHistoryKey] = useState(0);
    const { settings: automation } = useAutomationSettings();
    const navigate = useNavigate();
    const evidence = useMemo(() => (alert ? alertEvidence(alert) : null), [alert]);

    if (!alert || !evidence) return null;

    const snapshot = displaySnapshot(alert);
    const breakdown = alert.score_breakdown || snapshot?.score_breakdown;
    const ctx = alert.context_data ?? alert.event_data;
    const source = (alert.context_data?.source ?? {}) as NonNullable<NonNullable<Alert['context_data']>['source']>;
    const host = alert.source_hostname || source.hostname || '';
    const canWrite = authApi.canWriteAlerts();
    const canManageExceptions = authApi.hasRole(['admin', 'security']);
    const occurrences = alert.event_count || 1;
    const lastSeen = alert.last_seen_at && alert.last_seen_at !== alert.timestamp ? alert.last_seen_at : '';
    const script = evidence.pick('script_block_text') || evidence.pick('payload');

    const goAutomation = () => navigate('/itsm/automations', {
        state: {
            alertId: alert.id,
            alertDetails: {
                severity: alert.severity, ruleName: alert.rule_title,
                ruleId: alert.related_rule_ids?.length === 1 ? alert.related_rule_ids[0] : alert.rule_id,
                mitreTechniques: alert.mitre_techniques, agentId: alert.agent_id, title: alert.rule_title,
                description: alert.human_summary, riskScore: alert.risk_score,
            },
        },
    });

    // ── Header ───────────────────────────────────────────────────────────
    const statusButton = (status: string, label: string, Icon: typeof Check, tone: string) => (
        <button key={status} type="button" onClick={() => onStatusChange(alert.id, status)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-colors ${tone}`}>
            <Icon className="w-3.5 h-3.5" /> {label}
        </button>
    );
    const neutral = 'border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800';
    const statusActions = !canWrite ? [] : alert.status === 'open'
        ? [statusButton('acknowledged', 'Acknowledge', Check, neutral), statusButton('in_progress', 'Investigate', Clock, neutral)]
        : alert.status === 'acknowledged' || alert.status === 'in_progress'
            ? [statusButton('resolved', 'Resolve', CheckCircle, 'border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-900/20'),
               statusButton('false_positive', 'False positive', XCircle, neutral)]
            : [statusButton('open', 'Reopen', RotateCcw, neutral)];

    const header = (
        <div className="px-4 pt-4 pb-3 border-b border-slate-200 dark:border-slate-700 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
                <span className={`badge text-[11px] font-bold ${severityColors[alert.severity]}`}
                    title="Severity is the Sigma rule level assigned by the rule author; the risk score adds host context.">
                    {alert.severity.toUpperCase()}
                </span>
                <span className={`badge text-[11px] ${statusColors[alert.status]}`}>{alert.status.replace(/_/g, ' ')}</span>
                {alert.risk_score !== undefined && <RiskScoreBadge score={alert.risk_score} riskLevel={alert.risk_level} />}
                <span className="text-xs text-slate-500" title={lastSeen ? `First ${fmt(alert.timestamp)} · last ${fmt(lastSeen)}` : fmt(alert.timestamp)}>
                    {occurrences > 1 ? `${occurrences} occurrences` : '1 occurrence'}
                </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                <div className="flex items-center gap-1.5 min-w-0 text-slate-600 dark:text-slate-300"><Monitor className="w-3.5 h-3.5 shrink-0 text-slate-400" /><span className="truncate" title={alert.agent_id}>{host || 'Unknown host'}</span></div>
                <div className="flex items-center gap-1.5 min-w-0 text-slate-600 dark:text-slate-300"><User className="w-3.5 h-3.5 shrink-0 text-slate-400" /><span className="truncate">{evidence.pick('user_name') || 'Unknown user'}</span></div>
                <div className="flex items-center gap-1.5 min-w-0 text-slate-600 dark:text-slate-300"><Terminal className="w-3.5 h-3.5 shrink-0 text-slate-400" /><span className="truncate" title={evidence.image}>{evidence.processName || 'Process not captured'}</span></div>
            </div>
            {(statusActions.length > 0) && <div className="flex flex-wrap gap-2">{statusActions}</div>}
        </div>
    );

    // ── Tabs ─────────────────────────────────────────────────────────────
    const tabBar = (
        <div role="tablist" aria-label="Alert details" className="flex border-b border-slate-200 dark:border-slate-700 px-2 overflow-x-auto">
            {TABS.map(t => (
                <button key={t.id} type="button" role="tab" aria-selected={activeTab === t.id}
                    onClick={() => setActiveTab(t.id)}
                    className={`tab whitespace-nowrap ${activeTab === t.id ? 'tab-active' : ''}`}>
                    {t.label}
                </button>
            ))}
        </div>
    );

    const overview = (
        <div className="space-y-4">
            {alert.human_summary && (
                <div className="rounded-xl p-3.5 bg-indigo-50 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-800 flex items-start gap-3">
                    <Info className="w-5 h-5 text-indigo-500 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                        <p className="text-[10px] text-indigo-500 dark:text-indigo-400 uppercase tracking-wider font-bold mb-1">What happened</p>
                        <p dir="auto" className="text-sm font-medium text-slate-800 dark:text-slate-100 break-words">{alert.human_summary}</p>
                    </div>
                </div>
            )}
            <div className={`rounded-lg p-2.5 border flex items-center gap-2 text-sm font-medium ${(RECOMMENDED[alert.severity] || RECOMMENDED.medium).style}`}>
                <Shield className="w-4 h-4 shrink-0" />
                <span>{(RECOMMENDED[alert.severity] || RECOMMENDED.medium).text}</span>
            </div>
            <AlertEvidencePanel alert={alert} />
            <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                <SectionLabel>Endpoint &amp; timing</SectionLabel>
                <FactGrid facts={[
                    ['Host', host],
                    ['IP address', String(alert.context_data?.ip_address || source.ip_address || ''), true],
                    ['Operating system', [source.os_type, source.os_version && source.os_version !== 'unknown' ? source.os_version : ''].filter(Boolean).join(' ')],
                    ['Agent version', source.agent_version || '', true],
                    ['Agent ID', alert.agent_id, true],
                    ['Detected', fmt(alert.timestamp)],
                    ['Last occurrence', fmt(lastSeen)],
                    ['Occurrences', String(occurrences)],
                    ['Assigned to', alert.assigned_to || ''],
                    ['Acknowledged', fmt(alert.acknowledged_at)],
                    ['Resolved', fmt(alert.resolved_at)],
                ]} />
            </div>
            {alert.tags && Object.keys(alert.tags).length > 0 && (
                <div>
                    <SectionLabel>Tags</SectionLabel>
                    <div className="flex flex-wrap gap-1.5">
                        {Object.entries(alert.tags).map(([k, v]) => (
                            <span key={k} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                                <span className="text-slate-400">{k}:</span>{v}
                            </span>
                        ))}
                    </div>
                </div>
            )}
            {alert.notes && (
                <div className="rounded-lg border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/10 p-3">
                    <SectionLabel>Analyst notes</SectionLabel>
                    <p dir="auto" className="text-sm text-slate-700 dark:text-slate-300 break-words">{alert.notes}</p>
                </div>
            )}
        </div>
    );

    const eventTab = (
        <div className="space-y-4">
            {occurrences > 1 && (
                <p className="text-xs text-slate-500">
                    This alert groups {occurrences} occurrences of the rule on this endpoint; the fields below describe the first one.
                </p>
            )}
            {script && (
                <div className="rounded-lg bg-slate-900 p-3">
                    <p className="text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-1.5">PowerShell {evidence.pick('action') === 'module' ? 'module log' : 'script block'}</p>
                    <pre dir="ltr" className="text-xs text-emerald-300 font-mono whitespace-pre-wrap break-all max-h-80 overflow-auto">{script}</pre>
                </div>
            )}
            <AlertFieldsView context={ctx} matchedFields={alert.matched_fields} />
            {(alert.event_ids?.length || 0) > 0 && (
                <div>
                    <SectionLabel>Event IDs ({alert.event_ids!.length})</SectionLabel>
                    <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                        {alert.event_ids!.map(id => (
                            <span key={id} className="font-mono text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 px-2 py-0.5 rounded">{id}</span>
                        ))}
                    </div>
                </div>
            )}
            {ctx && (
                <div>
                    <button type="button" onClick={() => setShowRawJson(v => !v)}
                        className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300">
                        {showRawJson ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                        {showRawJson ? 'Hide full JSON' : 'Show full JSON'}
                    </button>
                    {showRawJson && (
                        <pre dir="ltr" className="mt-2 p-3 bg-slate-100 dark:bg-slate-900 rounded-lg overflow-auto max-h-96 text-[11px] font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all">
                            {JSON.stringify(ctx, null, 2)}
                        </pre>
                    )}
                </div>
            )}
        </div>
    );

    const processTab = (
        <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                <SectionLabel>Process</SectionLabel>
                <FactGrid facts={[
                    ['Process name', evidence.processName || 'Not available'],
                    ['Image', evidence.image, true],
                    ['PID', evidence.pick('pid')],
                    ['Command line', evidence.pick('command_line'), true],
                    ['Parent image', evidence.pick('parent_executable') || evidence.pick('parent_name'), true],
                    ['Parent PID', evidence.pick('ppid')],
                    ['Parent command line', evidence.pick('parent_command_line'), true],
                ]} />
            </div>
            {snapshot ? (
                <>
                    {snapshot.lineage_suspicion && (
                        <div className="rounded-lg p-3 border border-slate-200 dark:border-slate-700 flex items-center gap-3 text-sm">
                            <AlertTriangle className="w-4 h-4 shrink-0 text-amber-500" />
                            <span><span className="font-bold uppercase tracking-wider text-[11px]">Lineage suspicion: </span>{snapshot.lineage_suspicion}</span>
                        </div>
                    )}
                    <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                        <LineageTree snapshot={snapshot} />
                    </div>
                    {occurrences > 1 && <p className="text-xs text-slate-500">Lineage was captured during risk scoring and may describe a different occurrence of this grouped alert.</p>}
                </>
            ) : (
                <p className="text-sm text-slate-500">No process lineage was captured for this alert.</p>
            )}
        </div>
    );

    const detectionTab = (
        <div className="space-y-4">
            <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                <SectionLabel>Detection rule</SectionLabel>
                <FactGrid facts={[
                    ['Rule', alert.rule_title],
                    ['Rule ID', alert.rule_id, true],
                    ['Level (severity)', alert.severity],
                    ['Category', alert.category],
                    ['Confidence', alert.confidence !== undefined ? `${(alert.confidence * 100).toFixed(0)}%` : ''],
                    ['Rules matched on the event', alert.match_count ? String(alert.match_count) : ''],
                ]} />
            </div>
            {((alert.mitre_tactics?.length || 0) + (alert.mitre_techniques?.length || 0)) > 0 && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4 space-y-2">
                    <SectionLabel>MITRE ATT&amp;CK</SectionLabel>
                    <div className="flex flex-wrap gap-1.5">
                        {alert.mitre_tactics?.map(t => <span key={t} className="badge badge-warning">{t}</span>)}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                        {alert.mitre_techniques?.map(t => (
                            <a key={t} href={mitreUrl(t)} target="_blank" rel="noopener noreferrer"
                                className="badge badge-info inline-flex items-center gap-1 hover:underline">
                                {t}<ExternalLink className="w-3 h-3" />
                            </a>
                        ))}
                    </div>
                </div>
            )}
            {alert.matched_fields && Object.keys(alert.matched_fields).length > 0 && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                    <SectionLabel>What the rule matched</SectionLabel>
                    <FactGrid facts={Object.entries(alert.matched_fields).map(([k, v]) => [k, json_safe(v), true] as [string, string, boolean])} />
                </div>
            )}
            {(alert.related_rules?.length || 0) > 0 && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                    <SectionLabel>Other rules matched on the same event</SectionLabel>
                    <ul className="space-y-1">
                        {alert.related_rules!.map((r, i) => <li key={i} className="text-xs text-slate-700 dark:text-slate-300">{r}</li>)}
                    </ul>
                </div>
            )}
            {alert.risk_score !== undefined && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4 space-y-3">
                    <SectionLabel>Risk score</SectionLabel>
                    <div className="flex items-center gap-3">
                        <RiskScoreBadge score={alert.risk_score} riskLevel={alert.risk_level} />
                        <div className="text-sm">
                            <p className="font-semibold text-slate-800 dark:text-slate-100">{alert.risk_score}/100 — {getRiskScoreStyle(alert.risk_score).label}</p>
                            {alert.false_positive_risk !== undefined && (
                                <p className="text-xs text-slate-500">False-positive likelihood: {(alert.false_positive_risk * 100).toFixed(0)}%</p>
                            )}
                        </div>
                        {breakdown?.ueba_signal && breakdown.ueba_signal !== 'none' && <UEBASignalBadge signal={breakdown.ueba_signal} />}
                    </div>
                    {breakdown && <ScoreBreakdownPanel breakdown={breakdown} totalScore={alert.risk_score ?? breakdown.final_score} />}
                </div>
            )}
            {snapshot && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                    <UEBAPanel snapshot={snapshot} />
                </div>
            )}
            {snapshot?.missing_context_fields && snapshot.missing_context_fields.length > 0 && (
                <p className="text-xs text-slate-500">Context not captured: {snapshot.missing_context_fields.join(', ')}</p>
            )}
        </div>
    );

    const responseTab = (
        <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
                <button type="button" onClick={() => setRunPlaybookOpen(true)}
                    className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium bg-indigo-600 hover:bg-indigo-700 text-white">
                    <Play className="w-4 h-4" /> Run playbook
                </button>
                {canManageExceptions && alert.status !== 'false_positive' && (
                    <button type="button" onClick={() => setExceptionOpen(true)} title="Mark as false positive and create a precise detection exception"
                        className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border ${neutral}`}>
                        <ShieldOff className="w-4 h-4 text-amber-500" /> False positive…
                    </button>
                )}
                {automation?.enabled !== false && (
                    <button type="button" onClick={goAutomation} className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border ${neutral}`}>
                        <Settings className="w-4 h-4 text-blue-500" /> Automation rules
                    </button>
                )}
            </div>
            {automation && !automation.enabled && (
                <p className="text-xs text-slate-500">Automated response is turned off platform-wide{automation.locked ? ' by server configuration' : ''}; playbooks run only manually.</p>
            )}
            <div>
                <SectionLabel><span className="inline-flex items-center gap-1.5"><History className="w-3.5 h-3.5" /> Response history</span></SectionLabel>
                <AlertResponseHistory alertId={alert.id} refreshKey={historyKey} />
            </div>
        </div>
    );

    const innerContent = (
        <>
            {header}
            {tabBar}
            <div className="p-4" role="tabpanel">
                {activeTab === 'overview' && overview}
                {activeTab === 'event' && eventTab}
                {activeTab === 'process' && processTab}
                {activeTab === 'detection' && detectionTab}
                {activeTab === 'response' && responseTab}
            </div>
            {runPlaybookOpen && (
                <RunPlaybookModal key={alert.id} alert={alert} isOpen={runPlaybookOpen}
                    onClose={() => { setRunPlaybookOpen(false); setHistoryKey(k => k + 1); }} />
            )}
            {exceptionOpen && (
                <CreateExceptionModal isOpen={exceptionOpen} alert={alert} updateAlertStatus={false}
                    onClose={() => setExceptionOpen(false)}
                    onCreated={async (markedFP) => { if (markedFP) await onStatusChange(alert.id, 'false_positive', true); }} />
            )}
        </>
    );

    if (inlineMode) return innerContent;

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Alert Details" size="xl">
            {innerContent}
        </Modal>
    );
}

export default AlertDetailPanel;
