import { useState } from 'react';
import {
    Check, Clock, CheckCircle, XCircle, AlertTriangle,
    TrendingUp, Info, ChevronDown, ChevronUp, Shield, Play, Settings, ShieldOff, History
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

type TabId = 'summary' | 'context' | 'event' | 'mitre' | 'aggregation' | 'actions';

export function AlertDetailPanel({
    alert,
    isOpen,
    onClose,
    onStatusChange,
    inlineMode = false,
}: AlertDetailPanelProps) {
    const [activeTab, setActiveTab] = useState<TabId>('summary');
    const [showRawJson, setShowRawJson] = useState(false);
    const [runPlaybookOpen, setRunPlaybookOpen] = useState(false);
    const [exceptionOpen, setExceptionOpen] = useState(false);
    const [historyKey, setHistoryKey] = useState(0);
    const { settings: automation } = useAutomationSettings();
    const navigate = useNavigate();

    const handleNavigateWithContext = (path: string) => {
        if (!alert) return;
        navigate(path, {
            state: {
                alertId: alert.id,
                alertDetails: {
                    severity: alert.severity,
                    ruleName: alert.rule_title,
                    ruleId: alert.related_rule_ids?.length === 1 ? alert.related_rule_ids[0] : alert.rule_id,
                    mitreTechniques: alert.mitre_techniques,
                    agentId: alert.agent_id,
                    title: alert.rule_title,
                    description: alert.human_summary,
                    riskScore: alert.risk_score
                }
            }
        });
    };

    if (!alert) return null;

    const hasContext = !!(alert.context_snapshot);
    const snapshot = displaySnapshot(alert);
    const breakdown = alert.score_breakdown || snapshot?.score_breakdown;

    const hasAggregation = !!(alert as Alert & { match_count?: number }).match_count || !!(alert as Alert & { related_rules?: string[] }).related_rules?.length;
    const tabs = [
        { id: 'summary' as TabId, label: 'Summary' },
        { id: 'context' as TabId, label: '⚡ Context', highlight: hasContext },
        { id: 'event' as TabId, label: 'Events' },
        { id: 'mitre' as TabId, label: 'MITRE' },
        ...(hasAggregation ? [{ id: 'aggregation' as TabId, label: '🔗 Aggreg.' }] : []),
        ...(authApi.canWriteAlerts() ? [{ id: 'actions' as TabId, label: 'Actions' }] : []),
    ];

    const innerContent = (
        <>
            {/* Tabs */}
            <div className="flex border-b border-slate-200 dark:border-slate-700 px-4 mb-0 overflow-x-auto">
                {tabs.map((tab) => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`tab whitespace-nowrap ${activeTab === tab.id ? 'tab-active' : ''} ${tab.highlight ? 'relative' : ''}`}
                    >
                        {tab.label}
                        {tab.highlight && activeTab !== tab.id && (
                            <span className="absolute top-1 right-0 w-2 h-2 rounded-full bg-red-500" />
                        )}
                    </button>
                ))}
            </div>
            <div className="p-4">

                {/* Summary Tab */}
                {activeTab === 'summary' && (
                    <div className="space-y-4 animate-slide-up-fade">
                        {/* What Happened — human-readable summary */}
                        {alert.human_summary && (
                            <div className="rounded-xl p-3.5 bg-indigo-50 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-800 flex items-start gap-3">
                                <Info className="w-5 h-5 text-indigo-500 shrink-0 mt-0.5" />
                                <div>
                                    <p className="text-[10px] text-indigo-500 dark:text-indigo-400 uppercase tracking-wider font-bold mb-1">What Happened</p>
                                    <p className="text-sm font-medium text-slate-800 dark:text-slate-100">{alert.human_summary}</p>
                                </div>
                            </div>
                        )}

                        {/* Recommended Action */}
                        {(() => {
                            const actionMap: Record<string, { icon: string; text: string; style: string }> = {
                                critical: { icon: '🔴', text: 'Investigate immediately — potential active threat', style: 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300' },
                                high: { icon: '🟠', text: 'Investigate within 1 hour', style: 'bg-orange-50 dark:bg-orange-950/30 border-orange-200 dark:border-orange-800 text-orange-700 dark:text-orange-300' },
                                medium: { icon: '🟡', text: 'Review when possible — may be benign', style: 'bg-yellow-50 dark:bg-yellow-950/30 border-yellow-200 dark:border-yellow-800 text-yellow-700 dark:text-yellow-300' },
                                low: { icon: '🟢', text: 'Low priority — review during routine triage', style: 'bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-800 text-green-700 dark:text-green-300' },
                            };
                            const action = actionMap[alert.severity] || actionMap.medium;
                            return (
                                <div className={`rounded-lg p-2.5 border flex items-center gap-2 text-sm font-medium ${action.style}`}>
                                    <Shield className="w-4 h-4 shrink-0" />
                                    <span>{action.icon} {action.text}</span>
                                </div>
                            );
                        })()}

                        {/* What ran / triggered the detection */}
                        <AlertEvidencePanel alert={alert} />

                        {/* Risk Score hero */}
                        {alert.risk_score !== undefined && (
                            <div className={`rounded-xl p-4 flex items-center gap-4 ${alert.risk_score >= 90
                                    ? 'bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800'
                                    : alert.risk_score >= 70
                                        ? 'bg-orange-50 dark:bg-orange-950/30 border border-orange-200 dark:border-orange-800'
                                        : alert.risk_score >= 40
                                            ? 'bg-yellow-50 dark:bg-yellow-950/30 border border-yellow-200 dark:border-yellow-800'
                                            : 'bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800'
                                }`}>
                                <div className="shrink-0">
                                    <RiskScoreBadge score={alert.risk_score} riskLevel={alert.risk_level} />
                                </div>
                                <div>
                                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                                        Risk Score: {alert.risk_score}/100 — {getRiskScoreStyle(alert.risk_score).label}
                                    </p>
                                    {alert.false_positive_risk !== undefined && (
                                        <p className="text-xs text-slate-500" title="Estimated probability that this alert is a false alarm based on process signature and known-good patterns">
                                            False Positive Risk: {(alert.false_positive_risk * 100).toFixed(0)}% chance this is a false alarm
                                        </p>
                                    )}
                                    {breakdown?.ueba_signal && breakdown.ueba_signal !== 'none' && (
                                        <div className="mt-1">
                                            <UEBASignalBadge signal={breakdown.ueba_signal} />
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Core fields grid */}
                        <div className="grid grid-cols-2 gap-x-6 gap-y-3">
                            <div className="col-span-2">
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Rule</label>
                                <p className="font-semibold text-slate-900 dark:text-white text-sm mt-0.5">{alert.rule_title}</p>
                                {alert.rule_id && <p className="font-mono text-[10px] text-slate-400 mt-0.5 truncate" title={alert.rule_id}>{alert.rule_id}</p>}
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Category</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5">{alert.category || '—'}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Severity</label>
                                <p className="mt-0.5" title="Severity is the Sigma rule level assigned by the rule author; the risk score adds host context."><span className={`badge text-[11px] font-bold ${severityColors[alert.severity]}`}>{alert.severity.toUpperCase()}</span>
                                    <span className="ml-1.5 text-[10px] text-slate-400">rule level</span></p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Status</label>
                                <p className="mt-0.5"><span className={`badge text-[11px] ${statusColors[alert.status]}`}>{alert.status.replace(/_/g, ' ')}</span></p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Confidence</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5 font-semibold">{alert.confidence !== undefined ? `${(alert.confidence * 100).toFixed(1)}%` : '—'}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Event Count</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5 font-semibold">{alert.event_count}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Detected At</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5">{new Date(alert.timestamp).toLocaleString()}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Source Host</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5 font-semibold">{alert.source_hostname || alert.context_data?.source?.hostname || '—'}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">IP Address</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5 font-mono">{alert.context_data?.ip_address || alert.context_data?.source?.ip_address || '—'}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Operating System</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5">
                                    {alert.context_data?.source?.os_type
                                        ? `${alert.context_data.source.os_type}${alert.context_data.source.os_version && alert.context_data.source.os_version !== 'unknown' ? ' ' + alert.context_data.source.os_version : ''}`
                                        : '—'}
                                </p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Agent Version</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5 font-mono">{alert.context_data?.source?.agent_version || '—'}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Agent ID</label>
                                <p className="font-mono text-[10px] text-slate-400 mt-0.5 truncate" title={alert.agent_id}>{alert.agent_id}</p>
                            </div>
                            {alert.assigned_to && (
                                <div>
                                    <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Assigned To</label>
                                    <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5">{alert.assigned_to}</p>
                                </div>
                            )}
                            {alert.acknowledged_at && (
                                <div>
                                    <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Acknowledged At</label>
                                    <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5">{new Date(alert.acknowledged_at).toLocaleString()}</p>
                                </div>
                            )}
                            {alert.resolved_at && (
                                <div>
                                    <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Resolved At</label>
                                    <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5">{new Date(alert.resolved_at).toLocaleString()}</p>
                                </div>
                            )}
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Created</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5">{new Date(alert.created_at).toLocaleString()}</p>
                            </div>
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Updated</label>
                                <p className="text-slate-700 dark:text-slate-300 text-sm mt-0.5">{new Date(alert.updated_at).toLocaleString()}</p>
                            </div>
                        </div>

                        {/* Tags */}
                        {alert.tags && Object.keys(alert.tags).length > 0 && (
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mb-1.5">Tags</label>
                                <div className="flex flex-wrap gap-1.5">
                                    {Object.entries(alert.tags).map(([k, v]) => (
                                        <span key={k} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                                            <span className="text-slate-400">{k}:</span>{v}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Notes */}
                        {alert.notes && (
                            <div className="rounded-lg border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/10 p-3">
                                <label className="text-[10px] text-amber-600 dark:text-amber-400 uppercase tracking-wider font-bold block mb-1">Analyst Notes</label>
                                <p className="text-sm text-slate-700 dark:text-slate-300">{alert.notes}</p>
                            </div>
                        )}

                        {/* Response */}
                        <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700 space-y-3">
                            <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block">Response Actions</label>
                            <div className="flex flex-wrap gap-3">
                                <button
                                    onClick={() => setRunPlaybookOpen(true)}
                                    className="flex-1 py-2 px-3 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                                >
                                    <Play className="w-4 h-4 text-green-500" />
                                    Run Playbook
                                </button>
                                {automation?.enabled !== false && (
                                    <button
                                        onClick={() => handleNavigateWithContext('/itsm/automations')}
                                        className="flex-1 py-2 px-3 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                                    >
                                        <Settings className="w-4 h-4 text-blue-500" />
                                        Automation Rules
                                    </button>
                                )}
                                {authApi.hasRole(['admin', 'security']) && alert.status !== 'false_positive' && (
                                    <button
                                        onClick={() => setExceptionOpen(true)}
                                        className="flex-1 py-2 px-3 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2"
                                        title="Mark as false positive and create a precise detection exception"
                                    >
                                        <ShieldOff className="w-4 h-4 text-amber-500" />
                                        False Positive…
                                    </button>
                                )}
                            </div>
                            {automation && !automation.enabled && (
                                <p className="text-xs text-slate-500">Automated response is turned off platform-wide{automation.locked ? ' by server configuration' : ''}; playbooks run only manually.</p>
                            )}
                            <div>
                                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-bold flex items-center gap-1.5 mb-2">
                                    <History className="w-3.5 h-3.5" /> Response history
                                </span>
                                <AlertResponseHistory alertId={alert.id} refreshKey={historyKey} />
                            </div>
                        </div>
                    </div>
                )}

                {/* Context Tab — Process Lineage + UEBA + Score Breakdown */}
                {activeTab === 'context' && (
                    <div className="space-y-6">
                        {!hasContext ? (
                            <div className="text-center py-8">
                                <Info className="w-10 h-10 text-slate-300 mx-auto mb-3" />
                                <p className="text-sm text-slate-500">
                                    No context snapshot available for this alert.<br />
                                    <span className="text-xs">Recorded event evidence is available in the Events tab when captured.</span>
                                </p>
                            </div>
                        ) : (
                            <>
                                <p className="text-xs text-slate-500">Context captured during risk evaluation. For aggregated alerts, this may describe a different occurrence from the event shown in Events.</p>
                                {/* Process Command Line */}
                                {snapshot!.process_cmd_line && (
                                    <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-900 p-3">
                                        <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mb-1.5">Command Line</label>
                                        <code className="text-xs text-emerald-400 font-mono break-all whitespace-pre-wrap">{snapshot!.process_cmd_line}</code>
                                    </div>
                                )}

                                {/* Lineage suspicion verdict */}
                                {snapshot!.lineage_suspicion && (() => {
                                    const sus = snapshot!.lineage_suspicion.toLowerCase();
                                    const tone =
                                        sus === 'high' ? 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300'
                                        : sus === 'medium' ? 'bg-orange-50 dark:bg-orange-950/30 border-orange-200 dark:border-orange-800 text-orange-700 dark:text-orange-300'
                                        : sus === 'low' ? 'bg-yellow-50 dark:bg-yellow-950/30 border-yellow-200 dark:border-yellow-800 text-yellow-700 dark:text-yellow-300'
                                        : 'bg-slate-50 dark:bg-slate-900/30 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300';
                                    return (
                                        <div className={`rounded-lg p-3 border flex items-center gap-3 ${tone}`}>
                                            <AlertTriangle className="w-4 h-4 shrink-0" />
                                            <div className="text-sm">
                                                <span className="font-bold uppercase tracking-wider text-[11px]">Lineage Suspicion: </span>
                                                <span className="font-semibold">{snapshot!.lineage_suspicion}</span>
                                            </div>
                                        </div>
                                    );
                                })()}

                                {/* Process Lineage */}
                                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                                    <LineageTree snapshot={snapshot!} />
                                </div>

                                {/* Correlation graph signal */}
                                {snapshot!.correlation && (snapshot!.correlation.edges_added !== undefined || snapshot!.correlation.primary_type) && (
                                    <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                                        <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mb-2">Correlation Graph</label>
                                        <div className="grid grid-cols-3 gap-3">
                                            {snapshot!.correlation.edges_added !== undefined && (
                                                <div>
                                                    <p className="text-[10px] text-slate-400 uppercase tracking-wider">Edges Added</p>
                                                    <p className="text-lg font-bold text-indigo-600 dark:text-indigo-400">{snapshot!.correlation.edges_added}</p>
                                                </div>
                                            )}
                                            {snapshot!.correlation.primary_type && (
                                                <div>
                                                    <p className="text-[10px] text-slate-400 uppercase tracking-wider">Primary Type</p>
                                                    <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">{snapshot!.correlation.primary_type.replace(/_/g, ' ')}</p>
                                                </div>
                                            )}
                                            {snapshot!.correlation.strongest_score !== undefined && (
                                                <div>
                                                    <p className="text-[10px] text-slate-400 uppercase tracking-wider">Strongest Score</p>
                                                    <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">{(snapshot!.correlation.strongest_score * 100).toFixed(1)}%</p>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                )}

                                {/* UEBA & Burst Signals */}
                                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                                    <UEBAPanel snapshot={snapshot!} />
                                </div>

                                {/* Score Breakdown */}
                                {breakdown && (
                                    <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                                        <ScoreBreakdownPanel
                                            breakdown={breakdown}
                                            totalScore={alert.risk_score ?? breakdown.final_score}
                                        />
                                    </div>
                                )}

                                {/* Missing context fields */}
                                {snapshot!.missing_context_fields && snapshot!.missing_context_fields.length > 0 && (
                                    <div className="text-xs text-slate-400 border border-slate-200 dark:border-slate-700 rounded-lg p-3">
                                        <span className="font-bold text-slate-500">Missing context: </span>
                                        {snapshot!.missing_context_fields.join(', ')}
                                    </div>
                                )}

                                {/* Scored At */}
                                {snapshot?.scored_at && (
                                    <p className="text-xs text-slate-400 text-right">
                                        Context scored at {new Date(snapshot.scored_at).toLocaleString()}
                                    </p>
                                )}
                            </>
                        )}
                    </div>
                )}

                {/* Event Details Tab */}
                {activeTab === 'event' && (
                    <div className="space-y-4 animate-slide-up-fade">
                        {/* Matched Fields */}
                        {alert.matched_fields && Object.keys(alert.matched_fields).length > 0 && (
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mb-2">Matched Detection Fields</label>
                                <div className="space-y-1.5">
                                    {Object.entries(alert.matched_fields).map(([key, val]) => (
                                        <div key={key} className="grid min-w-0 grid-cols-1 sm:grid-cols-[144px_minmax(0,1fr)] gap-1 sm:gap-3 p-2 bg-slate-50 dark:bg-slate-800 rounded-lg text-sm">
                                            <span className="font-mono text-indigo-600 dark:text-indigo-400 text-xs shrink-0 mt-0.5 w-32 truncate" title={key}>{key}</span>
                                            <span className="font-mono text-slate-700 dark:text-slate-300 text-xs min-w-0 whitespace-pre-wrap break-all">{json_safe(val)}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                        {/* Event IDs */}
                        {((alert as Alert & { event_ids?: string[] }).event_ids?.length || 0) > 0 && (
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mb-2">Correlated Event IDs</label>
                                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
                                    {(alert as Alert & { event_ids?: string[] }).event_ids!.map(id => (
                                        <span key={id} className="font-mono text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 px-2 py-0.5 rounded">{id}</span>
                                    ))}
                                </div>
                            </div>
                        )}
                        {/* Simplified event key fields + toggleable raw JSON.
                            The by-id endpoint returns the agent envelope under
                            `context_data` (with a nested `data` sub-map for
                            collector-specific fields). Older summaries used
                            `event_data`; we read both for backward compat. */}
                        {(alert.context_data || alert.event_data) && (() => {
                            const ctx = (alert.context_data ?? {}) as Record<string, unknown>;
                            const { pick } = alertEvidence(alert);
                            const fields = [
                                ['event_id', 'Event ID'], ['timestamp', 'Event timestamp (source)'],
                                ['batch_id', 'Batch ID'], ['channel', 'Event log channel'],
                                ['ppid', 'Parent PID'], ['user_sid', 'User SID'],
                                ['is_elevated', 'Elevated'], ['signature_status', 'Signature status'],
                                ['signature_issuer', 'Signer'], ['script_path', 'Script path'],
                            ];
                            const rendered = fields.map(([key, label]) => ({ key, label, val: pick(key) })).filter(f => f.val !== '');

                            const kafka = {
                                topic: ctx._kafka_topic,
                                partition: ctx._kafka_partition,
                                offset: ctx._kafka_offset,
                                time: ctx._kafka_time,
                                key: ctx._kafka_key,
                            };
                            const hasKafka = Object.values(kafka).some(v => v !== undefined && v !== null && v !== '');

                            const rawSource = alert.context_data ?? alert.event_data;

                            return (
                                <div>
                                    <AlertEvidencePanel alert={alert} />
                                    <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mt-4 mb-2">Event metadata</label>
                                    <div className="space-y-1.5 mb-3">
                                        {rendered.map(({ key, label, val }) => (
                                            <div key={key} className="grid min-w-0 grid-cols-1 sm:grid-cols-[144px_minmax(0,1fr)] gap-1 sm:gap-3 p-2 bg-slate-50 dark:bg-slate-800 rounded-lg text-sm">
                                                <span className="text-indigo-600 dark:text-indigo-400 text-xs shrink-0 mt-0.5 w-36" title={key}>{label}</span>
                                                <span className="font-mono text-slate-700 dark:text-slate-300 text-xs min-w-0 whitespace-pre-wrap break-all">{String(val)}</span>
                                            </div>
                                        ))}
                                    </div>

                                    {hasKafka && (
                                        <div className="mb-3">
                                            <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mb-2">Kafka Pipeline Metadata</label>
                                            <div className="grid grid-cols-2 gap-1.5 text-xs">
                                                {kafka.topic !== undefined && (
                                                    <div className="flex items-start gap-2 p-2 bg-slate-50 dark:bg-slate-800 rounded-lg">
                                                        <span className="text-slate-400 w-20 shrink-0">topic</span>
                                                        <span className="font-mono text-slate-700 dark:text-slate-300 break-all">{String(kafka.topic)}</span>
                                                    </div>
                                                )}
                                                {kafka.partition !== undefined && (
                                                    <div className="flex items-start gap-2 p-2 bg-slate-50 dark:bg-slate-800 rounded-lg">
                                                        <span className="text-slate-400 w-20 shrink-0">partition</span>
                                                        <span className="font-mono text-slate-700 dark:text-slate-300">{String(kafka.partition)}</span>
                                                    </div>
                                                )}
                                                {kafka.offset !== undefined && (
                                                    <div className="flex items-start gap-2 p-2 bg-slate-50 dark:bg-slate-800 rounded-lg">
                                                        <span className="text-slate-400 w-20 shrink-0">offset</span>
                                                        <span className="font-mono text-slate-700 dark:text-slate-300">{String(kafka.offset)}</span>
                                                    </div>
                                                )}
                                                {kafka.time !== undefined && (
                                                    <div className="flex items-start gap-2 p-2 bg-slate-50 dark:bg-slate-800 rounded-lg">
                                                        <span className="text-slate-400 w-20 shrink-0">time</span>
                                                        <span className="font-mono text-slate-700 dark:text-slate-300 break-all">{String(kafka.time)}</span>
                                                    </div>
                                                )}
                                                {kafka.key !== undefined && (
                                                    <div className="flex items-start gap-2 p-2 bg-slate-50 dark:bg-slate-800 rounded-lg col-span-2">
                                                        <span className="text-slate-400 w-20 shrink-0">key</span>
                                                        <span className="font-mono text-slate-700 dark:text-slate-300 break-all">{String(kafka.key)}</span>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    <button
                                        onClick={() => setShowRawJson(!showRawJson)}
                                        className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors mb-2"
                                    >
                                        {showRawJson ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                                        {showRawJson ? 'Hide full JSON' : 'Show full JSON'}
                                    </button>
                                    {showRawJson && rawSource && (
                                        <pre className="p-3 bg-slate-100 dark:bg-slate-900 rounded-lg overflow-auto max-h-64 text-[11px] font-mono text-slate-700 dark:text-slate-300 whitespace-pre-wrap break-all">
                                            {JSON.stringify(rawSource, null, 2)}
                                        </pre>
                                    )}
                                </div>
                            );
                        })()}
                    </div>
                )}

                {/* Aggregation Tab */}
                {activeTab === 'aggregation' && (
                    <div className="space-y-5 animate-slide-up-fade">
                        <div className="grid grid-cols-2 gap-4">
                            {(alert as Alert & { match_count?: number }).match_count !== undefined && (
                                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4 text-center">
                                    <p className="text-3xl font-extrabold text-indigo-600 dark:text-indigo-400">{(alert as Alert & { match_count?: number }).match_count}</p>
                                    <p className="text-xs text-slate-500 mt-1 uppercase tracking-wider">Rule Matches</p>
                                </div>
                            )}
                            {(alert as Alert & { combined_confidence?: number }).combined_confidence !== undefined && (
                                <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4 text-center">
                                    <p className="text-3xl font-extrabold text-emerald-600 dark:text-emerald-400">{((alert as Alert & { combined_confidence?: number }).combined_confidence! * 100).toFixed(0)}%</p>
                                    <p className="text-xs text-slate-500 mt-1 uppercase tracking-wider">Combined Confidence</p>
                                </div>
                            )}
                        </div>
                        {(alert as Alert & { severity_promoted?: boolean }).severity_promoted && (
                            <div className="flex items-center gap-3 p-3 rounded-lg bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800">
                                <TrendingUp className="w-5 h-5 text-orange-500 shrink-0" />
                                <div>
                                    <p className="text-sm font-semibold text-orange-700 dark:text-orange-300">Severity Promoted</p>
                                    <p className="text-xs text-orange-600 dark:text-orange-400">
                                        Original: {(alert as Alert & { original_severity?: string }).original_severity?.toUpperCase() || '—'} → Promoted: {alert.severity.toUpperCase()}
                                    </p>
                                </div>
                            </div>
                        )}
                        {((alert as Alert & { related_rules?: string[] }).related_rules?.length || 0) > 0 && (
                            <div>
                                <label className="text-[10px] text-slate-400 uppercase tracking-wider font-bold block mb-2">Related Rules Detected</label>
                                <div className="space-y-1.5">
                                    {(alert as Alert & { related_rules?: string[] }).related_rules!.map((r, i) => (
                                        <div key={i} className="font-mono text-xs bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 px-3 py-1.5 rounded-lg">{r}</div>
                                    ))}
                                    {alert.related_rule_ids?.map(id => (
                                        <div key={id} className="font-mono text-[10px] text-slate-400 px-3 break-all">{id}</div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* MITRE ATT&CK Tab */}
                {activeTab === 'mitre' && (
                    <div className="space-y-4 animate-slide-up-fade">
                        <div>
                            <label className="text-xs text-slate-500 uppercase tracking-wider">Tactics</label>
                            <div className="flex flex-wrap gap-2 mt-2">
                                {(alert.mitre_tactics || []).length > 0 ? (
                                    alert.mitre_tactics?.map((tactic) => (
                                        <span key={tactic} className="badge badge-warning">{tactic}</span>
                                    ))
                                ) : (
                                    <span className="text-sm text-slate-400">No tactics identified</span>
                                )}
                            </div>
                        </div>
                        <div>
                            <label className="text-xs text-slate-500 uppercase tracking-wider">Techniques</label>
                            <div className="flex flex-wrap gap-2 mt-2">
                                {(alert.mitre_techniques || []).length > 0 ? (
                                    alert.mitre_techniques?.map((technique) => (
                                        <span key={technique} className="badge badge-info">{technique}</span>
                                    ))
                                ) : (
                                    <span className="text-sm text-slate-400">No techniques identified</span>
                                )}
                            </div>
                        </div>
                    </div>
                )}

                {/* Actions Tab */}
                {activeTab === 'actions' && (
                    <div className="space-y-4 animate-slide-up-fade">
                        <p className="text-sm text-slate-600 dark:text-slate-400">
                            Update the alert status to track investigation progress.
                        </p>
                        <div className="grid grid-cols-2 gap-3">
                            {alert.status === 'open' && (
                                <>
                                    <button
                                        onClick={() => onStatusChange(alert.id, 'acknowledged')}
                                        className="btn btn-primary flex items-center justify-center gap-2"
                                    >
                                        <Check className="w-4 h-4" />
                                        Acknowledge
                                    </button>
                                    <button
                                        onClick={() => onStatusChange(alert.id, 'in_progress')}
                                        className="btn btn-warning flex items-center justify-center gap-2"
                                    >
                                        <Clock className="w-4 h-4" />
                                        Start Investigation
                                    </button>
                                </>
                            )}
                            {(alert.status === 'acknowledged' || alert.status === 'in_progress') && (
                                <>
                                    <button
                                        onClick={() => onStatusChange(alert.id, 'resolved')}
                                        className="btn btn-success flex items-center justify-center gap-2"
                                    >
                                        <CheckCircle className="w-4 h-4" />
                                        Resolve
                                    </button>
                                    <button
                                        onClick={() => onStatusChange(alert.id, 'false_positive')}
                                        className="btn btn-secondary flex items-center justify-center gap-2"
                                    >
                                        <XCircle className="w-4 h-4" />
                                        False Positive
                                    </button>
                                </>
                            )}
                            {(alert.status === 'resolved' || alert.status === 'false_positive') && (
                                <button
                                    onClick={() => onStatusChange(alert.id, 'open')}
                                    className="btn btn-secondary flex items-center justify-center gap-2"
                                >
                                    <AlertTriangle className="w-4 h-4" />
                                    Reopen
                                </button>
                            )}
                        </div>
                    </div>
                )}
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
        <Modal isOpen={isOpen} onClose={onClose} title="Alert Details" size="lg">
            {innerContent}
        </Modal>
    );
}

export default AlertDetailPanel;
