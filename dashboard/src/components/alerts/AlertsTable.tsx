import {
    Check, Eye, ArrowUpDown, Zap, CheckCircle, GitBranch
} from 'lucide-react';
import { RiskScoreBadge } from './RiskScoreBadge';
import { severityColors, statusColors, severityStripe } from './alertsUtils';
import { statusIcons } from './alertsConstants';
import { authApi } from '../../api/client';
import { SkeletonTable } from '../';
import type { Alert } from '../../api/client';

type SortField = 'timestamp' | 'severity' | 'risk_score';

interface AlertsTableProps {
    alerts: Alert[];
    isLoading: boolean;
    selectedIds: Set<string>;
    selectedAlert: Alert | null;
    agentHostnameMap: Record<string, string>;
    sortBy: SortField;
    sortOrder: 'asc' | 'desc';
    hasFilters: boolean;
    onToggleSelectAll: () => void;
    onToggleSelect: (id: string) => void;
    onSelectAlert: (alert: Alert | null) => void;
    onStatusChange: (id: string, status: string) => void;
    onToggleSort: (field: SortField) => void;
    newAlertIds?: Set<string>;
}

export function AlertsTable({
    alerts,
    isLoading,
    selectedIds,
    selectedAlert,
    agentHostnameMap,
    sortBy,
    hasFilters,
    onToggleSelectAll,
    onToggleSelect,
    onSelectAlert,
    onStatusChange,
    onToggleSort,
    newAlertIds = new Set(),
}: AlertsTableProps) {
    if (isLoading) {
        return (
            <div className="p-4 flex-1 overflow-auto">
                <SkeletonTable rows={10} columns={8} />
            </div>
        );
    }

    if (alerts.length === 0) {
        return (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-12">
                <div className="w-12 h-12 text-green-400 mx-auto mb-4 opacity-50">
                    <svg className="w-full h-full" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                </div>
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">No Alerts Found</h3>
                <p className="text-slate-500">
                    {hasFilters
                        ? 'Try adjusting your filters'
                        : 'All clear! No alerts in this time range.'}
                </p>
            </div>
        );
    }

    return (
        <div className="flex-1 overflow-auto custom-scrollbar transform-gpu">
            <table className="w-full text-left text-sm whitespace-nowrap">
                <thead className="sticky top-0 z-10 bg-slate-100 dark:bg-slate-800 border-b-2 border-slate-200 dark:border-slate-700/80 text-xs uppercase tracking-wider text-slate-600 dark:text-slate-300 font-bold shadow-sm">
                    <tr>
                        <th className="py-4 px-4 w-10">
                            <input
                                type="checkbox"
                                checked={selectedIds.size === alerts.length && alerts.length > 0}
                                onChange={onToggleSelectAll}
                                className="rounded"
                            />
                        </th>
                        {/* Risk Score column — primary sort */}
                        <th className="py-4 px-4 w-24">
                            <button
                                onClick={() => onToggleSort('risk_score')}
                                className={`flex items-center gap-1 hover:text-slate-700 dark:hover:text-slate-200 ${sortBy === 'risk_score' ? 'text-primary-600 dark:text-primary-400' : ''}`}
                            >
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                                </svg>
                                Risk
                                <ArrowUpDown className={`w-3 h-3 ${sortBy === 'risk_score' ? 'text-primary-500' : ''}`} />
                            </button>
                        </th>
                        <th className="py-4 px-4">
                            <button
                                onClick={() => onToggleSort('timestamp')}
                                className="flex items-center gap-1 hover:text-slate-700 dark:hover:text-slate-200"
                            >
                                Created
                                <ArrowUpDown className={`w-3 h-3 ${sortBy === 'timestamp' ? 'text-primary-500' : ''}`} />
                            </button>
                        </th>
                        <th className="py-4 px-4">Rule</th>
                        <th className="py-4 px-4">
                            <button
                                disabled title="Filter by severity; pagination uses stable creation order"
                                className="flex items-center gap-1 hover:text-slate-700 dark:hover:text-slate-200"
                            >
                                Severity
                                <ArrowUpDown className={`w-3 h-3 ${sortBy === 'severity' ? 'text-primary-500' : ''}`} />
                            </button>
                        </th>
                        <th className="py-4 px-4">Status</th>
                        <th className="py-4 px-4">Agent</th>
                        <th className="py-4 px-4">Actions</th>
                    </tr>
                </thead>
                <tbody style={{ contentVisibility: 'auto', containIntrinsicSize: '1100px' } as React.CSSProperties}>
                    {alerts.map((alert) => {
                        const StatusIcon = statusIcons[alert.status] || statusIcons.open;
                        const hasContext = !!alert.context_snapshot;
                        const uebaSignal = alert.score_breakdown?.ueba_signal || alert.context_snapshot?.score_breakdown?.ueba_signal;
                        const isSelected = selectedAlert?.id === alert.id;
                        const hostname = alert.source_hostname || agentHostnameMap[alert.agent_id || ''] || alert.agent_id?.slice(0, 12) + '…';
                        const isNew = newAlertIds.has(alert.id) || (new Date().getTime() - new Date(alert.timestamp).getTime() < 5 * 60 * 1000);
                        return (
                            <tr
                                key={alert.id}
                                onClick={() => onSelectAlert(isSelected ? null : alert)}
                                className={`border-b border-slate-100 dark:border-slate-800/60 transition-all duration-200 cursor-pointer border-l-4 ${
                                    severityStripe[alert.severity] || 'border-l-slate-300'
                                } ${
                                    isSelected
                                        ? 'bg-primary-50 dark:bg-primary-900/20 ring-1 ring-inset ring-primary-400/30'
                                        : selectedIds.has(alert.id)
                                        ? 'bg-primary-50/50 dark:bg-primary-900/10'
                                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                                }`}
                            >
                                <td className="py-3 px-3" onClick={e => e.stopPropagation()}>
                                    <input
                                        type="checkbox"
                                        checked={selectedIds.has(alert.id)}
                                        onChange={() => onToggleSelect(alert.id)}
                                        className="rounded"
                                    />
                                </td>
                                {/* Risk Score */}
                                <td className="py-3 px-3">
                                    <div className="flex items-center gap-1.5">
                                        <RiskScoreBadge score={alert.risk_score} riskLevel={alert.risk_level} />
                                        {uebaSignal === 'anomaly' && <span title="Baseline Anomaly"><Zap className="w-3 h-3 text-red-500" /></span>}
                                        {uebaSignal === 'normal' && <span title="Normalcy Discount"><CheckCircle className="w-3 h-3 text-green-500" /></span>}
                                    </div>
                                </td>
                                <td className="whitespace-nowrap text-sm py-3 px-3 text-slate-500 dark:text-slate-400">
                                    {new Date(alert.created_at || alert.timestamp).toLocaleString()}
                                    {alert.last_seen_at && <span className="block text-[10px] text-slate-500">Last seen {new Date(alert.last_seen_at).toLocaleString()}</span>}
                                </td>
                                <td className="py-3 px-3">
                                    <div className="max-w-[220px]">
                                        <div className="flex items-center gap-2">
                                            <p className="font-semibold text-slate-800 dark:text-slate-200 truncate text-sm">
                                                {alert.rule_title}
                                            </p>
                                            {isNew && (
                                                <span className="shrink-0 px-1.5 py-0.5 rounded text-[9px] font-bold bg-cyan-500 text-white animate-pulse shadow-[0_0_8px_rgba(6,182,212,0.6)]">
                                                    NEW
                                                </span>
                                            )}
                                        </div>
                                        <div className="flex flex-wrap items-center gap-1 mt-1">
                                            {(alert.mitre_tactics || []).slice(0, 2).map(t => (
                                                <span key={t} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-600 dark:text-purple-300 border border-purple-500/20">
                                                    {t}
                                                </span>
                                            ))}
                                            {(alert.mitre_techniques || []).slice(0, 1).map(t => (
                                                <span key={t} className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-500/10 text-slate-500 dark:text-slate-400 border border-slate-500/20">
                                                    {t}
                                                </span>
                                            ))}
                                            {hasContext && <span title="Context snapshot available"><GitBranch className="w-3 h-3 text-slate-400" /></span>}
                                        </div>
                                    </div>
                                </td>
                                <td className="py-3 px-3">
                                    <span className={`badge px-2 py-0.5 text-[11px] font-bold ${severityColors[alert.severity]}`}>
                                        {alert.severity.toUpperCase()}
                                    </span>
                                </td>
                                <td className="py-3 px-3">
                                    <span className={`badge px-2 py-0.5 text-[11px] ${statusColors[alert.status]} flex items-center gap-1 w-fit font-medium`}>
                                        <StatusIcon className="w-3 h-3" />
                                        {alert.status.replace('_', ' ')}
                                    </span>
                                </td>
                                <td className="py-3 px-3">
                                    <div className="text-sm font-medium text-slate-700 dark:text-slate-300">{hostname}</div>
                                </td>
                                <td className="py-3 px-3" onClick={e => e.stopPropagation()}>
                                    <div className="flex gap-1">
                                        <button
                                            onClick={() => onSelectAlert(isSelected ? null : alert)}
                                            className={`p-1.5 rounded transition-colors ${ isSelected ? 'text-primary-600 bg-primary-100 dark:bg-primary-900/40' : 'text-slate-400 hover:text-primary-600 hover:bg-slate-100 dark:hover:bg-slate-700/50' }`}
                                            title="View Details"
                                        >
                                            <Eye className="w-4 h-4" />
                                        </button>
                                        {alert.status === 'open' && authApi.canWriteAlerts() && (
                                            <button
                                                onClick={() => onStatusChange(alert.id, 'acknowledged')}
                                                className="p-1.5 text-slate-400 hover:text-green-600 hover:bg-green-50 dark:hover:bg-green-900/20 rounded transition-colors"
                                                title="Acknowledge"
                                            >
                                                <Check className="w-4 h-4" />
                                            </button>
                                        )}
                                    </div>
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}

export default AlertsTable;
