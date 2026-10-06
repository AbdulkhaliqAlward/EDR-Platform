import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
    ArrowLeft, Activity, Terminal, Shield, HardDrive, Loader2,
    Server, Network, AlertTriangle, CheckCircle2, XCircle, Settings,
    RefreshCw, ChevronLeft, ChevronRight, FileText, List, Package,
    ShieldAlert, Pencil, Check, X as XIcon, Building2, Globe,
    Eye, Tag, Zap, Trash2
} from 'lucide-react';
import {
    agentPackagesApi,
    agentsApi,
    alertsApi,
    authApi,
    eventsApi,
    type Agent,
    type Alert,
    type CmEventSummary,
    type CommandListItem,
    type CommandRequest,
    type CommandType,
    type EndpointRiskSummary,
    type QuarantineItem,
    type ForensicCollection,
    type ForensicEvent,
} from '../api/client';
import { EventDetailModal, Modal, useToast } from '../components';
import { formatRelativeTime, getEffectiveStatus } from '../utils/agentDisplay';
import { IncidentTab } from './IncidentTab';

type DetailTab =
    | 'overview'
    | 'incident'
    | 'response'
    | 'quarantine'
    | 'activity'
    | 'forensics'
    | 'auto-proc'
    | 'configuration'
    | 'software';

const TAB_LABELS: { id: DetailTab; label: string; icon: React.FC<any> }[] = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'incident', label: 'Incident', icon: AlertTriangle },
    { id: 'response', label: 'Response', icon: Terminal },
    { id: 'quarantine', label: 'Quarantine', icon: Shield },
    { id: 'activity', label: 'Activity', icon: List },
    { id: 'forensics', label: 'Forensic Logs', icon: FileText },
    { id: 'auto-proc', label: 'Auto-Proc Termination', icon: ShieldAlert },
    { id: 'configuration', label: 'Configuration', icon: Settings },
    { id: 'software', label: 'Software', icon: Package },
];

/** Legacy `?tab=summary` from earlier builds → Overview. */
const LEGACY_TAB_MAP: Record<string, DetailTab> = { summary: 'overview' };

function normalizeTab(raw: string | null): DetailTab | null {
    if (!raw) return null;
    if (LEGACY_TAB_MAP[raw]) return LEGACY_TAB_MAP[raw];
    if (TAB_LABELS.some((t) => t.id === (raw as DetailTab))) return raw as DetailTab;
    return null;
}

const RESPONSE_OPTIONS: { value: CommandType; label: string; destructive?: boolean }[] = [
    { value: 'kill_process', label: 'Kill / terminate process' },
    { value: 'quarantine_file', label: 'Quarantine file' },
    { value: 'isolate_network', label: 'Isolate network' },
    { value: 'restore_network', label: 'Restore network (un-isolate)' },
    { value: 'block_ip', label: 'Block IP' },
    { value: 'unblock_ip', label: 'Unblock IP' },
    { value: 'block_domain', label: 'Block domain' },
    { value: 'unblock_domain', label: 'Unblock domain' },
    { value: 'run_cmd', label: 'Run CMD (whitelisted)' },
    { value: 'custom', label: 'Custom command (whitelisted)' },
    { value: 'collect_logs', label: 'Collect logs' },
    { value: 'collect_forensics', label: 'Collect forensics' },
    { value: 'scan_memory', label: 'Scan memory (file hash)' },
    { value: 'restart_agent', label: 'Restart agent' },
    { value: 'restart_service', label: 'Restart agent service' },
    { value: 'start_agent', label: 'Start agent service' },
    { value: 'restart_machine', label: 'Restart machine', destructive: true },
    { value: 'shutdown_machine', label: 'Shutdown machine', destructive: true },
    { value: 'uninstall_agent', label: 'Uninstall agent (permanent)', destructive: true },
];

function buildCommandParameters(cmd: CommandType, f: Record<string, string>): Record<string, string> {
    switch (cmd) {
        case 'kill_process':
        case 'terminate_process': {
            const p: Record<string, string> = {};
            if (f.pid?.trim()) p.pid = f.pid.trim();
            if (f.process_name?.trim()) p.process_name = f.process_name.trim();
            p.kill_tree = f.kill_tree === 'true' ? 'true' : 'false';
            return p;
        }
        case 'quarantine_file':
            return { path: (f.path || f.file_path || '').trim() };
        case 'block_ip':
        case 'unblock_ip': {
            const o: Record<string, string> = { ip: (f.ip || '').trim() };
            if (f.direction && cmd === 'block_ip') o.direction = f.direction;
            return o;
        }
        case 'block_domain':
        case 'unblock_domain':
            return { domain: (f.domain || '').trim() };
        case 'run_cmd':
            return { cmd: (f.cmd || '').trim() };
        case 'custom':
            return { cmd: (f.cmd || '').trim() };
        case 'collect_logs':
        case 'collect_forensics': {
            const o: Record<string, string> = {};
            const types = f.types?.trim() || f.log_types?.trim();
            if (types) o.log_types = types;
            const tr = f.time_range?.trim();
            if (tr) o.time_range = tr;
            if (f.max_events?.trim()) o.max_events = f.max_events.trim();
            if (f.file_path?.trim()) o.file_path = f.file_path.trim();
            // Return structured events so the backend can persist them for the Forensic Logs tab.
            o.return_events = 'true';
            return o;
        }
        case 'scan_memory':
        case 'scan_file':
            return { file_path: (f.file_path || f.path || '').trim() };
        case 'restart_agent':
            return { mode: 'restart' };
        case 'stop_agent':
            return { mode: 'stop' };
        case 'start_agent':
            return { mode: 'start' };
        case 'enable_sysmon': {
            const o: Record<string, string> = { mode: 'enable_sysmon' };
            if (f.sysmon_config_url?.trim()) o.config_url = f.sysmon_config_url.trim();
            return o;
        }
        case 'disable_sysmon':
            return { mode: 'disable_sysmon' };
        case 'update_signatures': {
            const o: Record<string, string> = { url: (f.sig_url || '').trim() };
            if (f.checksum_sha256?.trim()) o.checksum_sha256 = f.checksum_sha256.trim();
            if (f.format?.trim()) o.format = f.format.trim();
            if (f.force === 'true') o.force = 'true';
            return o;
        }
        case 'update_config': {
            const k = (f.config_key || '').trim();
            const v = (f.config_value || '').trim();
            if (!k) return {};
            return { [k]: v };
        }
        case 'update_vuln_config': {
            const p: Record<string, string> = {};
            if (f.vuln_scan_enabled !== undefined && f.vuln_scan_enabled !== '') p.vuln_scan_enabled = f.vuln_scan_enabled;
            if (f.vuln_scan_interval?.trim()) p.vuln_scan_interval = f.vuln_scan_interval.trim();
            if (f.vuln_scanner_type?.trim()) p.vuln_scanner_type = f.vuln_scanner_type.trim();
            if (f.vuln_scanner_path?.trim()) p.vuln_scanner_path = f.vuln_scanner_path.trim();
            if (f.vuln_scan_timeout?.trim()) p.vuln_scan_timeout = f.vuln_scan_timeout.trim();
            if (f.vuln_scan_args?.trim()) p.vuln_scan_args = f.vuln_scan_args.trim();
            if (f.process_prevention_mode?.trim()) p.process_prevention_mode = f.process_prevention_mode.trim();
            if (f.process_auto_kill_enabled !== undefined && f.process_auto_kill_enabled !== '') p.process_auto_kill_enabled = f.process_auto_kill_enabled;
            if (f.auto_quarantine !== undefined && f.auto_quarantine !== '') p.auto_quarantine = f.auto_quarantine;
            return p;
        }
        case 'update_filter_policy':
            return { policy: f.policy_json?.trim() || '{}' };
        case 'restart_machine':
        case 'shutdown_machine':
            return { confirm: f.confirm === 'true' ? 'true' : 'false' };
        case 'uninstall_agent': {
            const o: Record<string, string> = {};
            if (f.reason?.trim()) o.reason = f.reason.trim();
            return o;
        }
        default:
            return {};
    }
}

function resultPreview(result: unknown): string {
    if (result == null) return '—';
    if (typeof result === 'string') return result.slice(0, 120) + (result.length > 120 ? '…' : '');
    try {
        const s = JSON.stringify(result);
        return s.length > 140 ? `${s.slice(0, 140)}…` : s;
    } catch {
        return String(result);
    }
}

function commandHistoryOutputCell(c: CommandListItem, agentId: string): React.ReactNode {
    if (c.command_type !== 'collect_logs' && c.command_type !== 'collect_forensics') {
        return <span className="text-slate-600 dark:text-slate-300">{resultPreview(c.result)}</span>;
    }
    const st = String(c.status || '').toLowerCase();
    const forensicsTo = `/management/devices/${encodeURIComponent(agentId)}?tab=forensics&command_id=${encodeURIComponent(c.id)}`;
    const forensicsLink = (
        <Link to={forensicsTo} className="text-cyan-700 dark:text-cyan-300 font-semibold hover:underline">
            Forensic Logs
        </Link>
    );
    if (st === 'failed' || st === 'timeout' || st === 'cancelled') {
        return (
            <div className="space-y-1">
                <div className="text-slate-600 dark:text-slate-300">{resultPreview(c.result)}</div>
                <div className="text-slate-500 text-xs">Successful collections are browsable under {forensicsLink}.</div>
            </div>
        );
    }
    const done = st === 'completed';
    return (
        <div className="text-slate-600 dark:text-slate-300 text-xs space-y-1">
            <p>
                {done
                    ? <>Full log output is not shown here. Open the {forensicsLink} tab for this device to browse events.</>
                    : <>When this command completes, browse collected logs on the {forensicsLink} tab.</>}
            </p>
            <p className="font-mono text-[11px] text-slate-500 dark:text-slate-400 break-all">{forensicsTo}</p>
        </div>
    );
}

export default function EndpointDetail() {
    const { agentId = '' } = useParams<{ agentId: string }>();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const { showToast } = useToast();
    const [searchParams, setSearchParams] = useSearchParams();

    const [tab, setTab] = useState<DetailTab>(() => {
        const n = normalizeTab(searchParams.get('tab'));
        return n ?? 'overview';
    });

    useEffect(() => {
        const n = normalizeTab(searchParams.get('tab'));
        if (n) setTab(n);
    }, [searchParams]);

    const setTabAndUrl = useCallback(
        (next: DetailTab) => {
            setTab(next);
            setSearchParams((prev) => {
                const n = new URLSearchParams(prev);
                n.set('tab', next);
                return n;
            });
        },
        [setSearchParams]
    );

    const [cmdType, setCmdType] = useState<CommandType>('kill_process');
    const [fields, setFields] = useState<Record<string, string>>({
        kill_tree: 'false',
        timeout: '300',
        direction: 'both',
        confirm: 'false',
    });
    const [destructiveOpen, setDestructiveOpen] = useState(false);
    const [pendingDestructive, setPendingDestructive] = useState<'restart_machine' | 'shutdown_machine' | 'uninstall_agent' | null>(null);
    const [offlineToken, setOfflineToken] = useState<{ token: string; expires_at: string } | null>(null);
    const [removeOpen, setRemoveOpen] = useState(false);

    const { data: agent, isLoading: agentLoading, error: agentError } = useQuery({
        queryKey: ['agent', agentId],
        queryFn: () => agentsApi.get(agentId),
        enabled: !!agentId,
        // Poll every 30 s so the displayed online/offline status stays in sync
        // with the live backend. Without this, a cached last_seen value can age
        // past the staleness threshold and incorrectly show the agent as offline.
        refetchInterval: 30_000,
        refetchIntervalInBackground: false,
    });

    const { data: riskPayload } = useQuery({
        queryKey: ['endpoint-risk'],
        queryFn: () => alertsApi.endpointRisk(),
        staleTime: 60_000,
    });

    const riskRow: EndpointRiskSummary | undefined = useMemo(() => {
        const rows = riskPayload?.data;
        if (!rows) return undefined;
        return rows.find((r) => r.agent_id === agentId);
    }, [riskPayload, agentId]);

    const canViewAlerts = authApi.canViewAlerts();

    // Commands are fetched in Response tab (cmdPage). Overview uses that list for quick status panels.

    const { data: cmdPage, isLoading: cmdsLoading } = useQuery({
        queryKey: ['agent-commands', agentId, 'response'],
        queryFn: () => agentsApi.getCommands(agentId, { limit: 100 }),
        enabled: !!agentId && tab === 'response',
        // Poll every 8 s so command statuses (pending → completed/failed) update
        // in real-time without the analyst needing to manually refresh.
        refetchInterval: tab === 'response' ? 8_000 : false,
        refetchIntervalInBackground: false,
    });

    const { data: quarantineData, isLoading: qLoading } = useQuery({
        queryKey: ['agent-quarantine', agentId],
        queryFn: () => agentsApi.listQuarantine(agentId, { include_resolved: true }),
        enabled: !!agentId && tab === 'quarantine',
        // Poll every 5 s so auto-quarantine events from the agent appear in the
        // dashboard within seconds rather than 2-3 minutes.
        refetchInterval: tab === 'quarantine' ? 5_000 : false,
        refetchIntervalInBackground: false,
    });

    const { data: eventsPayload } = useQuery({
        queryKey: ['agent-events', agentId],
        queryFn: () => agentsApi.getAgentEvents(agentId),
        enabled: !!agentId && (tab === 'activity' || tab === 'overview'),
    });

    const { data: overviewAlerts, isLoading: overviewAlertsLoading } = useQuery({
        queryKey: ['sigma-alerts-overview', agentId],
        queryFn: () => alertsApi.list({ agent_id: agentId, limit: 6, order: 'desc' }),
        enabled: !!agentId && tab === 'overview' && canViewAlerts,
    });

    const { data: alertsForAgent, isLoading: alertsLoading } = useQuery({
        queryKey: ['sigma-alerts', agentId],
        queryFn: () => alertsApi.list({ agent_id: agentId, limit: 80, order: 'desc' }),
        enabled: !!agentId && tab === 'activity' && canViewAlerts,
    });

    const execMutation = useMutation({
        mutationFn: (req: CommandRequest) => agentsApi.executeCommand(agentId, req),
        onSuccess: (data, variables) => {
            showToast(`Command queued (${data.command_id})`, 'success');
            queryClient.invalidateQueries({ queryKey: ['agent-commands', agentId] });
            queryClient.invalidateQueries({ queryKey: ['commands'] });
            const t = variables.command_type;
            if (t === 'quarantine_file' || t === 'restore_quarantine_file' || t === 'delete_quarantine_file') {
                queryClient.invalidateQueries({ queryKey: ['agent-quarantine', agentId] });
            }
            if (t === 'collect_logs' || t === 'collect_forensics') {
                queryClient.invalidateQueries({ queryKey: ['forensics', 'collections', agentId] });
            }
        },
        onError: (e: Error) => showToast(e.message || 'Command failed', 'error'),
    });

    const removeDeviceMutation = useMutation({
        mutationFn: () => agentsApi.delete(agentId),
        onSuccess: () => {
            setRemoveOpen(false);
            showToast('Device removed from the dashboard (history kept)', 'success');
            queryClient.invalidateQueries({ queryKey: ['agents'] });
            queryClient.removeQueries({ queryKey: ['agent', agentId] });
            navigate('/management/devices');
        },
        onError: (e: unknown) => {
            // Surface the server's explanation (e.g. 409 "agent is currently connected").
            const ax = e as { response?: { data?: { message?: string } }; message?: string };
            showToast(ax?.response?.data?.message || ax?.message || 'Could not remove device', 'error');
        },
    });

    const offlineTokenMutation = useMutation({
        mutationFn: () => agentsApi.generateUninstallToken(agentId),
        onSuccess: (data) => {
            setOfflineToken({ token: data.token, expires_at: data.expires_at });
            showToast('Offline uninstall token generated (shown once)', 'success');
        },
        onError: (e: Error) => showToast(e.message || 'Could not generate uninstall token', 'error'),
    });

    const qDecisionMutation = useMutation({
        mutationFn: ({ entryId, decision }: { entryId: string; decision: 'acknowledge' | 'restore' | 'delete' }) =>
            agentsApi.quarantineDecision(agentId, entryId, decision),
        onSuccess: (_, v) => {
            showToast(`Quarantine: ${v.decision}`, 'success');
            queryClient.invalidateQueries({ queryKey: ['agent-quarantine', agentId] });
            queryClient.invalidateQueries({ queryKey: ['agent-commands', agentId] });
        },
        onError: (e: Error) => showToast(e.message || 'Decision failed', 'error'),
    });

    const submitCommand = () => {
        const opt = RESPONSE_OPTIONS.find((o) => o.value === cmdType);
        if (opt?.destructive) {
            setPendingDestructive(cmdType as 'restart_machine' | 'shutdown_machine' | 'uninstall_agent');
            setDestructiveOpen(true);
            return;
        }
        const timeout = Math.min(3600, Math.max(0, parseInt(fields.timeout || '300', 10) || 300));
        const parameters = buildCommandParameters(cmdType, fields);
        execMutation.mutate({
            command_type: cmdType,
            parameters,
            timeout,
        });
    };

    const confirmDestructive = () => {
        if (!pendingDestructive) return;
        const timeout = Math.min(3600, Math.max(0, parseInt(fields.timeout || '300', 10) || 300));
        // Uninstall carries an optional reason instead of a boolean confirm,
        // since the server-side audit trail is more useful than a re-confirm.
        const parameters =
            pendingDestructive === 'uninstall_agent'
                ? buildCommandParameters('uninstall_agent', fields)
                : { confirm: 'true' };
        execMutation.mutate({
            command_type: pendingDestructive,
            parameters,
            timeout,
        });
        setDestructiveOpen(false);
        setPendingDestructive(null);
    };

    const eff = agent ? getEffectiveStatus(agent) : 'offline';
    const canExec = authApi.canExecuteCommands();
    const canViewResp = authApi.canViewResponses();

    if (!agentId) {
        return (
            <div className="p-8 text-center text-slate-500">
                Invalid device ID. <Link className="text-primary-600" to="/management/devices">Back to devices</Link>
            </div>
        );
    }

    if (agentLoading) {
        return (
            <div className="flex items-center justify-center min-h-[40vh]">
                <Loader2 className="w-10 h-10 animate-spin text-cyan-500" />
            </div>
        );
    }

    if (agentError || !agent) {
        return (
            <div className="p-8 text-center">
                <AlertTriangle className="w-12 h-12 text-amber-500 mx-auto mb-3" />
                <p className="text-slate-700 dark:text-slate-200 mb-4">Could not load this endpoint.</p>
                <Link to="/management/devices" className="text-primary-600 hover:underline">
                    ← Back to Device Management
                </Link>
            </div>
        );
    }

    // lastCmd previously shown in Overview; Response tab now owns command details.

    return (
        <div className="relative flex flex-col min-h-[calc(100vh-2rem)] -mx-4 sm:-mx-6 lg:-mx-8 -my-4 sm:-my-6 lg:-my-8 p-4 sm:p-6 lg:p-8 bg-slate-100 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900">
            <div className="w-full space-y-5">
                {/* Back button */}
                <button
                    type="button"
                    onClick={() => navigate('/management/devices')}
                    className="inline-flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition-colors"
                >
                    <ArrowLeft className="w-4 h-4" />
                    Back to Devices
                </button>

                {/* Agent Header Card */}
                <div className="bg-white/95 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 backdrop-blur-md rounded-2xl p-5 sm:p-6 shadow-sm">
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                                <Server className="w-6 h-6 text-white" />
                            </div>
                            <div>
                                <h2 className="text-xl font-bold text-slate-900 dark:text-white break-all">{agent.hostname}</h2>
                                <div className="flex items-center gap-3 mt-1">
                                    <span className="text-xs text-slate-500 font-mono">{agent.id.slice(0, 20)}...</span>
                                    <span className="text-[10px] text-slate-400">{agent.os_type || 'Unknown OS'}</span>
                                    {agent.agent_version && <span className="text-[10px] text-slate-400">v{agent.agent_version}</span>}
                                </div>
                            </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                            <span
                                className={`px-3 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider border ${eff === 'online'
                                        ? 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50'
                                        : eff === 'offline'
                                            ? 'bg-slate-100 dark:bg-slate-800 text-slate-500 border-slate-200 dark:border-slate-700'
                                            : eff === 'uninstalled'
                                                ? 'bg-rose-50 dark:bg-rose-900/20 text-rose-600 dark:text-rose-400 border-rose-200 dark:border-rose-800/50'
                                                : eff === 'pending_uninstall'
                                                    ? 'bg-rose-50 dark:bg-rose-900/20 text-rose-500 border-rose-200 dark:border-rose-800/50'
                                                    : 'bg-amber-50 dark:bg-amber-900/20 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-800/50'
                                    }`}
                            >
                                {eff === 'pending_uninstall' ? 'Uninstalling…' : eff}
                            </span>
                            {agent.is_isolated && (
                                <span className="px-3 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-50 dark:bg-rose-900/20 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800/50">
                                    Isolated
                                </span>
                            )}
                            <Link
                                to={`/responses?agent_id=${encodeURIComponent(agent.id)}`}
                                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-50 dark:bg-cyan-900/20 text-cyan-700 dark:text-cyan-300 border border-cyan-200 dark:border-cyan-800/50 hover:bg-cyan-100 dark:hover:bg-cyan-900/40 transition-colors"
                            >
                                View Commands
                            </Link>
                            <Link
                                to={`/events?agent_id=${encodeURIComponent(agent.id)}`}
                                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
                            >
                                View Events
                            </Link>
                            {authApi.canManageEndpoints() && (
                                <button
                                    type="button"
                                    onClick={() => setRemoveOpen(true)}
                                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800/50 hover:bg-rose-100 dark:hover:bg-rose-900/40 transition-colors"
                                    title="Remove this device from the dashboard (its history is kept)"
                                >
                                    <Trash2 className="w-3.5 h-3.5" />
                                    Remove from dashboard
                                </button>
                            )}
                        </div>
                    </div>
                </div>

                <Modal
                    isOpen={removeOpen}
                    onClose={() => { if (!removeDeviceMutation.isPending) setRemoveOpen(false); }}
                    title="Remove device from dashboard"
                    footer={
                        <div className="flex justify-end gap-2">
                            <button
                                type="button"
                                className="btn btn-secondary"
                                disabled={removeDeviceMutation.isPending}
                                onClick={() => setRemoveOpen(false)}
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                className="btn bg-rose-600 hover:bg-rose-700 text-white"
                                disabled={removeDeviceMutation.isPending}
                                onClick={() => removeDeviceMutation.mutate()}
                            >
                                {removeDeviceMutation.isPending ? 'Removing…' : 'Remove'}
                            </button>
                        </div>
                    }
                >
                    <div className="space-y-2 text-sm text-slate-600 dark:text-slate-300">
                        <p>
                            Remove <strong>{agent.hostname}</strong> from the device list?
                        </p>
                        <ul className="list-disc pl-5 space-y-1 text-xs text-slate-500 dark:text-slate-400">
                            <li>Its alerts, events and command history are <strong>kept</strong> for investigations.</li>
                            <li>This does <strong>not</strong> uninstall the agent. Uninstall it first (remotely, or with an offline uninstall token) — a device whose agent is still connected cannot be removed.</li>
                            <li>If the agent is reinstalled on this machine later, the device returns with its history.</li>
                        </ul>
                    </div>
                </Modal>

                {/* Modern Tab Bar */}
                <div className="bg-white/95 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 backdrop-blur-md rounded-2xl p-1.5 shadow-sm flex flex-wrap gap-1 overflow-x-auto">
                    {TAB_LABELS.map(({ id, label, icon: Icon }) => (
                        <button
                            key={id}
                            type="button"
                            onClick={() => setTabAndUrl(id)}
                            className={`flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-xl transition-all duration-200 whitespace-nowrap ${tab === id
                                    ? 'bg-gradient-to-r from-cyan-500 to-indigo-600 text-white shadow-md shadow-cyan-500/20'
                                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800'
                                }`}
                        >
                            <Icon className="w-3.5 h-3.5" />
                            {label}
                        </button>
                    ))}
                </div>

                {/* Tab Content */}
                <div className="bg-white/95 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 backdrop-blur-md rounded-2xl p-5 sm:p-6 shadow-sm min-h-[400px]">
                    {tab === 'overview' && (
                        <OverviewTab
                            agent={agent}
                            eff={eff}
                            riskRow={riskRow}
                            cmds={cmdPage?.data || []}
                            overviewAlerts={overviewAlerts?.alerts ?? []}
                            overviewAlertsLoading={overviewAlertsLoading}
                            cmEvents={eventsPayload?.data || []}
                        />
                    )}

                    {tab === 'incident' && (
                        <IncidentTab
                            agent={agent}
                            onUnIsolate={() => {
                                setCmdType('restore_network');
                                setTab('response');
                            }}
                        />
                    )}

                    {tab === 'response' && canViewResp && (
                        <ResponseTab
                            agent={agent}
                            agentId={agentId}
                            cmds={cmdPage?.data || []}
                            cmdsLoading={cmdsLoading}
                            cmdType={cmdType}
                            setCmdType={setCmdType}
                            fields={fields}
                            setFields={setFields}
                            canExec={canExec}
                            execMutation={execMutation}
                            onSubmit={submitCommand}
                        />
                    )}

                    {tab === 'response' && !canViewResp && (
                        <div className="flex flex-col items-center justify-center py-16 text-center">
                            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4">
                                <Terminal className="w-8 h-8 text-slate-400" />
                            </div>
                            <h3 className="text-lg font-bold text-slate-800 dark:text-slate-200 mb-2">Access Required</h3>
                            <p className="text-sm text-slate-500 max-w-md">You need command execution permissions to access this section.</p>
                        </div>
                    )}

                    {tab === 'quarantine' && canViewResp && (
                        <QuarantineTab
                            items={quarantineData?.items || []}
                            loading={qLoading}
                            canExec={canExec}
                            onDecision={(id, d) => qDecisionMutation.mutate({ entryId: id, decision: d })}
                            busy={qDecisionMutation.isPending}
                            online={eff === 'online' || eff === 'degraded'}
                        />
                    )}

                    {tab === 'quarantine' && !canViewResp && (
                        <div className="flex flex-col items-center justify-center py-16 text-center">
                            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4">
                                <Shield className="w-8 h-8 text-slate-400" />
                            </div>
                            <h3 className="text-lg font-bold text-slate-800 dark:text-slate-200 mb-2">Access Required</h3>
                            <p className="text-sm text-slate-500 max-w-md">You need security permissions to view quarantined items.</p>
                        </div>
                    )}

                    {tab === 'activity' && (
                        <ActivityTab
                            events={eventsPayload?.data || []}
                            alerts={alertsForAgent?.alerts || []}
                            alertsLoading={alertsLoading}
                            canViewAlerts={canViewAlerts}
                            agentId={agentId}
                        />
                    )}

                    {tab === 'forensics' && canViewResp && (
                        <ForensicsTab agentId={agent.id} />
                    )}

                    {tab === 'forensics' && !canViewResp && (
                        <div className="flex flex-col items-center justify-center py-16 text-center">
                            <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4">
                                <FileText className="w-8 h-8 text-slate-400" />
                            </div>
                            <h3 className="text-lg font-bold text-slate-800 dark:text-slate-200 mb-2">Access Required</h3>
                            <p className="text-sm text-slate-500 max-w-md">You need forensics permissions to view collection data.</p>
                        </div>
                    )}

                    {tab === 'auto-proc' &&
                        (canViewResp ? (
                            <AutoProcTerminationTab agentId={agentId} canViewAlerts={canViewAlerts} canExec={canExec} />
                        ) : (
                            <div className="flex flex-col items-center justify-center py-16 text-center">
                                <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4">
                                    <ShieldAlert className="w-8 h-8 text-slate-400" />
                                </div>
                                <h3 className="text-lg font-bold text-slate-800 dark:text-slate-200 mb-2">Access Required</h3>
                                <p className="text-sm text-slate-500 max-w-md">
                                    You need security permissions to view auto-response termination events.
                                </p>
                            </div>
                        ))}

                    {tab === 'configuration' && <ConfigurationTab agent={agent} canExec={canExec} />}

                    {tab === 'software' && <SoftwareInventoryAgentTab agentId={agentId} />}
                </div>
            </div>

            <Modal
                isOpen={destructiveOpen}
                onClose={() => { setDestructiveOpen(false); setPendingDestructive(null); setOfflineToken(null); }}
                title="Confirm destructive action"
                footer={
                    <div className="flex justify-end gap-2">
                        <button type="button" className="btn btn-secondary" onClick={() => { setDestructiveOpen(false); setPendingDestructive(null); setOfflineToken(null); }}>
                            {offlineToken ? 'Close' : 'Cancel'}
                        </button>
                        <button type="button" className="btn bg-rose-600 hover:bg-rose-700 text-white" onClick={confirmDestructive}>
                            Confirm
                        </button>
                    </div>
                }
            >
                <p className="text-sm text-slate-600 dark:text-slate-300">
                    You are about to send <strong>{pendingDestructive}</strong> to <strong>{agent.hostname}</strong>.
                    This can disrupt the user session. Continue?
                </p>

                {pendingDestructive === 'uninstall_agent' && (
                    <div className="mt-4 border-t border-slate-200 dark:border-slate-700 pt-4">
                        <p className="text-sm font-medium text-slate-700 dark:text-slate-200">
                            Device offline, or won't accept the command?
                        </p>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                            Generate a signed, single-device uninstall token. Run it on the endpoint to remove
                            the agent even while it is disconnected. The token is bound to this device and expires shortly.
                        </p>
                        {!offlineToken ? (
                            <button
                                type="button"
                                className="btn btn-secondary mt-3"
                                disabled={offlineTokenMutation.isPending}
                                onClick={() => offlineTokenMutation.mutate()}
                            >
                                {offlineTokenMutation.isPending ? 'Generating…' : 'Generate offline uninstall token'}
                            </button>
                        ) : (
                            <div className="mt-3 space-y-3">
                                <div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs font-medium text-slate-600 dark:text-slate-300">Uninstall token (shown once)</span>
                                        <button
                                            type="button"
                                            className="text-xs text-primary-600 hover:underline"
                                            onClick={() => { navigator.clipboard.writeText(offlineToken.token); showToast('Token copied', 'success'); }}
                                        >
                                            Copy token
                                        </button>
                                    </div>
                                    <textarea
                                        readOnly
                                        className="input w-full font-mono text-[11px] mt-1 h-20 break-all"
                                        value={offlineToken.token}
                                        onFocus={(e) => e.currentTarget.select()}
                                    />
                                    <p className="text-[11px] text-slate-500 mt-1">
                                        Expires: {new Date(offlineToken.expires_at).toLocaleString()}
                                    </p>
                                </div>
                                <div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs font-medium text-slate-600 dark:text-slate-300">Run on the endpoint (elevated PowerShell)</span>
                                        <button
                                            type="button"
                                            className="text-xs text-primary-600 hover:underline"
                                            onClick={() => { navigator.clipboard.writeText(`echo '${offlineToken.token}' | .\\edr-agent.exe -uninstall -token-stdin`); showToast('Command copied', 'success'); }}
                                        >
                                            Copy command
                                        </button>
                                    </div>
                                    <pre className="input w-full font-mono text-[11px] mt-1 whitespace-pre-wrap break-all">{`echo '${offlineToken.token}' | .\\edr-agent.exe -uninstall -token-stdin`}</pre>
                                    <p className="text-[11px] text-slate-500 mt-1">
                                        Use the same <code>edr-agent.exe</code> you downloaded for this server. Only agents built with offline-uninstall support accept this token.
                                    </p>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </Modal>
        </div>
    );
}

const CRIT_CONFIG: Record<string, { label: string; badge: string }> = {
    critical: { label: 'Critical', badge: 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/30' },
    high: { label: 'High', badge: 'bg-orange-500/10 text-orange-700 dark:text-orange-300 border-orange-500/30' },
    medium: { label: 'Medium', badge: 'bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-500/30' },
    low: { label: 'Low', badge: 'bg-slate-500/10 text-slate-600 dark:text-slate-300 border-slate-500/20' },
};

function OverviewTab({
    agent,
    eff,
    riskRow,
    cmds,
    overviewAlerts,
    overviewAlertsLoading,
    cmEvents,
}: {
    agent: Agent;
    eff: string;
    riskRow?: EndpointRiskSummary;
    cmds: CommandListItem[];
    overviewAlerts: Alert[];
    overviewAlertsLoading: boolean;
    cmEvents: CmEventSummary[];
}) {
    const queryClient = useQueryClient();
    const { showToast } = useToast();
    const canManage = authApi.canExecuteCommands();

    const currentCrit = (agent.criticality || 'medium') as string;
    const [critEdit, setCritEdit] = useState(false);
    const [pendingCrit, setPendingCrit] = useState(currentCrit);
    const [buEdit, setBuEdit] = useState(false);
    const [pendingBU, setPendingBU] = useState(agent.business_unit || 'unknown');
    const [envEdit, setEnvEdit] = useState(false);
    const [pendingEnv, setPendingEnv] = useState(agent.environment || 'unknown');

    const displayBU = (!agent.business_unit || agent.business_unit === 'unknown') ? 'Unknown' : agent.business_unit;
    const displayEnv = (!agent.environment || agent.environment === 'unknown') ? 'Unknown'
        : agent.environment.charAt(0).toUpperCase() + agent.environment.slice(1);
    const displayProfile = agent.tags?.profile || agent.metadata?.profile || '';
    const displayLastUser = agent.metadata?.logged_in_user || agent.tags?.logged_in_user || '';

    const bCtxMutation = useMutation({
        mutationFn: (d: Parameters<typeof agentsApi.patchBusinessContext>[1]) =>
            agentsApi.patchBusinessContext(agent.id, d),
        onSuccess: (_, vars) => {
            const field = vars.criticality ? 'Criticality'
                : vars.business_unit !== undefined ? 'Business unit'
                    : 'Environment';
            showToast(`${field} updated`, 'success');
            queryClient.invalidateQueries({ queryKey: ['agent', agent.id] });
            setCritEdit(false); setBuEdit(false); setEnvEdit(false);
        },
        onError: (e: Error) => showToast(e.message || 'Update failed', 'error'),
    });

    const tagEntries = Object.entries(agent.tags || {});
    const eventsCollected = agent.events_collected || agent.events_delivered || 0;
    const eventsDropped = agent.events_dropped || 0;
    const eventsDelivered = agent.events_delivered || 0;
    const dropRate = eventsCollected > 0 ? (eventsDropped / eventsCollected) * 100 : 0;
    const deliveryRate = eventsCollected > 0 ? (eventsDelivered / eventsCollected) * 100 : 0;
    const certExpiry = agent.cert_expires_at ? new Date(agent.cert_expires_at) : null;
    const certDaysLeft = certExpiry ? Math.ceil((certExpiry.getTime() - Date.now()) / 86400000) : null;
    const cpuPct = agent.cpu_usage || 0;
    const memPct = agent.memory_mb && agent.memory_used_mb ? Math.min(100, (agent.memory_used_mb / agent.memory_mb) * 100) : 0;

    const sysmonCmd = useMemo(() => {
        const list = cmds || [];
        return list.find((c) => c.command_type === 'enable_sysmon' || c.command_type === 'disable_sysmon');
    }, [cmds]);

    const sysmonObserved = useMemo(() => {
        const list = cmds || [];
        // If we have a successful collection request that explicitly asked for sysmon logs,
        // we can treat Sysmon as "observed" even if it was installed/enabled manually.
        return list.find((c) => {
            if (c.status !== 'completed') return false;
            if (c.command_type !== 'collect_logs' && c.command_type !== 'collect_forensics') return false;
            const lt = String((c.parameters as any)?.log_types || (c.parameters as any)?.types || '').toLowerCase();
            return lt.includes('sysmon');
        });
    }, [cmds]);

    const sysmonStatus = (() => {
        // Primary source of truth: live heartbeat data from the agent
        if (agent.sysmon_installed !== undefined || agent.sysmon_running !== undefined) {
            if (agent.sysmon_running) return { label: 'Running', tone: 'ok' as const };
            if (agent.sysmon_installed) return { label: 'Installed (stopped)', tone: 'warn' as const };
            return { label: 'Not installed', tone: 'bad' as const };
        }
        // Fallback: infer from command history when heartbeat fields are absent
        if (!sysmonCmd) {
            if (sysmonObserved) return { label: 'Observed', tone: 'ok' as const };
            return { label: 'Unknown', tone: 'muted' as const };
        }
        const ok = sysmonCmd.status === 'completed';
        if (sysmonCmd.command_type === 'enable_sysmon') return { label: ok ? 'Enabled' : 'Enable failed', tone: ok ? ('ok' as const) : ('bad' as const) };
        return { label: ok ? 'Disabled' : 'Disable failed', tone: ok ? ('warn' as const) : ('bad' as const) };
    })();

    return (
        <div className="space-y-6">
            {/* Status Cards Row */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-4">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Status</div>
                    <div className={`text-lg font-bold mt-1.5 capitalize ${eff === 'online' ? 'text-emerald-600 dark:text-emerald-400' : eff === 'offline' ? 'text-slate-500' : 'text-amber-600 dark:text-amber-400'}`}>{eff}</div>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-4">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Health Score</div>
                    <div className="text-lg font-bold text-slate-900 dark:text-white mt-1.5">{Math.round(agent.health_score ?? 0)}%</div>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-4">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Active Alerts</div>
                    <div className="text-lg font-bold text-slate-900 dark:text-white mt-1.5">{riskRow?.open_count ?? '—'}</div>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-4">
                    <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Network Isolation</div>
                    <div className={`text-lg font-bold mt-1.5 ${agent.is_isolated ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{agent.is_isolated ? 'Isolated' : 'Normal'}</div>
                </div>
            </div>

            {/* Device Information + Sysmon - Two Column */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Device Info Card */}
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Server className="w-4 h-4 text-cyan-500" /> Device Information
                    </h3>
                    <dl className="text-sm space-y-2.5">
                        <div className="flex justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-700/40">
                            <dt className="text-slate-500">Agent ID</dt>
                            <dd className="flex items-center gap-1.5">
                                <span className="font-mono text-[11px] text-slate-600 dark:text-slate-300">{agent.id.slice(0, 18)}…</span>
                                <button
                                    type="button"
                                    title="Copy full ID"
                                    onClick={() => { navigator.clipboard.writeText(agent.id); }}
                                    className="p-0.5 text-slate-400 hover:text-cyan-500 transition-colors"
                                >
                                    <Tag className="w-3 h-3" />
                                </button>
                            </dd>
                        </div>
                        <div className="flex justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-700/40"><dt className="text-slate-500">Operating System</dt><dd className="text-right font-medium text-slate-800 dark:text-slate-200">{[agent.os_type, agent.os_version].filter(Boolean).join(' ')}</dd></div>
                        <div className="flex justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-700/40"><dt className="text-slate-500">Agent Version</dt><dd className="text-right font-medium text-slate-800 dark:text-slate-200">v{agent.agent_version || '—'}</dd></div>
                        <div className="flex justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-700/40"><dt className="text-slate-500">Last Seen</dt><dd className="text-right font-medium text-slate-800 dark:text-slate-200">{new Date(agent.last_seen).toLocaleString()}</dd></div>
                        <div className="flex justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-700/40"><dt className="text-slate-500">IP Addresses</dt><dd className="text-right font-medium text-slate-800 dark:text-slate-200 break-all">{(agent.ip_addresses || []).join(', ') || '—'}</dd></div>
                        <div className="flex justify-between gap-4 py-1 border-b border-slate-100 dark:border-slate-700/40"><dt className="text-slate-500">Install Date</dt><dd className="text-right font-medium text-slate-800 dark:text-slate-200">{agent.installed_date ? new Date(agent.installed_date).toLocaleDateString() : '—'}</dd></div>
                        {tagEntries.length > 0 && <div className="flex justify-between gap-4 py-1"><dt className="text-slate-500">Tags</dt><dd className="text-right text-xs font-mono text-slate-600 dark:text-slate-300 break-all">{tagEntries.map(([k, v]) => `${k}=${v}`).join(', ')}</dd></div>}
                    </dl>
                </div>
                {/* Sysmon Card */}
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Settings className="w-4 h-4 text-indigo-500" /> System Monitor (Sysmon)
                    </h3>
                    <div className="text-sm space-y-2">
                        {/* Status badge */}
                        <div className="flex items-center justify-between gap-3">
                            <span className="text-slate-500">Status</span>
                            <span
                                className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${sysmonStatus.tone === 'ok'
                                        ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-500/20'
                                        : sysmonStatus.tone === 'warn'
                                            ? 'bg-amber-500/10 text-amber-800 dark:text-amber-300 border-amber-500/20'
                                            : sysmonStatus.tone === 'bad'
                                                ? 'bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-500/20'
                                                : 'bg-slate-500/10 text-slate-700 dark:text-slate-300 border-slate-500/20'
                                    }`}
                            >
                                {sysmonStatus.label}
                            </span>
                        </div>

                        {/* Live heartbeat rows — shown whenever the agent reports them */}
                        {(agent.sysmon_installed !== undefined || agent.sysmon_running !== undefined) ? (
                            <dl className="space-y-1 pt-1">
                                <div className="flex justify-between gap-3 py-1 border-b border-slate-100 dark:border-slate-700/40">
                                    <dt className="text-xs text-slate-500">Installed</dt>
                                    <dd className="text-xs font-semibold">
                                        {agent.sysmon_installed
                                            ? <span className="text-emerald-600 dark:text-emerald-400">Yes</span>
                                            : <span className="text-rose-600 dark:text-rose-400">No</span>}
                                    </dd>
                                </div>
                                <div className="flex justify-between gap-3 py-1">
                                    <dt className="text-xs text-slate-500">Service running</dt>
                                    <dd className="text-xs font-semibold">
                                        {agent.sysmon_running
                                            ? <span className="text-emerald-600 dark:text-emerald-400">Yes</span>
                                            : <span className="text-slate-500 dark:text-slate-400">No</span>}
                                    </dd>
                                </div>
                            </dl>
                        ) : (
                            <div className="text-xs text-slate-500">
                                Monitoring: Windows System Monitor (Sysmon)
                            </div>
                        )}

                        {/* Command history detail */}
                        {sysmonCmd ? (
                            <div className="text-xs text-slate-500 space-y-1 pt-1">
                                <div>
                                    Last action: <code>{sysmonCmd.command_type}</code> · {new Date(sysmonCmd.issued_at).toLocaleString()}
                                </div>
                                {sysmonCmd.result?.output ? (
                                    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-900/40 p-2 text-[11px] text-slate-700 dark:text-slate-200 whitespace-pre-wrap">
                                        {String((sysmonCmd.result as any).output)}
                                    </div>
                                ) : null}
                            </div>
                        ) : sysmonObserved ? (
                            <div className="text-xs text-slate-500 space-y-1 pt-1">
                                <div>
                                    Observed via <code>{sysmonObserved.command_type}</code> · {new Date(sysmonObserved.issued_at).toLocaleString()}
                                </div>
                            </div>
                        ) : agent.sysmon_installed === undefined ? (
                            <p className="text-slate-500 text-xs pt-1">No Sysmon actions recorded yet.</p>
                        ) : null}
                    </div>
                </div>
            </div>

            {/* Asset Context Card */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <Shield className="w-4 h-4 text-violet-500" /> Asset Context
                </h3>
                <dl className="text-sm space-y-3">
                    {/* Criticality — always shown, editable */}
                    <div className="flex items-center justify-between gap-4">
                        <dt className="text-slate-500 shrink-0">Criticality</dt>
                        <dd className="flex items-center gap-2">
                            {critEdit ? (
                                <>
                                    <select
                                        autoFocus
                                        value={pendingCrit}
                                        onChange={e => setPendingCrit(e.target.value)}
                                        className="text-xs rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1 focus:outline-none focus:ring-2 focus:ring-violet-500/40"
                                    >
                                        {['low', 'medium', 'high', 'critical'].map(v => (
                                            <option key={v} value={v}>{v.charAt(0).toUpperCase() + v.slice(1)}</option>
                                        ))}
                                    </select>
                                    <button onClick={() => bCtxMutation.mutate({ criticality: pendingCrit as 'low' | 'medium' | 'high' | 'critical' })} disabled={bCtxMutation.isPending}
                                        className="p-1 text-emerald-600 hover:text-emerald-700 disabled:opacity-50"><Check className="w-3.5 h-3.5" /></button>
                                    <button onClick={() => { setCritEdit(false); setPendingCrit(currentCrit); }}
                                        className="p-1 text-slate-400 hover:text-slate-600"><XIcon className="w-3.5 h-3.5" /></button>
                                </>
                            ) : (
                                <>
                                    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${(CRIT_CONFIG[currentCrit] || CRIT_CONFIG.medium).badge}`}>
                                        {(CRIT_CONFIG[currentCrit] || CRIT_CONFIG.medium).label}
                                    </span>
                                    {canManage && (
                                        <button onClick={() => { setPendingCrit(currentCrit); setCritEdit(true); }}
                                            className="p-1 text-slate-300 hover:text-slate-500 dark:hover:text-slate-200 transition-colors"
                                            title="Edit criticality">
                                            <Pencil className="w-3 h-3" />
                                        </button>
                                    )}
                                </>
                            )}
                        </dd>
                    </div>

                    {/* Business Unit — always shown, editable (datalist: Finance / Engineering / HR or free text) */}
                    <div className="flex items-center justify-between gap-4 py-1 border-t border-slate-100 dark:border-slate-700/40">
                        <dt className="text-slate-500 flex items-center gap-1 shrink-0"><Building2 className="w-3.5 h-3.5" /> Business Unit</dt>
                        <dd className="flex items-center gap-2">
                            {buEdit ? (
                                <>
                                    <input
                                        autoFocus
                                        list="bu-options"
                                        value={pendingBU === 'unknown' ? '' : pendingBU}
                                        onChange={e => setPendingBU(e.target.value.trim() || 'unknown')}
                                        placeholder="Finance, Engineering, HR…"
                                        className="text-xs rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1 w-44 focus:outline-none focus:ring-2 focus:ring-violet-500/40"
                                    />
                                    <datalist id="bu-options">
                                        <option value="Finance" />
                                        <option value="Engineering" />
                                        <option value="HR" />
                                    </datalist>
                                    <button onClick={() => bCtxMutation.mutate({ business_unit: pendingBU })} disabled={bCtxMutation.isPending}
                                        className="p-1 text-emerald-600 hover:text-emerald-700 disabled:opacity-50"><Check className="w-3.5 h-3.5" /></button>
                                    <button onClick={() => { setBuEdit(false); setPendingBU(agent.business_unit || 'unknown'); }}
                                        className="p-1 text-slate-400 hover:text-slate-600"><XIcon className="w-3.5 h-3.5" /></button>
                                </>
                            ) : (
                                <>
                                    <span className={`font-medium ${displayBU === 'Unknown' ? 'text-slate-400 italic text-xs' : 'text-slate-800 dark:text-slate-200'}`}>{displayBU}</span>
                                    {canManage && (
                                        <button onClick={() => { setPendingBU(agent.business_unit || 'unknown'); setBuEdit(true); }}
                                            className="p-1 text-slate-300 hover:text-slate-500 dark:hover:text-slate-200 transition-colors"
                                            title="Edit business unit">
                                            <Pencil className="w-3 h-3" />
                                        </button>
                                    )}
                                </>
                            )}
                        </dd>
                    </div>

                    {/* Environment — always shown, select: production / staging / development */}
                    <div className="flex items-center justify-between gap-4 py-1 border-t border-slate-100 dark:border-slate-700/40">
                        <dt className="text-slate-500 flex items-center gap-1 shrink-0"><Globe className="w-3.5 h-3.5" /> Environment</dt>
                        <dd className="flex items-center gap-2">
                            {envEdit ? (
                                <>
                                    <select
                                        autoFocus
                                        value={pendingEnv}
                                        onChange={e => setPendingEnv(e.target.value)}
                                        className="text-xs rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1 focus:outline-none focus:ring-2 focus:ring-violet-500/40"
                                    >
                                        <option value="unknown">Unknown</option>
                                        <option value="production">Production</option>
                                        <option value="staging">Staging</option>
                                        <option value="development">Development</option>
                                    </select>
                                    <button onClick={() => bCtxMutation.mutate({ environment: pendingEnv })} disabled={bCtxMutation.isPending}
                                        className="p-1 text-emerald-600 hover:text-emerald-700 disabled:opacity-50"><Check className="w-3.5 h-3.5" /></button>
                                    <button onClick={() => { setEnvEdit(false); setPendingEnv(agent.environment || 'unknown'); }}
                                        className="p-1 text-slate-400 hover:text-slate-600"><XIcon className="w-3.5 h-3.5" /></button>
                                </>
                            ) : (
                                <>
                                    <span className={`font-medium ${displayEnv === 'Unknown' ? 'text-slate-400 italic text-xs' : 'text-slate-800 dark:text-slate-200 capitalize'}`}>{displayEnv}</span>
                                    {canManage && (
                                        <button onClick={() => { setPendingEnv(agent.environment || 'unknown'); setEnvEdit(true); }}
                                            className="p-1 text-slate-300 hover:text-slate-500 dark:hover:text-slate-200 transition-colors"
                                            title="Edit environment">
                                            <Pencil className="w-3 h-3" />
                                        </button>
                                    )}
                                </>
                            )}
                        </dd>
                    </div>

                    {/* Profile — read-only, populated automatically by the agent */}
                    {displayProfile && (
                        <div className="flex items-center justify-between gap-4 py-1 border-t border-slate-100 dark:border-slate-700/40">
                            <dt className="text-slate-500 flex items-center gap-1 shrink-0"><Server className="w-3.5 h-3.5" /> Profile</dt>
                            <dd>
                                <span className="font-medium text-slate-800 dark:text-slate-200">{displayProfile}</span>
                            </dd>
                        </div>
                    )}


                    {/* Last Logged In User — read-only, populated automatically by the agent */}
                    {displayLastUser && (
                        <div className="flex items-center justify-between gap-4 py-1 border-t border-slate-100 dark:border-slate-700/40">
                            <dt className="text-slate-500 flex items-center gap-1 shrink-0"><Activity className="w-3.5 h-3.5" /> Last Logged In User</dt>
                            <dd>
                                <span className="font-medium text-slate-800 dark:text-slate-200 font-mono text-xs">{displayLastUser}</span>
                            </dd>
                        </div>
                    )}
                </dl>
            </div>

            {/* Network, Health, Resources - Three Column */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                    <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                        <Network className="w-4 h-4 text-sky-500" /> Connectivity & Certificate
                    </div>
                    <div className="text-sm space-y-1.5">
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Heartbeat age</span><span>{formatRelativeTime(agent.last_seen)}</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">IPs</span><span className="text-right break-all">{(agent.ip_addresses || []).join(', ') || '—'}</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">mTLS</span><span className={certDaysLeft != null && certDaysLeft <= 14 ? 'text-rose-500 font-semibold' : ''}>{certDaysLeft != null ? (certDaysLeft > 0 ? `Valid (${certDaysLeft}d)` : 'Expired') : '—'}</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Expiry</span><span>{certExpiry ? certExpiry.toLocaleDateString() : '—'}</span></div>
                        {agent.current_cert_id && (
                            <div className="flex justify-between gap-2"><span className="text-slate-500">Cert ID</span><span className="font-mono text-[10px] text-slate-400 truncate max-w-[120px]" title={agent.current_cert_id}>{agent.current_cert_id.slice(0, 12)}…</span></div>
                        )}
                    </div>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                    <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                        <HardDrive className="w-4 h-4 text-emerald-500" /> Event Delivery
                    </div>
                    <div className="text-sm space-y-1.5">
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Events collected</span><span className="font-mono text-xs">{eventsCollected.toLocaleString()}</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Delivered</span><span className="font-mono text-xs">{eventsDelivered.toLocaleString()}</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Dropped</span><span className="font-mono text-xs">{eventsDropped.toLocaleString()}</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Drop rate</span><span className="font-mono text-xs">{dropRate.toFixed(1)}%</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Delivery</span><span className="font-mono text-xs">{deliveryRate.toFixed(1)}%</span></div>
                    </div>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                    <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                        <Activity className="w-4 h-4 text-violet-500" /> Resource Usage
                    </div>
                    <div className="text-sm space-y-1.5">
                        <div className="flex justify-between gap-2"><span className="text-slate-500">CPU</span><span className="font-mono text-xs">{cpuPct.toFixed(1)}%{agent.cpu_count ? ` · ${agent.cpu_count} cores` : ''}</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Memory</span><span className="font-mono text-xs">{agent.memory_used_mb || 0} / {agent.memory_mb || '—'} MB ({memPct.toFixed(0)}%)</span></div>
                        <div className="flex justify-between gap-2"><span className="text-slate-500">Queue depth</span><span className="font-mono text-xs">{(agent.queue_depth || 0).toLocaleString()}</span></div>
                    </div>
                </div>
            </div>

            {/* Recent Alerts */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <Shield className="w-4 h-4 text-rose-500" /> Recent Security Alerts
                </h3>
                {overviewAlertsLoading ? (
                    <Loader2 className="w-6 h-6 animate-spin text-cyan-500" />
                ) : overviewAlerts.length === 0 ? (
                    <p className="text-sm text-slate-500">No recent alerts detected for this device.</p>
                ) : (
                    <ul className="space-y-2">
                        {overviewAlerts.map((a) => (
                            <li key={a.id} className="text-sm border border-slate-200 dark:border-slate-700 rounded-lg p-2 flex justify-between gap-2">
                                <span className="font-medium text-slate-900 dark:text-slate-100 truncate">{a.rule_title || a.rule_id || 'Alert'}</span>
                                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${a.severity === 'critical' ? 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400' : a.severity === 'high' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' : a.severity === 'medium' ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'}`}>{a.severity || '—'}</span>
                            </li>
                        ))}
                    </ul>
                )}
            </div>

            {/* Recent Telemetry */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                    <Network className="w-4 h-4 text-cyan-500" /> Recent Events
                </h3>
                {cmEvents.length === 0 ? (
                    <p className="text-sm text-slate-500">
                        No recent events available. Events will appear here once the agent starts reporting telemetry data.
                    </p>
                ) : (
                    <ul className="text-sm space-y-1">
                        {cmEvents.slice(0, 5).map((e) => (
                            <li key={e.id} className="flex flex-wrap gap-x-2 border border-slate-100 dark:border-slate-800 rounded px-2 py-1">
                                <span className="font-mono text-xs text-cyan-700 dark:text-cyan-300">{e.event_type}</span>
                                <span className="text-slate-600 dark:text-slate-400">{e.summary}</span>
                                <span className="text-xs text-slate-400 ml-auto">{new Date(e.timestamp).toLocaleString()}</span>
                            </li>
                        ))}
                    </ul>
                )}
            </div>

            {/* Commands Quick Access */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white dark:bg-slate-800/60 p-5">
                <div className="flex items-center justify-between gap-3">
                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Command Center</h3>
                    <Link
                        to={`/management/devices/${encodeURIComponent(agent.id)}?tab=response`}
                        className="text-xs font-semibold text-cyan-700 dark:text-cyan-300 hover:underline"
                    >
                        Open Response tab
                    </Link>
                </div>
                <p className="text-sm text-slate-500 mt-2">
                    Use the <strong>Response</strong> tab to execute commands and view full command history.
                </p>
            </div>
        </div>
    );
}

/** First log channel for Forensics API (lowercase), derived from collection summary. */
function primaryLogTypeFromCollectionField(logTypesField: string): string {
    const s = (logTypesField || '').trim();
    const lower = s.toLowerCase();
    if (!s) return 'security';
    if (lower.includes('sysmon')) return 'sysmon';
    if (lower.includes('powershell')) return 'powershell';
    const first = s.split(',')[0].trim().toLowerCase();
    return first || 'security';
}

function ForensicsTab({ agentId }: { agentId: string }) {
    const [searchParams, setSearchParams] = useSearchParams();
    const { showToast } = useToast();

    const preselectedCommandId = searchParams.get('command_id') || '';
    const [selectedCommandId, setSelectedCommandId] = useState<string>(preselectedCommandId);
    const [logType, setLogType] = useState<string>('security');
    const lastLogTypeSyncCommandRef = useRef<string | null>(null);
    const [cursor, setCursor] = useState<number | undefined>(undefined);
    const [rows, setRows] = useState<ForensicEvent[]>([]);
    const [rawOpen, setRawOpen] = useState(false);
    const [rawEvent, setRawEvent] = useState<ForensicEvent | null>(null);
    const [forPage, setForPage] = useState(1);
    const FOR_PAGE_SIZE = 15;

    const collectionsQ = useQuery({
        queryKey: ['forensics', 'collections', agentId],
        queryFn: () => agentsApi.getForensicCollections(agentId, { limit: 25 }),
        refetchInterval: 30000,
    });

    const collections: ForensicCollection[] = (collectionsQ.data as any)?.data || [];

    useEffect(() => {
        lastLogTypeSyncCommandRef.current = null;
    }, [agentId]);

    useEffect(() => {
        if (!selectedCommandId) {
            const first = collections[0]?.command_id;
            if (first) setSelectedCommandId(first);
        }
    }, [collections, selectedCommandId]);

    useEffect(() => {
        // When the user picks another collection (View / dropdown), align log type with that run’s channels.
        if (!selectedCommandId) return;
        if (lastLogTypeSyncCommandRef.current === selectedCommandId) return;
        const sel = collections.find((c) => c.command_id === selectedCommandId);
        if (!sel) return;
        lastLogTypeSyncCommandRef.current = selectedCommandId;
        setLogType(primaryLogTypeFromCollectionField(sel.log_types || ''));
    }, [collections, selectedCommandId]);

    useEffect(() => {
        // Keep URL in sync so Command Center can deep-link.
        if (!selectedCommandId) return;
        const next = new URLSearchParams(searchParams);
        next.set('tab', 'forensics');
        next.set('command_id', selectedCommandId);
        setSearchParams(next, { replace: true });
        // Reset paging on selection changes.
        setCursor(undefined);
        setRows([]);
    }, [selectedCommandId, searchParams, setSearchParams]);

    const eventsQ = useQuery({
        queryKey: ['forensics', 'events', agentId, selectedCommandId, logType, cursor],
        enabled: Boolean(selectedCommandId && logType),
        queryFn: () =>
            agentsApi.getForensicEvents(agentId, selectedCommandId, {
                log_type: logType,
                limit: 100,
                cursor,
            }),
    });

    useEffect(() => {
        const payload: any = eventsQ.data;
        const data: ForensicEvent[] = payload?.data || [];
        if (!eventsQ.isSuccess) return;
        if (!cursor) setRows(data);
        else setRows((prev) => [...prev, ...data]);
    }, [eventsQ.data, eventsQ.isSuccess]);

    const nextCursor: number | undefined = (eventsQ.data as any)?.next_cursor;

    const selected = collections.find((c) => c.command_id === selectedCommandId);
    const summaryCounts = selected?.summary?.counts || selected?.summary?.output_text || '';
    const warnings = selected?.summary?.warnings as any[] | undefined;

    return (
        <div className="space-y-4 animate-slide-up-fade">
            <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">Forensic Logs</h2>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                    Browse security logs collected from this endpoint. Select a collection to view its events.
                </p>
            </div>

            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-900/40 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
                    <div className="text-sm font-semibold text-slate-700 dark:text-slate-200">Recent collections</div>
                    {collectionsQ.isLoading && <span className="text-xs text-slate-500">Loading…</span>}
                </div>
                <div className="overflow-x-auto">
                    <table className="min-w-full text-sm">
                        <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300">
                            <tr>
                                <th className="text-left px-4 py-2">Issued</th>
                                <th className="text-left px-4 py-2">Time range</th>
                                <th className="text-left px-4 py-2">Log types</th>
                                <th className="text-left px-4 py-2">Summary</th>
                                <th className="text-right px-4 py-2">View</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                            {collections.map((c) => (
                                <tr key={c.command_id} className={c.command_id === selectedCommandId ? 'bg-cyan-50/60 dark:bg-cyan-500/10' : ''}>
                                    <td className="px-4 py-2 text-slate-700 dark:text-slate-200 whitespace-nowrap">
                                        {new Date(c.issued_at).toLocaleString()}
                                    </td>
                                    <td className="px-4 py-2 text-slate-600 dark:text-slate-300">{c.time_range || '—'}</td>
                                    <td className="px-4 py-2 font-mono text-xs text-slate-600 dark:text-slate-300">{c.log_types || '—'}</td>
                                    <td className="px-4 py-2 text-slate-600 dark:text-slate-300 truncate max-w-[28rem]" title={String(c.summary?.counts || '')}>
                                        {String(c.summary?.counts || '').slice(0, 140) || '—'}
                                    </td>
                                    <td className="px-4 py-2 text-right">
                                        <button
                                            type="button"
                                            className="px-2.5 py-1.5 text-xs font-semibold rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-800 dark:text-cyan-300 hover:bg-cyan-500/20"
                                            onClick={() => setSelectedCommandId(c.command_id)}
                                        >
                                            View
                                        </button>
                                    </td>
                                </tr>
                            ))}
                            {!collectionsQ.isLoading && collections.length === 0 && (
                                <tr>
                                    <td className="px-4 py-3 text-slate-500" colSpan={5}>
                                        No forensic collections yet. Run <strong>Collect logs</strong> from the Response tab.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            <div className="flex flex-col lg:flex-row gap-3 lg:items-end">
                <div className="flex-1">
                    <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Collection</label>
                    <select
                        value={selectedCommandId}
                        onChange={(e) => setSelectedCommandId(e.target.value)}
                        className="w-full bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm"
                    >
                        {collections.map((c) => (
                            <option key={c.command_id} value={c.command_id}>
                                {c.command_id.slice(0, 8)} — {new Date(c.issued_at).toLocaleString()}
                            </option>
                        ))}
                    </select>
                </div>
                <div className="w-full lg:w-64">
                    <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Log type</label>
                    <select
                        value={logType}
                        onChange={(e) => {
                            setLogType(e.target.value);
                            setCursor(undefined);
                            setRows([]);
                            setForPage(1);
                        }}
                        className="w-full bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-2 text-sm"
                    >
                        <option value="security">security</option>
                        <option value="system">system</option>
                        <option value="application">application</option>
                        <option value="powershell">powershell</option>
                        <option value="sysmon">sysmon</option>
                    </select>
                </div>
            </div>

            {summaryCounts && (
                <div className="text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/40 px-3 py-2 text-slate-700 dark:text-slate-200">
                    <div className="font-semibold">Summary</div>
                    <div className="mt-1 font-mono whitespace-pre-wrap break-words">{String(summaryCounts)}</div>
                    {warnings && warnings.length > 0 && (
                        <div className="mt-2 text-amber-700 dark:text-amber-300">
                            <div className="font-semibold">Warnings</div>
                            <div className="mt-1 font-mono whitespace-pre-wrap break-words">{JSON.stringify(warnings, null, 2)}</div>
                        </div>
                    )}
                </div>
            )}

            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-900/40 overflow-hidden">
                <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
                    <div className="text-sm font-semibold text-slate-700 dark:text-slate-200">
                        Events ({rows.length})
                    </div>
                    {eventsQ.isFetching && <span className="text-xs text-slate-500">Loading…</span>}
                </div>
                <div className="overflow-x-auto">
                    <table className="min-w-full text-sm">
                        <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-300">
                            <tr>
                                <th className="text-left px-4 py-2">Time</th>
                                <th className="text-left px-4 py-2">LogType</th>
                                <th className="text-left px-4 py-2">EventID</th>
                                <th className="text-left px-4 py-2">Level</th>
                                <th className="text-left px-4 py-2">Provider</th>
                                <th className="text-left px-4 py-2">Message</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                            {rows.slice((forPage - 1) * FOR_PAGE_SIZE, forPage * FOR_PAGE_SIZE).map((e) => (
                                <tr
                                    key={e.id}
                                    className="hover:bg-slate-50 dark:hover:bg-slate-800/40 cursor-pointer"
                                    onClick={() => { setRawEvent(e); setRawOpen(true); }}
                                >
                                    <td className="px-4 py-2 whitespace-nowrap text-slate-700 dark:text-slate-200">
                                        {e.timestamp ? new Date(e.timestamp).toLocaleString() : '—'}
                                    </td>
                                    <td className="px-4 py-2 font-mono text-xs text-slate-600 dark:text-slate-300">{e.log_type}</td>
                                    <td className="px-4 py-2 font-mono text-xs text-slate-600 dark:text-slate-300">{e.event_id || '—'}</td>
                                    <td className="px-4 py-2 text-slate-600 dark:text-slate-300">{e.level || '—'}</td>
                                    <td className="px-4 py-2 text-slate-600 dark:text-slate-300">{e.provider || '—'}</td>
                                    <td className="px-4 py-2 text-slate-600 dark:text-slate-300 truncate max-w-[36rem]" title={e.message || ''}>
                                        {e.message || '—'}
                                    </td>
                                </tr>
                            ))}
                            {eventsQ.isSuccess && rows.length === 0 && (
                                <tr>
                                    <td className="px-4 py-3 text-slate-500" colSpan={6}>
                                        No events stored for this log type.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
                <div className="px-4 py-3 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <button type="button" className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40" disabled={forPage <= 1} onClick={() => setForPage((p) => Math.max(1, p - 1))}>
                            <ChevronLeft className="w-4 h-4" /> Previous
                        </button>
                        <span className="text-xs text-slate-500">Page <span className="font-semibold text-slate-700 dark:text-slate-200">{forPage}</span> of {Math.max(1, Math.ceil(rows.length / FOR_PAGE_SIZE))}</span>
                        <button type="button" className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40" disabled={forPage >= Math.max(1, Math.ceil(rows.length / FOR_PAGE_SIZE))} onClick={() => setForPage((p) => Math.min(Math.max(1, Math.ceil(rows.length / FOR_PAGE_SIZE)), p + 1))}>
                            Next <ChevronRight className="w-4 h-4" />
                        </button>
                    </div>
                    <button
                        type="button"
                        disabled={!nextCursor || eventsQ.isFetching}
                        onClick={() => setCursor(nextCursor)}
                        className="px-3 py-2 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900/60 disabled:opacity-50"
                    >
                        Fetch more from server
                    </button>
                </div>
            </div>

            <Modal
                isOpen={rawOpen}
                onClose={() => { setRawOpen(false); setRawEvent(null); }}
                title="Event Details"
                footer={
                    <div className="flex justify-end gap-2">
                        <button
                            type="button"
                            className="btn btn-secondary px-4 py-2"
                            onClick={() => { setRawOpen(false); setRawEvent(null); }}
                        >
                            Close
                        </button>
                        <button
                            type="button"
                            className="btn bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 flex items-center gap-2"
                            onClick={async () => {
                                try {
                                    await navigator.clipboard.writeText(JSON.stringify(rawEvent?.raw ?? {}, null, 2));
                                    showToast('Copied raw JSON to clipboard', 'success');
                                } catch {
                                    showToast('Copy failed', 'error');
                                }
                            }}
                        >
                            Copy Payload
                        </button>
                    </div>
                }
            >
                <div className="flex flex-col items-center justify-center space-y-4 p-2 w-full max-w-4xl mx-auto">
                    {rawEvent && (
                        <div className="w-full grid grid-cols-2 gap-4 mb-2 text-sm">
                            <div className="p-3 bg-slate-50 dark:bg-slate-800/40 rounded-lg border border-slate-200 dark:border-slate-700">
                                <span className="block text-xs font-semibold text-slate-500 uppercase">Provider</span>
                                <span className="font-medium text-slate-800 dark:text-slate-200">{rawEvent.provider || '—'}</span>
                            </div>
                            <div className="p-3 bg-slate-50 dark:bg-slate-800/40 rounded-lg border border-slate-200 dark:border-slate-700">
                                <span className="block text-xs font-semibold text-slate-500 uppercase">Event ID</span>
                                <span className="font-mono text-slate-800 dark:text-slate-200">{rawEvent.event_id || '—'}</span>
                            </div>
                        </div>
                    )}
                    <div className="w-full bg-[#1e1e1e] rounded-xl overflow-hidden border border-slate-700 shadow-xl">
                        <div className="bg-[#2d2d2d] px-4 py-2 text-xs font-mono text-slate-400 flex items-center justify-between border-b border-slate-700">
                            <span>raw_payload.json</span>
                            <span>{JSON.stringify(rawEvent?.raw ?? {}).length} bytes</span>
                        </div>
                        <pre className="p-4 text-[#d4d4d4] font-mono text-xs whitespace-pre-wrap break-words max-h-[50vh] overflow-y-auto">
                            {JSON.stringify(rawEvent?.raw ?? {}, null, 2)}
                        </pre>
                    </div>
                </div>
            </Modal>
        </div>
    );
}

const DEFAULT_SYSMON_XML = `<!--
  Minimal Sysmon configuration for EDR Platform.
  This is intentionally conservative (low noise) and safe as a default.
  You can replace it with a stricter config later (e.g. SwiftOnSecurity).
-->
<Sysmon schemaversion="4.90">
  <HashAlgorithms>sha256</HashAlgorithms>
  <EventFiltering>
    <!-- Process Create -->
    <ProcessCreate onmatch="include" />
    <!-- Network Connect -->
    <NetworkConnect onmatch="include" />
    <!-- File Create Time -->
    <FileCreateTime onmatch="include" />
    <!-- Image Loaded -->
    <ImageLoad onmatch="include" />
    <!-- Create Remote Thread -->
    <CreateRemoteThread onmatch="include" />
    <!-- Registry events -->
    <RegistryEvent onmatch="include" />
    <!-- DNS Query -->
    <DnsQuery onmatch="include" />
    <!-- File create -->
    <FileCreate onmatch="include" />
    <!-- Process Terminate -->
    <ProcessTerminate onmatch="include" />
  </EventFiltering>
</Sysmon>`;

function ConfigurationTab({ agent, canExec }: { agent: Agent; canExec: boolean }) {
    const { showToast } = useToast();
    const canPushPolicy = authApi.canPushPolicy();
    const queryClient = useQueryClient();

    // ── Operational settings ──────────────────────────────────────────────────
    const [batchSize, setBatchSize] = useState('200');
    const [customBatchSize, setCustomBatchSize] = useState('');
    const [batchInterval, setBatchInterval] = useState('1s');
    const [customBatchInterval, setCustomBatchInterval] = useState('');
    const [compression, setCompression] = useState('snappy');

    // ── Vulnerability scanner ─────────────────────────────────────────────────
    const [vulnEnabled, setVulnEnabled] = useState(true);
    const [vulnInterval, setVulnInterval] = useState('6h');
    const [customVulnInterval, setCustomVulnInterval] = useState('');
    const [vulnTimeout, setVulnTimeout] = useState('20m');
    const [customVulnTimeout, setCustomVulnTimeout] = useState('');

    // ── Response policy ───────────────────────────────────────────────────────
    const [autoQuarantine, setAutoQuarantine] = useState(true);
    const [autoKill, setAutoKill] = useState(true);
    const [preventionMode, setPreventionMode] = useState<'auto_kill_then_override' | 'detect_only'>('auto_kill_then_override');

    // ── Filter policy ─────────────────────────────────────────────────────────
    const [policyJson, setPolicyJson] = useState(() =>
        JSON.stringify({ exclude_processes: ['svchost.exe'], exclude_event_ids: [4, 7, 15, 22], trusted_hashes: [], rate_limit: { enabled: true, default_max_eps: 500, critical_bypass: true } }, null, 2)
    );
    const [policyError, setPolicyError] = useState('');

    // ── Process exception ─────────────────────────────────────────────────────
    const [exceptionProcess, setExceptionProcess] = useState('');
    const [exceptionReason, setExceptionReason] = useState('');

    // ── Sysmon ────────────────────────────────────────────────────────────────
    const [sysmonConfigXml, setSysmonConfigXml] = useState(DEFAULT_SYSMON_XML);

    // ── Effective values (resolve custom inputs) ──────────────────────────────
    const effectiveBatchSize = batchSize === 'custom' ? customBatchSize.trim() : batchSize;
    const effectiveBatchInterval = batchInterval === 'custom' ? customBatchInterval.trim() : batchInterval;
    const effectiveVulnInterval = vulnInterval === 'custom' ? customVulnInterval.trim() : vulnInterval;
    const effectiveVulnTimeout = vulnTimeout === 'custom' ? customVulnTimeout.trim() : vulnTimeout;

    // ── Validation ────────────────────────────────────────────────────────────
    const [errors, setErrors] = useState<Record<string, string>>({});
    const isValidDuration = (v: string) => /^\d+(\.\d+)?(ms|s|m|h)$/.test(v.trim());
    const isValidPosInt = (v: string) => /^\d+$/.test(v.trim()) && parseInt(v.trim(), 10) > 0;

    const validateOp = (): boolean => {
        const e: Record<string, string> = {};
        if (batchSize === 'custom') {
            if (!customBatchSize.trim()) e.batchSize = 'Required — enter a positive integer';
            else if (!isValidPosInt(customBatchSize)) e.batchSize = 'Must be a positive integer, e.g. 300';
        }
        if (batchInterval === 'custom') {
            if (!customBatchInterval.trim()) e.batchInterval = 'Required — enter a Go duration';
            else if (!isValidDuration(customBatchInterval)) e.batchInterval = 'Invalid format — use: 500ms · 1s · 2s · 30s · 1m';
        }
        setErrors(e);
        return Object.keys(e).length === 0;
    };

    const validateVuln = (): boolean => {
        const e: Record<string, string> = {};
        if (vulnInterval === 'custom') {
            if (!customVulnInterval.trim()) e.vulnInterval = 'Required — enter a Go duration';
            else if (!isValidDuration(customVulnInterval)) e.vulnInterval = 'Invalid format — use: 1h · 6h · 12h · 24h · 48h';
        }
        if (vulnTimeout === 'custom') {
            if (!customVulnTimeout.trim()) e.vulnTimeout = 'Required — enter a Go duration';
            else if (!isValidDuration(customVulnTimeout)) e.vulnTimeout = 'Invalid format — use: 10m · 20m · 30m · 1h';
        }
        setErrors(prev => ({ ...prev, ...e }));
        return Object.keys(e).length === 0;
    };

    const invalidate = () => {
        queryClient.invalidateQueries({ queryKey: ['agent', agent.id] });
        queryClient.invalidateQueries({ queryKey: ['agent-commands', agent.id] });
    };

    // ── Mutations ─────────────────────────────────────────────────────────────
    const opMutation = useMutation({
        mutationFn: () => agentsApi.executeCommand(agent.id, {
            command_type: 'update_config',
            parameters: { config: `agent:\n  batch_size: ${effectiveBatchSize}\n  batch_interval: ${effectiveBatchInterval}\n  compression: ${compression}\n` },
            timeout: 30,
        } as any),
        onSuccess: () => { showToast('Operational settings queued — batch settings apply immediately ⚡', 'success'); invalidate(); },
        onError: (e: Error) => showToast(e.message || 'Failed', 'error'),
    });

    const vulnMutation = useMutation({
        mutationFn: () => agentsApi.executeCommand(agent.id, {
            command_type: 'update_vuln_config',
            parameters: { vuln_scan_enabled: String(vulnEnabled), vuln_scanner_type: 'trivy', vuln_scan_interval: effectiveVulnInterval, vuln_scan_timeout: effectiveVulnTimeout },
            timeout: 30,
        } as any),
        onSuccess: () => { showToast('Vulnerability scanner config queued 🔄 (effective after restart)', 'success'); invalidate(); },
        onError: (e: Error) => showToast(e.message || 'Failed', 'error'),
    });

    const policyMutation = useMutation({
        mutationFn: () => agentsApi.executeCommand(agent.id, {
            command_type: 'update_vuln_config',
            parameters: { auto_quarantine: String(autoQuarantine), process_auto_kill_enabled: String(autoKill), process_prevention_mode: preventionMode },
            timeout: 30,
        } as any),
        onSuccess: () => { showToast('Response policy queued 🔄 (effective after restart)', 'success'); invalidate(); },
        onError: (e: Error) => showToast(e.message || 'Failed', 'error'),
    });

    const filterMutation = useMutation({
        mutationFn: async () => {
            const parsed = JSON.parse(policyJson);
            return agentsApi.updateFilterPolicy(agent.id, parsed);
        },
        onSuccess: (data: any) => { showToast(`Filter policy applied immediately ⚡ (${(data?.command_id || '').slice(0, 8)})`, 'success'); invalidate(); },
        onError: (e: Error) => showToast(e.message || 'Policy push failed', 'error'),
    });

    const exceptionMutation = useMutation({
        mutationFn: async () => {
            const pn = exceptionProcess.trim();
            if (!pn) throw new Error('process_name is required');
            return agentsApi.addProcessException(agent.id, { process_name: pn, reason: exceptionReason.trim() || undefined });
        },
        onSuccess: () => { showToast('Process exception applied ⚡', 'success'); setExceptionProcess(''); setExceptionReason(''); invalidate(); },
        onError: (e: Error) => showToast(e.message || 'Failed', 'error'),
    });

    const sysmonEnableMutation = useMutation({
        mutationFn: () => agentsApi.executeCommand(agent.id, {
            command_type: 'enable_sysmon',
            parameters: { mode: 'enable_sysmon', sysmon_config_xml: sysmonConfigXml },
            timeout: 180,
        } as any),
        onSuccess: () => { showToast('Sysmon enable command queued', 'success'); invalidate(); },
        onError: (e: Error) => showToast(e.message || 'Failed', 'error'),
    });

    const sysmonDisableMutation = useMutation({
        mutationFn: () => agentsApi.executeCommand(agent.id, {
            command_type: 'disable_sysmon',
            parameters: { mode: 'disable_sysmon' },
            timeout: 120,
        } as any),
        onSuccess: () => { showToast('Sysmon disable command queued', 'success'); invalidate(); },
        onError: (e: Error) => showToast(e.message || 'Failed', 'error'),
    });

    // ── UI helpers ────────────────────────────────────────────────────────────
    const HotBadge = () => (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/40">
            <Zap className="w-2.5 h-2.5" /> Hot-reload
        </span>
    );
    const RestartBadge = () => (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800/40">
            <RefreshCw className="w-2.5 h-2.5" /> After restart
        </span>
    );
    const Toggle = ({ value, onChange, disabled }: { value: boolean; onChange: (v: boolean) => void; disabled?: boolean }) => (
        <button type="button" onClick={() => !disabled && onChange(!value)} disabled={disabled}
            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-40 ${value ? 'bg-cyan-500' : 'bg-slate-300 dark:bg-slate-600'}`}>
            <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${value ? 'translate-x-[18px]' : 'translate-x-0.5'}`} />
        </button>
    );
    const card = 'rounded-xl border border-slate-200 dark:border-slate-700/60 p-5 bg-white/60 dark:bg-slate-900/40 space-y-4';
    const lbl = 'block text-[10px] font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1';
    const sel = 'w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500';
    const inp = 'w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-950 px-2.5 py-1.5 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500';
    const applyBtn = 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-700 text-white disabled:opacity-40 transition-colors';
    const sectionHead = 'text-sm font-bold text-slate-800 dark:text-slate-100 mb-3 flex items-center gap-2';

    return (
        <div className="space-y-8 text-sm">

            {/* ── Legend ────────────────────────────────────────────────── */}
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-700/60 text-xs text-slate-500 dark:text-slate-400">
                <span className="font-semibold text-slate-700 dark:text-slate-300">Legend:</span>
                <span className="flex items-center gap-1.5"><HotBadge /> — takes effect immediately, no restart needed</span>
                <span className="flex items-center gap-1.5"><RestartBadge /> — saved to Registry, effective after next service restart</span>
            </div>

            {/* ══════════════ CONFIGURATION ══════════════════════════════ */}
            <div>
                <h2 className={sectionHead}><Settings className="w-4 h-4 text-cyan-500" /> Configuration</h2>
                <div className="space-y-4">

                    {/* Operational settings */}
                    <div className={card}>
                        <div className="flex items-center justify-between flex-wrap gap-2">
                            <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-200">Operational Settings</h3>
                            <HotBadge />
                        </div>
                        <p className="text-xs text-slate-500">Batch pipeline parameters. Changes apply immediately via batcher hot-swap — no service restart required.</p>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                            <div>
                                <label className={lbl}>Batch Size</label>
                                <select className={sel} value={batchSize} onChange={e => setBatchSize(e.target.value)} disabled={!canExec}>
                                    <option value="100">100 events</option>
                                    <option value="200">200 events (default)</option>
                                    <option value="500">500 events</option>
                                    <option value="1000">1 000 events</option>
                                    <option value="custom">Custom…</option>
                                </select>
                                {batchSize === 'custom' && (
                                    <div className="mt-1.5">
                                        <input className={`${inp} ${errors.batchSize ? 'border-rose-400 ring-1 ring-rose-400' : ''}`} type="number" min="1" placeholder="e.g. 300" value={customBatchSize} onChange={e => { setCustomBatchSize(e.target.value); setErrors(p => ({ ...p, batchSize: '' })); }} disabled={!canExec} />
                                        {errors.batchSize
                                            ? <p className="text-[10px] text-rose-500 mt-0.5">{errors.batchSize}</p>
                                            : <p className="text-[10px] text-slate-400 mt-0.5">Positive integer — number of events per batch (e.g. 100–5 000)</p>}
                                    </div>
                                )}
                            </div>
                            <div>
                                <label className={lbl}>Batch Interval</label>
                                <select className={sel} value={batchInterval} onChange={e => setBatchInterval(e.target.value)} disabled={!canExec}>
                                    <option value="500ms">500 ms</option>
                                    <option value="1s">1 s (default)</option>
                                    <option value="2s">2 s</option>
                                    <option value="5s">5 s</option>
                                    <option value="custom">Custom…</option>
                                </select>
                                {batchInterval === 'custom' && (
                                    <div className="mt-1.5">
                                        <input className={`${inp} ${errors.batchInterval ? 'border-rose-400 ring-1 ring-rose-400' : ''}`} placeholder="e.g. 500ms · 1s · 2s" value={customBatchInterval} onChange={e => { setCustomBatchInterval(e.target.value); setErrors(p => ({ ...p, batchInterval: '' })); }} disabled={!canExec} />
                                        {errors.batchInterval
                                            ? <p className="text-[10px] text-rose-500 mt-0.5">{errors.batchInterval}</p>
                                            : <p className="text-[10px] text-slate-400 mt-0.5">Go duration — e.g. <code>500ms</code> (0.5 s) · <code>1s</code> · <code>30s</code> · <code>1m</code> (60 s)</p>}
                                    </div>
                                )}
                            </div>
                            <div>
                                <label className={lbl}>Compression</label>
                                <select className={sel} value={compression} onChange={e => setCompression(e.target.value)} disabled={!canExec}>
                                    <option value="snappy">snappy (default)</option>
                                    <option value="gzip">gzip</option>
                                </select>
                            </div>
                        </div>
                        <div className="flex justify-end">
                            <button type="button" className={applyBtn} disabled={!canExec || opMutation.isPending} onClick={() => { if (validateOp()) opMutation.mutate(); }}>
                                {opMutation.isPending ? 'Sending…' : 'Apply'}
                            </button>
                        </div>
                    </div>

                    {/* Vulnerability scanner */}
                    <div className={card}>
                        <div className="flex items-center justify-between flex-wrap gap-2">
                            <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-200">Vulnerability Scanner</h3>
                            <RestartBadge />
                        </div>
                        <p className="text-xs text-slate-500">Scanner settings are saved to Registry and take effect after the next service restart.</p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="flex items-center gap-3">
                                <Toggle value={vulnEnabled} onChange={setVulnEnabled} disabled={!canExec} />
                                <span className="text-xs text-slate-600 dark:text-slate-300">Vuln scan enabled</span>
                            </div>
                            <div>
                                <label className={lbl}>Scanner</label>
                                <p className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-200 mt-1">trivy</p>
                            </div>
                            <div>
                                <label className={lbl}>Scan Interval</label>
                                <select className={sel} value={vulnInterval} onChange={e => setVulnInterval(e.target.value)} disabled={!canExec}>
                                    <option value="1h">Every 1 hour</option>
                                    <option value="6h">Every 6 hours (default)</option>
                                    <option value="12h">Every 12 hours</option>
                                    <option value="24h">Every 24 hours</option>
                                    <option value="custom">Custom…</option>
                                </select>
                                {vulnInterval === 'custom' && (
                                    <div className="mt-1.5">
                                        <input className={`${inp} ${errors.vulnInterval ? 'border-rose-400 ring-1 ring-rose-400' : ''}`} placeholder="e.g. 6h · 12h · 48h" value={customVulnInterval} onChange={e => { setCustomVulnInterval(e.target.value); setErrors(p => ({ ...p, vulnInterval: '' })); }} disabled={!canExec} />
                                        {errors.vulnInterval
                                            ? <p className="text-[10px] text-rose-500 mt-0.5">{errors.vulnInterval}</p>
                                            : <p className="text-[10px] text-slate-400 mt-0.5">Go duration — e.g. <code>1h</code> (60 min) · <code>6h</code> · <code>24h</code> (1 day) · <code>48h</code> (2 days)</p>}
                                    </div>
                                )}
                            </div>
                            <div>
                                <label className={lbl}>Scan Timeout</label>
                                <select className={sel} value={vulnTimeout} onChange={e => setVulnTimeout(e.target.value)} disabled={!canExec}>
                                    <option value="10m">10 minutes</option>
                                    <option value="20m">20 minutes (default)</option>
                                    <option value="30m">30 minutes</option>
                                    <option value="custom">Custom…</option>
                                </select>
                                {vulnTimeout === 'custom' && (
                                    <div className="mt-1.5">
                                        <input className={`${inp} ${errors.vulnTimeout ? 'border-rose-400 ring-1 ring-rose-400' : ''}`} placeholder="e.g. 10m · 30m · 1h" value={customVulnTimeout} onChange={e => { setCustomVulnTimeout(e.target.value); setErrors(p => ({ ...p, vulnTimeout: '' })); }} disabled={!canExec} />
                                        {errors.vulnTimeout
                                            ? <p className="text-[10px] text-rose-500 mt-0.5">{errors.vulnTimeout}</p>
                                            : <p className="text-[10px] text-slate-400 mt-0.5">Go duration — e.g. <code>10m</code> (10 min) · <code>30m</code> · <code>1h</code> (60 min)</p>}
                                    </div>
                                )}
                            </div>
                        </div>
                        <div className="flex justify-end">
                            <button type="button" className={applyBtn} disabled={!canExec || vulnMutation.isPending} onClick={() => { if (validateVuln()) vulnMutation.mutate(); }}>
                                {vulnMutation.isPending ? 'Sending…' : 'Apply'}
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* ══════════════ POLICY ═════════════════════════════════════ */}
            <div>
                <h2 className={sectionHead}><Shield className="w-4 h-4 text-violet-500" /> Policy</h2>
                <div className="space-y-4">

                    {/* Response policy */}
                    <div className={card}>
                        <div className="flex items-center justify-between flex-wrap gap-2">
                            <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-200">Response Policy</h3>
                            <RestartBadge />
                        </div>
                        <p className="text-xs text-slate-500">Controls how the agent reacts to detected threats. Saved to Registry — effective after next service restart.</p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div className="flex items-center gap-3">
                                <Toggle value={autoQuarantine} onChange={setAutoQuarantine} disabled={!canExec} />
                                <div>
                                    <p className="text-xs font-medium text-slate-700 dark:text-slate-200">Auto Quarantine</p>
                                    <p className="text-[10px] text-slate-400">Automatically quarantine detected malicious files</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <Toggle value={autoKill} onChange={setAutoKill} disabled={!canExec} />
                                <div>
                                    <p className="text-xs font-medium text-slate-700 dark:text-slate-200">Process Auto-Kill</p>
                                    <p className="text-[10px] text-slate-400">Terminate processes flagged as malicious</p>
                                </div>
                            </div>
                            <div className="sm:col-span-2">
                                <label className={lbl}>Prevention Mode</label>
                                <div className="flex gap-6 mt-1">
                                    {([
                                        ['auto_kill_then_override', 'Active — auto-kill + override', 'Blocks and terminates malicious activity automatically'],
                                        ['detect_only', 'Passive — detect only', 'Logs and alerts without taking automated action'],
                                    ] as const).map(([v, title, desc]) => (
                                        <label key={v} className="flex items-start gap-2 cursor-pointer select-none">
                                            <input type="radio" className="accent-cyan-500 mt-0.5" checked={preventionMode === v} onChange={() => setPreventionMode(v)} disabled={!canExec} />
                                            <div>
                                                <p className="text-xs font-medium text-slate-700 dark:text-slate-200">{title}</p>
                                                <p className="text-[10px] text-slate-400">{desc}</p>
                                            </div>
                                        </label>
                                    ))}
                                </div>
                            </div>
                        </div>
                        <div className="flex justify-end">
                            <button type="button" className={applyBtn} disabled={!canExec || policyMutation.isPending} onClick={() => policyMutation.mutate()}>
                                {policyMutation.isPending ? 'Sending…' : 'Apply'}
                            </button>
                        </div>
                    </div>

                    {/* Filter policy */}
                    <div className={card}>
                        <div className="flex items-center justify-between flex-wrap gap-2">
                            <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-200">Filter Policy</h3>
                            <HotBadge />
                        </div>
                        <p className="text-xs text-slate-500">
                            Define processes, event IDs, and file hashes to exclude from monitoring.
                            Changes are pushed to the running agent and take effect immediately.
                        </p>
                        <textarea
                            className="w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-950 px-3 py-2 text-xs font-mono min-h-[160px] focus:outline-none focus:ring-1 focus:ring-cyan-500"
                            value={policyJson}
                            onChange={e => { setPolicyJson(e.target.value); setPolicyError(''); }}
                            spellCheck={false}
                            disabled={!canPushPolicy}
                        />
                        {policyError && <p className="text-xs text-rose-500">{policyError}</p>}
                        <div className="flex items-center justify-end gap-2">
                            {!canPushPolicy && <span className="text-xs text-slate-500">Missing policy push permission.</span>}
                            <button type="button" className={applyBtn} disabled={!canPushPolicy || filterMutation.isPending}
                                onClick={() => {
                                    try { JSON.parse(policyJson); } catch { setPolicyError('Invalid JSON — check syntax before pushing'); return; }
                                    filterMutation.mutate();
                                }}>
                                {filterMutation.isPending ? 'Pushing…' : 'Push filter policy'}
                            </button>
                        </div>
                    </div>

                    {/* Process exceptions */}
                    <div className={card}>
                        <div className="flex items-center justify-between flex-wrap gap-2">
                            <h3 className="text-xs font-semibold text-slate-700 dark:text-slate-200">Process Exceptions</h3>
                            <HotBadge />
                        </div>
                        <p className="text-xs text-slate-500">Allow a process to bypass process auto-response rules. Applied immediately.</p>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            <div>
                                <label className={lbl}>Process name</label>
                                <input className={inp} value={exceptionProcess} onChange={e => setExceptionProcess(e.target.value)} placeholder="e.g. powershell.exe" disabled={!canPushPolicy} />
                            </div>
                            <div className="md:col-span-2">
                                <label className={lbl}>Reason (optional)</label>
                                <input className={sel} value={exceptionReason} onChange={e => setExceptionReason(e.target.value)} placeholder="approved automation / known good" disabled={!canPushPolicy} />
                            </div>
                        </div>
                        <div className="flex items-center justify-end gap-2">
                            {!canPushPolicy && <span className="text-xs text-slate-500">Missing permission.</span>}
                            <button type="button" className={applyBtn} disabled={!canPushPolicy || exceptionMutation.isPending} onClick={() => exceptionMutation.mutate()}>
                                {exceptionMutation.isPending ? 'Pushing…' : 'Add exception'}
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* ══════════════ SYSMON ═════════════════════════════════════ */}
            <div>
                <h2 className={sectionHead}><Eye className="w-4 h-4 text-indigo-500" /> Sysmon</h2>
                <div className={card}>
                    <div className="flex items-center gap-6 flex-wrap">
                        <div className="flex items-center gap-2">
                            <span className="text-[10px] font-semibold uppercase text-slate-400">Installed</span>
                            {agent.sysmon_installed
                                ? <span className="flex items-center gap-1 text-xs font-semibold text-emerald-600 dark:text-emerald-400"><CheckCircle2 className="w-3.5 h-3.5" /> Yes</span>
                                : <span className="text-xs font-semibold text-slate-400">No</span>}
                        </div>
                        <div className="flex items-center gap-2">
                            <span className="text-[10px] font-semibold uppercase text-slate-400">Running</span>
                            {agent.sysmon_running
                                ? <span className="flex items-center gap-1 text-xs font-semibold text-emerald-600 dark:text-emerald-400"><CheckCircle2 className="w-3.5 h-3.5" /> Yes</span>
                                : <span className="flex items-center gap-1 text-xs font-semibold text-rose-500"><XCircle className="w-3.5 h-3.5" /> No</span>}
                        </div>
                    </div>
                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label className={lbl} style={{ marginBottom: 0 }}>Sysmon Config XML</label>
                            <span className="text-[10px] text-slate-400 font-mono">assets/sysmonconfig.xml</span>
                        </div>
                        <textarea
                            className="w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-950 px-3 py-2 text-xs font-mono min-h-[220px] focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-y"
                            value={sysmonConfigXml}
                            onChange={e => setSysmonConfigXml(e.target.value)}
                            spellCheck={false}
                            disabled={!canExec}
                        />
                        <p className="text-[10px] text-slate-400 mt-1">This XML is sent to the agent when you click “Enable Sysmon”. Edit to customise event filters.</p>
                    </div>
                    <div className="flex gap-2 justify-end">
                        <button type="button" disabled={!canExec || sysmonDisableMutation.isPending}
                            onClick={() => sysmonDisableMutation.mutate()}
                            className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-rose-300 dark:border-rose-700/50 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-900/20 disabled:opacity-40 transition-colors">
                            {sysmonDisableMutation.isPending ? 'Sending…' : 'Disable Sysmon'}
                        </button>
                        <button type="button" className={applyBtn} disabled={!canExec || sysmonEnableMutation.isPending} onClick={() => sysmonEnableMutation.mutate()}>
                            {sysmonEnableMutation.isPending ? 'Sending…' : 'Enable Sysmon'}
                        </button>
                    </div>
                </div>
            </div>

            {/* ══════════════ TAGS (read-only) ═══════════════════════════ */}
            <div>
                <h2 className={sectionHead}>
                    <Tag className="w-4 h-4 text-slate-400" /> Agent Tags
                    <span className="text-[10px] font-normal text-slate-400 dark:text-slate-500 ml-1">(read-only — populated by agent)</span>
                </h2>
                <div className={card}>
                    {Object.keys(agent.tags || {}).length === 0 ? (
                        <p className="text-xs text-slate-400">No tags yet.</p>
                    ) : (
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                            {Object.entries(agent.tags || {}).map(([k, v]) => (
                                <div key={k} className="bg-slate-50 dark:bg-slate-800/60 rounded-lg p-3">
                                    <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-400 mb-0.5">{k.replace(/_/g, ' ')}</p>
                                    <p className="text-xs font-mono text-slate-700 dark:text-slate-200 break-all">{String(v)}</p>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

function SoftwareInventoryAgentTab({ agentId }: { agentId: string }) {
    const canRead = authApi.canViewEndpoints();
    const { showToast } = useToast();
    const [search, setSearch] = useState('');
    const [page, setPage] = useState(1);
    const pageSize = 10;

    const { data, isLoading, isError, refetch, isFetching } = useQuery({
        queryKey: ['agent-software-inventory', agentId],
        queryFn: () => agentsApi.getSoftwareInventory(agentId),
        enabled: !!agentId && canRead,
        staleTime: 60_000,
        retry: 1,
    });

    const rows = data?.data ?? [];
    const filtered = useMemo(() => {
        if (!search.trim()) return rows;
        const q = search.toLowerCase();
        return rows.filter((r) =>
            (r.name || '').toLowerCase().includes(q) ||
            (r.publisher || '').toLowerCase().includes(q) ||
            (r.version || '').toLowerCase().includes(q)
        );
    }, [rows, search]);

    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
    useEffect(() => {
        if (page > totalPages) setPage(totalPages);
    }, [page, totalPages]);

    const pageRows = useMemo(() => {
        const start = (page - 1) * pageSize;
        return filtered.slice(start, start + pageSize);
    }, [filtered, page]);

    if (!canRead) {
        return <p className="text-sm text-rose-600">You do not have permission to view endpoint software inventory.</p>;
    }

    return (
        <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                    <h3 className="text-lg font-bold text-slate-800 dark:text-slate-200 mb-1">Software Inventory</h3>
                    <p className="text-sm text-slate-500">Installed software reported by this endpoint.</p>
                </div>
                <button
                    type="button"
                    onClick={() => void refetch()}
                    disabled={isFetching}
                    className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-600 bg-white/70 dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
                >
                    <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin' : ''}`} />
                    Refresh
                </button>
            </div>

            <div className="flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[220px]">
                    <label className="block text-[10px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Search</label>
                    <input
                        className="w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
                        value={search}
                        onChange={(e) => {
                            setSearch(e.target.value);
                            setPage(1);
                        }}
                        placeholder="Name, publisher, version…"
                    />
                </div>
                <div className="text-xs text-slate-500">{filtered.length} rows</div>
            </div>

            {isLoading ? (
                <div className="flex items-center justify-center py-16 text-slate-500 gap-2">
                    <Loader2 className="w-5 h-5 animate-spin" /> Loading…
                </div>
            ) : isError ? (
                <div className="rounded-xl border border-rose-200 dark:border-rose-900/40 p-4">
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">Failed to load software inventory</p>
                    <button
                        type="button"
                        onClick={() => {
                            showToast('Retrying…', 'info');
                            void refetch();
                        }}
                        className="mt-2 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 text-white hover:bg-slate-700"
                    >
                        Retry
                    </button>
                </div>
            ) : filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center">
                    <div className="w-16 h-16 rounded-2xl bg-slate-100 dark:bg-slate-800 flex items-center justify-center mb-4">
                        <Package className="w-8 h-8 text-slate-400" />
                    </div>
                    <p className="text-sm text-slate-500 max-w-md">
                        No software inventory rows reported yet for this endpoint. It will appear after the agent completes its first inventory cycle.
                    </p>
                </div>
            ) : (
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900/60 overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-sm border-collapse">
                            <thead>
                                <tr className="bg-slate-50/80 dark:bg-slate-800/40">
                                    <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Name</th>
                                    <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Version</th>
                                    <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Publisher</th>
                                    <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Install date</th>
                                    <th className="px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Last reported</th>
                                </tr>
                            </thead>
                            <tbody>
                                {pageRows.map((r, i) => (
                                    <tr
                                        key={`${r.name}::${r.version}::${r.publisher}::${i}`}
                                        className={`border-t border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/40 ${
                                            i % 2 === 1 ? 'bg-slate-50/40 dark:bg-slate-800/20' : ''
                                        }`}
                                    >
                                        <td className="px-4 py-2 font-mono text-xs font-semibold text-slate-900 dark:text-white">{r.name}</td>
                                        <td className="px-4 py-2 font-mono text-xs text-slate-700 dark:text-slate-300">{r.version || '—'}</td>
                                        <td className="px-4 py-2 text-xs text-slate-600 dark:text-slate-400">{r.publisher || '—'}</td>
                                        <td className="px-4 py-2 text-xs text-slate-500">{r.install_date || '—'}</td>
                                        <td className="px-4 py-2 text-xs text-slate-500 whitespace-nowrap">
                                            {r.last_reported ? new Date(r.last_reported).toLocaleString() : '—'}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200 dark:border-slate-700 text-xs">
                        <span className="text-slate-500">
                            Page {page} / {totalPages}
                        </span>
                        <div className="flex items-center gap-2">
                            <button
                                type="button"
                                onClick={() => setPage((p) => Math.max(1, p - 1))}
                                disabled={page <= 1}
                                className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 disabled:opacity-50"
                            >
                                Prev
                            </button>
                            <button
                                type="button"
                                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                                disabled={page >= totalPages}
                                className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 disabled:opacity-50"
                            >
                                Next
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

const NETWORK_PAGE_SIZE = 25;

// @ts-ignore — legacy NetworkTab kept for reference; now replaced by AutoProcTerminationTab
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _NetworkTab({ agentId, canViewAlerts }: { agentId: string; canViewAlerts: boolean }) {
    const queryClient = useQueryClient();
    const [detailId, setDetailId] = useState<string | null>(null);
    const [rangeDays, setRangeDays] = useState<7 | 30 | 90>(30);
    const [page, setPage] = useState(1);

    const { from, to } = useMemo(() => {
        const toDate = new Date();
        const fromDate = new Date(Date.now() - rangeDays * 24 * 60 * 60 * 1000);
        return { from: fromDate.toISOString(), to: toDate.toISOString() };
    }, [rangeDays]);

    useEffect(() => {
        setPage(1);
    }, [rangeDays]);

    const offset = (page - 1) * NETWORK_PAGE_SIZE;

    const networkSearch = useQuery({
        queryKey: ['events-search-network', agentId, from, to, offset, NETWORK_PAGE_SIZE],
        queryFn: () =>
            eventsApi.search({
                filters: [
                    { field: 'agent_id', operator: 'equals', value: agentId },
                    { field: 'event_type', operator: 'equals', value: 'network' },
                ],
                logic: 'AND',
                time_range: { from, to },
                limit: NETWORK_PAGE_SIZE,
                offset,
            }),
        enabled: !!agentId && canViewAlerts,
        staleTime: 15_000,
        retry: 1,
    });

    const rows = networkSearch.data?.data ?? [];
    const total = networkSearch.data?.pagination?.total ?? 0;
    const loading = networkSearch.isLoading;
    const totalPages = Math.max(1, Math.ceil(total / NETWORK_PAGE_SIZE));

    useEffect(() => {
        if (page > totalPages) setPage(totalPages);
    }, [page, totalPages]);

    const eventsPageHref = useMemo(() => {
        const p = new URLSearchParams();
        p.set('agent_id', agentId);
        p.set('event_type', 'network');
        p.set('from', from);
        p.set('to', to);
        p.set('page', '1');
        return `/events?${p.toString()}`;
    }, [agentId, from, to]);

    const refetchNetwork = () => {
        void queryClient.invalidateQueries({ queryKey: ['events-search-network', agentId] });
    };

    return (
        <div className="space-y-4 text-sm">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <p className="text-slate-600 dark:text-slate-400 max-w-3xl">
                    Network activity captured from this endpoint. Click any row to view the full event details.
                </p>
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <Link
                        to={eventsPageHref}
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-600 bg-white/70 dark:bg-slate-900/50 text-cyan-700 dark:text-cyan-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                        Open in Events
                    </Link>
                    <button
                        type="button"
                        onClick={refetchNetwork}
                        disabled={networkSearch.isFetching}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-600 bg-white/70 dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
                        title="Refresh list"
                    >
                        <RefreshCw className={`w-3.5 h-3.5 ${networkSearch.isFetching ? 'animate-spin' : ''}`} />
                        Refresh
                    </button>
                </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Time range</span>
                {([7, 30, 90] as const).map((d) => (
                    <button
                        key={d}
                        type="button"
                        onClick={() => setRangeDays(d)}
                        className={`px-2.5 py-1 rounded-md text-xs font-medium border transition-colors ${rangeDays === d
                                ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-800 dark:text-cyan-200'
                                : 'border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                            }`}
                    >
                        Last {d} days
                    </button>
                ))}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
                <span>
                    {loading ? 'Loading…' : <>Showing {rows.length} row{rows.length !== 1 ? 's' : ''}</>}
                    {!loading && total > 0 && (
                        <>
                            {' '}
                            · total <span className="font-mono text-slate-700 dark:text-slate-200">{total}</span> in range
                        </>
                    )}
                </span>
                <span className="font-mono text-[10px] truncate max-w-[min(100%,420px)]" title={`${from} → ${to}`}>
                    {from.slice(0, 19)}Z → {to.slice(0, 19)}Z
                </span>
            </div>

            {loading ? (
                <div className="flex justify-center py-12">
                    <Loader2 className="w-8 h-8 animate-spin text-cyan-500" />
                </div>
            ) : rows.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-300 dark:border-slate-600 p-4 text-slate-500">
                    No network events found in this time range. Try selecting a longer time range, or open{' '}
                    <Link className="text-cyan-600 dark:text-cyan-400 underline" to={eventsPageHref}>
                        Events
                    </Link>
                    for a broader search.
                </div>
            ) : (
                <>
                    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                        <table className="w-full text-left text-xs">
                            <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 uppercase">
                                <tr>
                                    <th className="p-2">Time</th>
                                    <th className="p-2">Type</th>
                                    <th className="p-2">Summary</th>
                                </tr>
                            </thead>
                            <tbody>
                                {rows.map((e: CmEventSummary) => (
                                    <tr
                                        key={e.id}
                                        role="button"
                                        tabIndex={0}
                                        className="border-t border-slate-100 dark:border-slate-800 cursor-pointer hover:bg-slate-50/90 dark:hover:bg-slate-800/40"
                                        onClick={() => setDetailId(e.id)}
                                        onKeyDown={(ev) => {
                                            if (ev.key === 'Enter' || ev.key === ' ') {
                                                ev.preventDefault();
                                                setDetailId(e.id);
                                            }
                                        }}
                                    >
                                        <td className="p-2 whitespace-nowrap">{new Date(e.timestamp).toLocaleString()}</td>
                                        <td className="p-2 font-mono">{e.event_type}</td>
                                        <td className="p-2 max-w-xl truncate" title={e.summary}>
                                            {e.summary}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {totalPages > 1 && (
                        <div className="flex items-center justify-between gap-3 pt-1">
                            <button
                                type="button"
                                className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40"
                                disabled={page <= 1}
                                onClick={() => setPage((p) => Math.max(1, p - 1))}
                            >
                                <ChevronLeft className="w-4 h-4" /> Prev
                            </button>
                            <span className="text-xs text-slate-500">
                                Page <span className="font-semibold text-slate-700 dark:text-slate-200">{page}</span> / {totalPages}
                            </span>
                            <button
                                type="button"
                                className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40"
                                disabled={page >= totalPages}
                                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                            >
                                Next <ChevronRight className="w-4 h-4" />
                            </button>
                        </div>
                    )}
                </>
            )}

            <EventDetailModal eventId={detailId} onClose={() => setDetailId(null)} fetchEnabled={canViewAlerts} />
        </div>
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Auto-Proc Termination Tab (per-agent)
// ─────────────────────────────────────────────────────────────────────────────

const AUTO_PROC_PAGE_SIZE = 25;

const ACTION_BADGE: Record<string, { label: string; color: string; bg: string; icon: React.ElementType }> = {
    auto_terminated: { label: 'Terminated', color: '#22c55e', bg: 'rgba(34,197,94,0.12)', icon: CheckCircle2 },
    auto_terminate_failed: { label: 'Failed', color: '#ef4444', bg: 'rgba(239,68,68,0.12)', icon: XCircle },
    process_rule_matched_detect_only: { label: 'Detect Only', color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', icon: AlertTriangle },
};

function AutoProcTerminationTab({ agentId, canViewAlerts, canExec }: { agentId: string; canViewAlerts: boolean; canExec: boolean }) {
    const queryClient = useQueryClient();
    const { showToast } = useToast();
    const [rangeDays, setRangeDays] = useState<7 | 30 | 90>(30);
    const [page, setPage] = useState(1);
    const [expandedId, setExpandedId] = useState<string | null>(null);
    const [allowTarget, setAllowTarget] = useState<{ name: string; rule: string } | null>(null);
    const [allowReason, setAllowReason] = useState('');

    const { from, to } = useMemo(() => {
        const toDate = new Date();
        const fromDate = new Date(Date.now() - rangeDays * 24 * 60 * 60 * 1000);
        return { from: fromDate.toISOString(), to: toDate.toISOString() };
    }, [rangeDays]);

    useEffect(() => { setPage(1); }, [rangeDays]);

    const offset = (page - 1) * AUTO_PROC_PAGE_SIZE;

    const q = useQuery({
        queryKey: ['auto-proc-events-v2', agentId, from, to, offset],
        queryFn: () => eventsApi.search({
            filters: [
                { field: 'agent_id', operator: 'equals', value: agentId },
                { field: 'event_type', operator: 'equals', value: 'process' },
                { field: 'data.action', operator: 'in', value: ['auto_terminated', 'auto_terminate_failed'] },
            ],
            logic: 'AND',
            time_range: { from, to },
            limit: AUTO_PROC_PAGE_SIZE,
            offset,
        }),
        enabled: !!agentId && canViewAlerts,
        staleTime: 15_000,
        refetchInterval: 30_000,
        retry: 1,
    });

    const rows = q.data?.data ?? [];
    const total = q.data?.pagination?.total ?? 0;
    const totalPages = Math.max(1, Math.ceil(total / AUTO_PROC_PAGE_SIZE));

    const exceptionMutation = useMutation({
        mutationFn: (body: { process_name: string; reason?: string }) =>
            agentsApi.addProcessException(agentId, body),
        onSuccess: () => {
            showToast('Process exception added — agent will allow this process', 'success');
            setAllowTarget(null);
            setAllowReason('');
        },
        onError: (e: Error) => showToast(e.message || 'Failed to add exception', 'error'),
    });

    const getActionBadge = (ev: CmEventSummary) => {
        const raw = ev as any;
        const action = raw.data?.action || raw.action || '';
        return ACTION_BADGE[action] || ACTION_BADGE['auto_terminate_failed'];
    };

    const getField = (ev: CmEventSummary, field: string): string => {
        const raw = ev as any;
        return String(raw.data?.[field] ?? raw[field] ?? '');
    };

    // Client-side filter: show only actual termination events
    const AUTONOMOUS_ACTIONS = ['auto_terminated', 'auto_terminate_failed'];
    const filteredRows = rows.filter(r => AUTONOMOUS_ACTIONS.includes(getField(r, 'action')));

    // Stats
    const terminated = filteredRows.filter(r => getField(r, 'action') === 'auto_terminated').length;
    const failed = filteredRows.filter(r => getField(r, 'action') === 'auto_terminate_failed').length;

    return (
        <div className="space-y-4 text-sm animate-slide-up-fade">
            {/* Header */}
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div>
                    <h3 className="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2 mb-1">
                        <ShieldAlert className="w-4 h-4 text-cyan-500" /> Auto-Proc Termination
                    </h3>
                    <p className="text-slate-500 dark:text-slate-400 text-xs">
                        Processes automatically terminated or detected by endpoint prevention rules.
                    </p>
                </div>
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                        type="button"
                        onClick={() => queryClient.invalidateQueries({ queryKey: ['auto-proc-events-v2', agentId] })}
                        disabled={q.isFetching}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-200 dark:border-slate-600 bg-white/70 dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
                    >
                        <RefreshCw className={`w-3.5 h-3.5 ${q.isFetching ? 'animate-spin' : ''}`} /> Refresh
                    </button>
                </div>
            </div>

            {/* Mini KPIs */}
            <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-emerald-200 dark:border-emerald-800/40 bg-emerald-50/50 dark:bg-emerald-900/10 p-3">
                    <div className="text-[10px] font-semibold text-emerald-600 dark:text-emerald-400 uppercase tracking-wider">Terminated</div>
                    <div className="text-lg font-bold text-emerald-700 dark:text-emerald-300 mt-0.5">{terminated}</div>
                </div>
                <div className="rounded-lg border border-rose-200 dark:border-rose-800/40 bg-rose-50/50 dark:bg-rose-900/10 p-3">
                    <div className="text-[10px] font-semibold text-rose-600 dark:text-rose-400 uppercase tracking-wider">Failed</div>
                    <div className="text-lg font-bold text-rose-700 dark:text-rose-300 mt-0.5">{failed}</div>
                </div>
            </div>

            {/* Time range */}
            <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">Time range</span>
                {([7, 30, 90] as const).map((d) => (
                    <button key={d} type="button" onClick={() => setRangeDays(d)}
                        className={`px-2.5 py-1 rounded-md text-xs font-medium border transition-colors ${rangeDays === d
                                ? 'border-cyan-500/60 bg-cyan-500/10 text-cyan-800 dark:text-cyan-200'
                                : 'border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                            }`}
                    >Last {d} days</button>
                ))}
                <span className="ml-auto text-[10px] text-slate-400">{total} event{total !== 1 ? 's' : ''} in range</span>
            </div>

            {/* Table */}
            {q.isLoading ? (
                <div className="flex justify-center py-12"><Loader2 className="w-8 h-8 animate-spin text-cyan-500" /></div>
            ) : rows.length === 0 ? (
                <div className="rounded-lg border border-dashed border-slate-300 dark:border-slate-600 p-8 text-center">
                    <ShieldAlert className="w-10 h-10 text-slate-300 dark:text-slate-600 mx-auto mb-3" />
                    <p className="text-slate-500 font-medium">No auto-response events in this time range</p>
                    <p className="text-xs text-slate-400 mt-1">Process termination events will appear here when the agent enforces prevention rules.</p>
                </div>
            ) : (
                <>
                    <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-700">
                        <table className="w-full text-left text-xs">
                            <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 dark:text-slate-400 uppercase text-[10px]">
                                <tr>
                                    <th className="p-2.5">Time</th>
                                    <th className="p-2.5">Action</th>
                                    <th className="p-2.5">Severity</th>
                                    <th className="p-2.5">Process</th>
                                    <th className="p-2.5">Rule</th>
                                    <th className="p-2.5">User</th>
                                    <th className="p-2.5 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filteredRows.map((ev) => {
                                    const badge = getActionBadge(ev);
                                    const BadgeIcon = badge.icon;
                                    const isExpanded = expandedId === ev.id;
                                    const processName = getField(ev, 'name') || getField(ev, 'process_name') || '—';
                                    const ruleName = getField(ev, 'matched_rule_title') || getField(ev, 'matched_rule_id') || '—';
                                    const userName = getField(ev, 'user_name') || '—';
                                    const severity = (ev as any).severity || getField(ev, 'severity') || 'medium';
                                    const sevColor = severity === 'critical' ? 'text-rose-600 dark:text-rose-400 bg-rose-500/10 border-rose-500/20'
                                        : severity === 'high' ? 'text-orange-600 dark:text-orange-400 bg-orange-500/10 border-orange-500/20'
                                            : 'text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/20';

                                    return (
                                        <React.Fragment key={ev.id}>
                                            <tr
                                                className="border-t border-slate-100 dark:border-slate-800 cursor-pointer hover:bg-slate-50/90 dark:hover:bg-slate-800/40 transition-colors"
                                                onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                                            >
                                                <td className="p-2.5 whitespace-nowrap text-slate-600 dark:text-slate-300">{new Date(ev.timestamp).toLocaleString()}</td>
                                                <td className="p-2.5">
                                                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', padding: '2px 8px', borderRadius: '9999px', fontSize: '10px', fontWeight: 600, color: badge.color, backgroundColor: badge.bg }}>
                                                        <BadgeIcon style={{ width: 12, height: 12 }} /> {badge.label}
                                                    </span>
                                                </td>
                                                <td className="p-2.5">
                                                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase border ${sevColor}`}>{severity}</span>
                                                </td>
                                                <td className="p-2.5 font-mono font-medium text-slate-800 dark:text-slate-200">{processName}</td>
                                                <td className="p-2.5 text-slate-600 dark:text-slate-300 max-w-[180px] truncate" title={ruleName}>{ruleName}</td>
                                                <td className="p-2.5 text-slate-500">{userName}</td>
                                                <td className="p-2.5 text-right">
                                                    {canExec && getField(ev, 'action') !== 'process_rule_matched_detect_only' && (
                                                        <button
                                                            type="button"
                                                            className="px-2 py-1 rounded border border-emerald-500/40 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-50"
                                                            onClick={(e) => { e.stopPropagation(); setAllowTarget({ name: processName, rule: ruleName }); }}
                                                        >Allow</button>
                                                    )}
                                                </td>
                                            </tr>
                                            {isExpanded && (
                                                <tr className="bg-slate-50/50 dark:bg-slate-900/30">
                                                    <td colSpan={7} className="p-4">
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">PID</span><div className="font-mono mt-0.5">{getField(ev, 'pid') || '—'}</div></div>
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">PPID</span><div className="font-mono mt-0.5">{getField(ev, 'ppid') || '—'}</div></div>
                                                            <div className="md:col-span-2"><span className="font-semibold text-slate-500 uppercase text-[10px]">Command Line</span><div className="font-mono mt-0.5 bg-slate-100 dark:bg-slate-900/60 p-2 rounded break-all max-h-24 overflow-auto">{getField(ev, 'command_line') || '—'}</div></div>
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Parent</span><div className="font-mono mt-0.5">{getField(ev, 'parent_name') || '—'}</div></div>
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Parent Executable</span><div className="font-mono mt-0.5 truncate" title={getField(ev, 'parent_executable')}>{getField(ev, 'parent_executable') || '—'}</div></div>
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Kill Tree</span><div className="mt-0.5">{getField(ev, 'kill_tree') === 'true' ? <span className="text-rose-600 font-bold">Yes</span> : 'No'}</div></div>
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Signature</span><div className="mt-0.5">{getField(ev, 'signature_status') || '—'}</div></div>
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Elevated</span><div className="mt-0.5">{getField(ev, 'is_elevated') === 'true' ? <span className="text-amber-600 font-bold">Yes</span> : 'No'}</div></div>
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Integrity Level</span><div className="mt-0.5">{getField(ev, 'integrity_level') || '—'}</div></div>
                                                            {getField(ev, 'kill_output') && (
                                                                <div className="md:col-span-2"><span className="font-semibold text-slate-500 uppercase text-[10px]">Kill Output</span><pre className="font-mono mt-0.5 bg-slate-900 text-slate-100 p-2 rounded text-[10px] max-h-20 overflow-auto">{getField(ev, 'kill_output')}</pre></div>
                                                            )}
                                                            {getField(ev, 'kill_error') && (
                                                                <div className="md:col-span-2"><span className="font-semibold text-rose-500 uppercase text-[10px]">Error</span><pre className="font-mono mt-0.5 bg-rose-500/10 text-rose-700 dark:text-rose-300 p-2 rounded text-[10px]">{getField(ev, 'kill_error')}</pre></div>
                                                            )}
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Rule ID</span><div className="font-mono mt-0.5 text-slate-400">{getField(ev, 'matched_rule_id') || '—'}</div></div>
                                                            <div><span className="font-semibold text-slate-500 uppercase text-[10px]">Decision Mode</span><div className="mt-0.5">{getField(ev, 'decision_mode') || '—'}</div></div>
                                                        </div>
                                                    </td>
                                                </tr>
                                            )}
                                        </React.Fragment>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>

                    {totalPages > 1 && (
                        <div className="flex items-center justify-between gap-3 pt-1">
                            <button type="button" className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>
                                <ChevronLeft className="w-4 h-4" /> Prev
                            </button>
                            <span className="text-xs text-slate-500">Page <span className="font-semibold text-slate-700 dark:text-slate-200">{page}</span> / {totalPages}</span>
                            <button type="button" className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40" disabled={page >= totalPages} onClick={() => setPage(p => Math.min(totalPages, p + 1))}>
                                Next <ChevronRight className="w-4 h-4" />
                            </button>
                        </div>
                    )}
                </>
            )}

            {/* Allow Confirmation Modal */}
            <Modal
                isOpen={!!allowTarget}
                onClose={() => { setAllowTarget(null); setAllowReason(''); }}
                title="Allow Process — Add Exception"
                footer={
                    <div className="flex justify-end gap-2">
                        <button type="button" className="btn btn-secondary" onClick={() => { setAllowTarget(null); setAllowReason(''); }}>Cancel</button>
                        <button
                            type="button"
                            className="px-4 py-2 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-700 text-white disabled:opacity-50"
                            disabled={exceptionMutation.isPending}
                            onClick={() => { if (allowTarget) exceptionMutation.mutate({ process_name: allowTarget.name, reason: allowReason || `Allowed from rule: ${allowTarget.rule}` }); }}
                        >
                            {exceptionMutation.isPending ? 'Adding…' : 'Confirm Allow'}
                        </button>
                    </div>
                }
            >
                <div className="space-y-3 text-sm">
                    <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/40 text-amber-800 dark:text-amber-300 text-xs flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                        <span>Adding an exception means this process will <strong>no longer be auto-terminated</strong> by the prevention engine on this agent.</span>
                    </div>
                    <div>
                        <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Process Name</label>
                        <code className="block bg-slate-100 dark:bg-slate-900/60 p-2 rounded text-slate-800 dark:text-slate-200">{allowTarget?.name}</code>
                    </div>
                    <div>
                        <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Matched Rule</label>
                        <code className="block bg-slate-100 dark:bg-slate-900/60 p-2 rounded text-slate-800 dark:text-slate-200 text-xs">{allowTarget?.rule}</code>
                    </div>
                    <div>
                        <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wide mb-1">Reason (optional)</label>
                        <input
                            className="w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-950 px-3 py-2 text-sm"
                            value={allowReason}
                            onChange={(e) => setAllowReason(e.target.value)}
                            placeholder="e.g., approved automation / known good"
                        />
                    </div>
                </div>
            </Modal>
        </div>
    );
}

const WHITELISTED_COMMANDS = [
    { value: 'ipconfig /all', label: 'ipconfig /all (Network Interfaces)' },
    { value: 'netstat -anob', label: 'netstat -anob (Active Connections)' },
    { value: 'tasklist /v', label: 'tasklist /v (Running Processes)' },
    { value: 'systeminfo', label: 'systeminfo (System Details)' },
    { value: 'whoami /all', label: 'whoami /all (Current User/Groups)' },
    { value: 'route print', label: 'route print (Routing Table)' },
    { value: 'arp -a', label: 'arp -a (ARP Cache)' },
    { value: 'vssadmin list shadows', label: 'vssadmin list shadows (Shadow Copies)' },
    { value: 'schtasks /query /fo LIST', label: 'schtasks (Scheduled Tasks)' }
];

function ResponseTab({
    agent: _agent,
    agentId,
    cmds,
    cmdsLoading,
    cmdType,
    setCmdType,
    fields,
    setFields,
    canExec,
    execMutation,
    onSubmit,
}: {
    agent: Agent;
    agentId: string;
    cmds: CommandListItem[];
    cmdsLoading: boolean;
    cmdType: CommandType;
    setCmdType: (c: CommandType) => void;
    fields: Record<string, string>;
    setFields: React.Dispatch<React.SetStateAction<Record<string, string>>>;
    canExec: boolean;
    execMutation: { isPending: boolean };
    onSubmit: () => void;
}) {
    const patch = (k: string, v: string) => setFields((f) => ({ ...f, [k]: v }));
    const uniqueOptions = useMemo(() => {
        const seen = new Set<string>();
        return RESPONSE_OPTIONS.filter((o) => {
            if (seen.has(o.value)) return false;
            // Remove custom command - run_cmd covers it
            if (o.value === 'custom') return false;
            seen.add(o.value);
            return true;
        });
    }, []);

    const [cmdPage, setCmdPage] = useState(1);
    const CMD_PAGE_SIZE = 10;
    const { showToast } = useToast();
    const queryClient = useQueryClient();
    const [upgradeOpen, setUpgradeOpen] = useState(false);
    const [upgradeForm, setUpgradeForm] = useState<{
        serverIP: string;
        serverDomain: string;
        serverPort: string;
        installSysmon: boolean;
    }>({ serverIP: '', serverDomain: '', serverPort: '47051', installSysmon: false });
    const [upgradeErrors, setUpgradeErrors] = useState<Record<string, string>>({});
    const [upgradeStep, setUpgradeStep] = useState<'form' | 'building' | 'pushing'>('form');

    const validateUpgrade = (): boolean => {
        const e: Record<string, string> = {};
        if (!upgradeForm.serverIP.trim() && !upgradeForm.serverDomain.trim()) {
            e.server = 'Server IP or Server Domain is required.';
        }
        if (!upgradeForm.serverPort.trim()) {
            e.port = 'Server port is required.';
        } else if (!/^\d+$/.test(upgradeForm.serverPort.trim())) {
            e.port = 'Port must be a valid number.';
        }
        setUpgradeErrors(e);
        return Object.keys(e).length === 0;
    };

    const upgradeMutation = useMutation<{ package_id: string; url: string; sha256: string }, Error, void>({
        mutationFn: async () => {
            setUpgradeStep('building');
            const pkg = await agentPackagesApi.create({
                server_ip: upgradeForm.serverIP.trim() || undefined,
                server_domain: upgradeForm.serverDomain.trim() || undefined,
                server_port: upgradeForm.serverPort.trim() || undefined,
                public_api_base_url: typeof window !== 'undefined' ? window.location.origin : undefined,
                skip_config: false,
                install_sysmon: (_agent.sysmon_installed && _agent.sysmon_running) ? false : upgradeForm.installSysmon,
                expires_in_seconds: 900,
                agent_id: agentId,
            });
            setUpgradeStep('pushing');
            await agentsApi.executeCommand(agentId, {
                command_type: 'update_agent',
                parameters: {
                    url: pkg.url,
                    checksum: pkg.sha256,
                    version: pkg.package_id,
                    server_domain: upgradeForm.serverDomain.trim(),
                    server_port: upgradeForm.serverPort.trim(),
                    server_ip: upgradeForm.serverIP.trim(),
                },
                timeout: 3600,
            });
            return pkg;
        },
        onSuccess: (pkg) => {
            showToast(`✅ Upgrade queued — package ${pkg.package_id.slice(0, 8)}`, 'success');
            queryClient.invalidateQueries({ queryKey: ['agent-commands', agentId] });
            queryClient.invalidateQueries({ queryKey: ['commands'] });
            setUpgradeOpen(false);
            setUpgradeStep('form');
        },
        onError: (e: Error) => {
            showToast(e.message || 'Upgrade failed', 'error');
            setUpgradeStep('form');
        },
    });

    const isCriticalAsset = useMemo(() => {
        const hn = (_agent.hostname || '').toLowerCase();
        return hn.includes('server') || hn.includes('dc') || hn.includes('prod');
    }, [_agent]);

    const handleExecute = () => {
        // Validate required fields based on command type
        if ((cmdType === 'kill_process' || cmdType === 'terminate_process') && !fields.pid?.trim()) {
            showToast('Please enter a Process ID (PID) before sending the command.', 'error');
            return;
        }
        if (cmdType === 'quarantine_file' && !fields.path?.trim()) {
            showToast('Please enter a file path before sending the command.', 'error');
            return;
        }
        if ((cmdType === 'block_ip' || cmdType === 'unblock_ip') && !fields.ip?.trim()) {
            showToast('Please enter an IP address before sending the command.', 'error');
            return;
        }
        if ((cmdType === 'block_domain' || cmdType === 'unblock_domain') && !fields.domain?.trim()) {
            showToast('Please enter a domain before sending the command.', 'error');
            return;
        }
        if (cmdType === 'run_cmd' && !fields.cmd?.trim()) {
            showToast('Please select a command to run.', 'error');
            return;
        }
        if ((cmdType === 'scan_memory' || cmdType === 'scan_file') && !fields.file_path?.trim()) {
            showToast('Please enter a file path to scan.', 'error');
            return;
        }
        if (isCriticalAsset && fields.manual_approval !== 'true') {
            showToast('This is a critical asset. Manual approval confirmation is required before executing commands.', 'error');
            return;
        }
        onSubmit();
    };

    return (
        <div className="space-y-8 animate-slide-up-fade">
            <div>
                <div className="flex items-center justify-between gap-3 mb-4">
                    <h3 className="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
                        <Terminal className="w-4 h-4" /> Execute command
                    </h3>
                    {canExec && (
                        <button
                            type="button"
                            onClick={() => setUpgradeOpen(true)}
                            className="px-3 py-2 rounded-lg text-xs font-semibold border border-cyan-500/40 bg-cyan-500/10 text-cyan-800 dark:text-cyan-300 hover:bg-cyan-500/20 transition-colors"
                        >
                            Upgrade agent
                        </button>
                    )}
                </div>

                {/* Rate Limiting Notice */}
                <div className="mb-6 rounded-lg border border-amber-200 dark:border-amber-800/40 bg-amber-50 dark:bg-amber-900/10 px-4 py-3 text-xs text-amber-800 dark:text-amber-200 flex items-start gap-3">
                    <Shield className="w-4 h-4 shrink-0 mt-0.5 text-amber-500" />
                    <div>
                        <strong>Rate Limit:</strong> To prevent accidental overload, a maximum of 5 critical commands per minute is enforced for this endpoint.
                    </div>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
                    <div className="xl:col-span-6 space-y-3">
                        <label className="block text-xs font-bold tracking-wider text-slate-500 uppercase mb-2">Select Action</label>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
                            {uniqueOptions.map((o) => {
                                const isSelected = cmdType === o.value;
                                return (
                                    <button
                                        key={o.value}
                                        type="button"
                                        disabled={!canExec}
                                        onClick={() => setCmdType(o.value)}
                                        className={`flex flex-col items-start p-3 rounded-xl border text-left transition-all ${isSelected
                                                ? 'border-cyan-500 bg-cyan-50 dark:bg-cyan-900/20 shadow-sm ring-1 ring-cyan-500'
                                                : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800/50 hover:border-slate-300 dark:hover:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800'
                                            } ${!canExec ? 'opacity-50 cursor-not-allowed' : ''}`}
                                    >
                                        <div className="flex items-center justify-between w-full">
                                            <span className={`text-sm font-medium ${isSelected ? 'text-cyan-700 dark:text-cyan-400 font-semibold' : 'text-slate-700 dark:text-slate-300'}`}>
                                                {o.label}
                                            </span>
                                            {o.destructive && (
                                                <AlertTriangle className={`w-3.5 h-3.5 shrink-0 ${isSelected ? 'text-rose-500' : 'text-slate-400'}`} />
                                            )}
                                        </div>
                                    </button>
                                );
                            })}
                        </div>
                    </div>

                    <div className="xl:col-span-6 bg-slate-50 dark:bg-slate-900/30 p-5 rounded-2xl border border-slate-200 dark:border-slate-700/60 flex flex-col">
                        <h4 className="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2 mb-4">
                            <Settings className="w-4 h-4 text-slate-400" /> Command Parameters
                        </h4>

                        <div className="space-y-4 flex-1">
                            {/* DECISION LOGIC SECTION */}
                            <div className="p-3 bg-white dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 rounded-xl space-y-3">
                                <div className="text-xs font-bold text-indigo-600 dark:text-indigo-400 uppercase tracking-widest mb-1 border-b border-slate-100 dark:border-slate-700 pb-1">Decision Logic & Auditability</div>

                                <div className="grid grid-cols-2 gap-3">
                                    <div>
                                        <label className="block text-[10px] text-slate-500 uppercase mb-1">Confidence Score</label>
                                        <select className="input w-full text-xs" value={fields.decision_confidence || 'High'} onChange={(e) => patch('decision_confidence', e.target.value)} disabled={!canExec}>
                                            <option value="High">High (Automated/Verified)</option>
                                            <option value="Medium">Medium (Suspicious)</option>
                                            <option value="Low">Low (Exploratory)</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label className="block text-[10px] text-slate-500 uppercase mb-1">D3FEND Category</label>
                                        <select className="input w-full text-xs" value={fields.d3fend_mapping || 'Process Eviction'} onChange={(e) => patch('d3fend_mapping', e.target.value)} disabled={!canExec}>
                                            <option value="Process Eviction">Process Eviction</option>
                                            <option value="File Eviction">File Eviction</option>
                                            <option value="Network Isolation">Network Isolation</option>
                                            <option value="Telemetry Collection">Telemetry Collection</option>
                                            <option value="System Configuration">System Configuration</option>
                                        </select>
                                    </div>
                                </div>
                                <div>
                                    <label className="block text-[10px] text-slate-500 uppercase mb-1">Reason / Justification</label>
                                    <input className="input w-full text-xs" placeholder="e.g. Mitigating ransomware behavioral pattern" value={fields.decision_reason || ''} onChange={(e) => patch('decision_reason', e.target.value)} disabled={!canExec} />
                                </div>
                            </div>

                            {/* ASSET CRITICALITY OVERRIDE */}
                            {isCriticalAsset && (
                                <div className="p-3 bg-rose-50 dark:bg-rose-900/10 border border-rose-200 dark:border-rose-800 rounded-xl">
                                    <label className="flex items-start gap-2 cursor-pointer">
                                        <input type="checkbox" className="mt-0.5 rounded border-rose-300 text-rose-600 focus:ring-rose-500" checked={fields.manual_approval === 'true'} onChange={(e) => patch('manual_approval', e.target.checked ? 'true' : 'false')} disabled={!canExec} />
                                        <div>
                                            <span className="text-xs font-bold text-rose-800 dark:text-rose-200 block mb-0.5">Asset Criticality Override Required</span>
                                            <span className="text-[10px] text-rose-600 dark:text-rose-400 leading-tight block">This asset ({_agent.hostname}) is classified as a Server/Domain Controller. Manual approval must be acknowledged to execute this response action.</span>
                                        </div>
                                    </label>
                                </div>
                            )}

                            {/* PARAMETERS SECTION */}
                            <div className="pt-2 border-t border-slate-200 dark:border-slate-700">
                                <label className="block text-xs font-semibold text-slate-500 uppercase mb-3">Action Parameters</label>

                                <div>
                                    <label className="block text-[10px] text-slate-500 uppercase mb-1">Timeout (seconds)</label>
                                    <input className="input w-full" type="number" min={0} max={3600} value={fields.timeout ?? '300'} onChange={(e) => patch('timeout', e.target.value)} disabled={!canExec} />
                                </div>

                                {(cmdType === 'kill_process' || cmdType === 'terminate_process') && (
                                    <div className="mt-3 space-y-3 p-3 bg-slate-100 dark:bg-slate-800/40 rounded-xl">
                                        <div>
                                            <label className="text-[10px] text-slate-500 uppercase">PID</label>
                                            <input className="input w-full mt-1" value={fields.pid || ''} onChange={(e) => patch('pid', e.target.value)} disabled={!canExec} />
                                        </div>
                                        <div>
                                            <label className="text-[10px] text-slate-500 uppercase">Process name (optional)</label>
                                            <input className="input w-full mt-1" value={fields.process_name || ''} onChange={(e) => patch('process_name', e.target.value)} disabled={!canExec} />
                                        </div>

                                        <div className="flex items-center justify-between gap-2 mt-2 pt-2 border-t border-slate-200 dark:border-slate-700">
                                            <label className="flex items-center gap-2 text-xs font-medium text-slate-700 dark:text-slate-300">
                                                <input type="checkbox" className="rounded" checked={fields.kill_tree === 'true'} onChange={(e) => patch('kill_tree', e.target.checked ? 'true' : 'false')} disabled={!canExec} />
                                                Kill Process Tree
                                            </label>
                                            <label className="flex items-center gap-2 text-xs font-medium text-emerald-600 dark:text-emerald-400" title="Retain Parent-Child Process Tree metadata to allow state restoration upon False Positive detection.">
                                                <input type="checkbox" className="rounded text-emerald-500 focus:ring-emerald-500" checked={fields.enable_rollback !== 'false'} onChange={(e) => patch('enable_rollback', e.target.checked ? 'true' : 'false')} disabled={!canExec} />
                                                Enable Action Rollback (Metadata tracking)
                                            </label>
                                        </div>
                                    </div>
                                )}

                                {cmdType === 'quarantine_file' && (
                                    <div className="mt-3 space-y-3 p-3 bg-slate-100 dark:bg-slate-800/40 rounded-xl">
                                        <div>
                                            <label className="text-[10px] text-slate-500 uppercase">File path</label>
                                            <input className="input w-full font-mono text-xs mt-1" placeholder="C:\path	oile" value={fields.path || ''} onChange={(e) => patch('path', e.target.value)} disabled={!canExec} />
                                        </div>
                                        <div className="flex items-center gap-2 mt-2 pt-2 border-t border-slate-200 dark:border-slate-700">
                                            <label className="flex items-center gap-2 text-xs font-medium text-emerald-600 dark:text-emerald-400" title="Preserve file hash and original path securely to allow restoration.">
                                                <input type="checkbox" className="rounded text-emerald-500 focus:ring-emerald-500" checked={fields.enable_rollback !== 'false'} onChange={(e) => patch('enable_rollback', e.target.checked ? 'true' : 'false')} disabled={!canExec} />
                                                Enable Action Rollback (Safe Quarantine)
                                            </label>
                                        </div>
                                    </div>
                                )}

                                {(cmdType === 'isolate_network' || cmdType === 'restore_network') && (
                                    <p className="text-xs text-slate-500 mt-3 p-3 bg-slate-100 dark:bg-slate-800/40 rounded-xl">No additional parameters needed. The platform will handle the isolation process automatically.</p>
                                )}

                                {(cmdType === 'block_ip' || cmdType === 'unblock_ip') && (
                                    <div className="mt-3 space-y-3">
                                        <label className="text-[10px] text-slate-500 uppercase">IP</label>
                                        <input className="input w-full" value={fields.ip || ''} onChange={(e) => patch('ip', e.target.value)} disabled={!canExec} />
                                        {cmdType === 'block_ip' && (
                                            <>
                                                <label className="text-[10px] text-slate-500 uppercase">Direction</label>
                                                <select className="input w-full" value={fields.direction || 'both'} onChange={(e) => patch('direction', e.target.value)} disabled={!canExec}>
                                                    <option value="both">both</option>
                                                    <option value="in">in</option>
                                                    <option value="out">out</option>
                                                </select>
                                            </>
                                        )}
                                    </div>
                                )}

                                {(cmdType === 'block_domain' || cmdType === 'unblock_domain') && (
                                    <div className="mt-3 space-y-3">
                                        <label className="text-[10px] text-slate-500 uppercase">Domain</label>
                                        <input className="input w-full" value={fields.domain || ''} onChange={(e) => patch('domain', e.target.value)} disabled={!canExec} />
                                    </div>
                                )}

                                {cmdType === 'run_cmd' && (
                                    <div className="mt-3 space-y-3">
                                        <label className="text-[10px] text-slate-500 uppercase">Select Command</label>
                                        <select className="input w-full font-mono text-xs" value={fields.cmd || ''} onChange={(e) => patch('cmd', e.target.value)} disabled={!canExec}>
                                            <option value="">Select a command...</option>
                                            {WHITELISTED_COMMANDS.map(cmd => (
                                                <option key={cmd.value} value={cmd.value}>{cmd.label}</option>
                                            ))}
                                        </select>
                                    </div>
                                )}



                                {(cmdType === 'collect_logs' || cmdType === 'collect_forensics') && (
                                    <div className="mt-3 space-y-3">
                                        <label className="text-[10px] text-slate-500 uppercase">Log types (comma-separated)</label>
                                        <input
                                            className="input w-full text-xs"
                                            placeholder="Security,System,Application,Sysmon,PowerShell"
                                            value={fields.log_types || ''}
                                            onChange={(e) => patch('log_types', e.target.value)}
                                            disabled={!canExec}
                                        />
                                        <label className="text-[10px] text-slate-500 uppercase">Time range</label>
                                        <input
                                            className="input w-full text-xs"
                                            placeholder="24h | 7d | Last 6 hours"
                                            value={fields.time_range || '24h'}
                                            onChange={(e) => patch('time_range', e.target.value)}
                                            disabled={!canExec}
                                        />
                                        <label className="text-[10px] text-slate-500 uppercase">Max events (per log)</label>
                                        <input className="input w-full" value={fields.max_events || '500'} onChange={(e) => patch('max_events', e.target.value)} disabled={!canExec} />
                                    </div>
                                )}

                                {(cmdType === 'scan_memory' || cmdType === 'scan_file') && (
                                    <div className="mt-3 space-y-3">
                                        <label className="text-[10px] text-slate-500 uppercase">File path</label>
                                        <input
                                            className="input w-full font-mono text-xs"
                                            placeholder="C:\path\to\file.exe"
                                            value={fields.file_path || ''}
                                            onChange={(e) => patch('file_path', e.target.value)}
                                            disabled={!canExec}
                                        />
                                    </div>
                                )}

                                {(cmdType === 'restart_agent' || cmdType === 'stop_agent' || cmdType === 'start_agent' || cmdType === 'restart_service') && (
                                    <p className="text-xs text-slate-500 mt-3 p-3 bg-slate-100 dark:bg-slate-800/40 rounded-xl">
                                        No additional parameters needed. The agent service will be managed automatically.
                                    </p>
                                )}

                                {(cmdType === 'restart_machine' || cmdType === 'shutdown_machine') && (
                                    <p className="text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 p-3 rounded-lg border border-amber-200 dark:border-amber-800/30 font-medium mt-3">You will be asked to confirm — these actions affect the whole host.</p>
                                )}
                            </div>
                        </div>

                        <div className="pt-5 mt-5 border-t border-slate-200 dark:border-slate-700/60 flex items-center justify-between">
                            {!canExec && <span className="text-xs text-rose-500 font-medium">Your role cannot execute remote commands.</span>}
                            <button
                                type="button"
                                disabled={!canExec || execMutation.isPending}
                                onClick={handleExecute}
                                className="ml-auto flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-sm disabled:opacity-50 transition-all"
                            >
                                {execMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Terminal className="w-4 h-4" />}
                                Send command
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <Modal
                isOpen={upgradeOpen}
                onClose={() => { if (!upgradeMutation.isPending) { setUpgradeOpen(false); setUpgradeStep('form'); setUpgradeErrors({}); } }}
                title="Upgrade Agent"
                footer={
                    <div className="flex items-center justify-between gap-3">
                        <button
                            type="button"
                            className="px-4 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40"
                            disabled={upgradeMutation.isPending}
                            onClick={() => { setUpgradeOpen(false); setUpgradeStep('form'); setUpgradeErrors({}); }}
                        >
                            Cancel
                        </button>
                        <button
                            type="button"
                            className="flex items-center gap-2 px-5 py-2 text-sm rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold disabled:opacity-50 transition-all shadow-sm"
                            disabled={upgradeMutation.isPending}
                            onClick={() => { if (validateUpgrade()) upgradeMutation.mutate(); }}
                        >
                            {upgradeMutation.isPending
                                ? <><Loader2 className="w-4 h-4 animate-spin" /> {upgradeStep === 'building' ? 'Building package…' : 'Pushing to agent…'}</>
                                : <><RefreshCw className="w-4 h-4" /> Start Upgrade</>
                            }
                        </button>
                    </div>
                }
            >
                <div className="space-y-5 p-1">
                    {/* Progress steps */}
                    {upgradeMutation.isPending && (
                        <div className="flex items-center gap-0 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700">
                            {(['Building', 'Pushing', 'Done'] as const).map((step, i) => {
                                const active = (i === 0 && upgradeStep === 'building') || (i === 1 && upgradeStep === 'pushing');
                                const done = (i === 0 && upgradeStep === 'pushing');
                                return (
                                    <div key={step} className={`flex-1 px-3 py-2 text-center text-xs font-semibold transition-colors ${active ? 'bg-cyan-500 text-white' : done ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300' : 'bg-slate-50 dark:bg-slate-800 text-slate-400'
                                        }`}>
                                        {done ? '✓ ' : active ? '⟳ ' : ''}{step}
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    {/* Server connectivity */}
                    <div className="space-y-3">
                        <p className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Server Connectivity</p>
                        {upgradeErrors.server && (
                            <p className="text-xs text-rose-600 dark:text-rose-400 bg-rose-50 dark:bg-rose-900/20 border border-rose-200 dark:border-rose-800/40 px-3 py-2 rounded-lg flex items-center gap-2">
                                <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> {upgradeErrors.server}
                            </p>
                        )}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                                <label className="block text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Server IP</label>
                                <input
                                    className={`input w-full text-sm font-mono ${upgradeErrors.server ? 'border-rose-400 ring-1 ring-rose-400' : ''
                                        }`}
                                    placeholder="e.g. 192.168.1.100"
                                    value={upgradeForm.serverIP}
                                    onChange={(e) => { setUpgradeForm(f => ({ ...f, serverIP: e.target.value })); setUpgradeErrors(prev => ({ ...prev, server: '' })); }}
                                    disabled={upgradeMutation.isPending}
                                />
                            </div>
                            <div>
                                <label className="block text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Server Domain</label>
                                <input
                                    className={`input w-full text-sm font-mono ${upgradeErrors.server ? 'border-rose-400 ring-1 ring-rose-400' : ''
                                        }`}
                                    placeholder="e.g. edr.company.com"
                                    value={upgradeForm.serverDomain}
                                    onChange={(e) => { setUpgradeForm(f => ({ ...f, serverDomain: e.target.value })); setUpgradeErrors(prev => ({ ...prev, server: '' })); }}
                                    disabled={upgradeMutation.isPending}
                                />
                            </div>
                        </div>
                        <p className="text-[10px] text-slate-400">Provide IP <em>or</em> Domain — at least one is required. Domain takes priority if both are given.</p>
                        <div>
                            <label className="block text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Server Port</label>
                            <input
                                className={`input w-full text-sm font-mono ${upgradeErrors.port ? 'border-rose-400 ring-1 ring-rose-400' : ''
                                    }`}
                                value={upgradeForm.serverPort}
                                onChange={(e) => { setUpgradeForm(f => ({ ...f, serverPort: e.target.value })); setUpgradeErrors(prev => ({ ...prev, port: '' })); }}
                                disabled={upgradeMutation.isPending}
                            />
                            {upgradeErrors.port && <p className="text-[10px] text-rose-500 mt-0.5">{upgradeErrors.port}</p>}
                        </div>
                    </div>

                    {/* Sysmon status */}
                    <div className="pt-3 border-t border-slate-200 dark:border-slate-700">
                        <p className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Sysmon</p>
                        {(_agent.sysmon_installed && _agent.sysmon_running) ? (
                            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800/40">
                                <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                                <div>
                                    <p className="text-xs font-semibold text-emerald-700 dark:text-emerald-300">Sysmon is installed and running</p>
                                    <p className="text-[10px] text-emerald-600 dark:text-emerald-400">No re-installation needed — Sysmon will be preserved during upgrade.</p>
                                </div>
                            </div>
                        ) : (
                            <label className="flex items-start gap-3 cursor-pointer p-3 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                                <input
                                    type="checkbox"
                                    className="rounded mt-0.5 text-cyan-500 focus:ring-cyan-500"
                                    checked={upgradeForm.installSysmon}
                                    onChange={(e) => setUpgradeForm(f => ({ ...f, installSysmon: e.target.checked }))}
                                    disabled={upgradeMutation.isPending}
                                />
                                <div>
                                    <p className="text-sm font-medium text-slate-700 dark:text-slate-200">Install Sysmon with this upgrade</p>
                                    <p className="text-[10px] text-slate-400">Bundles the Sysmon installer and default config into the package.</p>
                                </div>
                            </label>
                        )}
                    </div>
                </div>
            </Modal>

            <div>
                <h3 className="text-sm font-bold text-slate-800 dark:text-slate-100 mb-2">Command history</h3>
                {cmdsLoading ? (
                    <Loader2 className="w-8 h-8 animate-spin text-cyan-500" />
                ) : (
                    <>
                        <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                            <table className="w-full text-left text-xs">
                                <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 uppercase">
                                    <tr>
                                        <th className="p-2">Status</th>
                                        <th className="p-2">Type & Logic</th>
                                        <th className="p-2">D3FEND Mapping</th>
                                        <th className="p-2">Issued</th>
                                        <th className="p-2">By</th>
                                        <th className="p-2">Output / error</th>
                                        <th className="p-2">Rollback</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {cmds.length === 0 ? (
                                        <tr><td colSpan={7} className="p-4 text-slate-500">No commands</td></tr>
                                    ) : (
                                        cmds.slice((cmdPage - 1) * CMD_PAGE_SIZE, cmdPage * CMD_PAGE_SIZE).map((c) => (
                                            <tr key={c.id} className="border-t border-slate-100 dark:border-slate-800 align-top">
                                                <td className="p-2 whitespace-nowrap font-medium text-slate-700 dark:text-slate-200">{c.status}</td>
                                                <td className="p-2">
                                                    <div className="font-mono text-cyan-600 dark:text-cyan-400 font-semibold">{c.command_type}</div>
                                                    <div className="text-[10px] text-slate-500 mt-1 max-w-[200px] leading-tight">
                                                        Reason: {c.parameters?.decision_reason || 'Manual execution'} <br />
                                                        Confidence: {c.parameters?.decision_confidence || 'N/A'}
                                                    </div>
                                                </td>
                                                <td className="p-2">
                                                    <span className="bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400 px-1.5 py-0.5 rounded border border-indigo-200 dark:border-indigo-800/50 whitespace-nowrap">
                                                        {c.parameters?.d3fend_mapping || 'Unmapped'}
                                                    </span>
                                                </td>
                                                <td className="p-2 whitespace-nowrap text-slate-600 dark:text-slate-400">{new Date(c.issued_at).toLocaleString()}</td>
                                                <td className="p-2 max-w-[140px] break-all">{c.issued_by_user || c.issued_by || '—'}</td>
                                                <td className="p-2 max-w-md">
                                                    {c.error_message ? (
                                                        <span className="text-rose-600 dark:text-rose-400">{c.error_message}</span>
                                                    ) : (
                                                        commandHistoryOutputCell(c, agentId)
                                                    )}
                                                </td>
                                                <td className="p-2">
                                                    {(c.command_type === 'kill_process' || c.command_type === 'terminate_process' || c.command_type === 'quarantine_file') && c.status === 'completed' ? (
                                                        <button className="text-[10px] text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/20 hover:bg-emerald-100 dark:hover:bg-emerald-900/40 border border-emerald-200 dark:border-emerald-800/40 px-2 py-1 rounded transition-colors font-medium">
                                                            Rollback Action
                                                        </button>
                                                    ) : (
                                                        <span className="text-[10px] text-slate-400">—</span>
                                                    )}
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                        {cmds.length > CMD_PAGE_SIZE && (
                            <div className="flex items-center justify-between gap-3 pt-3 mt-3">
                                <button type="button" className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40" disabled={cmdPage <= 1} onClick={() => setCmdPage((p) => Math.max(1, p - 1))}>
                                    <ChevronLeft className="w-4 h-4" /> Previous
                                </button>
                                <span className="text-xs text-slate-500">Page <span className="font-semibold text-slate-700 dark:text-slate-200">{cmdPage}</span> of {Math.max(1, Math.ceil(cmds.length / CMD_PAGE_SIZE))}</span>
                                <button type="button" className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40" disabled={cmdPage >= Math.max(1, Math.ceil(cmds.length / CMD_PAGE_SIZE))} onClick={() => setCmdPage((p) => Math.min(Math.max(1, Math.ceil(cmds.length / CMD_PAGE_SIZE)), p + 1))}>
                                    Next <ChevronRight className="w-4 h-4" />
                                </button>
                            </div>
                        )}
                    </>
                )}
            </div>
        </div>
    );
}
function QuarantineTab({
    items,
    loading,
    canExec,
    onDecision,
    busy,
    online,
}: {
    items: QuarantineItem[];
    loading: boolean;
    canExec: boolean;
    onDecision: (id: string, d: 'acknowledge' | 'restore' | 'delete') => void;
    busy: boolean;
    online: boolean;
}) {
    return (
        <div className="space-y-4 animate-slide-up-fade">
            <div className="flex items-center gap-2 text-slate-600 dark:text-slate-400 text-sm">
                <HardDrive className="w-4 h-4" />
                Files that have been quarantined on this endpoint for security analysis.
            </div>
            {loading ? <Loader2 className="w-8 h-8 animate-spin text-cyan-500" /> : (
                <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
                    <table className="w-full text-left text-xs">
                        <thead className="bg-slate-100 dark:bg-slate-800/80 text-slate-600 uppercase">
                            <tr>
                                <th className="p-2">Original</th>
                                <th className="p-2">Quarantine</th>
                                <th className="p-2">Threat</th>
                                <th className="p-2">State</th>
                                <th className="p-2">Updated</th>
                                <th className="p-2">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {items.length === 0 ? (
                                <tr><td colSpan={6} className="p-4 text-slate-500">No quarantine items</td></tr>
                            ) : (
                                items.map((q) => (
                                    <tr key={q.id} className="border-t border-slate-100 dark:border-slate-800 align-top">
                                        <td className="p-2 font-mono break-all max-w-[200px]">{q.original_path}</td>
                                        <td className="p-2 font-mono break-all max-w-[200px]">{q.quarantine_path}</td>
                                        <td className="p-2">{q.threat_name || '—'}</td>
                                        <td className="p-2">{q.state}</td>
                                        <td className="p-2 whitespace-nowrap">{new Date(q.updated_at).toLocaleString()}</td>
                                        <td className="p-2">
                                            <div className="flex flex-wrap gap-1">
                                                <button
                                                    type="button"
                                                    className="px-2 py-1 rounded border border-slate-200 dark:border-slate-600 text-[10px] font-semibold hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
                                                    disabled={!canExec || busy || q.state !== 'quarantined'}
                                                    onClick={() => onDecision(q.id, 'acknowledge')}
                                                >
                                                    Ack
                                                </button>
                                                <button
                                                    type="button"
                                                    className="px-2 py-1 rounded border border-emerald-500/40 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-50"
                                                    disabled={!canExec || busy || !online || (q.state !== 'quarantined' && q.state !== 'acknowledged')}
                                                    title={!online ? 'Agent must be online' : undefined}
                                                    onClick={() => onDecision(q.id, 'restore')}
                                                >
                                                    Restore
                                                </button>
                                                <button
                                                    type="button"
                                                    className="px-2 py-1 rounded border border-rose-500/40 text-[10px] font-semibold text-rose-700 dark:text-rose-400 hover:bg-rose-500/10 disabled:opacity-50"
                                                    disabled={!canExec || busy || !online || (q.state !== 'quarantined' && q.state !== 'acknowledged')}
                                                    title={!online ? 'Agent must be online' : undefined}
                                                    onClick={() => onDecision(q.id, 'delete')}
                                                >
                                                    Delete
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

type TimelineRow =
    | { kind: 'alert'; at: number; id: string; alert: Alert }
    | { kind: 'event'; at: number; id: string; ev: CmEventSummary };

function ActivityTab({
    events,
    alerts,
    alertsLoading,
    canViewAlerts,
    agentId,
}: {
    events: CmEventSummary[];
    alerts: Alert[];
    alertsLoading: boolean;
    canViewAlerts: boolean;
    agentId: string;
}) {
    const [detailId, setDetailId] = useState<string | null>(null);
    const [actPage, setActPage] = useState(1);
    const ACT_PAGE_SIZE = 20;

    // Fetch network events to merge into the activity timeline
    const { data: netPayload } = useQuery({
        queryKey: ['activity-network-events', agentId],
        queryFn: () => eventsApi.search({
            filters: [
                { field: 'agent_id', operator: 'equals', value: agentId },
                { field: 'event_type', operator: 'equals', value: 'network' },
            ],
            logic: 'AND',
            time_range: {
                from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
                to: new Date().toISOString(),
            },
            limit: 50,
            offset: 0,
        }),
        enabled: !!agentId && canViewAlerts,
        staleTime: 30_000,
    });
    const networkEvents = netPayload?.data ?? [];

    const merged = useMemo(() => {
        const rows: TimelineRow[] = [];
        if (canViewAlerts) {
            for (const a of alerts) {
                const ts = new Date(a.timestamp || a.updated_at || a.created_at).getTime();
                rows.push({
                    kind: 'alert',
                    at: Number.isFinite(ts) ? ts : 0,
                    id: `alert-${a.id}`,
                    alert: a,
                });
            }
        }
        for (const e of events) {
            const ts = new Date(e.timestamp).getTime();
            rows.push({ kind: 'event', at: Number.isFinite(ts) ? ts : 0, id: `ev-${e.id}`, ev: e });
        }
        // Merge network events
        for (const n of networkEvents) {
            const ts = new Date(n.timestamp).getTime();
            rows.push({ kind: 'event', at: Number.isFinite(ts) ? ts : 0, id: `net-${n.id}`, ev: n });
        }
        rows.sort((a, b) => b.at - a.at);
        return rows;
    }, [alerts, events, networkEvents, canViewAlerts]);

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-sm font-bold text-slate-800 dark:text-slate-100 mb-2 flex items-center gap-2">
                    <Activity className="w-4 h-4" /> Activity Timeline
                </h3>
                {!canViewAlerts && (
                    <p className="text-sm text-amber-700 dark:text-amber-300 mb-2">
                        Detection alerts require additional permissions. Server events are still shown below.
                    </p>
                )}
                {alertsLoading && canViewAlerts ? (
                    <Loader2 className="w-6 h-6 animate-spin text-cyan-500" />
                ) : merged.length === 0 ? (
                    <p className="text-sm text-slate-500">
                        No activity recorded yet. Events and alerts will appear here as the agent reports data.
                    </p>
                ) : (
                    <>
                        <ul className="space-y-2">
                            {merged.slice((actPage - 1) * ACT_PAGE_SIZE, actPage * ACT_PAGE_SIZE).map((r) =>
                                r.kind === 'alert' ? (
                                    <li
                                        key={r.id}
                                        className="flex items-start gap-3 text-sm border border-slate-200 dark:border-slate-700 rounded-lg p-3"
                                    >
                                        {r.alert.severity === 'critical' || r.alert.severity === 'high' ? (
                                            <XCircle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
                                        ) : (
                                            <CheckCircle2 className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
                                        )}
                                        <div>
                                            <div className="font-medium text-slate-900 dark:text-slate-100">
                                                {r.alert.rule_title || r.alert.rule_id || 'Alert'}
                                            </div>
                                            <div className="text-xs text-slate-500">
                                                {new Date(r.at).toLocaleString()} · Sigma · {r.alert.severity || '—'}
                                            </div>
                                            <Link className="text-xs text-cyan-600 hover:underline mt-1 inline-block" to="/alerts">
                                                Open Alerts
                                            </Link>
                                        </div>
                                    </li>
                                ) : (
                                    <li
                                        key={r.id}
                                        role="button"
                                        tabIndex={0}
                                        className="flex items-start gap-3 text-sm border border-slate-200 dark:border-slate-700 rounded-lg p-3 cursor-pointer hover:bg-slate-50/90 dark:hover:bg-slate-800/50 transition-colors"
                                        onClick={() => setDetailId(r.ev.id)}
                                        onKeyDown={(ev) => {
                                            if (ev.key === 'Enter' || ev.key === ' ') {
                                                ev.preventDefault();
                                                setDetailId(r.ev.id);
                                            }
                                        }}
                                    >
                                        {r.ev.event_type === 'network'
                                            ? <Network className="w-4 h-4 text-indigo-500 shrink-0 mt-0.5" />
                                            : <Network className="w-4 h-4 text-cyan-500 shrink-0 mt-0.5" />
                                        }
                                        <div className="min-w-0 flex-1">
                                            <div className="font-mono text-xs text-cyan-700 dark:text-cyan-300">{r.ev.event_type}</div>
                                            <div className="text-slate-800 dark:text-slate-100">{r.ev.summary}</div>
                                            <div className="text-xs text-slate-500">{new Date(r.at).toLocaleString()} · Server event · Click to view details</div>
                                        </div>
                                    </li>
                                )
                            )}
                        </ul>
                        {merged.length > ACT_PAGE_SIZE && (
                            <div className="flex items-center justify-between gap-3 pt-3 border-t border-slate-200 dark:border-slate-700 mt-3">
                                <button type="button" className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40" disabled={actPage <= 1} onClick={() => setActPage((p) => Math.max(1, p - 1))}>
                                    <ChevronLeft className="w-4 h-4" /> Previous
                                </button>
                                <span className="text-xs text-slate-500">Page <span className="font-semibold text-slate-700 dark:text-slate-200">{actPage}</span> of {Math.max(1, Math.ceil(merged.length / ACT_PAGE_SIZE))}</span>
                                <button type="button" className="inline-flex items-center gap-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-medium disabled:opacity-40" disabled={actPage >= Math.max(1, Math.ceil(merged.length / ACT_PAGE_SIZE))} onClick={() => setActPage((p) => Math.min(Math.max(1, Math.ceil(merged.length / ACT_PAGE_SIZE)), p + 1))}>
                                    Next <ChevronRight className="w-4 h-4" />
                                </button>
                            </div>
                        )}
                    </>
                )}
            </div>

            <EventDetailModal
                eventId={detailId}
                onClose={() => setDetailId(null)}
                fetchEnabled={canViewAlerts}
            />
        </div>
    );
}


