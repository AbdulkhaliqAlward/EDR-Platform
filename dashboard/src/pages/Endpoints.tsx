import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authApi } from '../api/client';
import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
    Search, Monitor, Wifi, WifiOff, AlertTriangle, ChevronDown,
    Play, Shield, FileX, Folder, RefreshCw, X, Check, Clock, Loader2, Power, ShieldAlert, Square, Zap,
    LayoutGrid, List, PanelLeft, Building2, Layers, UserPlus, Terminal,
    Ban, ShieldOff, Globe, Globe2, Download, Settings, Trash2, ArchiveRestore, Wrench, PackageSearch,
} from 'lucide-react';
import {
    agentsApi,
    type Agent,
    type CommandType,
    type CommandRequest,
} from '../api/client';
import { Modal, useToast, SkeletonTable } from '../components';
import { useDebounce } from '../hooks/useDebounce';
import { formatRelativeTime, getEffectiveStatus } from '../utils/agentDisplay';

// Command definitions
const COMMAND_DEFINITIONS: Record<CommandType, { label: string; icon: typeof Play; description: string; color: string }> = {
    kill_process: { label: 'Kill Process', icon: X, description: 'Terminate a running process', color: 'text-red-500' },
    terminate_process: { label: 'Terminate Process', icon: X, description: 'Alternate name for kill/terminate pipeline', color: 'text-red-500' },
    quarantine_file: { label: 'Quarantine File', icon: FileX, description: 'Move file to quarantine', color: 'text-orange-500' },
    collect_logs: { label: 'Collect Logs', icon: Folder, description: 'Gather forensic logs', color: 'text-blue-500' },
    collect_forensics: { label: 'Collect Forensics', icon: PackageSearch, description: 'Collect logs, hashes, and artifacts', color: 'text-blue-600' },
    update_policy: { label: 'Update Policy', icon: Shield, description: 'Apply new security policy', color: 'text-indigo-500' },
    restart_agent: { label: 'Restart Agent', icon: RefreshCw, description: 'Restart MITRAS agent service', color: 'text-amber-500' },
    restart_service: { label: 'Restart Service', icon: Wrench, description: 'Restart a named OS/agent service', color: 'text-amber-600' },
    stop_agent: { label: 'Stop Agent', icon: Square, description: 'Stop the MITRAS agent service', color: 'text-red-500' },
    start_agent: { label: 'Start Agent', icon: Play, description: 'Start / re-enable the MITRAS agent service', color: 'text-green-500' },
    restart_machine: { label: 'Restart Machine', icon: RefreshCw, description: 'Reboot the endpoint machine (OS-level restart)', color: 'text-red-500' },
    shutdown_machine: { label: 'Shutdown Machine', icon: Power, description: 'Power off the endpoint machine (OS-level shutdown)', color: 'text-red-700' },
    isolate_network: { label: 'Isolate Network', icon: WifiOff, description: 'Block all network traffic', color: 'text-red-600' },
    unisolate_network: { label: 'Un-isolate Network', icon: Wifi, description: 'Lift network isolation', color: 'text-green-500' },
    restore_network: { label: 'Restore Network', icon: Wifi, description: 'Restore network connectivity', color: 'text-green-500' },
    scan_file: { label: 'Scan File', icon: Search, description: 'Scan a specific file', color: 'text-purple-500' },
    scan_memory: { label: 'Scan Memory', icon: Monitor, description: 'Perform memory analysis', color: 'text-cyan-500' },
    run_cmd: { label: 'Run Command', icon: Terminal, description: 'Run whitelisted diagnostic command', color: 'text-slate-600' },
    block_ip: { label: 'Block IP', icon: Ban, description: 'Add firewall block for an IP', color: 'text-rose-600' },
    unblock_ip: { label: 'Unblock IP', icon: ShieldOff, description: 'Remove IP block', color: 'text-emerald-600' },
    block_domain: { label: 'Block Domain', icon: Globe, description: 'Block DNS/domain', color: 'text-rose-600' },
    unblock_domain: { label: 'Unblock Domain', icon: Globe2, description: 'Remove domain block', color: 'text-emerald-600' },
    update_signatures: { label: 'Update Signatures', icon: Download, description: 'Pull signature / intel bundle', color: 'text-indigo-500' },
    update_config: { label: 'Update Config', icon: Settings, description: 'Hot-reload agent configuration key', color: 'text-slate-600' },
    update_vuln_config: { label: 'Update Vuln Config', icon: Settings, description: 'Update vulnerability scanner and response settings', color: 'text-indigo-500' },
    restore_quarantine_file: { label: 'Restore Quarantine File', icon: ArchiveRestore, description: 'Restore file from quarantine', color: 'text-green-600' },
    delete_quarantine_file: { label: 'Delete Quarantine File', icon: Trash2, description: 'Permanently delete quarantined file', color: 'text-red-600' },
    custom: { label: 'Custom Command', icon: Zap, description: 'Execute custom command', color: 'text-slate-500' },
    update_filter_policy: { label: 'Update Filter Policy', icon: Shield, description: 'Push new filtering rules to agent', color: 'text-teal-500' },
    enable_sysmon: { label: 'Enable Sysmon', icon: Shield, description: 'Install Sysmon and enable Operational channel', color: 'text-cyan-600' },
    disable_sysmon: { label: 'Disable Sysmon', icon: ShieldOff, description: 'Disable Sysmon channel and uninstall', color: 'text-slate-500' },
    update_agent: { label: 'Upgrade Agent', icon: Download, description: 'In-place upgrade of the agent binary', color: 'text-cyan-600' },
    uninstall_agent: { label: 'Uninstall Agent', icon: Trash2, description: 'Server-authorised permanent removal (RBAC + audit)', color: 'text-rose-600' },
};

// Status badge component
const StatusBadge = React.memo(function StatusBadge({ status }: { status: Agent['status'] }) {
    const config = {
        online: { label: 'Online', color: 'badge-online', icon: Wifi },
        offline: { label: 'Offline', color: 'badge-offline', icon: WifiOff },
        degraded: { label: 'Degraded', color: 'badge-degraded', icon: AlertTriangle },
        pending: { label: 'Pending', color: 'badge-warning', icon: Clock },
        suspended: { label: 'Suspended', color: 'badge-danger', icon: X },
        pending_uninstall: { label: 'Uninstalling…', color: 'badge-warning', icon: Trash2 },
        uninstalled: { label: 'Uninstalled', color: 'badge-offline', icon: Trash2 },
    } as const;

    const { label, color, icon: Icon } = config[status as keyof typeof config] || config.offline;

    return (
        <span className={`badge ${color} flex items-center gap-1`}>
            <Icon className="w-3 h-3" />
            {label}
        </span>
    );
});

// Isolation badge — red warning indicator
const IsolationBadge = React.memo(function IsolationBadge({ isIsolated }: { isIsolated?: boolean }) {
    if (!isIsolated) return null;
    return (
        <span className="badge flex items-center gap-1 text-xs font-bold px-2 py-0.5 rounded-full bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400 border border-red-300 dark:border-red-700 animate-pulse">
            <ShieldAlert className="w-3 h-3" />
            ISOLATED
        </span>
    );
});

// Health Score Bar
const HealthScoreBar = React.memo(function HealthScoreBar({ score }: { score: number }) {
    const getColor = () => {
        if (score >= 80) return 'bg-green-500';
        if (score >= 60) return 'bg-amber-500';
        return 'bg-red-500';
    };

    return (
        <div className="flex items-center gap-2">
            <div className="health-bar w-16">
                <div
                    className={`health-bar-fill ${getColor()}`}
                    style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
                />
            </div>
            <span className="text-sm text-slate-600 dark:text-slate-300">{score.toFixed(0)}%</span>
        </div>
    );
});

// OS Icon
const OSIcon = React.memo(function OSIcon({ os }: { os: string }) {
    const icons: Record<string, string> = {
        windows: '🖥️',
        linux: '🐧',
        macos: '🍎',
    };
    return <span className="text-lg">{icons[os?.toLowerCase()] || '💻'}</span>;
});

// Command Execution Modal
function CommandExecutionModal({
    isOpen,
    onClose,
    agent,
    commandType,
}: {
    isOpen: boolean;
    onClose: () => void;
    agent: Agent | null;
    commandType: CommandType | null;
}) {
    const queryClient = useQueryClient();
    const { showToast } = useToast();
    const [parameters, setParameters] = useState<Record<string, string>>({});
    const [status, setStatus] = useState<'idle' | 'executing' | 'completed' | 'failed'>('idle');

    // Sensible defaults so one-click "Collect" and memory snapshot work without empty params.
    useEffect(() => {
        if (!isOpen || !commandType) return;
        if (commandType === 'collect_logs') {
            setParameters({ log_types: 'security', time_range: '24h' });
        } else if (commandType === 'scan_memory') {
            setParameters({ log_types: 'security,system', time_range: '24h' });
        }
    }, [isOpen, commandType]);

    const executeMutation = useMutation({
        mutationFn: async ({ agentId, command }: { agentId: string; command: CommandRequest }) => {
            return agentsApi.executeCommand(agentId, command);
        },
        onSuccess: (data, variables) => {
            setStatus('completed');
            showToast(`Command queued successfully (ID: ${data.command_id})`, 'success');
            // Immediate invalidation for status changes that DB updates right away
            queryClient.invalidateQueries({ queryKey: ['agents'] });
            queryClient.invalidateQueries({ queryKey: ['agent-commands', variables.agentId] });
            // Isolation commands take 5-15s for the agent to respond with SUCCESS.
            // The backend only writes is_isolated AFTER the agent's gRPC ACK arrives.
            // Schedule a delayed re-fetch so the UI reflects the actual state.
            const cmdType = variables.command.command_type;
            if (cmdType === 'isolate_network' || cmdType === 'restore_network') {
                setTimeout(() => {
                    queryClient.invalidateQueries({ queryKey: ['agents'] });
                }, 10000);
                setTimeout(() => {
                    queryClient.invalidateQueries({ queryKey: ['agents'] });
                }, 20000);
            }
        },
        onError: (error: Error) => {
            setStatus('failed');
            showToast(`Command failed: ${error.message}`, 'error');
        },
    });

    const handleExecute = () => {
        if (!agent || !commandType) return;

        // Force 'confirm: true' for dangerous OS commands
        const finalParams = { ...parameters };
        if (commandType === 'restart_machine' || commandType === 'shutdown_machine') {
            finalParams['confirm'] = 'true';
        }
        if (commandType === 'collect_logs') {
            const lt = (finalParams.log_types || '').trim();
            if (!lt) {
                showToast('Select at least one log type (or use defaults by re-opening this dialog).', 'error');
                return;
            }
        }
        if (commandType === 'custom') {
            if (!(finalParams.cmd || '').trim()) {
                showToast('Enter a command (e.g. ipconfig /all). Only whitelisted diagnostics are allowed on the agent.', 'error');
                return;
            }
        }

        const forensicCmd =
            commandType === 'collect_logs' ||
            commandType === 'scan_memory' ||
            commandType === 'scan_file' ||
            commandType === 'collect_forensics';
        const timeoutSec = forensicCmd ? 900 : 300;

        setStatus('executing');
        executeMutation.mutate({
            agentId: agent.id,
            command: {
                command_type: commandType,
                parameters: finalParams,
                timeout: timeoutSec,
            },
        });
    };

    const handleClose = () => {
        setStatus('idle');
        setParameters({});
        onClose();
    };

    if (!agent || !commandType) return null;

    const cmdDef = COMMAND_DEFINITIONS[commandType];

    // Parameter fields based on command type
    const renderParameterFields = () => {
        switch (commandType) {
            case 'kill_process':
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Process ID (PID)
                            </label>
                            <input
                                type="text"
                                className="input"
                                placeholder="e.g., 1234"
                                value={parameters.pid || ''}
                                onChange={(e) => setParameters({ ...parameters, pid: e.target.value })}
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Process Name (optional)
                            </label>
                            <input
                                type="text"
                                className="input"
                                placeholder="e.g., malware.exe"
                                value={parameters.process_name || ''}
                                onChange={(e) => setParameters({ ...parameters, process_name: e.target.value })}
                            />
                        </div>
                    </div>
                );

            case 'quarantine_file':
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                File Path
                            </label>
                            <input
                                type="text"
                                className="input"
                                placeholder="C:\Users\...\malware.exe"
                                value={parameters.file_path || ''}
                                onChange={(e) => setParameters({ ...parameters, file_path: e.target.value })}
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                SHA256 Hash (optional)
                            </label>
                            <input
                                type="text"
                                className="input font-mono text-xs"
                                placeholder="abc123..."
                                value={parameters.hash_sha256 || ''}
                                onChange={(e) => setParameters({ ...parameters, hash_sha256: e.target.value })}
                            />
                        </div>
                    </div>
                );

            case 'isolate_network':
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Allow List (comma-separated IPs/domains)
                            </label>
                            <input
                                type="text"
                                className="input"
                                placeholder="10.0.0.1, management-server.local"
                                value={parameters.allow_list || ''}
                                onChange={(e) => setParameters({ ...parameters, allow_list: e.target.value })}
                            />
                            <p className="text-xs text-slate-500 mt-1">
                                Device will only communicate with these addresses
                            </p>
                        </div>
                    </div>
                );

            case 'collect_logs':
                return (
                    <div className="space-y-3">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Log Types
                            </label>
                            <div className="flex flex-wrap gap-2">
                                {['security', 'sysmon', 'application', 'powershell'].map((type) => (
                                    <label key={type} className="flex items-center gap-1.5">
                                        <input
                                            type="checkbox"
                                            checked={(parameters.log_types || '').includes(type)}
                                            onChange={(e) => {
                                                const current = (parameters.log_types || '').split(',').filter(Boolean);
                                                const updated = e.target.checked
                                                    ? [...current, type]
                                                    : current.filter(t => t !== type);
                                                setParameters({ ...parameters, log_types: updated.join(',') });
                                            }}
                                            className="rounded"
                                        />
                                        <span className="text-sm capitalize">{type}</span>
                                    </label>
                                ))}
                            </div>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Time Range
                            </label>
                            <select
                                className="input"
                                value={parameters.time_range || '24h'}
                                onChange={(e) => setParameters({ ...parameters, time_range: e.target.value })}
                            >
                                <option value="1h">Last 1 hour</option>
                                <option value="6h">Last 6 hours</option>
                                <option value="24h">Last 24 hours</option>
                                <option value="7d">Last 7 days</option>
                            </select>
                        </div>
                    </div>
                );

            case 'scan_file':
                return (
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                            File Path to Scan
                        </label>
                        <input
                            type="text"
                            className="input"
                            placeholder="C:\Users\...\suspicious.exe"
                            value={parameters.file_path || ''}
                            onChange={(e) => setParameters({ ...parameters, file_path: e.target.value })}
                        />
                    </div>
                );

            case 'custom':
                return (
                    <div className="space-y-2">
                        <p className="text-xs text-amber-800 dark:text-amber-200/90 bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-lg p-2.5">
                            The agent runs <strong>only whitelisted</strong> diagnostics (no cmd.exe): ipconfig, netstat, ping, tracert, pathping, nslookup, whoami, hostname, systeminfo, tasklist, arp, route.
                        </p>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                            Executable + arguments
                        </label>
                        <input
                            type="text"
                            className="input font-mono text-xs"
                            placeholder="ipconfig /all"
                            value={parameters.cmd || ''}
                            onChange={(e) => setParameters({ ...parameters, cmd: e.target.value })}
                        />
                    </div>
                );

            case 'scan_memory':
                return (
                    <div className="space-y-3">
                        <p className="text-xs text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800/80 rounded-lg p-2.5 border border-slate-200 dark:border-slate-700">
                            Pulls a <strong>forensic event sample</strong> from the endpoint (Security + System by default) — not a full physical memory image.
                            Add Sysmon below if it is installed.
                        </p>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Log channels (comma-separated keys)
                            </label>
                            <input
                                type="text"
                                className="input font-mono text-xs"
                                placeholder="security,system"
                                value={parameters.log_types || ''}
                                onChange={(e) => setParameters({ ...parameters, log_types: e.target.value })}
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                                Time range
                            </label>
                            <select
                                className="input"
                                value={parameters.time_range || '24h'}
                                onChange={(e) => setParameters({ ...parameters, time_range: e.target.value })}
                            >
                                <option value="1h">Last 1 hour</option>
                                <option value="6h">Last 6 hours</option>
                                <option value="24h">Last 24 hours</option>
                                <option value="7d">Last 7 days</option>
                            </select>
                        </div>
                    </div>
                );

            case 'restart_machine':
                return (
                    <div className="space-y-3">
                        <div className="p-3 bg-red-50 dark:bg-red-950/40 border border-red-300 dark:border-red-800 rounded-lg">
                            <p className="text-sm font-bold text-red-700 dark:text-red-300 flex items-center gap-2">
                                <AlertTriangle className="w-4 h-4" />
                                Critical Action Warning
                            </p>
                            <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                                This will forcibly reboot the endpoint at the OS level. Any unsaved work on the target machine will be lost.
                            </p>
                        </div>
                        {/* Hidden input to satisfy React state, but we'll also force it on Mount/Execute */}
                        <p className="text-xs text-slate-500">
                            By clicking Execute, you confirm this action. (Safety parameter <code>confirm="true"</code> will be sent to the agent).
                        </p>
                    </div>
                );

            case 'shutdown_machine':
                return (
                    <div className="space-y-3">
                        <div className="p-3 bg-red-50 dark:bg-red-950/40 border border-red-300 dark:border-red-800 rounded-lg">
                            <p className="text-sm font-bold text-red-700 dark:text-red-300 flex items-center gap-2">
                                <AlertTriangle className="w-4 h-4" />
                                Critical Action Warning
                            </p>
                            <p className="text-xs text-red-600 dark:text-red-400 mt-1">
                                This will completely power off the endpoint. You will NOT be able to start it back up from this console.
                            </p>
                        </div>
                        <p className="text-xs text-slate-500">
                            By clicking Execute, you confirm this action. (Safety parameter <code>confirm="true"</code> will be sent to the agent).
                        </p>
                    </div>
                );

            default:
                return (
                    <p className="text-sm text-slate-500">
                        No additional parameters required for this command.
                    </p>
                );
        }
    };

    return (
        <Modal
            isOpen={isOpen}
            onClose={handleClose}
            title={`${cmdDef.label} - ${agent.hostname}`}
            size="md"
        >
            <div className="space-y-4 animate-slide-up-fade">
                {/* Status indicator */}
                {status !== 'idle' && (
                    <div className={`p-3 rounded-lg flex items-center gap-3 ${status === 'executing' ? 'bg-blue-50 dark:bg-blue-900/20' :
                        status === 'completed' ? 'bg-green-50 dark:bg-green-900/20' :
                            'bg-red-50 dark:bg-red-900/20'
                        }`}>
                        {status === 'executing' && <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />}
                        {status === 'completed' && <Check className="w-5 h-5 text-green-500" />}
                        {status === 'failed' && <X className="w-5 h-5 text-red-500" />}
                        <span className="text-sm font-medium">
                            {status === 'executing' && 'Executing command...'}
                            {status === 'completed' && 'Command queued successfully'}
                            {status === 'failed' && 'Command failed'}
                        </span>
                    </div>
                )}

                {/* Target info */}
                <div className="p-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg">
                    <div className="flex items-center gap-3">
                        <OSIcon os={agent.os_type} />
                        <div>
                            <p className="font-medium text-slate-900 dark:text-white">{agent.hostname}</p>
                            <p className="text-xs text-slate-500">{agent.os_version}</p>
                        </div>
                        <StatusBadge status={agent.status} />
                    </div>
                </div>

                {/* Command description */}
                <div className="flex items-start gap-3 p-3 border border-slate-200 dark:border-slate-700 rounded-lg">
                    <cmdDef.icon className={`w-5 h-5 mt-0.5 ${cmdDef.color}`} />
                    <div>
                        <p className="font-medium text-slate-900 dark:text-white">{cmdDef.label}</p>
                        <p className="text-sm text-slate-500">{cmdDef.description}</p>
                    </div>
                </div>

                {/* Parameters */}
                {status === 'idle' && renderParameterFields()}

                {/* Actions */}
                <div className="flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
                    <button onClick={handleClose} className="btn btn-secondary">
                        {status === 'idle' ? 'Cancel' : 'Close'}
                    </button>
                    {status === 'idle' && (
                        <button
                            onClick={handleExecute}
                            disabled={executeMutation.isPending}
                            className="btn btn-primary flex items-center gap-2"
                        >
                            {executeMutation.isPending ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                            ) : (
                                <Play className="w-4 h-4" />
                            )}
                            Execute
                        </button>
                    )}
                </div>
            </div>
        </Modal>
    );
}

function buildAvailableCommands(agent: Agent): CommandType[] {
    return [
        ...(agent.is_isolated ? (['restore_network'] as CommandType[]) : (['isolate_network'] as CommandType[])),
        'kill_process',
        'quarantine_file',
        'collect_logs',
        'scan_memory',
        'custom',
        'restart_agent',
        'stop_agent',
        'start_agent',
        'restart_machine',
        'shutdown_machine',
    ];
}

function isCommandDisabledForAgent(agent: Agent, cmd: CommandType): boolean {
    const effectiveStatus = getEffectiveStatus(agent);
    // A confirmed uninstall is terminal: no command (not even a repeat
    // UNINSTALL_AGENT) is meaningful, and the server will reject it anyway.
    if (effectiveStatus === 'uninstalled') return true;
    const agentRunning = effectiveStatus === 'online' || effectiveStatus === 'degraded';
    const agentSuspended = effectiveStatus === 'suspended';
    const machineOnline = effectiveStatus !== 'offline' && effectiveStatus !== 'pending';
    switch (cmd) {
        case 'start_agent':
            return !agentSuspended;
        case 'stop_agent':
        case 'restart_agent':
            return !agentRunning;
        case 'restart_machine':
        case 'shutdown_machine':
            return !machineOnline;
        case 'restore_network':
            return false;
        default:
            return !agentRunning;
    }
}

function dmProfile(agent: Agent): string {
    return agent.tags?.profile ?? agent.metadata?.profile ?? '';
}
function dmLastUser(agent: Agent): string {
    return agent.metadata?.logged_in_user ?? agent.tags?.logged_in_user ?? '';
}

function dmComponentsLabel(agent: Agent): string {
    const eff = getEffectiveStatus(agent);
    return eff === 'online' || eff === 'degraded' ? 'EDR' : '—';
}

function dmSignatureVersion(agent: Agent): string {
    const raw = agent.tags?.signature_server_version ?? agent.metadata?.signature_server_version ?? '';
    return String(raw || '').trim();
}

function criticalityPillClass(v?: string): string {
    switch ((v || 'medium').toLowerCase()) {
        case 'critical':
            return 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30';
        case 'high':
            return 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30';
        case 'low':
            return 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30';
        default:
            return 'bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/30';
    }
}

// Main Endpoints Page
export default function Endpoints() {
    const queryClient = useQueryClient();
    const { showToast } = useToast();
    const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
    const [selectedCommand, setSelectedCommand] = useState<CommandType | null>(null);
    const [filters, setFilters] = useState({
        status: '',
        os_type: '',
        search: '',
    });
    const [viewMode, setViewMode] = useState<'table' | 'grid'>('table');
    const [treeVisible, setTreeVisible] = useState(false);
    const [treeSearch, setTreeSearch] = useState('');
    const [selectedGroupId, setSelectedGroupId] = useState<string>('g1');
    const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());

    const debouncedSearch = useDebounce(filters.search, 300);

    const toggleSelectOne = (id: string) => {
        setSelectedIds((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    // Fetch agents
    const { data, isLoading, error } = useQuery({
        queryKey: ['agents', filters.status, filters.os_type, debouncedSearch],
        queryFn: () => agentsApi.list({
            limit: 50,
            status: filters.status || undefined,
            os_type: filters.os_type || undefined,
            search: debouncedSearch || undefined,
            sort_by: 'health_score',
            sort_order: 'desc',
        }),
        refetchInterval: 10000, // Refresh every 10 seconds for near-real-time status
    });

    const agents = data?.data || [];
    const total = data?.pagination?.total || 0;

    const patchBusinessContextMutation = useMutation({
        mutationFn: ({ agentId, ...data }: { agentId: string } & Parameters<typeof agentsApi.patchBusinessContext>[1]) =>
            agentsApi.patchBusinessContext(agentId, data),
        onSuccess: (_, vars) => {
            showToast(vars.criticality ? 'Criticality updated' : 'Asset context updated', 'success');
            queryClient.invalidateQueries({ queryKey: ['agents'] });
            if (vars.criticality) {
                queryClient.invalidateQueries({ queryKey: ['vuln-findings'] });
                queryClient.invalidateQueries({ queryKey: ['vuln-stats'] });
            }
        },
        onError: (error: Error) => {
            showToast(error.message || 'Failed to update', 'error');
        },
    });

    const toggleSelectAll = () => {
        setSelectedIds((prev) => {
            if (prev.size === agents.length && agents.length > 0) return new Set();
            return new Set(agents.map((a) => a.id));
        });
    };

    useEffect(() => {
        const valid = new Set(agents.map((a) => a.id));
        setSelectedIds((prev) => {
            const next = new Set<string>();
            prev.forEach((id) => {
                if (valid.has(id)) next.add(id);
            });
            return next;
        });
    }, [agents]);

    const handleCommand = (agent: Agent, command: CommandType) => {
        setSelectedAgent(agent);
        setSelectedCommand(command);
    };

    const toolbarTargetAgent = useMemo(() => {
        if (selectedIds.size !== 1) return null;
        const id = [...selectedIds][0];
        return agents.find((a) => a.id === id) ?? null;
    }, [selectedIds, agents]);

    if (error) {
        return (
            <div className="card text-center py-12">
                <WifiOff className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                    Connection Manager Unavailable
                </h3>
                <p className="text-slate-500 mb-4">
                    Unable to connect to the Connection Manager service.
                </p>
                <button
                    onClick={() => queryClient.invalidateQueries({ queryKey: ['agents'] })}
                    className="btn btn-primary"
                >
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Retry
                </button>
            </div>
        );
    }

    return (
        <div
            data-section-id="management-devices-root"
            className="relative flex flex-col min-h-[calc(100vh-2rem)] lg:min-h-[calc(100vh-1rem)] h-full w-full p-4 sm:p-6 lg:p-8 bg-slate-200 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900 transition-colors overflow-hidden rounded-2xl border border-slate-300/40 dark:border-slate-700/40"
        >
            {/* Background ambient glow effect for Endpoints interface */}
            <div className="absolute top-1/4 right-1/4 w-[600px] h-[600px] pointer-events-none -translate-y-1/2 translate-x-1/3" style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%)' }} />
            
            <div className="relative flex-1 flex flex-col min-h-0  w-full space-y-4 lg:space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-3 shrink-0">
                    <div>
                        <h2 className="text-2xl sm:text-[1.75rem] font-bold text-slate-900 dark:text-white tracking-tight">Devices (Fleet)</h2>
                        <p className="text-[15px] text-slate-500 dark:text-slate-400 mt-1.5 leading-relaxed max-w-[70ch]">
                            Fleet inventory for Open a device for response, activity, network, and configuration tabs.
                        </p>
                    </div>
                {agents.length > 0 && (() => {
                    let onlineCount = 0, offlineCount = 0, degradedCount = 0;
                    agents.forEach((a) => {
                        const eff = getEffectiveStatus(a);
                        if (eff === 'online') onlineCount++;
                        else if (eff === 'degraded') degradedCount++;
                        else offlineCount++;
                    });
                    return (
                            <div className="flex flex-wrap items-center gap-2 sm:gap-3">
                                <span className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 dark:bg-green-500/20 text-green-700 dark:text-green-400 border border-green-500/20 rounded-full text-xs font-bold uppercase tracking-wider">
                                    <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                                {onlineCount} Online
                            </span>
                            <span className="flex items-center gap-2 px-3 py-1.5 bg-slate-500/10 dark:bg-slate-500/20 text-slate-600 dark:text-slate-400 border border-slate-500/20 rounded-full text-xs font-bold uppercase tracking-wider">
                                <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                                {offlineCount} Offline
                            </span>
                                <span className="flex items-center gap-2 px-3 py-1.5 bg-amber-500/10 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 border border-amber-500/20 rounded-full text-xs font-bold uppercase tracking-wider">
                                    <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
                                {degradedCount} Degraded
                            </span>
                        </div>
                    );
                })()}
            </div>

                <div
                    data-section-id="dm-structure"
                    className="flex flex-1 min-h-0 rounded-xl border border-slate-200/90 dark:border-slate-700/60 bg-white dark:bg-slate-900/35 overflow-hidden shadow-sm"
                >
                    {treeVisible && (
                        <aside className="w-[min(100%,260px)] sm:w-[260px] shrink-0 border-r border-slate-200 dark:border-slate-700 flex flex-col bg-slate-50/90 dark:bg-slate-950/80">
                            <div className="p-3 border-b border-slate-200 dark:border-slate-700 space-y-2">
                        <div className="relative">
                                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                    <input
                                        type="text"
                                        placeholder="Search group name"
                                        value={treeSearch}
                                        onChange={(e) => setTreeSearch(e.target.value)}
                                        className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-primary-500/40"
                                    />
                                </div>
                                <button
                                    type="button"
                                    onClick={() => {
                                        setSelectedGroupId('g1');
                                        setFilters((f) => ({ ...f, search: '' }));
                                    }}
                                    className="w-full flex items-center gap-2 px-2 py-1.5 text-xs font-medium rounded-lg border border-dashed border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/80"
                                >
                                    <Layers className="w-3.5 h-3.5 opacity-70" />
                                    Show all
                                </button>
                            </div>
                            <div className="flex-1 p-2 text-sm">
                                {(!treeSearch.trim() || 'default tenant'.includes(treeSearch.trim().toLowerCase())) && (
                                    <div className="mb-1">
                                        <div className="flex items-center gap-2 px-2 py-1.5 text-slate-700 dark:text-slate-200 font-medium">
                                            <Building2 className="w-4 h-4 shrink-0 text-slate-500" />
                                            <span className="truncate">Default tenant</span>
                                        </div>
                                        {(!treeSearch.trim() || 'all endpoints'.includes(treeSearch.trim().toLowerCase()) || 'default'.includes(treeSearch.trim().toLowerCase())) && (
                                            <div className="pl-3 ml-1.5 border-l border-slate-200 dark:border-slate-700">
                                                <button
                                                    type="button"
                                                    onClick={() => setSelectedGroupId('g1')}
                                                    className={`w-full text-left flex items-center gap-2 px-2 py-1.5 rounded-md transition-colors ${selectedGroupId === 'g1' ? 'bg-primary-500/15 text-primary-700 dark:text-primary-300' : 'hover:bg-slate-200/60 dark:hover:bg-slate-800'}`}
                                                >
                                                    <Folder className="w-4 h-4 shrink-0 text-slate-500" />
                                                    <span className="truncate">All endpoints</span>
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        </aside>
                    )}

                    <div className="flex-1 flex flex-col min-w-0 min-h-0">
                        <div className="flex items-stretch border-b border-slate-200 dark:border-slate-700 bg-slate-50/80 dark:bg-slate-900/50">
                            <button
                                type="button"
                                onClick={() => setTreeVisible((v) => !v)}
                                className={`shrink-0 px-2.5 flex items-center justify-center border-r border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 ${treeVisible ? 'text-[#f19637]' : 'text-slate-500'}`}
                                title={treeVisible ? 'Hide tree' : 'Show tree'}
                            >
                                <PanelLeft className="w-4 h-4" />
                            </button>
                            <nav className="flex items-end gap-1 px-1 min-w-0 overflow-x-auto">
                                <span className="shrink-0 px-3 py-2.5 text-sm font-semibold text-slate-900 dark:text-white border-b-2 border-[#f19637]">
                                    Device management
                                </span>
                            </nav>
                        </div>

                        <div
                            className="sticky top-0 z-20 flex flex-wrap items-center gap-x-1 gap-y-1 px-2 py-2 border-b border-slate-700/40 shadow-[0_1px_0_rgba(0,0,0,0.06)] overflow-x-auto custom-scrollbar"
                            style={{ background: 'var(--xc-nav-bg, #0a043d)' }}
                        >
                            {authApi.canExecuteCommands() && (() => {
                                // Always render action buttons — use a generic command list when no device is selected
                                const genericCommands: CommandType[] = [
                                    'isolate_network', 'kill_process', 'quarantine_file',
                                    'collect_logs', 'scan_memory', 'custom', 'restart_agent',
                                    'stop_agent', 'start_agent', 'restart_machine', 'shutdown_machine',
                                ];
                                const cmds = toolbarTargetAgent
                                    ? buildAvailableCommands(toolbarTargetAgent)
                                    : genericCommands;
                                return cmds.map((cmd) => {
                                    const def = COMMAND_DEFINITIONS[cmd];
                                    const Icon = def.icon;
                                    // Disabled if: no device selected OR device is not eligible
                                    const disabled = !toolbarTargetAgent || isCommandDisabledForAgent(toolbarTargetAgent, cmd);
                                    const showSeparator = cmd === 'restart_machine';
                                    return (
                                        <React.Fragment key={cmd}>
                                            {showSeparator && (
                                                <div
                                                    className="hidden sm:block w-px h-6 bg-white/25 mx-0.5 shrink-0 self-center"
                                                    aria-hidden
                                                />
                                            )}
                                            <button
                                                type="button"
                                                disabled={disabled}
                                                title={
                                                    !toolbarTargetAgent
                                                        ? `${def.label} — Select an online device first`
                                                        : `${def.label} — ${def.description}`
                                                }
                                                onClick={() => toolbarTargetAgent && handleCommand(toolbarTargetAgent, cmd)}
                                                className="inline-flex items-center gap-1 px-2 py-1.5 rounded text-[11px] text-white/90 border border-white/10 disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap hover:bg-white/10"
                                            >
                                                <Icon className={`w-3.5 h-3.5 shrink-0 ${def.color}`} />
                                                <span className="max-xl:hidden">{def.label}</span>
                                            </button>
                                        </React.Fragment>
                                    );
                                });
                            })()}
                        </div>

                        <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-slate-200 dark:border-slate-700 bg-slate-50/90 dark:bg-slate-900/40">
                            <div className="relative flex-1 min-w-[200px]">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                <input
                                    type="text"
                                    placeholder="Search for devices"
                                    value={filters.search}
                                    onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                                    className="w-full bg-white dark:bg-slate-900/70 border border-slate-200 dark:border-slate-600 text-slate-800 dark:text-slate-100 rounded-lg pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500/40"
                                />
                            </div>
                            <Link
                                to="/deploy"
                                className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-900/70 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap text-sm font-semibold"
                                title="Enroll a new endpoint"
                            >
                                <UserPlus className="w-4 h-4 shrink-0" />
                                Enroll device
                            </Link>
                            <button
                                type="button"
                                onClick={() => queryClient.invalidateQueries({ queryKey: ['agents'] })}
                                className="p-2 rounded-lg border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                                title="Refresh table"
                            >
                                <RefreshCw className="w-4 h-4" />
                            </button>
                            <button
                                type="button"
                                onClick={() => setFilters({ status: '', os_type: '', search: '' })}
                                className="p-2 rounded-lg border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
                                title="Clear filters"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        </div>

                        <div className="flex flex-wrap gap-3 items-end px-3 py-2 border-b border-slate-200 dark:border-slate-700 bg-white/60 dark:bg-slate-900/20">
                            <div className="relative">
                                <label className="block text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1">Status</label>
                            <select
                                value={filters.status}
                                onChange={(e) => setFilters({ ...filters, status: e.target.value })}
                                    className="w-40 appearance-none bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 rounded-lg pl-3 pr-8 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500/50"
                            >
                                    <option value="">All</option>
                                <option value="online">Online</option>
                                <option value="offline">Offline</option>
                                <option value="degraded">Degraded</option>
                                <option value="pending">Pending</option>
                            </select>
                                <ChevronDown className="pointer-events-none absolute right-2 bottom-2.5 w-4 h-4 text-slate-500" />
                            </div>
                        <div className="relative">
                                <label className="block text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1">OS</label>
                            <select
                                value={filters.os_type}
                                onChange={(e) => setFilters({ ...filters, os_type: e.target.value })}
                                    className="w-40 appearance-none bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 rounded-lg pl-3 pr-8 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500/50"
                            >
                                    <option value="">All</option>
                                <option value="windows">Windows</option>
                                <option value="linux">Linux</option>
                                <option value="macos">macOS</option>
                            </select>
                                <ChevronDown className="pointer-events-none absolute right-2 bottom-2.5 w-4 h-4 text-slate-500" />
                            </div>
                            <div className="ml-auto flex items-center gap-1">
                <button
                                    type="button"
                    onClick={() => setViewMode('table')}
                                    className={`p-2 rounded-lg transition-all ${viewMode === 'table' ? 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-400' : 'text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'}`}
                                    title="Table"
                                >
                                    <List className="w-4 h-4" />
                                </button>
                <button
                                    type="button"
                    onClick={() => setViewMode('grid')}
                                    className={`p-2 rounded-lg transition-all ${viewMode === 'grid' ? 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-400' : 'text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-800'}`}
                                    title="Grid"
                                >
                                    <LayoutGrid className="w-4 h-4" />
                                </button>
                            </div>
            </div>

            <div className="relative z-10 flex-1 flex flex-col min-h-0 overflow-hidden">
            {isLoading ? (
                <div className="p-4 bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700/50">
                    <SkeletonTable rows={8} columns={7} />
                </div>
            ) : agents.length === 0 ? (
                <div className="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700/50 flex flex-col items-center justify-center text-center py-16">
                    <Monitor className="w-12 h-12 text-blue-400 mx-auto mb-4 opacity-50" />
                    <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">No Endpoints Found</h3>
                    <p className="text-slate-500">{filters.search || filters.status || filters.os_type ? 'Try adjusting your filters' : 'No agents have registered yet'}</p>
                </div>
            ) : viewMode === 'grid' ? (
                /* Card Grid View */
                <div className="flex-1 overflow-auto custom-scrollbar">
                    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-4 pb-4">
                        {agents.map(agent => {
                            const eff = getEffectiveStatus(agent);
                            const pulseCls = eff === 'online' ? 'bg-emerald-500 status-pulse-online' : eff === 'degraded' ? 'bg-amber-400 status-pulse-degraded' : 'bg-slate-400 status-pulse-offline';
                            const health = agent.health_score ?? 0;
                            const healthClr = health >= 80 ? 'bg-emerald-500' : health >= 50 ? 'bg-amber-400' : 'bg-rose-500';
                            const osIcon = agent.os_type === 'windows' ? '⊞' : agent.os_type === 'linux' ? '🐧' : '🍎';
                            return (
                                <div key={agent.id} className="agent-card bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700/50 rounded-xl p-4 flex flex-col gap-3 shadow-sm" style={{ animation: 'slideInRight 0.15s ease-out' }}>
                                    {/* Card Header */}
                                    <div className="flex items-center gap-3">
                                        <span className={`w-3 h-3 rounded-full shrink-0 ${pulseCls}`} />
                                        <Link
                                            to={`/management/devices/${agent.id}`}
                                            className="font-bold text-slate-800 dark:text-white text-sm truncate flex-1 hover:text-primary-600 dark:hover:text-primary-400"
                                            onClick={(e) => e.stopPropagation()}
                                        >
                                            {agent.hostname}
                                        </Link>
                                        <span className="text-lg" title={agent.os_type}>{osIcon}</span>
                                    </div>
                                    {/* Health bar */}
                                    <div>
                                        <div className="flex justify-between text-[11px] text-slate-500 mb-1">
                                            <span>Health</span><span className="font-semibold">{health}%</span>
                                        </div>
                                        <div className="h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                                            <div className={`h-full rounded-full transition-all ${healthClr}`} style={{ width: `${health}%` }} />
                                        </div>
                                    </div>
                                    {/* Meta */}
                                    <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
                                        <span className="font-mono truncate max-w-[120px]" title={(agent.ip_addresses || [])[0] || ''}>{(agent.ip_addresses || [])[0] || '—'}</span>
                                        <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{agent.last_seen ? new Date(agent.last_seen).toLocaleTimeString() : '—'}</span>
                                    </div>
                                    {/* Actions */}
                                        {authApi.canViewResponses() && (
                                        <div className="flex gap-2 pt-1 border-t border-slate-100 dark:border-slate-800">
                                            <button type="button" onClick={() => handleCommand(agent, 'isolate_network')} className="flex-1 py-1.5 rounded-lg text-[11px] font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 hover:bg-rose-500/20 transition-colors border border-rose-500/20" title="Isolate Network">Isolate</button>
                                            <button type="button" onClick={() => handleCommand(agent, 'collect_logs')} className="flex-1 py-1.5 rounded-lg text-[11px] font-semibold bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/20 transition-colors border border-cyan-500/20" title="Collect Logs">Collect</button>
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                </div>
            ) : (
                <div className="flex-1 flex flex-col min-h-0 bg-white dark:bg-slate-800 border-t border-slate-200 dark:border-slate-700/50 overflow-hidden">
                    <div className="flex-1 overflow-auto overflow-x-auto custom-scrollbar">
                        <table className="w-full text-left text-sm whitespace-nowrap min-w-[1000px]">
                            <thead className="sticky top-0 z-10 bg-slate-100 dark:bg-slate-800 border-b-2 border-slate-200 dark:border-slate-700/80 text-[10px] uppercase tracking-wider text-slate-600 dark:text-slate-300 font-bold shadow-sm">
                                <tr>
                                    <th className="py-3 px-2 w-11">
                                        <input
                                            type="checkbox"
                                            className="rounded border-slate-300 dark:border-slate-600"
                                            checked={agents.length > 0 && selectedIds.size === agents.length}
                                            onChange={toggleSelectAll}
                                            aria-label="Select all on page"
                                        />
                                    </th>
                                    <th className="py-3 px-2">OS</th>
                                    <th className="py-3 px-3 min-w-[180px]">Name</th>
                                    <th className="py-3 px-2">Status</th>
                                    <th className="py-3 px-2">Health</th>
                                    <th className="py-3 px-2">Criticality</th>
                                    <th className="py-3 px-2">Profile</th>
                                    <th className="py-3 px-2">Active components</th>
                                    <th className="py-3 px-2">Signatures DB</th>
                                    <th className="py-3 px-2 min-w-[120px]">Last logged in user</th>
                                    <th className="py-3 px-2">Last activity</th>
                                </tr>
                            </thead>
                            <tbody style={{ contentVisibility: 'auto', containIntrinsicSize: '900px' } as any}>
                                {agents.map((agent, rowIdx) => (
                                    <tr
                                        key={agent.id}
                                        className={`transition-colors border-b border-slate-100 dark:border-slate-700/50 ${rowIdx % 2 === 0 ? 'bg-slate-50/80 dark:bg-slate-900/30' : 'bg-white dark:bg-slate-800/80'} hover:bg-slate-100/80 dark:hover:bg-slate-800/90`}
                                    >
                                            <td className="py-3 px-2 align-middle">
                                                <input
                                                    type="checkbox"
                                                    className="rounded border-slate-300 dark:border-slate-600"
                                                    checked={selectedIds.has(agent.id)}
                                                    onChange={() => toggleSelectOne(agent.id)}
                                                    aria-label={`Select ${agent.hostname}`}
                                                />
                                            </td>
                                            <td className="py-3 px-2 align-middle">
                                                <div className="flex items-center gap-1.5">
                                                    <OSIcon os={agent.os_type} />
                                                    <span className="text-xs capitalize text-slate-700 dark:text-slate-200">{agent.os_type}</span>
                                                </div>
                                            </td>
                                            <td className="py-3 px-3 align-middle">
                                                <div className="flex items-start gap-2 min-w-0">
                                                    <div className="min-w-0 flex-1">
                                                        <Link
                                                            to={`/management/devices/${agent.id}`}
                                                            className="font-medium text-slate-900 dark:text-white truncate block hover:text-primary-600 dark:hover:text-primary-400"
                                                        >
                                                            {agent.hostname}
                                                        </Link>
                                                        <p className="text-[11px] text-slate-500 truncate">
                                                            {agent.ip_addresses?.[0] || agent.id.slice(0, 8)}
                                                            {agent.agent_version ? ` · v${agent.agent_version}` : ''}
                                                        </p>
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="py-3 px-2 align-middle">
                                                <div className="flex flex-wrap items-center gap-1">
                                                    <StatusBadge status={getEffectiveStatus(agent)} />
                                                    <IsolationBadge isIsolated={agent.is_isolated} />
                                                </div>
                                            </td>
                                            <td className="py-3 px-2 align-middle max-w-[120px]">
                                                <HealthScoreBar score={agent.health_score} />
                                            </td>
                                            <td className="py-3 px-2 align-middle">
                                                {authApi.canManageEndpoints() ? (
                                                    <select
                                                        value={(agent.criticality || 'medium').toLowerCase()}
                                                        onChange={(e) => patchBusinessContextMutation.mutate({
                                                            agentId: agent.id,
                                                            criticality: e.target.value as 'low' | 'medium' | 'high' | 'critical',
                                                        })}
                                                        className="w-28 appearance-none bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 rounded-lg px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-primary-500/50"
                                                    >
                                                        <option value="low">Low</option>
                                                        <option value="medium">Medium</option>
                                                        <option value="high">High</option>
                                                        <option value="critical">Critical</option>
                                                    </select>
                                                ) : (
                                                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full border text-[11px] font-semibold ${criticalityPillClass(agent.criticality)}`}>
                                                        {(agent.criticality || 'medium').toLowerCase()}
                                                    </span>
                                                )}
                                            </td>
                                            <td className="py-3 px-2 align-middle text-xs text-slate-600 dark:text-slate-300 max-w-[130px] truncate" title={dmProfile(agent) || undefined}>
                                                {dmProfile(agent) || '—'}
                                            </td>
                                            <td className="py-3 px-2 align-middle text-xs text-slate-600 dark:text-slate-300">
                                                {dmComponentsLabel(agent)}
                                            </td>
                                            <td className="py-3 px-2 align-middle text-xs text-slate-600 dark:text-slate-300">
                                                {dmSignatureVersion(agent)
                                                    ? <span className="font-mono">v{dmSignatureVersion(agent)}</span>
                                                    : '—'}
                                            </td>
                                            <td className="py-3 px-2 align-middle text-xs text-slate-600 dark:text-slate-300 max-w-[140px] truncate" title={dmLastUser(agent) || undefined}>
                                                {dmLastUser(agent) || '—'}
                                            </td>
                                            <td className="py-3 px-2 align-middle text-xs text-slate-500">
                                                <span title={new Date(agent.last_seen).toLocaleString()}>
                                                    {formatRelativeTime(agent.last_seen)}
                                                </span>
                                            </td>
                                        </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    <div className="shrink-0 px-4 py-2.5 bg-slate-50/50 dark:bg-slate-900/40 border-t border-slate-200 dark:border-slate-700/60 text-xs text-slate-500 flex flex-wrap items-center justify-between gap-2">
                        <span>Showing {agents.length} of {total} devices</span>
                        {selectedIds.size > 0 && (
                            <span className="text-slate-600 dark:text-slate-400">{selectedIds.size} selected</span>
                        )}
                    </div>
                </div>
            )}
                        </div>
                    </div>
            </div>

            <CommandExecutionModal
                isOpen={!!selectedAgent && !!selectedCommand}
                onClose={() => {
                    setSelectedAgent(null);
                    setSelectedCommand(null);
                }}
                agent={selectedAgent}
                commandType={selectedCommand}
            />

            </div>
        </div>
    );
}


