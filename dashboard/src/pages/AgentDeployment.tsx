import { useState, useEffect, useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from 'react-router-dom';
import {
    Download, Shield, Server, Key, Terminal, CheckCircle,
    AlertTriangle, Copy, Loader2, HardDrive, Info,
    ShieldCheck, Cpu, ChevronRight, ExternalLink
} from 'lucide-react';
import { agentBuildApi, authApi, type EnrollmentToken } from '../api/client';
import { Modal } from '../components';

// ─────────────────────────────────────────────────────────────────────────────
// Session-persistent form state
// ─────────────────────────────────────────────────────────────────────────────
const STORAGE_KEY = 'edr_agent_build_form';

interface BuildFormState {
    serverIP: string;
    serverDomain: string;
    serverPort: string;
    tokenId: string;
    installSysmon: boolean;
}

function loadFormState(): BuildFormState {
    try {
        const raw = sessionStorage.getItem(STORAGE_KEY);
        if (raw) return JSON.parse(raw);
    } catch { /* ignore */ }
    return { serverIP: '', serverDomain: '', serverPort: '47051', tokenId: '', installSysmon: false };
}

function saveFormState(state: BuildFormState) {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function clearFormState() {
    sessionStorage.removeItem(STORAGE_KEY);
}

// ─────────────────────────────────────────────────────────────────────────────
// Build Configuration Modal
// ─────────────────────────────────────────────────────────────────────────────
function BuildModal({
    isOpen,
    onClose,
    tokens,
    tokensLoading,
}: {
    isOpen: boolean;
    onClose: () => void;
    tokens: EnrollmentToken[];
    tokensLoading: boolean;
}) {
    const navigate = useNavigate();
    const [form, setForm] = useState<BuildFormState>(loadFormState);
    const [isBuilding, setIsBuilding] = useState(false);
    const [buildProgress, setBuildProgress] = useState('');
    const [error, setError] = useState('');
    const [buildResult, setBuildResult] = useState<{
        sha256: string;
        filename: string;
        token: string;
        build_id: string;
        install_command: string;
    } | null>(null);

    // Persist form state on change
    useEffect(() => {
        saveFormState(form);
    }, [form]);

    const updateField = (field: keyof BuildFormState, value: string | boolean) => {
        setForm(prev => ({ ...prev, [field]: value as never }));
    };

    const handleBuild = async (skip: boolean) => {
        setError('');
        setBuildResult(null);

        if (!form.tokenId) {
            setError('An enrollment token is required. Select a valid token.');
            return;
        }
        if (!skip && (!form.serverIP || !form.serverDomain)) {
            setError('Server IP and Domain are required unless you choose "Skip Config".');
            return;
        }

        setIsBuilding(true);
        setBuildProgress('Preparing build environment...');

        try {
            setBuildProgress('Cross-compiling agent for Windows (amd64)...');

            const result = await agentBuildApi.build({
                server_ip: skip ? undefined : form.serverIP,
                server_domain: skip ? undefined : form.serverDomain,
                server_port: skip ? undefined : (form.serverPort || '47051'),
                token_id: form.tokenId,
                skip_config: skip,
                install_sysmon: form.installSysmon,
            });

            setBuildProgress('Build complete. Starting download...');

            // Trigger browser download
            const url = URL.createObjectURL(result.blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = result.filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            // A build with embedded server settings needs only the token; a
            // "skip config" build must be told where the server is.
            const install = skip
                ? `echo '${result.token}' | .\\edr-agent.exe -install -token-stdin -server-ip <SERVER_IP> -server-domain <DOMAIN> -server-port 47051`
                : `echo '${result.token}' | .\\edr-agent.exe -install -token-stdin`;
            setBuildResult({
                sha256: result.sha256,
                filename: result.filename,
                token: result.token,
                build_id: result.build_id,
                install_command: install,
            });
            setBuildProgress('');
            clearFormState();

            // Write token to sessionStorage so the Enrollment Tokens page can display
            // the one-time reveal modal. Consumed immediately on mount by that page.
            const revealPayload = JSON.stringify({
                token: result.token,
                tokenId: form.tokenId,
                description: tokens.find(t => t.id === form.tokenId)?.description ?? 'Agent Build',
                serverIP: skip ? undefined : form.serverIP,
                serverDomain: skip ? undefined : form.serverDomain,
            });
            sessionStorage.setItem('edr_post_build_reveal', revealPayload);

            // Navigate to Enrollment Tokens page to show the one-time reveal modal.
            onClose();
            navigate('/security/tokens');

        } catch (err: unknown) {
            // Try to read error from blob response
            let message = 'Build failed. Check server logs for details.';
            if (err && typeof err === 'object' && 'response' in err) {
                const resp = (err as { response?: { data?: Blob } }).response;
                if (resp?.data instanceof Blob) {
                    try {
                        const text = await resp.data.text();
                        const parsed = JSON.parse(text);
                        message = parsed.message || parsed.build_output || message;
                    } catch { /* ignore */ }
                }
            }
            setError(message);
            setBuildProgress('');
        } finally {
            setIsBuilding(false);
        }
    };

    const handleClose = () => {
        if (!isBuilding) {
            onClose();
        }
    };

    const selectedToken = tokens.find(t => t.id === form.tokenId);

    return (
        <Modal isOpen={isOpen} onClose={handleClose} title="Build Agent Binary" size="lg" closeOnOverlayClick={!isBuilding}>
            <div className="space-y-5 animate-slide-up-fade">
                {/* Error message */}
                {error && (
                    <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300 flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
                        <span>{error}</span>
                    </div>
                )}

                {/* Build success */}
                {buildResult && (
                    <div className="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 rounded-lg space-y-4">
                        <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-300 font-medium">
                            <CheckCircle className="w-5 h-5" />
                            Agent Built Successfully
                        </div>
                        <div className="text-sm text-emerald-600 dark:text-emerald-400 space-y-1">
                            <p><span className="font-medium">File:</span> {buildResult.filename}</p>
                            <p className="font-mono text-xs break-all">
                                <span className="font-medium font-sans">SHA256:</span> {buildResult.sha256}
                            </p>
                        </div>

                        {/* ── ONE-TIME TOKEN REVEAL ── */}
                        <div className="mt-3 p-4 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-lg">
                            <div className="flex items-center gap-2 text-amber-700 dark:text-amber-300 font-medium text-sm mb-2">
                                <AlertTriangle className="w-4 h-4" />
                                One-Time Token — Save Securely
                            </div>
                            <p className="text-xs text-amber-600 dark:text-amber-400 mb-3">
                                This token is shown <strong>once</strong>. It is not stored in the binary.
                                Copy it now and use it during installation.
                            </p>
                            <div className="relative group">
                                <div className="bg-slate-900 dark:bg-black rounded-lg p-3 font-mono text-xs text-green-400 break-all select-all">
                                    {buildResult.token}
                                </div>
                                <button
                                    onClick={() => {
                                        navigator.clipboard.writeText(buildResult.token);
                                    }}
                                    className="absolute top-1.5 right-1.5 p-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-md opacity-0 group-hover:opacity-100 transition-opacity"
                                    title="Copy token"
                                >
                                    <Copy className="w-3.5 h-3.5" />
                                </button>
                            </div>
                        </div>

                        {/* ── INSTALL COMMAND ── */}
                        <div className="mt-2">
                            <span className="text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 block">Install Command (run as Administrator):</span>
                            <div className="relative group">
                                <div className="bg-slate-900 dark:bg-black rounded-lg p-3 font-mono text-xs text-green-400 break-all">
                                    {buildResult.install_command}
                                </div>
                                <button
                                    onClick={() => {
                                        navigator.clipboard.writeText(buildResult.install_command);
                                    }}
                                    className="absolute top-1.5 right-1.5 p-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-md opacity-0 group-hover:opacity-100 transition-opacity"
                                    title="Copy install command"
                                >
                                    <Copy className="w-3.5 h-3.5" />
                                </button>
                            </div>
                        </div>
                    </div>
                )}

                {/* Token Selection */}
                <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                        <span className="flex items-center gap-1.5">
                            <Key className="w-4 h-4 text-cyan-500" />
                            Enrollment Token <span className="text-red-500">*</span>
                        </span>
                    </label>
                    {tokensLoading ? (
                        <div className="flex items-center gap-2 text-sm text-slate-500 py-2">
                            <Loader2 className="w-4 h-4 animate-spin" /> Loading tokens...
                        </div>
                    ) : tokens.length === 0 ? (
                        <div className="p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg">
                            <p className="text-sm text-amber-700 dark:text-amber-300 mb-2">
                                No valid enrollment tokens available.
                            </p>
                            <button
                                onClick={() => navigate('/security/tokens')}
                                className="text-sm text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1"
                            >
                                Create a new token <ExternalLink className="w-3.5 h-3.5" />
                            </button>
                        </div>
                    ) : (
                        <>
                            <select
                                value={form.tokenId}
                                onChange={e => updateField('tokenId', e.target.value)}
                                className="input w-full"
                                disabled={isBuilding}
                            >
                                <option value="">— Select a token —</option>
                                {tokens.map(t => (
                                    <option key={t.id} value={t.id}>
                                        {t.description || 'Unnamed'} — uses: {t.use_count}{t.max_uses ? `/${t.max_uses}` : '/∞'}
                                        {t.expires_at ? ` — expires: ${new Date(t.expires_at).toLocaleDateString()}` : ''}
                                    </option>
                                ))}
                            </select>
                            {selectedToken && (
                                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                                    Token: <span className="font-mono">{selectedToken.token.slice(0, 8)}...{selectedToken.token.slice(-4)}</span>
                                </p>
                            )}
                        </>
                    )}
                </div>

                {/* Divider */}
                <div className="relative">
                    <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-slate-200 dark:border-slate-700" /></div>
                    <div className="relative flex justify-center text-xs">
                        <span className="bg-white dark:bg-slate-800 px-3 text-slate-500">Server Configuration</span>
                    </div>
                </div>

                {/* Optional bootstrap features */}
                <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white/70 dark:bg-slate-900/40 p-4 space-y-2">
                    <label className="flex items-start gap-3 text-sm text-slate-700 dark:text-slate-200">
                        <input
                            type="checkbox"
                            className="mt-1"
                            checked={form.installSysmon}
                            onChange={(e) => updateField('installSysmon', e.target.checked)}
                            disabled={isBuilding}
                        />
                        <span>
                            <span className="font-semibold">Install and enable Sysmon on first run</span>
                            <span className="block text-xs text-slate-500 mt-0.5">
                                Best-effort bootstrap: installs Sysmon (if missing) and enables <code>Microsoft-Windows-Sysmon/Operational</code>.
                            </span>
                        </span>
                    </label>
                </div>

                {/* Server Config */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                            Server IP
                        </label>
                        <input
                            type="text"
                            value={form.serverIP}
                            onChange={e => updateField('serverIP', e.target.value)}
                            placeholder="e.g. 192.168.1.10"
                            className="input w-full"
                            disabled={isBuilding}
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                            Server Domain
                        </label>
                        <input
                            type="text"
                            value={form.serverDomain}
                            onChange={e => updateField('serverDomain', e.target.value)}
                            placeholder="e.g. edr.local"
                            className="input w-full"
                            disabled={isBuilding}
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                            gRPC Port
                        </label>
                        <input
                            type="text"
                            value={form.serverPort}
                            onChange={e => updateField('serverPort', e.target.value)}
                            placeholder="47051"
                            className="input w-full"
                            disabled={isBuilding}
                        />
                    </div>
                </div>

                    <div className="p-3 bg-blue-50 dark:bg-blue-900/15 border border-blue-200 dark:border-blue-800 rounded-lg text-xs text-blue-700 dark:text-blue-300 flex items-start gap-2">
                    <Info className="w-4 h-4 mt-0.5 shrink-0" />
                    <div>
                        <strong>Zero-Embed Security:</strong> The binary contains no token material.
                        The token is returned once after build and must be provided via stdin at install time.
                    </div>
                </div>

                {/* Building progress */}
                {isBuilding && (
                    <div className="p-4 bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-700 rounded-lg">
                        <div className="flex items-center gap-3">
                            <Loader2 className="w-5 h-5 text-cyan-500 animate-spin" />
                            <div>
                                <p className="text-sm font-medium text-slate-900 dark:text-white">Building Agent...</p>
                                <p className="text-xs text-slate-500 dark:text-slate-400">{buildProgress}</p>
                            </div>
                        </div>
                        <div className="mt-3 w-full bg-slate-200 dark:bg-slate-700 rounded-full h-1.5 overflow-hidden">
                            <div className="bg-cyan-500 h-full rounded-full animate-pulse" style={{ width: '60%' }} />
                        </div>
                    </div>
                )}

                {/* Action buttons */}
                <div className="flex flex-col sm:flex-row gap-3 pt-2">
                    <button
                        onClick={() => handleBuild(false)}
                        disabled={isBuilding || tokens.length === 0}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium text-sm"
                    >
                        <Download className="w-4 h-4" />
                        Build & Download
                    </button>
                    <button
                        onClick={() => handleBuild(true)}
                        disabled={isBuilding || tokens.length === 0}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-600 hover:bg-slate-700 dark:bg-slate-700 dark:hover:bg-slate-600 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium text-sm"
                    >
                        <Terminal className="w-4 h-4" />
                        Build (Skip Config)
                    </button>
                </div>
            </div>
        </Modal>
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Copyable Code Block
// ─────────────────────────────────────────────────────────────────────────────
function CodeBlock({ code, label }: { code: string; label?: string }) {
    const [copied, setCopied] = useState(false);

    const handleCopy = useCallback(() => {
        navigator.clipboard.writeText(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    }, [code]);

    return (
        <div className="relative group">
            {label && (
                <span className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">{label}</span>
            )}
            <div className="bg-slate-900 dark:bg-black rounded-lg p-4 font-mono text-sm text-green-400 overflow-x-auto">
                <pre className="whitespace-pre-wrap">{code}</pre>
            </div>
            <button
                onClick={handleCopy}
                className="absolute top-2 right-2 p-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-md opacity-0 group-hover:opacity-100 transition-opacity"
                title="Copy to clipboard"
            >
                {copied ? <CheckCircle className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
            </button>
        </div>
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Step Card
// ─────────────────────────────────────────────────────────────────────────────
function StepCard({ step, title, children, icon: Icon }: {
    step: number;
    title: string;
    children: React.ReactNode;
    icon: React.ElementType;
}) {
    return (
        <div className="relative flex gap-4">
            {/* Step number + connector */}
            <div className="flex flex-col items-center">
                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white font-bold text-sm shadow-lg shadow-cyan-500/20 shrink-0">
                    {step}
                </div>
                <div className="w-0.5 flex-1 bg-gradient-to-b from-cyan-500/30 to-transparent mt-2" />
            </div>

            {/* Content */}
            <div className="flex-1 pb-8">
                <div className="flex items-center gap-2 mb-2">
                    <Icon className="w-5 h-5 text-cyan-500" />
                    <h3 className="text-base font-semibold text-slate-900 dark:text-white">{title}</h3>
                </div>
                <div className="text-sm text-slate-600 dark:text-slate-400 space-y-3">
                    {children}
                </div>
            </div>
        </div>
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────────────────────────────────────
export default function AgentDeployment() {
    const [isModalOpen, setIsModalOpen] = useState(false);

    const { data: validTokens = [], isLoading: tokensLoading } = useQuery({
        queryKey: ['valid-enrollment-tokens'],
        queryFn: () => agentBuildApi.listValidTokens(),
        staleTime: 30_000,
    });

    return (
        <div className="space-y-6">
            {/* Page Header */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                        <div className="p-2.5 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-xl shadow-lg shadow-cyan-500/20">
                            <Download className="w-6 h-6 text-white" />
                        </div>
                        Agent Deployment
                    </h2>
                    <p className="text-slate-500 dark:text-slate-400 mt-1">
                        Build a bound agent binary, install it on Windows endpoints and verify enrollment.
                    </p>
                </div>
                {authApi.canBuildAgent() && (
                    <button
                        id="build-agent-btn"
                        onClick={() => setIsModalOpen(true)}
                        className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 text-white rounded-xl font-medium transition-all duration-200 shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30"
                    >
                        <Cpu className="w-5 h-5" />
                        Build Agent
                    </button>
                )}
            </div>

            {/* Status Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="card p-5">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 bg-emerald-100 dark:bg-emerald-900/30 rounded-lg">
                            <ShieldCheck className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                        </div>
                        <h3 className="font-semibold text-slate-900 dark:text-white">Bound, token-free binary</h3>
                    </div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                        Each build embeds the platform CA, the server address (unless skipped) and a one-way binding to its
                        enrollment token — never the token itself.
                    </p>
                </div>

                <div className="card p-5">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 bg-cyan-100 dark:bg-cyan-900/30 rounded-lg">
                            <Key className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
                        </div>
                        <h3 className="font-semibold text-slate-900 dark:text-white">Unused enrollment tokens</h3>
                    </div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                        {tokensLoading ? (
                            <span className="flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin" /> Loading...</span>
                        ) : (
                            <><span className="text-2xl font-bold text-cyan-600 dark:text-cyan-400">{validTokens.length}</span> available. Each token builds <strong>one</strong> agent.{' '}
                                <Link to="/security/tokens" className="text-cyan-600 dark:text-cyan-400 hover:underline">Manage tokens</Link></>
                        )}
                    </p>
                </div>

                <div className="card p-5">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 bg-violet-100 dark:bg-violet-900/30 rounded-lg">
                            <HardDrive className="w-5 h-5 text-violet-600 dark:text-violet-400" />
                        </div>
                        <h3 className="font-semibold text-slate-900 dark:text-white">Windows x64</h3>
                    </div>
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                        A single <code className="px-1 bg-slate-100 dark:bg-slate-700 rounded text-xs font-mono">edr-agent.exe</code> that installs itself as the
                        <code className="px-1 bg-slate-100 dark:bg-slate-700 rounded text-xs font-mono">EDRAgent</code> service (LocalSystem).
                    </p>
                </div>
            </div>

            {/* Main Content — Two Column Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
                {/* Left: Instructions */}
                <div className="lg:col-span-3 card p-6">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-6 flex items-center gap-2">
                        <Terminal className="w-5 h-5 text-cyan-500" />
                        Deployment Guide
                    </h2>

                    <StepCard step={1} title="Build the agent" icon={Cpu}>
                        <p>
                            Click <strong className="text-cyan-600 dark:text-cyan-400">Build Agent</strong>, choose an unused enrollment token and
                            enter the server IP, domain and gRPC port (default <code className="px-1 bg-slate-100 dark:bg-slate-700 rounded text-xs font-mono">47051</code>).
                            The binary downloads automatically and the token is shown <strong>once</strong> — copy it now; it is not stored anywhere you can retrieve it later.
                        </p>
                    </StepCard>

                    <StepCard step={2} title="Transfer to the endpoint" icon={HardDrive}>
                        <p>
                            Copy <code className="px-1.5 py-0.5 bg-slate-100 dark:bg-slate-700 rounded text-xs font-mono">edr-agent.exe</code> to the Windows machine
                            over a trusted channel (internal share, SCCM/Intune, USB). Optionally compare its SHA-256 with the value shown after the build.
                        </p>
                    </StepCard>

                    <StepCard step={3} title="Install (token via stdin)" icon={Shield}>
                        <p>
                            In an <strong>elevated</strong> PowerShell, pipe the token so it never appears in the process list or shell history.
                            Server settings come from the build:
                        </p>
                        <CodeBlock label="Run as Administrator" code={`echo '<YOUR_TOKEN>' | .\\edr-agent.exe -install -token-stdin`} />
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                            Built with “skip server config”? Add <code className="font-mono">-server-ip &lt;IP&gt; -server-domain &lt;DOMAIN&gt; -server-port 47051</code>.
                            The installer checks DNS and TCP reachability before registering the service; the legacy
                            <code className="font-mono"> -token &lt;TOKEN&gt;</code> flag still works but exposes the token in the process list.
                        </p>
                    </StepCard>

                    <StepCard step={4} title="Verify" icon={CheckCircle}>
                        <p>Confirm the service is running and the agent connected:</p>
                        <CodeBlock code={`sc.exe query EDRAgent\nGet-Content C:\\ProgramData\\EDR\\logs\\agent.log -Tail 20`} />
                        <p>
                            The endpoint appears in{' '}
                            <Link to="/management/devices" className="text-cyan-600 dark:text-cyan-400 hover:underline inline-flex items-center gap-1">
                                Devices (Fleet) <ChevronRight className="w-3 h-3" />
                            </Link>{' '}
                            within seconds of enrollment.
                        </p>
                    </StepCard>

                    <StepCard step={5} title="Upgrade or remove" icon={Terminal}>
                        <p>
                            Upgrade in place with <code className="px-1 bg-slate-100 dark:bg-slate-700 rounded text-xs font-mono">.\edr-agent.exe -update</code> (keeps
                            identity and configuration). To remove an agent, use <strong>Uninstall</strong> on its device page while it is online, or generate an
                            offline uninstall token there and run the command in the panel on the right.
                        </p>
                    </StepCard>
                </div>

                {/* Right: Quick Reference Panel */}
                <div className="lg:col-span-2 space-y-4">
                    <div className="card p-5">
                        <h3 className="font-semibold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                            <Server className="w-4 h-4 text-cyan-500" />
                            How enrollment works
                        </h3>
                        <ol className="space-y-3 text-sm text-slate-600 dark:text-slate-400 list-none">
                            <li className="flex items-start gap-2">
                                <span className="w-5 h-5 rounded-full bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 text-[11px] font-bold flex items-center justify-center shrink-0">1</span>
                                <span>The installer checks the token locally against the binding baked into this build, so a token only works with its own binary.</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="w-5 h-5 rounded-full bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 text-[11px] font-bold flex items-center justify-center shrink-0">2</span>
                                <span>The agent enrolls over TLS (pinned to the embedded CA) and receives its own client certificate.</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="w-5 h-5 rounded-full bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 text-[11px] font-bold flex items-center justify-center shrink-0">3</span>
                                <span>From then on it streams telemetry and receives commands over mutual TLS; the token is no longer needed.</span>
                            </li>
                        </ol>
                    </div>

                    <div className="card p-5">
                        <h3 className="font-semibold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-amber-500" />
                            Important notes
                        </h3>
                        <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
                            <li className="flex items-start gap-2">
                                <ChevronRight className="w-4 h-4 text-cyan-500 mt-0.5 shrink-0" />
                                <span>An enrollment token can be used for <strong className="text-slate-800 dark:text-slate-200">one build only</strong>; create a new token for each additional binary.</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <ChevronRight className="w-4 h-4 text-cyan-500 mt-0.5 shrink-0" />
                                <span>Run the installer as <strong className="text-slate-800 dark:text-slate-200">Administrator</strong>; it writes the hosts entry for the server domain idempotently.</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <ChevronRight className="w-4 h-4 text-cyan-500 mt-0.5 shrink-0" />
                                <span>If the platform CA is rotated, rebuild and redeploy every agent.</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <ChevronRight className="w-4 h-4 text-cyan-500 mt-0.5 shrink-0" />
                                <span>Offline uninstall only works with agents built by a version that embeds the uninstall key.</span>
                            </li>
                        </ul>
                    </div>

                    <div className="card p-5">
                        <h3 className="font-semibold text-slate-900 dark:text-white mb-3 flex items-center gap-2">
                            <Terminal className="w-4 h-4 text-cyan-500" />
                            Offline uninstall
                        </h3>
                        <CodeBlock code={`echo '<UNINSTALL_TOKEN>' | .\\edr-agent.exe -uninstall -token-stdin`} />
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">
                            Generate the token on the endpoint's device page (Uninstall → generate token). It is signed by the server,
                            valid for that one endpoint only and expires after about 30 minutes.
                        </p>
                    </div>
                </div>
            </div>

            {/* Build Modal */}
            <BuildModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                tokens={validTokens}
                tokensLoading={tokensLoading}
            />
        </div>
    );
}
