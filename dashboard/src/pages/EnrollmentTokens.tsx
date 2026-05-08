import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, useEffect } from 'react';
import {
    Key, Plus, Copy, ShieldOff, CheckCircle, XCircle,
    Clock, AlertTriangle, RefreshCw, Hash, Eye, EyeOff, Download, Terminal
} from 'lucide-react';
import { enrollmentTokensApi, authApi, type EnrollmentToken } from '../api/client';
import { Modal, SkeletonTable } from '../components';

// --------------------------------------------------------------------------
// Generate Token Modal
// --------------------------------------------------------------------------
function GenerateTokenModal({
    isOpen,
    onClose,
    onGenerated,
}: {
    isOpen: boolean;
    onClose: () => void;
    onGenerated: (token: EnrollmentToken) => void;
}) {
    const [description, setDescription] = useState('');
    const [expiresInHours, setExpiresInHours] = useState<string>('');
    const [maxUses, setMaxUses] = useState<string>('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setIsSubmitting(true);

        try {
            const data: { description: string; expires_in_hours?: number; max_uses?: number } = {
                description: description.trim() || 'Unnamed Token',
            };
            if (expiresInHours && parseInt(expiresInHours) > 0) {
                data.expires_in_hours = parseInt(expiresInHours);
            }
            if (maxUses && parseInt(maxUses) > 0) {
                data.max_uses = parseInt(maxUses);
            }

            const token = await enrollmentTokensApi.generate(data);
            onGenerated(token);
            setDescription('');
            setExpiresInHours('');
            setMaxUses('');
            onClose();
        } catch {
            setError('Failed to generate token. Please try again.');
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Generate Enrollment Token" size="md">
            <form onSubmit={handleSubmit} className="space-y-4">
                {error && (
                    <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">
                        {error}
                    </div>
                )}

                <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        Description / Label
                    </label>
                    <input
                        type="text"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        placeholder="e.g. HR Department Deployment"
                        className="input w-full"
                        autoFocus
                    />
                    <p className="text-xs text-slate-500 mt-1">
                        A friendly name to identify this token's purpose.
                    </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                            Expires In (hours)
                        </label>
                        <input
                            type="number"
                            value={expiresInHours}
                            onChange={(e) => setExpiresInHours(e.target.value)}
                            placeholder="Never"
                            min="1"
                            className="input w-full"
                        />
                        <p className="text-xs text-slate-500 mt-1">Leave empty for no expiry.</p>
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                            Max Uses
                        </label>
                        <input
                            type="number"
                            value={maxUses}
                            onChange={(e) => setMaxUses(e.target.value)}
                            placeholder="Unlimited"
                            min="1"
                            className="input w-full"
                        />
                        <p className="text-xs text-slate-500 mt-1">Leave empty for unlimited.</p>
                    </div>
                </div>

                <div className="flex justify-end gap-3 pt-2">
                    <button type="button" onClick={onClose} className="btn btn-secondary">
                        Cancel
                    </button>
                    <button type="submit" disabled={isSubmitting} className="btn btn-primary flex items-center gap-2">
                        {isSubmitting ? (
                            <RefreshCw className="w-4 h-4 animate-spin" />
                        ) : (
                            <Plus className="w-4 h-4" />
                        )}
                        Generate Token
                    </button>
                </div>
            </form>
        </Modal>
    );
}

// --------------------------------------------------------------------------
// Token Created / Build Reveal Modal (shows once — token will not be shown again)
// --------------------------------------------------------------------------
function TokenCreatedModal({
    token,
    isOpen,
    onClose,
    installCommand,
    binaryBlob,
    title,
}: {
    token: EnrollmentToken | null;
    isOpen: boolean;
    onClose: () => void;
    /** If provided, shows the stdin install command (post-build reveal). */
    installCommand?: string;
    /** If provided, shows a download button for the agent binary. */
    binaryBlob?: Blob | null;
    title?: string;
}) {
    const [copied, setCopied] = useState(false);
    const [cmdCopied, setCmdCopied] = useState(false);

    const handleCopy = async (text: string, setter: (v: boolean) => void) => {
        try {
            await navigator.clipboard.writeText(text);
        } catch {
            const el = document.createElement('textarea');
            el.value = text;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
        }
        setter(true);
        setTimeout(() => setter(false), 2000);
    };

    const handleDownload = () => {
        if (!binaryBlob) return;
        const url = URL.createObjectURL(binaryBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'edr-agent.exe';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    if (!token) return null;

    const isPostBuild = !!installCommand;

    return (
        <Modal isOpen={isOpen} onClose={onClose} title={title ?? 'Token Generated Successfully'} size="lg">
            <div className="space-y-4 animate-slide-up-fade">
                {/* Warning banner for post-build reveals */}
                {isPostBuild && (
                    <div className="p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-lg flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
                        <p className="text-xs text-amber-700 dark:text-amber-300 font-medium">
                            This token will <strong>not</strong> be shown again. The server does not store it.
                            Copy it now and keep it secure.
                        </p>
                    </div>
                )}

                {/* Token value */}
                <div className="p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                        <CheckCircle className="w-5 h-5 text-green-600" />
                        <span className="font-medium text-green-800 dark:text-green-300">
                            {isPostBuild ? 'Plaintext Enrollment Token' : 'Token Ready'}
                        </span>
                    </div>
                    {!isPostBuild && (
                        <p className="text-xs text-green-700 dark:text-green-400 mb-3">
                            Copy this token now. You can always copy it later from the token list.
                        </p>
                    )}
                    <div className="flex items-center gap-2">
                        <code className="flex-1 p-2 bg-white dark:bg-slate-900 border border-green-300 dark:border-green-700 rounded font-mono text-xs break-all text-slate-900 dark:text-slate-100 select-all">
                            {token.token}
                        </code>
                        <button
                            onClick={() => handleCopy(token.token, setCopied)}
                            className={`btn ${copied ? 'btn-success' : 'btn-primary'} flex items-center gap-1 whitespace-nowrap`}
                        >
                            {copied ? <CheckCircle className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                            {copied ? 'Copied!' : 'Copy'}
                        </button>
                    </div>
                </div>

                {/* Install command — post-build only */}
                {isPostBuild && installCommand && (
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <Terminal className="w-4 h-4 text-slate-500" />
                            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                                Ready-to-use Install Command (run as Administrator):
                            </span>
                        </div>
                        <div className="relative group">
                            <pre className="p-3 bg-slate-900 dark:bg-black rounded-lg text-xs text-green-400 font-mono break-all whitespace-pre-wrap">
                                {installCommand}
                            </pre>
                            <button
                                onClick={() => handleCopy(installCommand, setCmdCopied)}
                                className="absolute top-1.5 right-1.5 p-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-md opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-xs"
                                title="Copy command"
                            >
                                {cmdCopied ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                                {cmdCopied ? 'Copied' : 'Copy'}
                            </button>
                        </div>
                    </div>
                )}

                {token.description && (
                    <p className="text-sm text-slate-600 dark:text-slate-400">
                        <strong>Label:</strong> {token.description}
                    </p>
                )}

                <div className="flex items-center justify-between gap-3 pt-1">
                    {binaryBlob && (
                        <button
                            onClick={handleDownload}
                            className="btn btn-secondary flex items-center gap-2"
                        >
                            <Download className="w-4 h-4" />
                            Download agent.exe
                        </button>
                    )}
                    <button onClick={onClose} className="btn btn-primary ml-auto">Done</button>
                </div>
            </div>
        </Modal>
    );
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

function isExpired(token: EnrollmentToken): boolean {
    if (!token.expires_at) return false;
    return new Date(token.expires_at) < new Date();
}

function isMaxedOut(token: EnrollmentToken): boolean {
    if (token.max_uses === null) return false;
    return token.use_count >= token.max_uses;
}

function getStatusBadge(token: EnrollmentToken): { label: string; color: string; icon: typeof CheckCircle } {
    if (!token.is_active) return { label: 'Revoked', color: 'bg-rose-500/10 text-rose-500 border border-rose-500/20', icon: XCircle };
    if (isExpired(token)) return { label: 'Expired', color: 'bg-orange-500/10 text-orange-500 border border-orange-500/20', icon: Clock };
    if (isMaxedOut(token)) return { label: 'Max Uses', color: 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20', icon: Hash };
    return { label: 'Active', color: 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20', icon: CheckCircle };
}

// ---------------------------------------------------------------------------
// Build-reveal session storage key: AgentDeployment.tsx writes here after a
// successful build, then navigates (or the admin switches tabs) to this page.
// ---------------------------------------------------------------------------
const BUILD_REVEAL_KEY = 'edr_post_build_reveal';

interface BuildRevealPayload {
    token: string;
    tokenId: string;
    description: string;
    serverIP?: string;
    serverDomain?: string;
}

// --------------------------------------------------------------------------
// Main Page
// --------------------------------------------------------------------------
export default function EnrollmentTokens() {
    const queryClient = useQueryClient();
    const [showGenerateModal, setShowGenerateModal] = useState(false);
    const [createdToken, setCreatedToken] = useState<EnrollmentToken | null>(null);
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const [showExpired, setShowExpired] = useState(false);

    // Post-build reveal state — populated from sessionStorage (written by AgentDeployment)
    const [buildReveal, setBuildReveal] = useState<{
        fakeToken: EnrollmentToken;
        installCommand: string;
    } | null>(null);

    // On mount: check if AgentDeployment left a post-build reveal payload.
    useEffect(() => {
        const raw = sessionStorage.getItem(BUILD_REVEAL_KEY);
        if (!raw) return;
        sessionStorage.removeItem(BUILD_REVEAL_KEY); // consume immediately
        try {
            const payload: BuildRevealPayload = JSON.parse(raw);
            const serverIP = payload.serverIP ?? '<SERVER_IP>';
            const serverDomain = payload.serverDomain ?? '<DOMAIN>';
            const cmd = `echo '${payload.token}' | .\\edr-agent.exe -install -token-stdin -server-ip ${serverIP} -server-domain ${serverDomain}`;
            // Construct a fake EnrollmentToken shell just to reuse TokenCreatedModal.
            setBuildReveal({
                fakeToken: {
                    id: payload.tokenId,
                    token: payload.token,
                    description: payload.description,
                    is_active: true,
                    use_count: 0,
                    max_uses: null,
                    expires_at: null,
                    created_at: new Date().toISOString(),
                    created_by: 'build',
                },
                installCommand: cmd,
            });
        } catch { /* ignore malformed payload */ }
    }, []);

    const canManage = authApi.canManageTokens();

    // Fetch tokens
    const { data, isLoading, error } = useQuery({
        queryKey: ['enrollmentTokens'],
        queryFn: () => enrollmentTokensApi.list(),
    });

    // Revoke mutation
    const revokeMutation = useMutation({
        mutationFn: (id: string) => enrollmentTokensApi.revoke(id),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['enrollmentTokens'] });
        },
    });

    const tokens: EnrollmentToken[] = data?.data || [];

    // Change 2: Filter out expired tokens unless the admin toggles "Show expired".
    const visibleTokens = showExpired ? tokens : tokens.filter(t => !isExpired(t));

    const handleCopyToken = async (token: string, id: string) => {
        try {
            await navigator.clipboard.writeText(token);
        } catch {
            const el = document.createElement('textarea');
            el.value = token;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
        }
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    const handleRevoke = (id: string) => {
        if (confirm('Are you sure you want to revoke this token? Agents using it will no longer be able to enroll.')) {
            revokeMutation.mutate(id);
        }
    };

    const handleTokenGenerated = (token: EnrollmentToken) => {
        queryClient.invalidateQueries({ queryKey: ['enrollmentTokens'] });
        setCreatedToken(token);
    };

    // Stats
    const activeCount = tokens.filter(t => t.is_active && !isExpired(t) && !isMaxedOut(t)).length;
    const revokedCount = tokens.filter(t => !t.is_active).length;
    const totalUses = tokens.reduce((sum, t) => sum + t.use_count, 0);

    if (error) {
        return (
            <div className="card text-center py-12">
                <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                    Failed to Load Enrollment Tokens
                </h3>
                <p className="text-slate-500">Please try again later.</p>
            </div>
        );
    }

    return (
        <div className="relative flex flex-col min-h-[calc(100vh-2rem)] lg:min-h-[calc(100vh-1rem)] h-full -mx-4 sm:-mx-6 lg:-mx-8 -my-4 sm:-my-6 lg:-my-8 p-4 sm:p-6 lg:p-8 bg-slate-200 dark:bg-gradient-to-br dark:from-slate-900 dark:via-[#0b1120] dark:to-slate-900 transition-colors overflow-hidden">
            {/* Background ambient glow matching Alerts/Endpoints */}
            <div className="absolute top-0 right-0 w-[500px] h-[500px] pointer-events-none mix-blend-screen" style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.08) 0%, transparent 70%)' }} />

            <div className="relative flex-1 flex flex-col min-h-0 space-y-4 lg:space-y-6  w-full">
                {/* Header */}
                <div className="flex items-center justify-between shrink-0">
                    <div>
                        <h2 className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-slate-900 to-slate-600 dark:from-white dark:to-slate-300">
                            Enrollment Tokens
                        </h2>
                        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">Manage tokens for agent zero-touch provisioning</p>
                    </div>
                    {canManage && (
                        <button
                            onClick={() => setShowGenerateModal(true)}
                            className="btn bg-cyan-600 hover:bg-cyan-700 text-white shadow-lg shadow-cyan-500/20 border-0 flex items-center gap-2"
                        >
                            <Plus className="w-4 h-4" />
                            Generate Token
                        </button>
                    )}
                </div>

                {/* Stats */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 shrink-0">
                    <div className="relative bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-6 shadow-sm overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 -mr-10 -mt-10 transition-opacity group-hover:opacity-100 opacity-50" style={{ background: 'radial-gradient(circle, rgba(16,185,129,0.1) 0%, transparent 70%)' }} />
                        <div className="relative flex items-center gap-4">
                            <div className="p-3 bg-emerald-500/10 dark:bg-emerald-500/20 rounded-xl border border-emerald-500/20 shrink-0 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
                                <Key className="w-6 h-6 text-emerald-600 dark:text-emerald-400" />
                            </div>
                            <div>
                                <p className="text-3xl font-bold text-slate-900 dark:text-white">{activeCount}</p>
                                <p className="text-sm font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mt-1">Active Tokens</p>
                            </div>
                        </div>
                    </div>
                    
                    <div className="relative bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-6 shadow-sm overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 -mr-10 -mt-10 transition-opacity group-hover:opacity-100 opacity-50" style={{ background: 'radial-gradient(circle, rgba(244,63,94,0.1) 0%, transparent 70%)' }} />
                        <div className="relative flex items-center gap-4">
                            <div className="p-3 bg-rose-500/10 dark:bg-rose-500/20 rounded-xl border border-rose-500/20 shrink-0 shadow-[0_0_15px_rgba(244,63,94,0.15)]">
                                <ShieldOff className="w-6 h-6 text-rose-600 dark:text-rose-400" />
                            </div>
                            <div>
                                <p className="text-3xl font-bold text-slate-900 dark:text-white">{revokedCount}</p>
                                <p className="text-sm font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mt-1">Revoked</p>
                            </div>
                        </div>
                    </div>
                    
                    <div className="relative bg-white/60 dark:bg-slate-900/40 backdrop-blur-md border border-slate-200/80 dark:border-slate-700/50 rounded-xl p-6 shadow-sm overflow-hidden group">
                        <div className="absolute top-0 right-0 w-32 h-32 -mr-10 -mt-10 transition-opacity group-hover:opacity-100 opacity-50" style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.1) 0%, transparent 70%)' }} />
                        <div className="relative flex items-center gap-4">
                            <div className="p-3 bg-cyan-500/10 dark:bg-cyan-500/20 rounded-xl border border-cyan-500/20 shrink-0 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
                                <Hash className="w-6 h-6 text-cyan-600 dark:text-cyan-400" />
                            </div>
                            <div>
                                <p className="text-3xl font-bold text-slate-900 dark:text-white">{totalUses}</p>
                                <p className="text-sm font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mt-1">Total Enrollments</p>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Tokens Table */}
                <div className="relative flex-1 flex flex-col min-h-0 bg-white dark:bg-slate-800/70 rounded-2xl border border-slate-200 dark:border-slate-700/60 shadow-sm overflow-hidden">
                    {isLoading ? (
                        <div className="p-4">
                            <SkeletonTable rows={5} columns={7} />
                        </div>
                    ) : tokens.length === 0 ? (
                        <div className="text-center py-12 flex-1 flex flex-col justify-center items-center">
                            <Key className="w-12 h-12 text-slate-400 mx-auto mb-4 opacity-50" />
                            <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">
                                No Enrollment Tokens
                            </h3>
                            <p className="text-slate-500 mb-6">
                                Generate a token to start enrolling agents automatically.
                            </p>
                            {canManage && (
                                <button
                                    onClick={() => setShowGenerateModal(true)}
                                    className="btn bg-cyan-600 hover:bg-cyan-700 text-white shadow-lg shadow-cyan-500/20 border-0"
                                >
                                    Generate First Token
                                </button>
                            )}
                        </div>
                    ) : visibleTokens.length === 0 ? (
                        <div className="text-center py-12 flex-1 flex flex-col justify-center items-center">
                            <Clock className="w-10 h-10 text-slate-400 mx-auto mb-3 opacity-40" />
                            <p className="text-slate-500">All tokens have expired.</p>
                            <button
                                onClick={() => setShowExpired(true)}
                                className="mt-3 text-sm text-cyan-600 dark:text-cyan-400 hover:underline"
                            >
                                Show expired tokens
                            </button>
                        </div>
                    ) : (
                        <div className="flex-1 overflow-auto custom-scrollbar">
                            <table className="w-full text-left border-collapse">
                                <thead className="sticky top-0 z-10 bg-slate-100 dark:bg-slate-800 border-b-2 border-slate-200 dark:border-slate-700/80">
                                    <tr>
                                        <th className="py-3 px-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Status</th>
                                        <th className="py-3 px-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Description</th>
                                        <th className="py-3 px-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Token</th>
                                        <th className="py-3 px-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Uses</th>
                                        <th className="py-3 px-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Created</th>
                                        <th className="py-3 px-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Expires</th>
                                        <th className="py-3 px-4 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                {visibleTokens.map((token) => {
                                    const status = getStatusBadge(token);
                                    const StatusIcon = status.icon;

                                    return (
                                        <tr key={token.id} className="border-b border-slate-100 dark:border-slate-800/60 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors group">
                                            <td className="py-4 px-4">
                                                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold tracking-wide uppercase shadow-sm ${status.color}`}>
                                                    <StatusIcon className="w-3.5 h-3.5" />
                                                    {status.label}
                                                </span>
                                            </td>
                                            <td className="py-4 px-4">
                                                <p className="font-semibold text-slate-900 dark:text-slate-200 text-sm">
                                                    {token.description || 'No description'}
                                                </p>
                                                <p className="text-xs text-slate-500 font-medium mt-0.5">by {token.created_by}</p>
                                            </td>
                                            <td className="py-4 px-4">
                                                <code className="px-2 py-1 text-[11px] font-mono bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-300 rounded border border-slate-200 dark:border-slate-700 select-all">
                                                    {token.token.slice(0, 16)}...
                                                </code>
                                            </td>
                                            <td className="py-4 px-4">
                                                <span className="text-sm font-semibold text-slate-900 dark:text-slate-200">
                                                    {token.use_count}
                                                    {token.max_uses !== null && (
                                                        <span className="text-slate-500 font-normal"> / {token.max_uses}</span>
                                                    )}
                                                </span>
                                            </td>
                                            <td className="py-4 px-4">
                                                <div className="text-sm font-medium text-slate-900 dark:text-slate-200">
                                                    {new Date(token.created_at).toLocaleDateString()}
                                                </div>
                                                <div className="text-xs text-slate-500 mt-0.5">
                                                    {new Date(token.created_at).toLocaleTimeString()}
                                                </div>
                                            </td>
                                            <td className="py-4 px-4">
                                                {token.expires_at ? (
                                                    <div>
                                                        <div className={`text-sm font-medium ${isExpired(token) ? 'text-rose-600 dark:text-rose-400' : 'text-slate-900 dark:text-slate-200'}`}>
                                                            {new Date(token.expires_at).toLocaleDateString()}
                                                        </div>
                                                        <div className="text-xs text-slate-500 mt-0.5">
                                                            {new Date(token.expires_at).toLocaleTimeString()}
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold tracking-wide uppercase bg-slate-100 dark:bg-slate-800 text-slate-500 border border-slate-200 dark:border-slate-700">Never</span>
                                                )}
                                            </td>
                                            <td className="py-4 px-4 text-right">
                                                <div className="flex items-center justify-end gap-1">
                                                    {canManage && (
                                                        <button
                                                            onClick={() => handleCopyToken(token.token, token.id)}
                                                            className="p-1.5 text-slate-400 hover:text-cyan-500 hover:bg-cyan-50 dark:hover:bg-cyan-500/10 rounded transition-colors"
                                                            title="Copy Token"
                                                        >
                                                            {copiedId === token.id ? (
                                                                <CheckCircle className="w-4 h-4 text-emerald-500" />
                                                            ) : (
                                                                <Copy className="w-4 h-4" />
                                                            )}
                                                        </button>
                                                    )}
                                                    {canManage && token.is_active && (
                                                        <button
                                                            onClick={() => handleRevoke(token.id)}
                                                            disabled={revokeMutation.isPending}
                                                            className="p-1.5 text-slate-400 hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-500/10 rounded transition-colors disabled:opacity-50"
                                                            title="Revoke Token"
                                                        >
                                                            <ShieldOff className="w-4 h-4" />
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
                )}

                {/* Footer Strip */}
                {tokens.length > 0 && (
                    <div className="shrink-0 px-4 py-3 bg-slate-50/50 dark:bg-slate-900/40 border-t border-slate-200 dark:border-slate-800/60 text-sm text-slate-500 flex justify-between items-center">
                        <span>
                            Showing {visibleTokens.length} of {tokens.length} tokens
                            {!showExpired && tokens.some(isExpired) && (
                                <span className="ml-2 text-xs text-amber-500">({tokens.filter(isExpired).length} expired hidden)</span>
                            )}
                        </span>
                        <button
                            onClick={() => setShowExpired(v => !v)}
                            className="flex items-center gap-1 text-xs text-slate-500 hover:text-cyan-500 transition-colors"
                        >
                            {showExpired ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                            {showExpired ? 'Hide expired' : 'Show expired'}
                        </button>
                    </div>
                )}
            </div>

            {/* Generate Token Modal */}
            <GenerateTokenModal
                isOpen={showGenerateModal}
                onClose={() => setShowGenerateModal(false)}
                onGenerated={handleTokenGenerated}
            />

            {/* Simple generation reveal */}
            <TokenCreatedModal
                token={createdToken}
                isOpen={!!createdToken}
                onClose={() => setCreatedToken(null)}
            />

            {/* Post-build one-time reveal (populated by AgentDeployment via sessionStorage) */}
            {buildReveal && (
                <TokenCreatedModal
                    token={buildReveal.fakeToken}
                    isOpen={!!buildReveal}
                    onClose={() => setBuildReveal(null)}
                    installCommand={buildReveal.installCommand}
                    title="Agent Built — Save Your Token"
                />
            )}
        </div>
        </div>
    );
}
