import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogIn, AlertCircle, ShieldCheck, ArrowLeft, Mail } from 'lucide-react';
import { authApi, type MFAChallenge } from '../api/client';
import ProtocolLogo from '../components/ProtocolLogo';

export default function Login() {
    const navigate = useNavigate();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    // When the backend asks for MFA we stash the challenge here and
    // switch the card into "enter the code" mode. password/username are
    // discarded from memory so they aren't held for any longer than needed.
    const [challenge, setChallenge] = useState<MFAChallenge | null>(null);
    const [code, setCode] = useState('');
    const codeInputRef = useRef<HTMLInputElement | null>(null);

    useEffect(() => {
        if (challenge && codeInputRef.current) {
            codeInputRef.current.focus();
        }
    }, [challenge]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const result = await authApi.login(username, password);
            if (result.mfa_required && result.mfa_challenge) {
                // Don't navigate yet — show the OTP step.
                setChallenge(result.mfa_challenge);
                setPassword('');
                setCode('');
                return;
            }
            navigate('/');
        } catch (err: any) {
            setError(err.response?.data?.message || 'Invalid username or password');
        } finally {
            setLoading(false);
        }
    };

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!challenge) return;
        setError('');
        setLoading(true);
        try {
            await authApi.verifyMfa(challenge.id, code.trim());
            navigate('/');
        } catch (err: any) {
            const apiError = err.response?.data;
            // If the challenge is gone (expired or locked), force the user
            // back to the password step — there's no code they can enter
            // that will work against that challenge_id anymore.
            const code = apiError?.error?.code ?? apiError?.code;
            if (code === 'MFA_EXPIRED' || code === 'MFA_LOCKED') {
                setChallenge(null);
                setCode('');
            }
            setError(apiError?.message || 'MFA verification failed');
        } finally {
            setLoading(false);
        }
    };

    const backToPassword = () => {
        setChallenge(null);
        setCode('');
        setError('');
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 px-4 relative overflow-hidden">
            {/* Subtle glowing radial background */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] pointer-events-none" style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.15) 0%, transparent 70%)' }}></div>

            <div className="max-w-md w-full relative z-10">
                {/* Logo */}
                <div className="flex justify-center items-center mb-10 w-full">
                    <div className="flex items-center justify-center gap-5">
                        <ProtocolLogo className="w-24 h-24 shrink-0 drop-shadow-[0_0_15px_rgba(6,182,212,0.4)]" idPrefix="login" />
                        
                        {/* Typography */}
                        <div className="flex flex-col items-start justify-center border-l border-slate-300 dark:border-slate-700/50 pl-5">
                            <span className="text-cyan-600 dark:text-cyan-400 text-xs font-bold tracking-[0.3em] uppercase mb-1">Protocol Soft</span>
                            <div className="flex items-baseline gap-2">
                                <span className="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-slate-900 to-slate-500 dark:from-white dark:to-slate-400 tracking-tight uppercase">EDR</span>
                                <span className="text-4xl font-light text-slate-700 dark:text-white uppercase">Platform</span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Login Form */}
                <div className="bg-white/80 dark:bg-slate-900/60 backdrop-blur-md border border-slate-200 dark:border-slate-700/50 rounded-2xl shadow-xl dark:shadow-2xl shadow-slate-200/50 dark:shadow-cyan-900/20 p-8">
                    <h2 className="text-xl font-semibold text-slate-800 dark:text-white mb-6 text-center">
                        {challenge ? 'Two-Factor Verification' : 'Authenticate Session'}
                    </h2>

                    {error && (
                        <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-500/50 rounded-lg flex items-center gap-3 text-red-600 dark:text-red-400 text-sm font-medium">
                            <AlertCircle className="w-5 h-5 shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    {challenge ? (
                        <form onSubmit={handleVerify} className="space-y-5">
                            <div className="flex items-start gap-3 p-4 bg-cyan-50 dark:bg-cyan-500/5 border border-cyan-100 dark:border-cyan-500/20 rounded-lg">
                                <ShieldCheck className="w-5 h-5 text-cyan-600 dark:text-cyan-400 shrink-0 mt-0.5" />
                                <div className="text-sm text-slate-600 dark:text-slate-300">
                                    <p className="font-semibold text-slate-800 dark:text-slate-200">Check your inbox</p>
                                    <p className="mt-1 text-slate-500 dark:text-slate-400">
                                        We sent a 6-digit verification code to{' '}
                                        <span className="inline-flex items-center gap-1 text-cyan-700 dark:text-cyan-300 font-mono">
                                            <Mail className="w-3.5 h-3.5" />
                                            {challenge.masked_email}
                                        </span>
                                        . The code expires in a few minutes.
                                    </p>
                                </div>
                            </div>
                            <div>
                                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-2">
                                    Verification code
                                </label>
                                <input
                                    ref={codeInputRef}
                                    type="text"
                                    inputMode="numeric"
                                    autoComplete="one-time-code"
                                    pattern="[0-9]*"
                                    maxLength={6}
                                    value={code}
                                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                                    className="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/50 rounded-lg px-4 py-3 text-slate-900 dark:text-white text-center text-2xl tracking-[0.6em] font-mono placeholder-slate-400 dark:placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all"
                                    placeholder="●●●●●●"
                                    required
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={loading || code.length < 4}
                                className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-bold py-3.5 px-4 rounded-lg flex items-center justify-center gap-2 hover:scale-[1.02] active:scale-[0.98] transition-all duration-200 shadow-[0_4px_10px_rgba(6,182,212,0.2)] dark:shadow-[0_0_20px_rgba(6,182,212,0.3)] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
                            >
                                {loading ? (
                                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                                ) : (
                                    <>
                                        <ShieldCheck className="w-5 h-5" />
                                        Verify &amp; Continue
                                    </>
                                )}
                            </button>
                            <button
                                type="button"
                                onClick={backToPassword}
                                className="w-full flex items-center justify-center gap-2 text-sm text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors"
                            >
                                <ArrowLeft className="w-4 h-4" />
                                Use a different account
                            </button>
                        </form>
                    ) : (
                    <form onSubmit={handleSubmit} className="space-y-5">
                        <div>
                            <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider mb-2">
                                Username
                            </label>
                            <input
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                className="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/50 rounded-lg px-4 py-3 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all font-medium"
                                placeholder="Enter Username"
                                required
                            />
                        </div>

                        <div>
                            <div className="flex items-center justify-between mb-2">
                                <label className="block text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
                                    Password
                                </label>
                                <a href="#" className="text-xs font-semibold text-cyan-600 dark:text-cyan-400 hover:text-cyan-500 dark:hover:text-cyan-300 transition-colors">
                                    Reset Access?
                                </a>
                            </div>
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="w-full bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700/50 rounded-lg px-4 py-3 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all font-medium"
                                placeholder="••••••••"
                                required
                            />
                        </div>

                        <div className="flex items-center">
                            <label className="flex items-center cursor-pointer group">
                                <input type="checkbox" className="w-4 h-4 rounded border-slate-300 dark:border-slate-600 bg-slate-50 dark:bg-slate-800 text-cyan-600 dark:text-cyan-500 focus:ring-cyan-500 focus:ring-offset-white dark:focus:ring-offset-slate-900 cursor-pointer" />
                                <span className="ml-2 text-sm font-medium text-slate-600 dark:text-slate-400 group-hover:text-slate-800 dark:group-hover:text-slate-300 transition-colors">Remember node session</span>
                            </label>
                        </div>

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-bold py-3.5 px-4 rounded-lg flex items-center justify-center gap-2 hover:scale-[1.02] active:scale-[0.98] transition-all duration-200 shadow-[0_4px_10px_rgba(6,182,212,0.2)] dark:shadow-[0_0_20px_rgba(6,182,212,0.3)] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 mt-4"
                        >
                            {loading ? (
                                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                            ) : (
                                <>
                                    <LogIn className="w-5 h-5" />
                                    Secure Login
                                </>
                            )}
                        </button>
                    </form>
                    )}
                </div>

                {/* Footer */}
                <p className="text-center text-xs font-medium text-slate-500 mt-8 tracking-widest uppercase">
                    EDR Platform v1.0.0 • Secure Node
                </p>
            </div>
        </div>
    );
}
