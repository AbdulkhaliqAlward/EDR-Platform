import { useState, useEffect, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
    User as UserIcon,
    Lock,
    Save,
    Check,
    AlertCircle,
    Eye,
    EyeOff,
    Shield,
    Fingerprint,
    Settings,
} from 'lucide-react';
import { authApi, usersApi, type User } from '../../api/client';
import InsightHero from '../InsightHero';
import { formatDateTime } from '../../utils/agentDisplay';

export default function UserProfile() {
    const queryClient = useQueryClient();
    const sessionUser = authApi.getCurrentUser();

    const meQ = useQuery({
        queryKey: ['auth', 'me', 'profile-page'],
        queryFn: authApi.fetchMe,
        staleTime: 45_000,
        retry: 1,
        enabled: !!sessionUser && !!sessionUser.id,
    });

    useEffect(() => {
        document.title = 'Profile — System | MITRAS';
    }, []);

    /** Prefer live API; fallback to JWT/session cache */
    const profile =
        meQ.data ??
        sessionUser ??
        null;

    const [fullName, setFullName] = useState(profile?.full_name || '');
    const [email, setEmail] = useState(profile?.email || '');
    const [hydrated, setHydrated] = useState(false);

    useEffect(() => {
        if (!meQ.data || hydrated) return;
        setFullName(meQ.data.full_name || '');
        setEmail(meQ.data.email || '');
        setHydrated(true);
    }, [meQ.data, hydrated]);

    const [saving, setSaving] = useState(false);
    const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

    const [pwExpanded, setPwExpanded] = useState(false);
    const [oldPw, setOldPw] = useState('');
    const [newPw, setNewPw] = useState('');
    const [confirmPw, setConfirmPw] = useState('');
    const [showNew, setShowNew] = useState(false);

    useEffect(() => {
        if (feedback) {
            const t = setTimeout(() => setFeedback(null), 4000);
            return () => clearTimeout(t);
        }
    }, [feedback]);

    const mergeSession = useCallback(
        (partial: Partial<User>) => {
            const base = authApi.getCurrentUser();
            if (!base) return;
            localStorage.setItem('user', JSON.stringify({ ...base, ...partial }));
            void queryClient.invalidateQueries({ queryKey: ['auth', 'me'] });
        },
        [queryClient]
    );

    const handleSaveProfile = async () => {
        if (!profile?.id) return;
        setSaving(true);
        try {
            const updated = await usersApi.update(profile.id, { full_name: fullName, email });
            mergeSession(updated);
            setFeedback({ type: 'success', msg: 'Profile updated successfully' });
        } catch (err: unknown) {
            const ax = err as { response?: { data?: { message?: string } } };
            setFeedback({ type: 'error', msg: ax?.response?.data?.message || 'Failed to update profile' });
        } finally {
            setSaving(false);
        }
    };

    const handleChangePassword = async () => {
        if (!profile?.id) return;
        if (newPw !== confirmPw) {
            setFeedback({ type: 'error', msg: 'New passwords do not match' });
            return;
        }
        if (newPw.length < 12) {
            setFeedback({ type: 'error', msg: 'Password must be at least 12 characters' });
            return;
        }
        setSaving(true);
        try {
            await usersApi.changePassword(profile.id, oldPw, newPw);
            localStorage.removeItem('auth_token');
            localStorage.removeItem('user');
            setFeedback({ type: 'success', msg: 'Password changed — redirecting to login…' });
            setTimeout(() => {
                window.location.href = '/login';
            }, 1200);
        } catch (err: unknown) {
            const ax = err as { response?: { data?: { message?: string } } };
            setFeedback({ type: 'error', msg: ax?.response?.data?.message || 'Failed to change password' });
        } finally {
            setSaving(false);
        }
    };

    const inputClass =
        'w-full px-3.5 py-2.5 bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-colors';
    const readonlyClass =
        'w-full px-3.5 py-2.5 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-500 dark:text-slate-400 cursor-not-allowed';
    const labelClass = 'block text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5';

    if (!sessionUser) {
        return (
            <div className="rounded-xl border border-amber-200 dark:border-amber-800 bg-amber-50/80 dark:bg-amber-950/30 p-6 text-sm text-amber-900 dark:text-amber-200">
                No session found. <Link className="font-semibold text-cyan-600 dark:text-cyan-400 underline" to="/login">Sign in</Link>.
            </div>
        );
    }

    return (
        <div className="space-y-6 w-full min-w-0 animate-slide-up-fade">
            <InsightHero
                
                accent="indigo"
                icon={Fingerprint}
                eyebrow="System hub"
                title="Your profile"
                segments={[
                    {
                        heading: 'Canonical route',
                        children: (
                            <>
                                Use <code className="text-[11px] text-indigo-200/95 bg-white/10 px-1 rounded">/system/profile</code> to edit display name and email and to rotate credentials — the
                                dedicated operator-facing surface for your own account.
                            </>
                        ),
                    },
                    {
                        heading: 'API source of truth',
                        children: (
                            <>
                                Identity is refreshed from <code className="text-[11px] text-indigo-200/95 bg-white/10 px-1 rounded">GET /api/v1/auth/me</code>; updates persist with{' '}
                                <code className="text-[11px] text-indigo-200/95 bg-white/10 px-1 rounded">PATCH /api/v1/users/:id</code> — aligned with the read-only Management → Account summary.
                            </>
                        ),
                    },
                ]}
            />

            <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <Shield className="w-4 h-4 text-violet-500" />
                        vs Account (read-only)
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/management/account">
                            Management → Account
                        </Link>{' '}
                        shows a <strong>read-only</strong> capability matrix. Here you <strong>change</strong> profile fields and password.
                    </p>
                </div>
                <div className="rounded-xl border border-slate-200 dark:border-slate-700/60 bg-white/90 dark:bg-slate-800/80 p-4 shadow-sm">
                    <div className="text-xs font-semibold uppercase text-slate-500 dark:text-slate-400 flex items-center gap-2">
                        <Settings className="w-4 h-4 text-slate-500" />
                        vs Access management
                    </div>
                    <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                        <Link className="text-cyan-600 dark:text-cyan-400 font-medium hover:underline" to="/system/access/users">
                            Users &amp; roles
                        </Link>{' '}
                        is for <strong>administrators</strong> managing other accounts — not your own editing flow.
                    </p>
                </div>
            </div>

            {meQ.isError && (
                <div className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 px-4 py-2 text-xs text-amber-900 dark:text-amber-200">
                    Could not refresh profile from <code className="text-[10px]">/auth/me</code> — using session cache. Save still writes to the API.
                </div>
            )}

            {feedback && (
                <div
                    className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm border transition-all ${
                        feedback.type === 'success'
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/20'
                            : 'bg-red-50 text-red-700 border-red-200 dark:bg-red-500/10 dark:text-red-400 dark:border-red-500/20'
                    }`}
                >
                    {feedback.type === 'success' ? <Check size={15} /> : <AlertCircle size={15} />}
                    {feedback.msg}
                </div>
            )}

            <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden shadow-sm">
                <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50/80 dark:bg-slate-800/50">
                    <div className="w-9 h-9 rounded-lg bg-sky-500/15 text-sky-600 dark:text-sky-400 flex items-center justify-center">
                        <UserIcon size={17} className="text-inherit" />
                    </div>
                    <div>
                        <h2 className="text-[15px] font-semibold text-slate-900 dark:text-white leading-tight">Personal information</h2>
                        <p className="text-[12px] text-slate-500 dark:text-slate-400 leading-tight mt-0.5">
                            Name and email (username and role are directory-controlled)
                        </p>
                    </div>
                </div>

                <div className="p-6">
                    {meQ.isLoading && !meQ.data ? (
                        <div className="h-24 rounded-lg bg-slate-100 dark:bg-slate-900 animate-pulse" />
                    ) : (
                        <>
                            <div className="grid sm:grid-cols-2 gap-4">
                                <div>
                                    <label className={labelClass}>Username</label>
                                    <input type="text" value={profile?.username || ''} disabled className={readonlyClass} />
                                </div>
                                <div>
                                    <label className={labelClass}>Role</label>
                                    <input
                                        type="text"
                                        value={(profile?.role || '').charAt(0).toUpperCase() + (profile?.role || '').slice(1)}
                                        disabled
                                        className={readonlyClass}
                                    />
                                </div>
                                <div>
                                    <label className={labelClass}>Full name</label>
                                    <input
                                        type="text"
                                        value={fullName}
                                        onChange={(e) => setFullName(e.target.value)}
                                        className={inputClass}
                                        placeholder="Your full name"
                                    />
                                </div>
                                <div>
                                    <label className={labelClass}>Email</label>
                                    <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className={inputClass} placeholder="you@org.com" />
                                </div>
                                <div className="sm:col-span-2 grid sm:grid-cols-2 gap-4 text-xs text-slate-500 dark:text-slate-400 border-t border-slate-100 dark:border-slate-700/80 pt-4 mt-1">
                                    <div>
                                        <span className="font-semibold text-slate-400 uppercase tracking-wide">Last login</span>
                                        <div className="mt-1 font-mono text-slate-700 dark:text-slate-200">
                                            {profile?.last_login ? formatDateTime(profile.last_login) : '—'}
                                        </div>
                                    </div>
                                    <div>
                                        <span className="font-semibold text-slate-400 uppercase tracking-wide">Account status</span>
                                        <div className="mt-1 capitalize text-slate-700 dark:text-slate-200">{profile?.status || '—'}</div>
                                    </div>
                                </div>
                            </div>

                            <div className="flex justify-end mt-5">
                                <button
                                    type="button"
                                    onClick={handleSaveProfile}
                                    disabled={saving}
                                    className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-medium rounded-lg disabled:opacity-50 transition-colors"
                                >
                                    <Save size={14} /> {saving ? 'Saving…' : 'Save profile'}
                                </button>
                            </div>
                        </>
                    )}
                </div>
            </section>

            <section className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden shadow-sm">
                <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50/80 dark:bg-slate-800/50">
                    <div className="w-9 h-9 rounded-lg bg-amber-500/15 text-amber-600 dark:text-amber-400 flex items-center justify-center">
                        <Lock size={17} className="text-inherit" />
                    </div>
                    <div>
                        <h2 className="text-[15px] font-semibold text-slate-900 dark:text-white leading-tight">Security</h2>
                        <p className="text-[12px] text-slate-500 dark:text-slate-400 leading-tight mt-0.5">Change password (invalidates current session)</p>
                    </div>
                </div>

                <div className="p-6">
                    {!pwExpanded ? (
                        <button
                            type="button"
                            onClick={() => setPwExpanded(true)}
                            className="px-4 py-2 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-700 dark:text-slate-300 hover:border-cyan-500/50 transition-all font-medium"
                        >
                            Change password
                        </button>
                    ) : (
                        <div className="max-w-sm space-y-4">
                            <div>
                                <label className={labelClass}>Current password</label>
                                <input type="password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} className={inputClass} placeholder="Current password" />
                            </div>
                            <div>
                                <label className={labelClass}>New password</label>
                                <div className="relative">
                                    <input
                                        type={showNew ? 'text' : 'password'}
                                        value={newPw}
                                        onChange={(e) => setNewPw(e.target.value)}
                                        className={inputClass + ' pr-10'}
                                        placeholder="Min 12 characters"
                                    />
                                    <button
                                        type="button"
                                        onClick={() => setShowNew(!showNew)}
                                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
                                    >
                                        {showNew ? <EyeOff size={15} /> : <Eye size={15} />}
                                    </button>
                                </div>
                                {newPw.length > 0 && newPw.length < 12 && (
                                    <p className="text-[11px] text-red-500 dark:text-red-400 mt-1.5 font-medium">At least 12 characters</p>
                                )}
                            </div>
                            <div>
                                <label className={labelClass}>Confirm new password</label>
                                <input type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} className={inputClass} placeholder="Repeat new password" />
                                {confirmPw.length > 0 && confirmPw !== newPw && (
                                    <p className="text-[11px] text-red-500 dark:text-red-400 mt-1.5 font-medium">Passwords do not match</p>
                                )}
                            </div>
                            <div className="flex gap-2 pt-2">
                                <button
                                    type="button"
                                    onClick={() => {
                                        setPwExpanded(false);
                                        setOldPw('');
                                        setNewPw('');
                                        setConfirmPw('');
                                    }}
                                    className="px-4 py-2 text-sm text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="button"
                                    onClick={handleChangePassword}
                                    disabled={saving || newPw.length < 12 || confirmPw !== newPw}
                                    className="flex items-center gap-2 px-4 py-2 text-sm bg-amber-600 hover:bg-amber-700 text-white rounded-lg disabled:opacity-40 font-medium transition-colors"
                                >
                                    <Lock size={13} /> {saving ? 'Updating…' : 'Update password'}
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </section>
        </div>
    );
}
