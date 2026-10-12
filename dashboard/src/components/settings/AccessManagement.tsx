import { useState, useEffect } from 'react';

import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Search, Plus, Edit3, Trash2, Lock, Unlock, RefreshCw, X, AlertCircle, Check, UserPlus, ChevronDown, ChevronLeft, ChevronRight, Users, ShieldCheck, ShieldOff } from 'lucide-react';
import { usersApi, authApi, type User } from '../../api/client';
import { ROLE_COLORS, STATUS_STYLES } from './types';
import { formatDateTime } from '../../utils/agentDisplay';
import { useDebounce } from '../../hooks/useDebounce';
import InsightHero from '../InsightHero';

const ROLES = ['admin', 'security', 'analyst', 'operations', 'viewer'] as const;
const PAGE_SIZE = 50;

// ─── Role Badge ─────────────────────────────────────────────────────────────
function RoleBadge({ role }: { role: string }) {
    const s = ROLE_COLORS[role] || ROLE_COLORS.viewer;
    return (
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold uppercase tracking-wide border ${s.bg} ${s.text} ${s.border}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
            {role}
        </span>
    );
}

function StatusBadge({ status }: { status: string }) {
    const s = STATUS_STYLES[status] || STATUS_STYLES.inactive;
    return (
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-medium ${s.bg} ${s.text}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
            {status}
        </span>
    );
}

function lastLoginDisplay(last?: string | null): string {
    if (!last || last.startsWith('0001')) return '';
    return formatDateTime(last);
}

// ─── Main Component ─────────────────────────────────────────────────────────
export default function AccessManagement() {
    const queryClient = useQueryClient();
    const [search, setSearch] = useState('');
    const debouncedSearch = useDebounce(search.trim(), 350);
    const [roleFilter, setRoleFilter] = useState('');
    const [statusFilter, setStatusFilter] = useState('');
    const [page, setPage] = useState(1);
    const [feedback, setFeedback] = useState('');
    const [error, setError] = useState('');

    const [showAddModal, setShowAddModal] = useState(false);
    const [editUser, setEditUser] = useState<User | null>(null);
    const [saving, setSaving] = useState(false);
    const [form, setForm] = useState({
        username: '',
        email: '',
        password: '',
        full_name: '',
        role: 'analyst',
        mfa_enabled: false,
    });

    useEffect(() => {
        document.title = 'Users · Access · System';
    }, []);

    useEffect(() => {
        setPage(1);
    }, [debouncedSearch, roleFilter, statusFilter]);

    const listQ = useQuery({
        queryKey: ['users', 'access', page, debouncedSearch, roleFilter, statusFilter],
        queryFn: () =>
            usersApi.list({
                limit: PAGE_SIZE,
                offset: (page - 1) * PAGE_SIZE,
                search: debouncedSearch || undefined,
                role: roleFilter || undefined,
                status: statusFilter || undefined,
            }),
        staleTime: 15_000,
    });

    const users = listQ.data?.data ?? [];
    const total = listQ.data?.pagination?.total ?? 0;
    const hasMore = listQ.data?.pagination?.has_more ?? false;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

    useEffect(() => {
        if (page > totalPages) setPage(totalPages);
    }, [totalPages, page]);

    useEffect(() => {
        if (feedback) {
            const t = setTimeout(() => setFeedback(''), 3500);
            return () => clearTimeout(t);
        }
    }, [feedback]);

    const invalidateUsers = () =>
        queryClient.invalidateQueries({ queryKey: ['users', 'access'] });

    const queryErr =
        listQ.isError &&
        ((listQ.error as { response?: { data?: { message?: string } } })?.response?.data?.message ||
            (listQ.error as Error)?.message ||
            'Failed to load users');

    const inputClass =
        'w-full px-3.5 py-2.5 bg-white dark:bg-gray-800 border border-slate-300 dark:border-slate-600 rounded-lg text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-colors';
    const labelClass = 'block text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1.5';

    const handleCreate = async () => {
        if (!form.username || !form.email || !form.password || !form.role) {
            setError('All fields are required');
            return;
        }
        setSaving(true);
        setError('');
        try {
            await usersApi.create(form);
            setShowAddModal(false);
            setForm({ username: '', email: '', password: '', full_name: '', role: 'analyst', mfa_enabled: false });
            setFeedback('User created successfully');
            await invalidateUsers();
        } catch (err: unknown) {
            const ax = err as { response?: { data?: { message?: string } } };
            setError(ax?.response?.data?.message || 'Failed to create user');
        } finally {
            setSaving(false);
        }
    };

    const handleUpdate = async () => {
        if (!editUser) return;
        setSaving(true);
        setError('');
        try {
            await usersApi.update(editUser.id, {
                email: editUser.email,
                full_name: editUser.full_name,
                role: editUser.role,
                status: editUser.status,
                mfa_enabled: editUser.mfa_enabled ?? false,
            });
            setEditUser(null);
            setFeedback('User updated');
            await invalidateUsers();
        } catch (err: unknown) {
            const ax = err as { response?: { data?: { message?: string } } };
            setError(ax?.response?.data?.message || 'Failed to update user');
        } finally {
            setSaving(false);
        }
    };

    const handleDelete = async (id: string, name: string) => {
        if (!confirm(`Deactivate "${name}"? They will no longer be able to log in.`)) return;
        setError('');
        try {
            await usersApi.delete(id);
            setFeedback('User deactivated');
            await invalidateUsers();
        } catch (err: unknown) {
            const ax = err as { response?: { data?: { message?: string } } };
            setError(ax?.response?.data?.message || 'Failed');
        }
    };

    const handleToggleStatus = async (user: User) => {
        const next = user.status === 'active' ? 'inactive' : 'active';
        setError('');
        try {
            await usersApi.update(user.id, { status: next });
            setFeedback(`User ${next === 'active' ? 'activated' : 'deactivated'}`);
            await invalidateUsers();
        } catch (err: unknown) {
            const ax = err as { response?: { data?: { message?: string } } };
            setError(ax?.response?.data?.message || 'Failed');
        }
    };

    // Inline MFA toggle from the row. Optimistic UX: we just call the API
    // and then refetch — if it fails, the error banner tells the admin why.
    const handleToggleMFA = async (user: User) => {
        const next = !(user.mfa_enabled ?? false);
        setError('');
        try {
            await usersApi.update(user.id, { mfa_enabled: next });
            setFeedback(`MFA ${next ? 'enabled' : 'disabled'} for ${user.username}`);
            await invalidateUsers();
        } catch (err: unknown) {
            const ax = err as { response?: { data?: { message?: string } } };
            setError(ax?.response?.data?.message || 'Failed to update MFA');
        }
    };

    const loading = listQ.isLoading;
    const fetching = listQ.isFetching;

    return (
        <div className="space-y-6 w-full min-w-0 animate-fade-in">
            <InsightHero eyebrow="System"
                variant="light"
                accent="cyan"
                icon={Users}
                title="Directory users"
                actions={
                    authApi.canManageUsers() ? (
                        <button
                            type="button"
                            onClick={() => setShowAddModal(true)}
                            className="shrink-0 flex items-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-700 text-white rounded-xl transition-colors text-sm font-medium shadow-sm"
                        >
                            <UserPlus size={15} /> Add user
                        </button>
                    ) : null
                }
            />

            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                <div>
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-white">User list</h2>
                    <p className="text-[13px] text-slate-500 dark:text-slate-400">
                        {total} account{total !== 1 ? 's' : ''} match filters
                        {total > 0 && (
                            <span className="text-slate-400 dark:text-slate-500">
                                {' '}
                                · page {page} of {totalPages}
                            </span>
                        )}
                    </p>
                </div>
            </div>

            {feedback && (
                <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/20 text-sm">
                    <Check size={14} /> {feedback}
                </div>
            )}
            {(error || queryErr) && (
                <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-50 text-red-600 border border-red-200 dark:bg-red-500/10 dark:text-red-400 dark:border-red-500/20 text-sm">
                    <AlertCircle size={14} /> {error || queryErr}
                    <button
                        type="button"
                        onClick={() => {
                            setError('');
                            listQ.refetch();
                        }}
                        className="ml-auto text-red-500/70 hover:text-red-600 dark:text-red-400/60 dark:hover:text-red-400"
                    >
                        <X size={14} />
                    </button>
                </div>
            )}

            <div className="flex flex-wrap gap-3">
                <div className="relative flex-1 min-w-[200px]">
                    <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                        type="search"
                        placeholder="Search name, email, or username…"
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        className={inputClass + ' pl-9'}
                        autoComplete="off"
                    />
                </div>
                <div className="relative">
                    <select
                        value={roleFilter}
                        onChange={(e) => setRoleFilter(e.target.value)}
                        className={inputClass + ' pr-8 appearance-none min-w-[140px]'}
                    >
                        <option value="">All roles</option>
                        {ROLES.map((r) => (
                            <option key={r} value={r}>
                                {r.charAt(0).toUpperCase() + r.slice(1)}
                            </option>
                        ))}
                    </select>
                    <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                </div>
                <div className="relative">
                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className={inputClass + ' pr-8 appearance-none min-w-[140px]'}
                    >
                        <option value="">All status</option>
                        <option value="active">Active</option>
                        <option value="inactive">Inactive</option>
                        <option value="locked">Locked</option>
                    </select>
                    <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                </div>
                <button
                    type="button"
                    onClick={() => listQ.refetch()}
                    className="p-2.5 text-slate-500 hover:text-slate-900 dark:hover:text-white border border-slate-300 dark:border-slate-600 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                    title="Refresh"
                >
                    <RefreshCw size={15} className={fetching ? 'animate-spin' : ''} />
                </button>
            </div>

            <div className="bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                    <table className="w-full text-sm min-w-[720px]">
                        <thead>
                            <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50">
                                {['User', 'Role', 'Status', 'MFA', 'Last login', 'Created', 'Actions'].map((h, i) => (
                                    <th
                                        key={h}
                                        className={`px-4 sm:px-5 py-3 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider ${
                                            h === 'Created' ? 'hidden lg:table-cell' : ''
                                        } ${i === 6 ? 'text-right' : 'text-left'}`}
                                    >
                                        {h}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                            {loading ? (
                                <tr>
                                    <td colSpan={7} className="text-center py-16 text-slate-500 dark:text-slate-400">
                                        <RefreshCw size={18} className="inline animate-spin mr-2 align-middle" />
                                        Loading users…
                                    </td>
                                </tr>
                            ) : users.length === 0 ? (
                                <tr>
                                    <td colSpan={7} className="text-center py-16 text-slate-500 dark:text-slate-400">
                                        No users match these filters.
                                    </td>
                                </tr>
                            ) : (
                                users.map((user) => {
                                    const loginStr = lastLoginDisplay(user.last_login);
                                    return (
                                    <tr key={user.id} className="hover:bg-slate-50 dark:hover:bg-slate-700/40 transition-colors">
                                        <td className="px-4 sm:px-5 py-3.5">
                                            <div className="flex items-center gap-3">
                                                <div className="w-9 h-9 rounded-lg bg-cyan-100 dark:bg-cyan-500/15 flex items-center justify-center text-cyan-800 dark:text-cyan-300 font-bold text-xs shrink-0">
                                                    {(user.full_name || user.username).charAt(0).toUpperCase()}
                                                </div>
                                                <div className="min-w-0">
                                                    <div className="font-medium text-slate-900 dark:text-white truncate">
                                                        {user.full_name || user.username}
                                                    </div>
                                                    <div className="text-[12px] text-slate-500 dark:text-slate-400 truncate">
                                                        {user.email || '—'} · @{user.username}
                                                    </div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-4 sm:px-5 py-3.5">
                                            <RoleBadge role={user.role} />
                                        </td>
                                        <td className="px-4 sm:px-5 py-3.5">
                                            <StatusBadge status={user.status} />
                                        </td>
                                        <td className="px-4 sm:px-5 py-3.5">
                                            {user.mfa_enabled ? (
                                                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold uppercase tracking-wide border bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:border-emerald-500/30">
                                                    <ShieldCheck size={11} />
                                                    On
                                                </span>
                                            ) : (
                                                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-medium uppercase tracking-wide border bg-slate-100 text-slate-500 border-slate-200 dark:bg-slate-700/40 dark:text-slate-400 dark:border-slate-600">
                                                    <ShieldOff size={11} />
                                                    Off
                                                </span>
                                            )}
                                        </td>
                                        <td className="px-4 sm:px-5 py-3.5 text-slate-600 dark:text-slate-300 text-[13px] whitespace-nowrap">
                                            {loginStr ? loginStr : <span className="italic text-slate-400">Never</span>}
                                        </td>
                                        <td className="hidden lg:table-cell px-4 sm:px-5 py-3.5 text-slate-600 dark:text-slate-300 text-[13px] whitespace-nowrap">
                                            {user.created_at ? formatDateTime(user.created_at) : '—'}
                                        </td>
                                        <td className="px-4 sm:px-5 py-3.5">
                                            {authApi.canManageUsers() ? (
                                                <div className="flex items-center justify-end gap-1">
                                                    <button
                                                        type="button"
                                                        onClick={() => setEditUser({ ...user })}
                                                        className="p-2 text-slate-400 hover:text-cyan-600 hover:bg-cyan-50 dark:hover:bg-cyan-500/10 dark:hover:text-cyan-400 rounded-lg transition-all"
                                                        title="Edit"
                                                    >
                                                        <Edit3 size={15} />
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleToggleMFA(user)}
                                                        className="p-2 text-slate-400 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-500/10 dark:hover:text-emerald-400 rounded-lg transition-all"
                                                        title={user.mfa_enabled ? 'Disable MFA' : 'Enable MFA'}
                                                    >
                                                        {user.mfa_enabled ? <ShieldOff size={15} /> : <ShieldCheck size={15} />}
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleToggleStatus(user)}
                                                        className="p-2 text-slate-400 hover:text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-500/10 dark:hover:text-amber-400 rounded-lg transition-all"
                                                        title={user.status === 'active' ? 'Deactivate' : 'Activate'}
                                                    >
                                                        {user.status === 'active' ? <Lock size={15} /> : <Unlock size={15} />}
                                                    </button>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleDelete(user.id, user.full_name || user.username)}
                                                        className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 dark:hover:text-red-400 rounded-lg transition-all"
                                                        title="Deactivate account"
                                                    >
                                                        <Trash2 size={15} />
                                                    </button>
                                                </div>
                                            ) : (
                                                <span className="text-xs text-slate-400 italic">View only</span>
                                            )}
                                        </td>
                                    </tr>
                                    );
                                })
                            )}
                        </tbody>
                    </table>
                </div>

                {!loading && users.length > 0 && (
                    <div className="flex flex-col sm:flex-row items-center justify-between gap-3 px-4 py-3 border-t border-slate-200 dark:border-slate-700 bg-slate-50/80 dark:bg-slate-900/30">
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                            Showing {(page - 1) * PAGE_SIZE + 1}–{(page - 1) * PAGE_SIZE + users.length} of {total}
                            {hasMore ? ' · more pages available' : ''}
                        </p>
                        <div className="flex items-center gap-2">
                            <button
                                type="button"
                                disabled={page <= 1 || fetching}
                                onClick={() => setPage((p) => Math.max(1, p - 1))}
                                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 disabled:opacity-40 hover:bg-white dark:hover:bg-slate-800"
                            >
                                <ChevronLeft size={16} /> Previous
                            </button>
                            <span className="text-sm text-slate-600 dark:text-slate-300 tabular-nums px-2">
                                {page} / {totalPages}
                            </span>
                            <button
                                type="button"
                                disabled={page >= totalPages || fetching}
                                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-700 dark:text-slate-200 disabled:opacity-40 hover:bg-white dark:hover:bg-slate-800"
                            >
                                Next <ChevronRight size={16} />
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {showAddModal && (
                <div
                    className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100] flex items-center justify-center p-4 transition-opacity"
                    onClick={() => setShowAddModal(false)}
                    onKeyDown={(e) => e.key === 'Escape' && setShowAddModal(false)}
                    role="presentation"
                >
                    <div
                        className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl w-full max-w-md shadow-2xl"
                        onClick={(e) => e.stopPropagation()}
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="add-user-title"
                    >
                        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                            <div className="flex items-center gap-2.5">
                                <div className="w-8 h-8 rounded-lg bg-cyan-100 dark:bg-cyan-500/10 flex items-center justify-center">
                                    <Plus size={16} className="text-cyan-600 dark:text-cyan-400" />
                                </div>
                                <h3 id="add-user-title" className="text-[15px] font-semibold text-slate-900 dark:text-white">
                                    Add user
                                </h3>
                            </div>
                            <button type="button" onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-slate-900 dark:hover:text-white p-1">
                                <X size={18} />
                            </button>
                        </div>
                        <div className="p-6 space-y-4">
                            {[
                                { key: 'full_name', label: 'Full name', type: 'text', placeholder: 'John Doe' },
                                { key: 'username', label: 'Username', type: 'text', placeholder: 'johndoe' },
                                { key: 'email', label: 'Email', type: 'email', placeholder: 'john@edr.local' },
                                { key: 'password', label: 'Password', type: 'password', placeholder: 'Min 12 characters' },
                            ].map((f) => (
                                <div key={f.key}>
                                    <label className={labelClass}>{f.label}</label>
                                    <input
                                        type={f.type}
                                        value={(form as unknown as Record<string, string>)[f.key]}
                                        onChange={(e) => setForm((p) => ({ ...p, [f.key]: e.target.value }))}
                                        className={inputClass}
                                        placeholder={f.placeholder}
                                    />
                                </div>
                            ))}
                            <div>
                                <label className={labelClass}>Role</label>
                                <div className="relative">
                                    <select
                                        value={form.role}
                                        onChange={(e) => setForm((p) => ({ ...p, role: e.target.value }))}
                                        className={inputClass + ' appearance-none pr-8'}
                                    >
                                        {ROLES.map((r) => (
                                            <option key={r} value={r}>
                                                {r.charAt(0).toUpperCase() + r.slice(1)}
                                            </option>
                                        ))}
                                    </select>
                                    <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                </div>
                            </div>
                            <label className="flex items-start gap-3 p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-900/40 cursor-pointer">
                                <input
                                    type="checkbox"
                                    checked={form.mfa_enabled}
                                    onChange={(e) => setForm((p) => ({ ...p, mfa_enabled: e.target.checked }))}
                                    className="mt-0.5 w-4 h-4 rounded border-slate-400 text-cyan-600 focus:ring-cyan-500"
                                />
                                <span className="text-sm">
                                    <span className="flex items-center gap-1.5 font-semibold text-slate-800 dark:text-slate-100">
                                        <ShieldCheck size={14} className="text-emerald-500" />
                                        Require email MFA at sign-in
                                    </span>
                                    <span className="block mt-1 text-[12px] text-slate-500 dark:text-slate-400">
                                        A 6-digit code will be emailed to the user each time they log in.
                                    </span>
                                </span>
                            </label>
                        </div>
                        <div className="flex justify-end gap-2 px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50 rounded-b-xl">
                            <button type="button" onClick={() => setShowAddModal(false)} className="px-4 py-2 text-sm text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={handleCreate}
                                disabled={saving}
                                className="flex items-center gap-2 px-5 py-2 text-sm bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50 font-medium transition-colors"
                            >
                                {saving ? 'Creating…' : 'Create user'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {editUser && (
                <div
                    className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100] flex items-center justify-center p-4 transition-opacity"
                    onClick={() => setEditUser(null)}
                    role="presentation"
                >
                    <div
                        className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl w-full max-w-md shadow-2xl"
                        onClick={(e) => e.stopPropagation()}
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="edit-user-title"
                    >
                        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
                            <div className="flex items-center gap-2.5">
                                <div className="w-8 h-8 rounded-lg bg-amber-100 dark:bg-amber-500/10 flex items-center justify-center">
                                    <Edit3 size={15} className="text-amber-600 dark:text-amber-400" />
                                </div>
                                <h3 id="edit-user-title" className="text-[15px] font-semibold text-slate-900 dark:text-white">
                                    Edit user: <span className="text-cyan-600 dark:text-cyan-400">{editUser.username}</span>
                                </h3>
                            </div>
                            <button type="button" onClick={() => setEditUser(null)} className="text-slate-400 hover:text-slate-900 dark:hover:text-white p-1">
                                <X size={18} />
                            </button>
                        </div>
                        <div className="p-6 space-y-4">
                            <div>
                                <label className={labelClass}>Full name</label>
                                <input
                                    type="text"
                                    value={editUser.full_name || ''}
                                    onChange={(e) => setEditUser((p) => (p ? { ...p, full_name: e.target.value } : null))}
                                    className={inputClass}
                                />
                            </div>
                            <div>
                                <label className={labelClass}>Email</label>
                                <input
                                    type="email"
                                    value={editUser.email || ''}
                                    onChange={(e) => setEditUser((p) => (p ? { ...p, email: e.target.value } : null))}
                                    className={inputClass}
                                />
                            </div>
                            <div>
                                <label className={labelClass}>Role</label>
                                <div className="relative">
                                    <select
                                        value={editUser.role}
                                        onChange={(e) =>
                                            setEditUser((p) => (p ? { ...p, role: e.target.value as User['role'] } : null))
                                        }
                                        className={inputClass + ' appearance-none pr-8'}
                                    >
                                        {ROLES.map((r) => (
                                            <option key={r} value={r}>
                                                {r.charAt(0).toUpperCase() + r.slice(1)}
                                            </option>
                                        ))}
                                    </select>
                                    <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                </div>
                            </div>
                            <div>
                                <label className={labelClass}>Status</label>
                                <div className="relative">
                                    <select
                                        value={editUser.status}
                                        onChange={(e) =>
                                            setEditUser((p) => (p ? { ...p, status: e.target.value as User['status'] } : null))
                                        }
                                        className={inputClass + ' appearance-none pr-8'}
                                    >
                                        <option value="active">Active</option>
                                        <option value="inactive">Inactive</option>
                                        <option value="locked">Locked</option>
                                    </select>
                                    <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
                                </div>
                            </div>
                            <label className="flex items-start gap-3 p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-900/40 cursor-pointer">
                                <input
                                    type="checkbox"
                                    checked={editUser.mfa_enabled ?? false}
                                    onChange={(e) =>
                                        setEditUser((p) => (p ? { ...p, mfa_enabled: e.target.checked } : null))
                                    }
                                    className="mt-0.5 w-4 h-4 rounded border-slate-400 text-cyan-600 focus:ring-cyan-500"
                                />
                                <span className="text-sm">
                                    <span className="flex items-center gap-1.5 font-semibold text-slate-800 dark:text-slate-100">
                                        <ShieldCheck size={14} className="text-emerald-500" />
                                        Require email MFA at sign-in
                                    </span>
                                    <span className="block mt-1 text-[12px] text-slate-500 dark:text-slate-400">
                                        Codes are delivered to <code className="font-mono text-[11px]">{editUser.email || '— no email —'}</code>.
                                        Toggling off will not sign out existing sessions.
                                    </span>
                                </span>
                            </label>
                        </div>
                        <div className="flex justify-end gap-2 px-6 py-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50 rounded-b-xl">
                            <button type="button" onClick={() => setEditUser(null)} className="px-4 py-2 text-sm text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors">
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={handleUpdate}
                                disabled={saving}
                                className="flex items-center gap-2 px-5 py-2 text-sm bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50 font-medium transition-colors"
                            >
                                {saving ? 'Saving…' : 'Save changes'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
