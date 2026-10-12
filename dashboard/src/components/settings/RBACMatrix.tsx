import { useMemo, useState, useEffect, Fragment } from 'react';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Save, RefreshCw, Shield, AlertCircle, Check, Lock, Eye } from 'lucide-react';
import { rolesApi, authApi, type Role, type Permission } from '../../api/client';
import { ROLE_COLORS } from './types';
import InsightHero from '../InsightHero';

const ROLE_ORDER = ['admin', 'security', 'analyst', 'operations', 'viewer'] as const;

function sortRoles(roles: Role[]): Role[] {
    return [...roles].sort((a, b) => {
        const ia = ROLE_ORDER.indexOf(a.name as (typeof ROLE_ORDER)[number]);
        const ib = ROLE_ORDER.indexOf(b.name as (typeof ROLE_ORDER)[number]);
        const ca = ia === -1 ? 999 : ia;
        const cb = ib === -1 ? 999 : ib;
        if (ca !== cb) return ca - cb;
        return a.name.localeCompare(b.name);
    });
}

function groupPermissions(perms: Permission[]): { resource: string; permissions: Permission[] }[] {
    const acc: Record<string, Permission[]> = {};
    for (const p of perms) {
        (acc[p.resource] ??= []).push(p);
    }
    for (const k of Object.keys(acc)) {
        acc[k].sort((a, b) => a.action.localeCompare(b.action));
    }
    return Object.keys(acc)
        .sort((a, b) => a.localeCompare(b))
        .map((resource) => ({ resource, permissions: acc[resource] }));
}

export default function RBACMatrix() {
    const queryClient = useQueryClient();
    const canEdit = authApi.canManageRoles();
    const [edits, setEdits] = useState<Record<string, Set<string>>>({});
    const [feedback, setFeedback] = useState('');
    const [localErr, setLocalErr] = useState('');

    useEffect(() => {
        document.title = 'Roles & permissions · Access · System';
    }, []);

    useEffect(() => {
        if (feedback) {
            const t = setTimeout(() => setFeedback(''), 3500);
            return () => clearTimeout(t);
        }
    }, [feedback]);

    const matrixQ = useQuery({
        queryKey: ['rbac', 'matrix'],
        queryFn: () => rolesApi.loadMatrix(),
        staleTime: 30_000,
    });

    const roles = useMemo(() => sortRoles(matrixQ.data?.roles ?? []), [matrixQ.data?.roles]);
    const grouped = useMemo(
        () => groupPermissions(matrixQ.data?.permissions ?? []),
        [matrixQ.data?.permissions]
    );

    const dirty = Object.keys(edits).length > 0;

    const saveMutation = useMutation({
        mutationFn: async (payload: Record<string, string[]>) => {
            for (const [roleId, ids] of Object.entries(payload)) {
                await rolesApi.updatePermissions(roleId, ids);
            }
        },
        onSuccess: async () => {
            setEdits({});
            setFeedback('Permissions saved — data reloaded from the API.');
            setLocalErr('');
            await queryClient.invalidateQueries({ queryKey: ['rbac', 'matrix'] });
        },
        onError: (err: unknown) => {
            const ax = err as { response?: { data?: { message?: string } } };
            setLocalErr(ax?.response?.data?.message || 'Failed to save permissions');
        },
    });

    const hasPermission = (role: Role, permId: string): boolean => {
        if (edits[role.id]) return edits[role.id].has(permId);
        return role.permissions?.some((p) => p.id === permId) ?? false;
    };

    const toggle = (role: Role, permId: string) => {
        if (!canEdit) return;
        if (role.name === 'admin' && role.is_built_in) return;

        const current = edits[role.id] ?? new Set(role.permissions?.map((p) => p.id) || []);
        const next = new Set(current);
        next.has(permId) ? next.delete(permId) : next.add(permId);
        setEdits((prev) => ({ ...prev, [role.id]: next }));
        setLocalErr('');
    };

    const handleSave = () => {
        const payload: Record<string, string[]> = {};
        for (const [roleId, set] of Object.entries(edits)) {
            payload[roleId] = Array.from(set);
        }
        saveMutation.mutate(payload);
    };

    const loading = matrixQ.isLoading;
    const fetching = matrixQ.isFetching;
    const queryErr =
        matrixQ.isError &&
        ((matrixQ.error as { response?: { data?: { message?: string } } })?.response?.data?.message ||
            (matrixQ.error as Error)?.message ||
            'Failed to load RBAC data');

    const allPerms = matrixQ.data?.permissions ?? [];

    if (loading) {
        return (
            <div className="flex items-center justify-center py-24 text-slate-500 dark:text-slate-400">
                <RefreshCw size={18} className="animate-spin mr-2" /> Loading roles and permissions from API…
            </div>
        );
    }

    if (matrixQ.isError) {
        return (
            <div className="flex flex-col items-center justify-center py-24 text-slate-600 dark:text-slate-300 px-4">
                <AlertCircle size={32} className="mb-3 text-amber-500 opacity-90" />
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Could not load RBAC data</h3>
                <p className="text-sm max-w-md text-center text-slate-500">{String(queryErr)}</p>
                <button
                    type="button"
                    onClick={() => matrixQ.refetch()}
                    className="mt-5 flex items-center gap-2 px-4 py-2 border border-slate-300 dark:border-slate-600 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-sm font-medium"
                >
                    <RefreshCw size={14} /> Retry
                </button>
            </div>
        );
    }

    if (roles.length === 0 || allPerms.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center py-24 text-slate-600 dark:text-slate-300 px-4">
                <AlertCircle size={32} className="mb-3 text-amber-500 opacity-90" />
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">No RBAC seed data</h3>
                <p className="text-sm max-w-md text-center">
                    Roles or permissions returned empty from <code className="text-xs font-mono">/api/v1/roles</code> or{' '}
                    <code className="text-xs font-mono">/api/v1/permissions</code>. Apply backend migrations and seed scripts,
                    then retry.
                </p>
                <button
                    type="button"
                    onClick={() => matrixQ.refetch()}
                    className="mt-5 flex items-center gap-2 px-4 py-2 border border-slate-300 dark:border-slate-600 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-sm font-medium"
                >
                    <RefreshCw size={14} /> Retry
                </button>
            </div>
        );
    }

    return (
        <div className="space-y-6 w-full max-w-none animate-fade-in">
            <InsightHero eyebrow="System"
                variant="light"
                accent="cyan"
                icon={Shield}
                title="Authorization matrix"
                actions={
                    !canEdit ? (
                        <div className="flex items-center gap-2 shrink-0 rounded-xl border border-amber-200 dark:border-amber-800/60 bg-amber-50/90 dark:bg-amber-500/10 px-3 py-2 text-xs text-amber-900 dark:text-amber-200 max-w-xs">
                            <Eye className="w-4 h-4 shrink-0" />
                            <span>
                                View only — your role can read <code className="font-mono">roles:read</code> but not <code className="font-mono">roles:write</code>.
                            </span>
                        </div>
                    ) : null
                }
            />

            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Permission matrix</h2>
                    <p className="text-[13px] text-slate-500 dark:text-slate-400 mt-0.5">
                        {allPerms.length} permissions · {grouped.length} resources · {roles.length} roles — data from live API
                    </p>
                </div>
                <div className="flex gap-2 shrink-0">
                    <button
                        type="button"
                        onClick={() => matrixQ.refetch()}
                        className="p-2.5 text-slate-500 hover:text-slate-900 dark:hover:text-white border border-slate-300 dark:border-slate-600 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                        title="Refresh"
                    >
                        <RefreshCw size={15} className={fetching ? 'animate-spin' : ''} />
                    </button>
                    <button
                        type="button"
                        onClick={handleSave}
                        disabled={!canEdit || !dirty || saveMutation.isPending}
                        className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium transition-colors ${
                            canEdit && dirty
                                ? 'bg-cyan-600 hover:bg-cyan-700 text-white shadow-sm'
                                : 'bg-slate-100 text-slate-400 dark:bg-slate-800 dark:text-slate-600 cursor-not-allowed'
                        }`}
                    >
                        <Save size={14} /> {saveMutation.isPending ? 'Saving…' : 'Save changes'}
                    </button>
                </div>
            </div>

            {feedback && (
                <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/20 text-sm">
                    <Check size={14} /> {feedback}
                </div>
            )}
            {localErr && (
                <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-50 text-red-600 border border-red-200 dark:bg-red-500/10 dark:text-red-400 dark:border-red-500/20 text-sm">
                    <AlertCircle size={14} /> {localErr}
                </div>
            )}

            <div className="bg-white dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900/50">
                                <th className="text-left px-5 py-3 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider sticky left-0 bg-slate-50 dark:bg-slate-900/90 z-10 min-w-[220px] shadow-[1px_0_0_0_#e2e8f0] dark:shadow-[1px_0_0_0_#334155]">
                                    Permission
                                </th>
                                {roles.map((role) => {
                                    const s = ROLE_COLORS[role.name] || ROLE_COLORS.viewer;
                                    return (
                                        <th key={role.id} className="text-center px-3 py-3 min-w-[104px] align-bottom">
                                            <div className="flex flex-col items-center gap-1" title={role.description}>
                                                <span
                                                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-wide border ${s.bg} ${s.text} ${s.border}`}
                                                >
                                                    <Shield size={9} /> {role.name}
                                                </span>
                                                {role.is_built_in && role.name === 'admin' && (
                                                    <span className="flex items-center gap-0.5 text-[9px] text-slate-500 dark:text-slate-400">
                                                        <Lock size={8} /> Full access
                                                    </span>
                                                )}
                                            </div>
                                        </th>
                                    );
                                })}
                            </tr>
                        </thead>
                        <tbody>
                            {grouped.map(({ resource, permissions: perms }) => (
                                <Fragment key={resource}>
                                    <tr className="bg-slate-50/70 dark:bg-slate-800/50 border-y border-slate-200 dark:border-slate-700">
                                        <td
                                            colSpan={roles.length + 1}
                                            className="px-5 py-2 text-[10px] font-bold text-slate-700 dark:text-slate-300 uppercase tracking-[0.1em]"
                                        >
                                            {resource}
                                        </td>
                                    </tr>
                                    {perms.map((perm) => (
                                        <tr
                                            key={perm.id}
                                            className="border-b border-slate-200/60 dark:border-slate-700/60 last:border-b-0 hover:bg-slate-50 dark:hover:bg-slate-700/40 transition-colors"
                                        >
                                            <td className="px-5 py-2.5 sticky left-0 bg-white dark:bg-slate-800 z-10 shadow-[1px_0_0_0_#e2e8f0] dark:shadow-[1px_0_0_0_#334155]">
                                                <div className="text-slate-900 dark:text-white font-medium text-[13px]">{perm.action}</div>
                                                <div className="text-[11px] text-slate-500 dark:text-slate-400 leading-tight">{perm.description}</div>
                                            </td>
                                            {roles.map((role) => {
                                                const granted = hasPermission(role, perm.id);
                                                const isAdmin = role.name === 'admin' && role.is_built_in;
                                                const modified = edits[role.id] !== undefined;
                                                const disabledCell = !canEdit || isAdmin;

                                                return (
                                                    <td key={role.id} className="text-center px-3 py-2.5">
                                                        <button
                                                            type="button"
                                                            onClick={() => toggle(role, perm.id)}
                                                            disabled={disabledCell}
                                                            className={`
                                                                w-7 h-7 rounded-md flex items-center justify-center mx-auto
                                                                transition-all duration-150
                                                                ${granted
                                                                    ? isAdmin
                                                                        ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 cursor-not-allowed opacity-80'
                                                                        : modified
                                                                          ? 'bg-amber-100 dark:bg-amber-500/20 text-amber-600 dark:text-amber-400 ring-1 ring-amber-300 dark:ring-amber-500/40 hover:bg-amber-200 dark:hover:bg-amber-500/30'
                                                                          : 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 hover:bg-emerald-200 dark:hover:bg-emerald-500/30'
                                                                    : isAdmin
                                                                      ? 'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 cursor-not-allowed opacity-80'
                                                                      : 'bg-slate-100 dark:bg-slate-700 text-slate-400 dark:text-slate-500 hover:bg-slate-200 dark:hover:bg-slate-600'
                                                                }
                                                                ${disabledCell && !isAdmin ? 'opacity-60 cursor-not-allowed' : ''}
                                                            `}
                                                            title={
                                                                !canEdit
                                                                    ? 'View only'
                                                                    : isAdmin
                                                                      ? 'Built-in admin — always fully authorized'
                                                                      : `${granted ? 'Revoke' : 'Grant'} ${resource}:${perm.action}`
                                                            }
                                                        >
                                                            {granted || isAdmin ? (
                                                                <Check size={13} strokeWidth={2.5} />
                                                            ) : (
                                                                <span className="text-[10px]">—</span>
                                                            )}
                                                        </button>
                                                    </td>
                                                );
                                            })}
                                        </tr>
                                    ))}
                                </Fragment>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[11px] text-slate-500 dark:text-slate-400 px-1">
                <div className="flex items-center gap-1.5">
                    <div className="w-5 h-5 rounded-md bg-emerald-100 dark:bg-emerald-500/20 flex items-center justify-center">
                        <Check size={10} strokeWidth={2.5} className="text-emerald-600 dark:text-emerald-400" />
                    </div>
                    Granted
                </div>
                <div className="flex items-center gap-1.5">
                    <div className="w-5 h-5 rounded-md bg-amber-100 dark:bg-amber-500/20 flex items-center justify-center ring-1 ring-amber-300 dark:ring-amber-500/40">
                        <Check size={10} strokeWidth={2.5} className="text-amber-600 dark:text-amber-400" />
                    </div>
                    Modified (unsaved)
                </div>
                <div className="flex items-center gap-1.5">
                    <div className="w-5 h-5 rounded-md bg-slate-100 dark:bg-slate-700 flex items-center justify-center">
                        <span className="text-[9px] text-slate-400 dark:text-slate-500">—</span>
                    </div>
                    Not granted
                </div>
                <div className="flex items-center gap-1.5 sm:ml-auto">
                    <Lock size={10} /> Built-in admin column is locked; saves call{' '}
                    <code className="font-mono text-[10px]">PATCH /api/v1/roles/:id/permissions</code>
                </div>
            </div>
        </div>
    );
}
