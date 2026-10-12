import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus, Save, Trash2, ShieldAlert, Key, Globe, LayoutList, Server, Shield } from 'lucide-react';
import { agentsApi, alertsApi, contextPoliciesApi, type ContextPolicy } from '../../api/client';
import { useToast } from '../../components/Toast';
import InsightHero from '../../components/InsightHero';

type EditablePolicy = Omit<ContextPolicy, 'id' | 'created_at' | 'updated_at'> & { id?: number };

const NEW_POLICY: EditablePolicy = {
    name: '',
    scope_type: 'agent',
    scope_value: '',
    enabled: true,
    user_role_weight: 1.0,
    device_criticality_weight: 1.0,
    network_anomaly_factor: 1.0,
    trusted_networks: [],
    notes: '',
};

const CIDR_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;

function parseTrustedNetworks(value: string): string[] {
    return value.split(',').map(v => v.trim()).filter(Boolean);
}

export default function ContextPolicies() {
    const queryClient = useQueryClient();
    const { showToast } = useToast();
    const [draft, setDraft] = useState<EditablePolicy>(NEW_POLICY);
    const [trustedNetworksText, setTrustedNetworksText] = useState('');
    const [validationError, setValidationError] = useState<string>('');

    const { data, isLoading, error } = useQuery({
        queryKey: ['contextPolicies'],
        queryFn: contextPoliciesApi.list,
        refetchInterval: 15000,
    });

    const { data: agentsData } = useQuery({
        queryKey: ['contextPolicyAgents'],
        queryFn: () => agentsApi.list({ limit: 500, offset: 0, sort_by: 'hostname', sort_order: 'asc' }),
        staleTime: 30000,
    });

    // alertsApi.list returns { alerts: Alert[], total: number }
    const { data: alertsData } = useQuery({
        queryKey: ['contextPolicyAlerts'],
        queryFn: () => alertsApi.list({ limit: 200, offset: 0, sort: 'timestamp', order: 'desc' }),
        staleTime: 60000,
    });

    const items: ContextPolicy[] = data?.data ?? [];

    // Extract unique usernames from alerts context
    const endpointUsers = useMemo(() => {
        const alerts = alertsData?.alerts ?? [];
        const users = new Set<string>();
        alerts.forEach((a: any) => {
            const username = a.endpoint_context?.username || a.username;
            if (username && username !== 'unknown') users.add(username);
        });
        return Array.from(users).sort();
    }, [alertsData]);

    const mutationCreate = useMutation({
        mutationFn: contextPoliciesApi.create,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['contextPolicies'] });
            setDraft(NEW_POLICY);
            setTrustedNetworksText('');
            setValidationError('');
            showToast('Policy created successfully', 'success');
        },
        onError: (err: any) => showToast(err.message || 'Failed to create policy', 'error'),
    });

    const mutationUpdate = useMutation({
        mutationFn: ({ id, policy }: { id: number; policy: Omit<ContextPolicy, 'id' | 'created_at' | 'updated_at'> }) =>
            contextPoliciesApi.update(id, policy),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['contextPolicies'] });
            setDraft(NEW_POLICY);
            setTrustedNetworksText('');
            setValidationError('');
            showToast('Policy updated successfully', 'success');
        },
        onError: (err: any) => showToast(err.message || 'Failed to update policy', 'error'),
    });

    const mutationDelete = useMutation({
        mutationFn: contextPoliciesApi.remove,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['contextPolicies'] });
            showToast('Policy deleted', 'success');
        },
        onError: (err: any) => showToast(err.message || 'Failed to delete policy', 'error'),
    });

    const handleSave = () => {
        setValidationError('');
        if (!draft.name.trim()) return setValidationError('Name is required.');
        if (!draft.scope_value.trim() && draft.scope_type !== 'global') return setValidationError('Scope target is required.');

        const parsedNetworks = parseTrustedNetworks(trustedNetworksText);
        const invalidNetworks = parsedNetworks.filter(net => !CIDR_PATTERN.test(net));
        if (invalidNetworks.length > 0) return setValidationError(`Invalid CIDR: ${invalidNetworks.join(', ')}`);

        const policyData: Omit<ContextPolicy, 'id' | 'created_at' | 'updated_at'> = {
            name: draft.name,
            scope_type: draft.scope_type,
            scope_value: draft.scope_value,
            enabled: draft.enabled,
            user_role_weight: draft.user_role_weight,
            device_criticality_weight: draft.device_criticality_weight,
            network_anomaly_factor: draft.network_anomaly_factor,
            trusted_networks: parsedNetworks,
            notes: draft.notes,
        };

        if (draft.id) mutationUpdate.mutate({ id: draft.id, policy: policyData });
        else mutationCreate.mutate(policyData);
    };

    const handleEdit = (p: ContextPolicy) => {
        setDraft(p);
        setTrustedNetworksText((p.trusted_networks || []).join(', '));
        setValidationError('');
    };

    const handleDelete = (id: number) => {
        if (window.confirm('Delete this policy?')) mutationDelete.mutate(id);
    };

    if (error) return (
        <div className="p-4 text-rose-500 bg-rose-50 dark:bg-rose-950/20 rounded-xl border border-rose-200 dark:border-rose-900">
            Failed to load context policies.
        </div>
    );

    return (
        <div className="space-y-6 w-full min-w-0 animate-slide-up-fade">
            <InsightHero
                icon={ShieldAlert}
                accent="cyan"
                eyebrow="Management"
                title="Context Policies"
            />

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

                {/* FORM PANEL */}
                <div className="xl:col-span-1">
                    <div className="bg-white/95 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 backdrop-blur-md rounded-2xl p-5 shadow-sm">
                        <h3 className="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2 mb-4">
                            <LayoutList className="w-4 h-4 text-cyan-500" />
                            {draft.id ? 'Edit Policy' : 'Create New Policy'}
                        </h3>

                        {validationError && (
                            <div className="mb-4 p-3 rounded-xl bg-rose-50 dark:bg-rose-900/20 text-rose-600 dark:text-rose-400 text-xs font-medium border border-rose-100 dark:border-rose-900/50">
                                {validationError}
                            </div>
                        )}

                        <div className="space-y-4">
                            <div>
                                <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">Policy Name</label>
                                <input className="input w-full" value={draft.name} onChange={e => setDraft(d => ({ ...d, name: e.target.value }))} placeholder="e.g. Exec Laptop Trust" />
                            </div>

                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">Scope Type</label>
                                    <select className="input w-full" value={draft.scope_type} onChange={e => setDraft(d => ({ ...d, scope_type: e.target.value as any, scope_value: '' }))}>
                                        <option value="global">Global</option>
                                        <option value="agent">Agent</option>
                                        <option value="user">User</option>
                                    </select>
                                </div>
                                {draft.scope_type !== 'global' && (
                                    <div>
                                        <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">Target</label>
                                        {draft.scope_type === 'agent' ? (
                                            <select className="input w-full" value={draft.scope_value} onChange={e => setDraft(d => ({ ...d, scope_value: e.target.value }))}>
                                                <option value="">Select Agent…</option>
                                                {(agentsData?.data ?? []).map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
                                            </select>
                                        ) : (
                                            <select className="input w-full" value={draft.scope_value} onChange={e => setDraft(d => ({ ...d, scope_value: e.target.value }))}>
                                                <option value="">Select User…</option>
                                                {endpointUsers.map(u => <option key={u} value={u}>{u}</option>)}
                                            </select>
                                        )}
                                    </div>
                                )}
                            </div>

                            <div className="grid grid-cols-3 gap-3 pt-1">
                                {[
                                    { label: 'Role Weight', field: 'user_role_weight' as const },
                                    { label: 'Criticality', field: 'device_criticality_weight' as const },
                                    { label: 'Net Factor', field: 'network_anomaly_factor' as const },
                                ].map(({ label, field }) => (
                                    <div key={field}>
                                        <label className="block text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1">{label}</label>
                                        <input
                                            type="number" step="0.1" min="0" max="10"
                                            className="input w-full font-mono text-sm"
                                            value={draft[field]}
                                            onChange={e => setDraft(d => ({ ...d, [field]: parseFloat(e.target.value) || 1.0 }))}
                                        />
                                    </div>
                                ))}
                            </div>

                            <div className="pt-1">
                                <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">
                                    Trusted Networks <span className="normal-case font-normal">(CIDR, comma-separated)</span>
                                </label>
                                <textarea
                                    className="input w-full font-mono text-xs min-h-[56px]"
                                    placeholder="192.168.1.0/24, 10.0.0.0/8"
                                    value={trustedNetworksText}
                                    onChange={e => setTrustedNetworksText(e.target.value)}
                                />
                            </div>

                            <div>
                                <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">Notes</label>
                                <input className="input w-full text-xs" value={draft.notes || ''} onChange={e => setDraft(d => ({ ...d, notes: e.target.value }))} placeholder="Optional notes" />
                            </div>

                            <label className="flex items-center gap-2 select-none cursor-pointer">
                                <input type="checkbox" className="rounded" checked={draft.enabled} onChange={e => setDraft(d => ({ ...d, enabled: e.target.checked }))} />
                                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Policy Enabled</span>
                            </label>

                            <div className="flex justify-end gap-2 pt-4 border-t border-slate-100 dark:border-slate-800 mt-4">
                                {draft.id && (
                                    <button type="button" className="btn text-xs" onClick={() => { setDraft(NEW_POLICY); setTrustedNetworksText(''); setValidationError(''); }}>
                                        Cancel
                                    </button>
                                )}
                                <button
                                    type="button"
                                    className="btn btn-primary text-xs flex items-center gap-2"
                                    disabled={mutationCreate.isPending || mutationUpdate.isPending}
                                    onClick={handleSave}
                                >
                                    {draft.id ? <Save className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
                                    {draft.id ? 'Save Changes' : 'Create Policy'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                {/* LIST PANEL */}
                <div className="xl:col-span-2">
                    <div className="bg-white/95 dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 backdrop-blur-md rounded-2xl shadow-sm overflow-hidden">
                        <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                            <h3 className="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
                                <Shield className="w-4 h-4 text-indigo-500" />
                                Active Policies
                            </h3>
                            <span className="text-xs font-semibold text-slate-500 bg-slate-100 dark:bg-slate-800 px-2.5 py-1 rounded-full">
                                {items.length} {items.length === 1 ? 'rule' : 'rules'}
                            </span>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-sm">
                                <thead className="bg-slate-50/80 dark:bg-slate-900/50 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                                    <tr>
                                        <th className="px-5 py-3">Policy</th>
                                        <th className="px-5 py-3">Scope</th>
                                        <th className="px-5 py-3">Weights</th>
                                        <th className="px-5 py-3">Status</th>
                                        <th className="px-5 py-3 text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                                    {isLoading ? (
                                        <tr><td colSpan={5} className="px-5 py-8 text-center text-slate-400 text-sm">Loading policies…</td></tr>
                                    ) : items.length === 0 ? (
                                        <tr><td colSpan={5} className="px-5 py-8 text-center text-slate-400 text-sm">No context policies defined yet.</td></tr>
                                    ) : items.map(p => (
                                        <tr key={p.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/30 transition-colors group">
                                            <td className="px-5 py-4">
                                                <div className="font-semibold text-slate-800 dark:text-slate-100">{p.name}</div>
                                                {p.notes && <div className="text-[10px] text-slate-500 mt-0.5 max-w-[180px] truncate">{p.notes}</div>}
                                            </td>
                                            <td className="px-5 py-4">
                                                <div className="flex items-center gap-1.5">
                                                    {p.scope_type === 'global'
                                                        ? <Globe className="w-3.5 h-3.5 text-indigo-500" />
                                                        : p.scope_type === 'agent'
                                                            ? <Server className="w-3.5 h-3.5 text-cyan-500" />
                                                            : <Key className="w-3.5 h-3.5 text-amber-500" />}
                                                    <span className="capitalize text-xs font-medium text-slate-700 dark:text-slate-300">{p.scope_type}</span>
                                                </div>
                                                {p.scope_type !== 'global' && (
                                                    <div className="text-[10px] font-mono text-slate-500 mt-0.5 max-w-[150px] truncate">{p.scope_value}</div>
                                                )}
                                            </td>
                                            <td className="px-5 py-4">
                                                <div className="flex flex-col gap-0.5 text-[10px] font-mono text-slate-500">
                                                    <span>Role: <span className="text-slate-700 dark:text-slate-300 font-medium">{p.user_role_weight}×</span></span>
                                                    <span>Crit: <span className="text-slate-700 dark:text-slate-300 font-medium">{p.device_criticality_weight}×</span></span>
                                                    <span>Net:  <span className="text-slate-700 dark:text-slate-300 font-medium">{p.network_anomaly_factor}×</span></span>
                                                </div>
                                            </td>
                                            <td className="px-5 py-4">
                                                <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border ${p.enabled
                                                    ? 'bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800/50'
                                                    : 'bg-slate-100 dark:bg-slate-800 text-slate-500 border-slate-200 dark:border-slate-700'}`}>
                                                    {p.enabled ? 'Active' : 'Disabled'}
                                                </span>
                                            </td>
                                            <td className="px-5 py-4 text-right">
                                                <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                                    <button
                                                        onClick={() => handleEdit(p)}
                                                        className="p-1.5 text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 hover:bg-cyan-50 dark:hover:bg-cyan-900/30 rounded-lg transition-colors"
                                                        title="Edit"
                                                    >
                                                        <Save className="w-4 h-4" />
                                                    </button>
                                                    <button
                                                        onClick={() => handleDelete(p.id)}
                                                        className="p-1.5 text-slate-400 hover:text-rose-600 dark:hover:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-900/30 rounded-lg transition-colors"
                                                        title="Delete"
                                                        disabled={mutationDelete.isPending}
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
}
