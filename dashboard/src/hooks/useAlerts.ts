import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { alertsApi, agentsApi, createAlertStream, type Alert } from '../api/client';
import { useToast } from '../components';
import type { DateRange } from '../components/DateRangePicker';
import { usePaginatedQuery } from './usePaginatedQuery';
import { createAlertRefresh, rememberAlert } from './alertRefresh';
import { usePageFilters } from './usePageFilters';

export type SortField = 'timestamp' | 'severity' | 'risk_score';
export interface AlertFilters { severities: string[]; statuses: string[]; search: string }
export function useAlerts() {
    const queryClient = useQueryClient();
    const { showToast } = useToast();
    const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
    const [selection, setSelection] = useState<{ scope: string; ids: Set<string> }>({ scope: '', ids: new Set() });
    const [newAlertIds, setNewAlertIds] = useState<Set<string>>(new Set());
    const [pendingCount, setPendingCount] = useState(0);
    const pending = useRef(new Set<string>());
    const visibleAlerts = useRef<Alert[]>([]);
    const paramsRef = useRef<Record<string, string>>({});
    const [defaults] = useState(() => ({
        date_from: new Date(Date.now() - 24 * 3600_000).toISOString(), date_to: new Date().toISOString(), sort: 'created_at', order: 'desc',
    }));
    const query = usePaginatedQuery<Alert>({ name: 'alerts', defaults, fetchPage: alertsApi.page });
    const alerts = query.rows;
    useEffect(() => { visibleAlerts.current = alerts; }, [alerts]);
    useEffect(() => { paramsRef.current = query.params; }, [query.params]);
    // New-item counts belong to one filter set; navigating pages keeps them.
    const filterIdentity = useMemo(() => { const { cursor: _cursor, ...rest } = query.params; void _cursor; return JSON.stringify(rest); }, [query.params]);
    useEffect(() => { pending.current.clear(); setPendingCount(0); }, [filterIdentity]);
    const [filterDraft, updateFilters] = usePageFilters(query.params, { severity: '', status: '', search: '' }, query.setFilters);
    const filters: AlertFilters = { severities: filterDraft.severity.split(',').filter(Boolean), statuses: filterDraft.status.split(',').filter(Boolean), search: filterDraft.search };
    const dateRange = { from: new Date(query.params.date_from), to: new Date(query.params.date_to) };
    const setFilters = (next: AlertFilters) => updateFilters({ severity: next.severities.join(','), status: next.statuses.join(','), search: next.search });
    const selectionScope = JSON.stringify(query.params);
    const selectedIds = selection.scope === selectionScope ? selection.ids : new Set<string>();
    const setSelectedIds = (change: Set<string> | ((old: Set<string>) => Set<string>)) => setSelection(old => ({ scope: selectionScope,
        ids: typeof change === 'function' ? change(old.scope === selectionScope ? old.ids : new Set()) : change }));
    const clearSelection = () => setSelectedIds(new Set());
    const { data: agentData } = useQuery({ queryKey: ['agentsForAlerts'], queryFn: () => agentsApi.list({ limit: 100 }), staleTime: 120000 });
    const agentHostnameMap = useMemo(() => Object.fromEntries((agentData?.data || []).map(a => [a.id, a.hostname])), [agentData]);
    const detail = useQuery({ queryKey: ['alert', selectedAlert?.id], queryFn: () => alertsApi.get(selectedAlert!.id), enabled: !!selectedAlert?.id, staleTime: 30_000 });
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !document.querySelector('[role="dialog"][aria-modal="true"]')) setSelectedAlert(null); };
        window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey);
    }, []);
    // Reconcile a bounded first-page preview on outages/reconnects. Neither this
    // probe nor the stream writes into the analyst's current page cache.
    useEffect(() => {
        let connected = false, hasConnected = false, disposed = false;
        let request: AbortController | undefined;
        const flush = createAlertRefresh(() => setPendingCount(pending.current.size));
        const matches = (alert: Alert) => {
            const { severity = '', status = '' } = paramsRef.current;
            return (!severity || severity.split(',').includes(alert.severity)) && (!status || status.split(',').includes(alert.status));
        };
        const queue = (alert: Alert) => { if (alert?.id && matches(alert)) { rememberAlert(pending.current, alert.id, 1000); flush.schedule(); } };
        const probe = async () => {
            if (disposed || request || document.visibilityState !== 'visible') return;
            request = new AbortController();
            try {
                const current = paramsRef.current;
                const params: Record<string, string> = { ...current, limit: '25', sort: 'created_at', order: 'desc', date_to: new Date().toISOString() };
                delete params.cursor;
                const page = await alertsApi.page(params, request.signal);
                if (disposed) return;
                const known = new Map(visibleAlerts.current.map(alert => [alert.id, JSON.stringify(alert)]));
                const fence = Date.parse(current.date_to);
                for (const alert of page.data) {
                    const old = known.get(alert.id);
                    if (old ? old !== JSON.stringify(alert) : Date.parse(alert.created_at || alert.timestamp) > fence) queue(alert);
                }
            } catch { /* Keep the current page; retry on the next visible interval. */ }
            finally { request = undefined; }
        };
        const stream = createAlertStream(queue, undefined, online => {
            connected = online;
            if (online && hasConnected) void probe();
            if (online) hasConnected = true;
        });
        const timer = setInterval(() => { if (!connected) void probe(); }, 5000);
        const onVisible = () => { if (document.visibilityState === 'visible') void probe(); };
        document.addEventListener('visibilitychange', onVisible);
        return () => { disposed = true; clearInterval(timer); request?.abort(); flush.dispose(); stream.close(); document.removeEventListener('visibilitychange', onVisible); };
    }, []);
    const refresh = () => {
        setNewAlertIds(new Set(pending.current)); pending.current.clear(); setPendingCount(0); clearSelection();
        query.setFilters({ date_to: new Date().toISOString() });
    };
    // An analyst's own change re-reads the current page with the same cursor and
    // fence, so rows stay in place (a row leaves only if it no longer matches).
    const reloadPage = () => {
        void queryClient.invalidateQueries({ queryKey: ['alertStats'] });
        void queryClient.invalidateQueries({ queryKey: ['alerts', 'page'] });
    };
    const update = useMutation({ mutationFn: ({ id, status }: { id: string; status: string }) => alertsApi.updateStatus(id, status), onSuccess: (_data, { id }) => {
        reloadPage(); void queryClient.invalidateQueries({ queryKey: ['alert', id] });
        showToast('Alert status updated', 'success');
    }, onError: () => showToast('Failed to update alert status', 'error') });
    const bulk = useMutation({ mutationFn: ({ ids, status }: { ids: string[]; status: string }) => alertsApi.bulkUpdateStatus(ids, status), onSuccess: (_data, { ids }) => {
        clearSelection(); reloadPage(); showToast(`${ids.length} alert${ids.length === 1 ? '' : 's'} updated`, 'success');
    }, onError: () => showToast('Failed to update alerts', 'error') });
    const handleStatusChange = useCallback(async (id: string, status: string, requireSuccess = false) => {
        try { await update.mutateAsync({ id, status }); setSelectedAlert(null); }
        catch (error) { if (requireSuccess) throw error; }
    }, [update]);
    const handleBulkAction = (status: string) => {
        if (query.busy) return;
        const ids = alerts.filter(a => selectedIds.has(a.id)).map(a => a.id);
        if (ids.length) bulk.mutate({ ids, status });
    };
    const toggleSelect = (id: string) => {
        if (query.busy || !alerts.some(a => a.id === id)) return;
        setSelectedIds(previous => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next; });
    };
    const toggleSelectAll = () => { if (!query.busy) setSelectedIds(selectedIds.size === alerts.length ? new Set() : new Set(alerts.map(a => a.id))); };
    return { alerts, agentHostnameMap, isLoading: query.isLoading, isError: query.isError, error: query.error,
        pagination: query, pendingCount, refresh, retry: () => query.refetch(),
        filters, dateRange,
        setFilters, setDateRange: (range: DateRange) => query.setFilters({ date_from: range.from?.toISOString(), date_to: range.to?.toISOString() }),
        sortBy: (query.params.sort === 'risk_score' ? 'risk_score' : 'timestamp') as SortField, sortOrder: (query.params.order === 'asc' ? 'asc' : 'desc') as 'asc' | 'desc',
        // Keyset sorts the server supports: creation time and risk score.
        toggleSort: (field: SortField) => {
            const sort = field === 'risk_score' ? 'risk_score' : field === 'timestamp' ? 'created_at' : '';
            if (!sort) return;
            const order = query.params.sort === sort && query.params.order !== 'asc' ? 'asc' : 'desc';
            query.setFilters({ sort, order });
        },
        selectedIds, selectedAlert: detail.data?.id === selectedAlert?.id ? detail.data ?? null : selectedAlert, setSelectedAlert,
        toggleSelectAll, toggleSelect, clearSelection, handleStatusChange, handleBulkAction,
        isUpdating: update.isPending, isBulkUpdating: bulk.isPending, newAlertIds,
    };
}
export type UseAlertsReturn = ReturnType<typeof useAlerts>;
export default useAlerts;
