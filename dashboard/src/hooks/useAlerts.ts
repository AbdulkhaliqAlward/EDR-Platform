import { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { alertsApi, agentsApi, createAlertStream, type Alert } from '../api/client';
import { useToast } from '../components';
import { useDebounce } from './useDebounce';
import type { DateRange } from '../components/DateRangePicker';
import { createAlertRefresh, rememberAlert } from './alertRefresh';

export type SortField = 'timestamp' | 'severity' | 'risk_score';

export interface AlertFilters {
    severities: string[];
    statuses: string[];
    search: string;
}

export interface UseAlertsReturn {
    // Data
    alerts: Alert[];
    total: number;
    totalPages: number;
    agentHostnameMap: Record<string, string>;

    // Loading states
    isLoading: boolean;
    isError: boolean;
    error: Error | null;

    // Pagination
    page: number;
    pageSize: number;
    setPage: (page: number) => void;
    setPageSize: (size: number) => void;

    // Sorting
    sortBy: SortField;
    sortOrder: 'asc' | 'desc';
    toggleSort: (field: SortField) => void;

    // Filters
    filters: AlertFilters;
    dateRange: DateRange;
    setFilters: (filters: AlertFilters) => void;
    setDateRange: (range: DateRange) => void;

    // Selection
    selectedIds: Set<string>;
    selectedAlert: Alert | null;
    toggleSelectAll: () => void;
    toggleSelect: (id: string) => void;
    setSelectedAlert: (alert: Alert | null) => void;
    clearSelection: () => void;

    // Actions
    handleStatusChange: (id: string, status: string, requireSuccess?: boolean) => Promise<void>;
    handleBulkAction: (status: string) => void;
    isUpdating: boolean;
    isBulkUpdating: boolean;
    newAlertIds: Set<string>;
}

export function useAlerts(): UseAlertsReturn {
    const queryClient = useQueryClient();
    const { showToast } = useToast();

    // Refs for stream handling
    const seenAlertIdsRef = useRef<Set<string>>(new Set());
    const pendingStreamIdsRef = useRef<Set<string>>(new Set());
    const [streamConnected, setStreamConnected] = useState(false);

    // State
    const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
    const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(10);
    const [sortBy, setSortBy] = useState<SortField>('timestamp');
    const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
    const [newAlertIds, setNewAlertIds] = useState<Set<string>>(new Set());

    const [filters, setFilters] = useState<AlertFilters>({
        severities: [],
        statuses: [],
        search: '',
    });

    const [dateRange, setDateRange] = useState<DateRange>(() => ({
        from: new Date(Date.now() - 24 * 60 * 60 * 1000),
        to: new Date(),
    }));

    const debouncedSearch = useDebounce(filters.search, 300);

    // Close drawer on Escape
    useEffect(() => {
        const handler = (e: KeyboardEvent) => {
            if (e.key === 'Escape' && !document.querySelector('[role="dialog"][aria-modal="true"]')) setSelectedAlert(null);
        };
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, []);

    // Agent hostname lookup map
    const { data: agentListData } = useQuery({
        queryKey: ['agentsForAlerts'],
        queryFn: () => agentsApi.list({ limit: 500 }),
        staleTime: 120000,
        refetchInterval: 120000,
    });

    const agentHostnameMap = useMemo(() => agentListData?.data?.reduce((acc: Record<string, string>, agent) => {
        acc[agent.id] = agent.hostname;
        return acc;
    }, {}) || {}, [agentListData]);

    // Fetch alerts
    const { data, isLoading, isError, error } = useQuery({
        queryKey: ['alerts', filters.severities, filters.statuses, debouncedSearch, dateRange.from?.toISOString(), page, pageSize, sortBy, sortOrder],
        queryFn: () => alertsApi.list({
            limit: pageSize,
            offset: (page - 1) * pageSize,
            severity: filters.severities.length > 0 ? filters.severities.join(',') : undefined,
            status: filters.statuses.length > 0 ? filters.statuses.join(',') : undefined,
            date_from: dateRange.from?.toISOString(),
            date_to: new Date().toISOString(),
            search: debouncedSearch || undefined,
            sort: sortOrder === 'desc' ? `-${sortBy}` : sortBy,
            order: sortOrder,
        }),
        refetchInterval: streamConnected ? 30_000 : 5_000,
        refetchOnWindowFocus: true,
    });

    const alerts = useMemo(() => data?.alerts || [], [data?.alerts]);
    const total = data?.total || 0;
    const totalPages = Math.ceil(total / pageSize);

    // Fetch full alert details when one is selected.
    //
    // The list endpoint (/api/v1/sigma/alerts) returns a compact projection
    // suitable for table rendering — it omits context_snapshot, score_breakdown,
    // ancestor_chain, matched_fields, mitre_*, human_summary, etc. Those fields
    // are only returned by /api/v1/sigma/alerts/{id}. Without this query the
    // detail drawer would render placeholder/empty sections even though the
    // data exists server-side.
    const { data: selectedAlertFull } = useQuery({
        queryKey: ['alert', selectedAlert?.id],
        queryFn: () => alertsApi.get(selectedAlert!.id),
        enabled: !!selectedAlert?.id,
        staleTime: 30_000,
    });

    // Prefer the fully-hydrated record when it matches the currently-selected
    // alert; fall back to the list row while the detail fetch is in-flight so
    // the drawer never flashes empty.
    const effectiveSelectedAlert =
        selectedAlertFull && selectedAlertFull.id === selectedAlert?.id
            ? selectedAlertFull
            : selectedAlert;

    // Track IDs already rendered from DB
    useEffect(() => {
        for (const alert of alerts) {
            rememberAlert(seenAlertIdsRef.current, alert.id);
        }
    }, [alerts]);

    // Realtime stream setup
    useEffect(() => {
        const pendingStreamIds = pendingStreamIdsRef.current;
        const refresh = createAlertRefresh(() => {
                const newCount = pendingStreamIds.size;
                
                if (newCount > 0) {
                    setNewAlertIds(prev => {
                        const next = new Set(prev);
                        pendingStreamIds.forEach(id => rememberAlert(next, id, 500));
                        return next;
                    });
                }
                
                pendingStreamIds.clear();

                const refetchType = document.visibilityState === 'visible' ? 'active' : 'none';
                void queryClient.invalidateQueries({ queryKey: ['alerts'], refetchType }, { cancelRefetch: false });
                void queryClient.invalidateQueries({ queryKey: ['alertStats'], refetchType }, { cancelRefetch: false });

                if (newCount > 0 && document.visibilityState === 'visible') {
                    showToast(`Received ${newCount} new alert${newCount > 1 ? 's' : ''}`, 'success');
                }
        });

        let hasConnected = false;
        const onConnectionChange = (connected: boolean) => {
            setStreamConnected(connected);
            if (connected && hasConnected) refresh.schedule();
            if (connected) hasConnected = true;
        };
        const stream = createAlertStream((alert) => {
            if (!alert?.id) return;
            if (!seenAlertIdsRef.current.has(alert.id)) {
                rememberAlert(seenAlertIdsRef.current, alert.id);
                rememberAlert(pendingStreamIds, alert.id);
            }
            // Existing alert IDs can carry aggregation/status updates too.
            refresh.schedule();
        }, undefined, onConnectionChange);

        return () => {
            stream.close();
            refresh.dispose();
            pendingStreamIds.clear();
        };
    }, [queryClient, showToast]);

    // Mutations
    const updateStatusMutation = useMutation({
        mutationFn: ({ id, status }: { id: string; status: string }) =>
            alertsApi.updateStatus(id, status),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['alerts'] });
            queryClient.invalidateQueries({ queryKey: ['alertStats'] });
            showToast('Alert status updated', 'success');
        },
        onError: () => {
            showToast('Failed to update alert status', 'error');
        },
    });

    const bulkUpdateMutation = useMutation({
        mutationFn: ({ ids, status }: { ids: string[]; status: string }) =>
            alertsApi.bulkUpdateStatus(ids, status),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['alerts'] });
            queryClient.invalidateQueries({ queryKey: ['alertStats'] });
            setSelectedIds(new Set());
            showToast(`${selectedIds.size} alerts updated`, 'success');
        },
        onError: () => {
            showToast('Failed to update alerts', 'error');
        },
    });

    // Handlers
    const handleStatusChange = useCallback(async (id: string, status: string, requireSuccess = false) => {
        try {
            await updateStatusMutation.mutateAsync({ id, status });
            setSelectedAlert(null);
        } catch (err) {
            // The exception dialog needs a rejection to retry only its follow-up.
            // Other action buttons already surface the mutation's error toast.
            if (requireSuccess) throw err;
        }
    }, [updateStatusMutation]);

    const handleBulkAction = useCallback((status: string) => {
        bulkUpdateMutation.mutate({ ids: Array.from(selectedIds), status });
    }, [bulkUpdateMutation, selectedIds]);

    const toggleSelectAll = useCallback(() => {
        if (selectedIds.size === alerts.length) {
            setSelectedIds(new Set());
        } else {
            setSelectedIds(new Set(alerts.map((a) => a.id)));
        }
    }, [selectedIds, alerts]);

    const toggleSelect = useCallback((id: string) => {
        const newSet = new Set(selectedIds);
        if (newSet.has(id)) {
            newSet.delete(id);
        } else {
            newSet.add(id);
        }
        setSelectedIds(newSet);
    }, [selectedIds]);

    const toggleSort = useCallback((field: SortField) => {
        if (sortBy === field) {
            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
        } else {
            setSortBy(field);
            setSortOrder('desc');
        }
        setPage(1);
    }, [sortBy, sortOrder]);

    const clearSelection = useCallback(() => {
        setSelectedIds(new Set());
    }, []);

    // Wrapper for setPageSize that resets page
    const handleSetPageSize = useCallback((size: number) => {
        setPageSize(size);
        setPage(1);
    }, []);

    return {
        // Data
        alerts,
        total,
        totalPages,
        agentHostnameMap,

        // Loading states
        isLoading,
        isError,
        error,

        // Pagination
        page,
        pageSize,
        setPage,
        setPageSize: handleSetPageSize,

        // Sorting
        sortBy,
        sortOrder,
        toggleSort,

        // Filters
        filters,
        dateRange,
        setFilters,
        setDateRange,

        // Selection
        selectedIds,
        selectedAlert: effectiveSelectedAlert,
        toggleSelectAll,
        toggleSelect,
        setSelectedAlert,
        clearSelection,

        // Actions
        handleStatusChange,
        handleBulkAction,
        isUpdating: updateStatusMutation.isPending,
        isBulkUpdating: bulkUpdateMutation.isPending,
        newAlertIds,
    };
}

export default useAlerts;
