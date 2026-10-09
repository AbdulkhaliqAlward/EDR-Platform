import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo, useState, useCallback } from 'react';
import { createAlertRefresh } from './alertRefresh';
import {
    statsApi,
    alertsApi,
    agentsApi,
    createAlertStream,
    type Alert,
    type Agent,
    type AgentStats,
    type AlertStats,
    type TimelineDataPoint,
} from '../api/client';

const STALE_THRESHOLD_MS = 1 * 60 * 1000;

export interface DashboardData {
    // Alert stats
    alertStats: AlertStats | undefined;
    statsLoading: boolean;

    // Agent stats
    agentStats: AgentStats | undefined;

    // Agent list
    agents: Agent[];

    // Recent alerts (from polling)
    recentAlerts: Alert[];

    // Live alerts (from WebSocket + polling)
    liveAlerts: Alert[];

    // Timeline data for sparklines
    timelineData: TimelineDataPoint[] | undefined;

    // Computed
    agentMap: Record<string, string>;
    threatScore: number;
    sparklines: {
        critical: number[];
        high: number[];
        total: number[];
    };

    // Actions
    handleAlertClick: (alert: Alert) => void;
    handleCloseDrawer: () => void;
    drawerAlert: Alert | null;
}

function calcThreatScore(stats: AlertStats | undefined): number {
    if (!stats) return 0;
    const s = stats.by_severity || {};
    const raw = (s.critical || 0) * 20 + (s.high || 0) * 8 + (s.medium || 0) * 3 + (s.low || 0);
    return Math.min(100, Math.round((raw / Math.max(raw, 200)) * 100));
}

export function useDashboard(): DashboardData {
    const queryClient = useQueryClient();
    const [streamAlerts, setStreamAlerts] = useState<Alert[]>([]);
    const [drawerAlert, setDrawerAlert] = useState<Alert | null>(null);
    const [streamConnected, setStreamConnected] = useState(false);

    // ── Queries ───────────────────────────────────────────────
    const { data: alertStats, isLoading: statsLoading } = useQuery({
        queryKey: ['alertStats'],
        queryFn: statsApi.alerts,
        refetchInterval: streamConnected ? 30_000 : 10_000,
        refetchOnWindowFocus: true,
    });

    const { data: agentStats } = useQuery({
        queryKey: ['agentStats'],
        queryFn: agentsApi.stats,
        retry: false,
        refetchInterval: 5000,
    });

    const { data: agentListData } = useQuery({
        queryKey: ['agents'],
        queryFn: () => agentsApi.list({ limit: 200 }),
        retry: false,
        refetchInterval: 10000,
    });

    const { data: recentAlertsData } = useQuery({
        queryKey: ['recentAlerts'],
        queryFn: () => alertsApi.list({ limit: 100 }),
        refetchInterval: streamConnected ? 30_000 : 5_000,
        refetchOnWindowFocus: true,
    });

    const { data: timelineData } = useQuery({
        queryKey: ['dashboardTimeline'],
        queryFn: () => {
            const to = new Date().toISOString();
            const from = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
            return statsApi.timeline({ from, to, granularity: '1d' });
        },
        refetchInterval: 60000,
    });

    // ── Computed values ───────────────────────────────────────
    const agents = useMemo(() => agentListData?.data || [], [agentListData]);

    const agentMap = useMemo<Record<string, string>>(() => {
        const map: Record<string, string> = {};
        agents.forEach((a) => {
            map[a.id] = a.hostname;
        });
        return map;
    }, [agents]);

    const threatScore = useMemo(() => calcThreatScore(alertStats), [alertStats]);

    const sparklines = useMemo(() => {
        const pts = timelineData?.data || [];
        const critical = pts.map((p) => p.critical);
        const high = pts.map((p) => p.high);
        const total = pts.map((p) => p.critical + p.high + p.medium + p.low + p.informational);
        return { critical, high, total };
    }, [timelineData]);

    const recentAlerts = useMemo(() => recentAlertsData?.alerts || [], [recentAlertsData]);

    // ── WebSocket stream ──────────────────────────────────────
    const liveAlerts = useMemo(() => {
        const byId = new Map<string, Alert>();
        for (const alert of [...streamAlerts, ...recentAlerts]) {
            const previous = byId.get(alert.id);
            if (!previous || Date.parse(alert.timestamp) >= Date.parse(previous.timestamp)) byId.set(alert.id, alert);
        }
        return [...byId.values()].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 100);
    }, [streamAlerts, recentAlerts]);

    useEffect(() => {
        const pending = new Map<string, Alert>();
        const refresh = createAlertRefresh(() => {
            const batch = [...pending.values()].reverse();
            pending.clear();
            setStreamAlerts(previous => [...batch, ...previous.filter(alert => !batch.some(item => item.id === alert.id))].slice(0, 100));
            const refetchType = document.visibilityState === 'visible' ? 'active' : 'none';
            void queryClient.invalidateQueries({ queryKey: ['alertStats'], refetchType }, { cancelRefetch: false });
            void queryClient.invalidateQueries({ queryKey: ['recentAlerts'], refetchType }, { cancelRefetch: false });
        });
        let hasConnected = false;
        const onConnectionChange = (connected: boolean) => {
            setStreamConnected(connected);
            if (connected && hasConnected) refresh.schedule();
            if (connected) hasConnected = true;
        };
        const stream = createAlertStream(
            (alert) => {
                if (!alert?.id) return;
                pending.set(alert.id, alert);
                if (pending.size > 100) pending.delete(pending.keys().next().value!);
                refresh.schedule();
            },
            { severity: ['critical', 'high', 'medium', 'low'] },
            onConnectionChange,
        );

        return () => {
            stream.close();
            refresh.dispose();
            pending.clear();
        };
    }, [queryClient]);

    // ── Actions ───────────────────────────────────────────────
    const handleAlertClick = useCallback((alert: Alert) => {
        setDrawerAlert(alert);
    }, []);

    const handleCloseDrawer = useCallback(() => {
        setDrawerAlert(null);
    }, []);

    // ── Document title ─────────────────────────────────────────
    useEffect(() => {
        document.title = 'Security Posture — MITRAS';
    }, []);

    return {
        alertStats,
        statsLoading,
        agentStats,
        agents,
        recentAlerts,
        liveAlerts,
        timelineData: timelineData?.data,
        agentMap,
        threatScore,
        sparklines,
        handleAlertClick,
        handleCloseDrawer,
        drawerAlert,
    };
}

// Export helper for components
export { STALE_THRESHOLD_MS, calcThreatScore };
