import { useCallback } from 'react';
import { useQuery } from '@tanstack/react-query';
import { systemApi, type SystemTime } from '../api/client';
import { browserSkewMs, formatInZone, zoneName } from '../utils/serverTime';

export type ServerClock = SystemTime & { skewMs: number };

/**
 * The platform time base: the server's clock and display zone. `now()` is the
 * server's current time (corrected for this browser's clock error) and
 * `format()` renders any timestamp in the server display zone.
 */
export function useServerClock() {
    const { data, isError } = useQuery({
        queryKey: ['system-time'],
        queryFn: async (): Promise<ServerClock> => {
            const sent = Date.now();
            const st = await systemApi.time();
            return { ...st, skewMs: browserSkewMs(st.server_time, sent, Date.now()) };
        },
        // Re-checked so a server time zone change reaches open dashboards.
        staleTime: 5 * 60_000,
        refetchInterval: 5 * 60_000,
        retry: 1,
    });
    const skew = data?.skewMs ?? 0;
    const now = useCallback(() => Date.now() + skew, [skew]);
    const format = useCallback((value: string | number | Date) => formatInZone(value, data), [data]);
    // ready: the server clock is known (or unavailable — then the browser
    // clock is the best remaining estimate).
    return { clock: data, ready: !!data || isError, now, format, zoneLabel: zoneName(data) };
}
