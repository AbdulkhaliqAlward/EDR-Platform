// The platform's single time base: times are shown in the server's display
// zone (EDR_TIMEZONE on the server), not the viewer's browser zone, so every
// operator sees the same wall-clock time for the same event.

export interface DisplayZone {
    /** IANA name ("Asia/Riyadh"); "" when the server only knows its offset. */
    timezone: string;
    utc_offset_seconds: number;
}

const FIELDS: Intl.DateTimeFormatOptions = {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
};

function offsetLabel(seconds: number): string {
    if (seconds === 0) return 'UTC';
    const sign = seconds < 0 ? '-' : '+';
    const abs = Math.abs(seconds);
    const h = String(Math.floor(abs / 3600)).padStart(2, '0');
    const m = String(Math.floor((abs % 3600) / 60)).padStart(2, '0');
    return `UTC${sign}${h}:${m}`;
}

/** e.g. "12 Oct 2026, 13:04:05 GMT+3". Invalid input is returned as-is. */
export function formatInZone(value: string | number | Date, zone?: DisplayZone | null): string {
    const d = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(d.getTime())) return String(value);
    if (!zone) return d.toLocaleString();
    if (zone.timezone) {
        try {
            return new Intl.DateTimeFormat('en-GB', { ...FIELDS, timeZone: zone.timezone, timeZoneName: 'short' }).format(d);
        } catch {
            // Unknown to this browser: fall through to the numeric offset.
        }
    }
    const shifted = new Date(d.getTime() + zone.utc_offset_seconds * 1000);
    return `${new Intl.DateTimeFormat('en-GB', { ...FIELDS, timeZone: 'UTC' }).format(shifted)} ${offsetLabel(zone.utc_offset_seconds)}`;
}

/** Short zone name for headers, e.g. "Asia/Riyadh" or "UTC+03:00". */
export function zoneName(zone?: DisplayZone | null): string {
    if (!zone) return 'browser time';
    return zone.timezone || offsetLabel(zone.utc_offset_seconds);
}

/**
 * Browser clock error relative to the server, from one request: positive when
 * the browser is behind. Uses the request midpoint to cancel network latency.
 */
export function browserSkewMs(serverTimeIso: string, sentAt: number, receivedAt: number): number {
    const server = Date.parse(serverTimeIso);
    if (Number.isNaN(server)) return 0;
    return Math.round(server - (sentAt + receivedAt) / 2);
}

/** "+5m 12s" style description of an agent clock offset (ms, server − agent). */
export function describeClockOffset(ms: number): string {
    const abs = Math.abs(ms);
    const s = Math.round(abs / 1000);
    const parts = s >= 3600 ? [`${Math.floor(s / 3600)}h`, `${Math.floor((s % 3600) / 60)}m`]
        : s >= 60 ? [`${Math.floor(s / 60)}m`, `${s % 60}s`]
        : [`${s}s`];
    return `${parts.join(' ')} ${ms > 0 ? 'behind' : 'ahead of'} the server`;
}
