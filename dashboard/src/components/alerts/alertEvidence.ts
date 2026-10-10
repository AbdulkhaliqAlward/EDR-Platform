import type { Alert, ContextSnapshot } from '../../api/client';

const record = (value: unknown): Record<string, unknown> =>
    value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
const scalar = (value: unknown): string =>
    typeof value === 'string' ? value.trim() : typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value)) ? String(value) : '';
const known = (value: string) => /^(unknown|null|undefined|n\/a)$/i.test(value) ? '' : value;
const basename = (value: string) => value.split(/[\\/]/).pop() || '';

// Resolve only the represented event. A scoring snapshot or matched fields may
// belong to another event in an aggregate and must not fill missing identity.
export function alertEvidence(alert: Pick<Alert, 'context_data' | 'event_data'>) {
    const ctx = record(alert.context_data ?? alert.event_data);
    const data = record(ctx.data);
    const pick = (...keys: string[]): string => {
        for (const source of [data, ctx]) {
            for (const key of keys) {
                const value = known(scalar(source[key]));
                if (value) return value;
            }
        }
        return '';
    };
    const eventType = (scalar(ctx.event_type) || pick('event_type')).toLowerCase();
    const isProcess = ['process', 'process_creation', 'process_termination'].includes(eventType);
    const isFile = eventType === 'file' || eventType.startsWith('file_');
    const image = pick('executable', 'process_path', 'image_path', 'Image');
    const processName = pick('process_name') || basename(image) || (isProcess ? pick('name') : '');
    const target = pick('target_filename', 'TargetFilename') || (isFile ? pick('path') : '');
    return { pick, eventType, image, processName, target, isFile };
}

// Old snapshots put the file's generic name into process_name. Do not replace
// it with a process from a different aggregated event; retain raw JSON for audit.
export function displaySnapshot(alert: Alert): ContextSnapshot | undefined {
    const snapshot = alert.context_snapshot;
    if (!snapshot) return undefined;
    const evidence = alertEvidence(alert);
    if (evidence.isFile && !snapshot.process_path && snapshot.process_name &&
        [evidence.pick('name'), basename(evidence.target)].some(name => name && name.toLowerCase() === snapshot.process_name!.toLowerCase())) {
        return { ...snapshot, process_name: undefined };
    }
    return snapshot;
}

export function evidenceDate(value: string): string {
    if (!value) return '';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? `Unavailable (invalid timestamp: ${value})` : `${date.toLocaleString()} (${Intl.DateTimeFormat().resolvedOptions().timeZone})`;
}
