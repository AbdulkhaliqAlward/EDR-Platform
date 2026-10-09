import type { Alert, DetectionExceptionInput, ExceptionCondition } from '../../api/client';

export const EXCEPTION_FIELDS = [
    'Image', 'ParentImage', 'CommandLine', 'ParentCommandLine', 'OriginalFileName', 'Hashes', 'User',
    'IntegrityLevel', 'Company', 'Product', 'Description', 'CurrentDirectory', 'TargetFilename', 'ImageLoaded',
    'TargetObject', 'Details', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'QueryName', 'PipeName',
    'SourceImage', 'TargetImage', 'ScriptBlockText', 'Path',
] as const;
export const EXCEPTION_OPS: ExceptionCondition['op'][] = ['equals', 'startswith', 'endswith', 'contains'];
export const MAX_CONDITIONS = 10;
export const EXPIRY_DAYS = [7, 30, 90, 365, 0];
export interface ExceptionCandidate extends ExceptionCondition { use: boolean }
export interface ExceptionDraft {
    name: string;
    reason: string;
    ruleScope: 'rule' | 'all';
    ruleId: string;
    hostScope: 'host' | 'all';
    agentId: string;
    expiryDays: string;
    conditions: ExceptionCandidate[];
}
const bytes = (value: string) => new TextEncoder().encode(value).length;

export function candidatesFromAlert(alert: Alert | null): ExceptionCandidate[] {
    if (!alert) return [];
    const ctx = (alert.context_data ?? {}) as Record<string, unknown>;
    const data = (ctx.data ?? {}) as Record<string, unknown>;
    const legacy = (alert.event_data ?? {}) as Record<string, unknown>;
    const sources = [data, ctx, (legacy.data ?? {}) as Record<string, unknown>, legacy];
    const pick = (...keys: string[]) => {
        for (const key of keys) {
            for (const source of sources) {
                const value = source[key];
                if (typeof value === 'string' && value.trim()) return value.trim();
            }
        }
        return '';
    };
    const result: ExceptionCandidate[] = [];
    const add = (field: string, op: ExceptionCondition['op'], value: string, use = false) => {
        if (value) result.push({ field, op, value, use });
    };
    const image = pick('executable', 'process_path', 'image_path', 'Image', 'process.executable');
    add('Image', 'equals', image.includes('\\') || image.startsWith('/') ? image : '', true);
    add('ParentImage', 'equals', pick('parent_executable', 'ParentImage', 'process.parent.executable'), true);
    add('CommandLine', 'equals', pick('command_line'));
    add('Hashes', 'contains', pick('sha256') ? `SHA256=${pick('sha256').toUpperCase()}` : '');
    add('User', 'equals', pick('user_name'));
    add('TargetFilename', 'equals', pick('target_filename'));
    add('DestinationHostname', 'equals', pick('destination_hostname'));
    add('QueryName', 'equals', pick('query_name'));
    add('TargetObject', 'equals', pick('target_object', 'key_path'));
    return result;
}

export function validateExceptionDraft(draft: ExceptionDraft): string | null {
    if (!draft.name.trim() || bytes(draft.name.trim()) > 255) return 'Enter a name of up to 255 bytes.';
    if (!draft.reason.trim() || bytes(draft.reason.trim()) > 1000) return 'Enter a justification of up to 1,000 bytes.';
    if (draft.ruleScope === 'rule' && (!draft.ruleId.trim() || bytes(draft.ruleId.trim()) > 255)) {
        return 'Enter the Sigma rule ID (up to 255 bytes).';
    }
    if (draft.hostScope === 'host' && !draft.agentId) return 'Select the endpoint this exception applies to.';
    if (!EXPIRY_DAYS.includes(Number(draft.expiryDays))) return 'Select a valid expiry.';
    const selected = draft.conditions.filter(condition => condition.use);
    if (!selected.length) return 'Enable at least one condition.';
    if (selected.length > MAX_CONDITIONS) return `Use at most ${MAX_CONDITIONS} conditions.`;
    for (const [index, condition] of selected.entries()) {
        const value = condition.value.trim();
        const prefix = `Condition ${index + 1} (${condition.field}): `;
        if (!(EXCEPTION_FIELDS as readonly string[]).includes(condition.field) || !EXCEPTION_OPS.includes(condition.op)) {
            return prefix + 'select a supported field and operator.';
        }
        // Match the server's validation; selected blank conditions must never be silently dropped.
        if (!value) return prefix + 'enter the value to match. Selecting a field alone is not a complete condition.';
        const hasControls = Array.from(value).some(character => character.charCodeAt(0) < 0x20 || character.charCodeAt(0) === 0x7f);
        if (bytes(value) > 1024 || hasControls) return prefix + 'enter a value of up to 1,024 bytes without control characters.';
        if (/[*?]/.test(value)) return prefix + 'wildcards are not supported. Choose starts with, ends with or contains.';
        if (condition.op !== 'equals' && bytes(value) < 4) return prefix + 'partial matches require at least 4 bytes.';
    }
    if (draft.ruleScope === 'all' && !selected.some(c => c.op === 'equals' && ['Image', 'Hashes'].includes(c.field))) {
        return 'All rules requires an exact Image or Hashes condition (equals).';
    }
    return null;
}

export function buildExceptionInput(draft: ExceptionDraft, alert: Alert | null, now = Date.now()): DetectionExceptionInput {
    const error = validateExceptionDraft(draft);
    if (error) throw new Error(error);
    const days = Number(draft.expiryDays);
    return {
        name: draft.name.trim(), reason: draft.reason.trim(),
        rule_id: draft.ruleScope === 'rule' ? draft.ruleId.trim() : '',
        rule_title: draft.ruleScope === 'rule' && draft.ruleId === alert?.rule_id ? alert.rule_title : '',
        agent_id: draft.hostScope === 'host' ? draft.agentId : undefined,
        conditions: draft.conditions.filter(c => c.use).map(({ field, op, value }) => ({ field, op, value: value.trim() })),
        expires_at: days > 0 ? new Date(now + days * 86_400_000).toISOString() : undefined,
        source_alert_id: alert?.id,
    };
}
