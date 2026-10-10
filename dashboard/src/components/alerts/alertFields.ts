// Groups every collected event field of an alert into labelled sections so
// the analyst sees ALL telemetry (nothing silently hidden), in a stable,
// predictable order. Pure module: no React, unit-tested.

export interface FieldRow {
    key: string;
    label: string;
    value: string;
    mono?: boolean;
    /** The detection rule matched on this field. */
    matched?: boolean;
}

export interface FieldSection {
    id: string;
    title: string;
    rows: FieldRow[];
}

type Def = [key: string, label: string, mono?: boolean];

// Section definitions in display order. A key is shown in the first section
// that claims it; unclaimed keys go to "Other fields".
const SECTIONS: { id: string; title: string; when?: (t: string) => boolean; fields: Def[] }[] = [
    {
        id: 'event', title: 'Event', fields: [
            ['event_type', 'Event type'], ['action', 'Action'], ['timestamp', 'Event time (agent)'],
            ['event_time', 'Event time (log)'], ['event_code', 'Event code'], ['channel', 'Event log channel'],
            ['severity', 'Collector severity'], ['event_id', 'Event ID', true], ['batch_id', 'Batch ID', true],
        ],
    },
    {
        id: 'process', title: 'Process', fields: [
            ['process_name', 'Process name'], ['executable', 'Image', true], ['process_path', 'Image', true],
            ['pid', 'PID'], ['process_start_time', 'Started'], ['command_line', 'Command line', true],
            ['working_directory', 'Working directory', true], ['original_file_name', 'Original file name'],
            ['description', 'Description'], ['company', 'Company'], ['product', 'Product'],
            ['sha256', 'SHA-256', true], ['hashes', 'Hashes', true],
            ['signature_status', 'Signature'], ['signature_issuer', 'Signer'],
            ['integrity_level', 'Integrity level'], ['is_elevated', 'Elevated token'],
        ],
    },
    {
        id: 'parent', title: 'Parent process', fields: [
            ['ppid', 'Parent PID'], ['parent_name', 'Parent name'], ['parent_executable', 'Parent image', true],
            ['parent_command_line', 'Parent command line', true],
        ],
    },
    {
        id: 'user', title: 'User', fields: [
            ['user_name', 'User'], ['user', 'User'], ['user_sid', 'User SID', true], ['logon_id', 'Logon ID', true],
        ],
    },
    {
        id: 'file', title: 'File', when: t => t === 'file', fields: [
            ['target_filename', 'Target file', true], ['path', 'Target file', true], ['name', 'File name'],
            ['directory', 'Directory', true], ['extension', 'Extension'], ['size', 'Size'],
        ],
    },
    {
        id: 'image_load', title: 'Loaded module', when: t => t === 'image_load', fields: [
            ['ImageLoaded', 'Module', true], ['path', 'Module path', true], ['name', 'Module name'],
            ['is_signed', 'Signed'], ['hash_sha256', 'Module SHA-256', true],
        ],
    },
    {
        id: 'network', title: 'Network', fields: [
            ['protocol', 'Protocol'], ['direction', 'Direction'], ['source_ip', 'Source IP', true],
            ['source_port', 'Source port'], ['destination_ip', 'Destination IP', true],
            ['destination_port', 'Destination port'], ['destination_hostname', 'Destination host'],
        ],
    },
    {
        id: 'dns', title: 'DNS', fields: [
            ['query_name', 'Query'], ['query_type', 'Record type'], ['query_status', 'Status'],
            ['query_results', 'Answers', true],
        ],
    },
    {
        id: 'registry', title: 'Registry', fields: [
            ['target_object', 'Key', true], ['TargetObject', 'Key', true], ['key_path', 'Key', true],
            ['value_name', 'Value name'], ['details', 'Value data', true], ['value_data', 'Value data', true],
        ],
    },
    {
        id: 'process_access', title: 'Process access', fields: [
            ['source_process_path', 'Source image', true], ['source_pid', 'Source PID'],
            ['target_process_path', 'Target image', true], ['target_pid', 'Target PID'],
            ['access_mask', 'Access mask', true], ['call_trace', 'Call trace', true],
        ],
    },
    {
        id: 'pipe', title: 'Named pipe', fields: [['pipe_name', 'Pipe', true]],
    },
    {
        id: 'powershell', title: 'PowerShell', fields: [
            ['script_path', 'Script path', true], ['script_block_id', 'Script block ID', true],
            ['message_number', 'Part'], ['message_total', 'Parts'], ['context_info', 'Context', true],
            ['reassembled', 'Reassembled'], ['truncated', 'Truncated'],
        ],
    },
    {
        id: 'host', title: 'Endpoint', fields: [
            ['hostname', 'Hostname'], ['ip_address', 'IP address', true], ['os_type', 'OS'],
            ['os_version', 'OS version'], ['agent_version', 'Agent version'], ['agent_id', 'Agent ID', true],
        ],
    },
    {
        id: 'pipeline', title: 'Pipeline', fields: [
            ['_kafka_topic', 'Kafka topic'], ['_kafka_partition', 'Partition'], ['_kafka_offset', 'Offset'],
            ['_kafka_time', 'Broker time'], ['_kafka_key', 'Key', true],
        ],
    },
];

/** Long text shown in dedicated blocks, not in the field table. */
export const BLOCK_FIELDS = new Set(['script_block_text', 'payload']);

const record = (v: unknown): Record<string, unknown> =>
    v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {};

export function fieldText(v: unknown): string {
    if (v === null || v === undefined) return '';
    if (typeof v === 'string') return v;
    if (typeof v === 'number' || typeof v === 'boolean') return String(v);
    if (Array.isArray(v)) return v.map(fieldText).filter(Boolean).join(', ');
    try {
        return JSON.stringify(v);
    } catch {
        return '';
    }
}

/**
 * Flattens the alert's event envelope: data.* wins over top-level keys,
 * the nested source object provides endpoint fields.
 */
export function flattenEvent(context: unknown): Record<string, string> {
    const ctx = record(context);
    const data = record(ctx.data);
    const source = record(ctx.source);
    const out: Record<string, string> = {};
    const put = (k: string, v: unknown) => {
        const s = fieldText(v).trim();
        if (s && !(k in out)) out[k] = s;
    };
    for (const [k, v] of Object.entries(data)) put(k, v);
    for (const [k, v] of Object.entries(ctx)) {
        if (k !== 'data' && k !== 'source') put(k, v);
    }
    for (const [k, v] of Object.entries(source)) put(k, v);
    return out;
}

/** Groups the flattened fields into ordered sections (empty ones omitted). */
export function groupEventFields(context: unknown, matched: Record<string, unknown> = {}): FieldSection[] {
    const flat = flattenEvent(context);
    const eventType = (flat.event_type || '').toLowerCase();
    // On process events "name" is the process image name; elsewhere it is
    // the object's name (file, module) and must not pose as the process.
    if (eventType === 'process' && flat.name && !flat.process_name) {
        flat.process_name = flat.name;
        delete flat.name;
    }
    const matchedValues = new Set(Object.values(matched).map(v => fieldText(v).toLowerCase()).filter(Boolean));
    const used = new Set<string>(BLOCK_FIELDS);
    const sections: FieldSection[] = [];

    for (const sec of SECTIONS) {
        if (sec.when && !sec.when(eventType)) continue;
        const rows: FieldRow[] = [];
        const labels = new Set<string>();
        for (const [key, label, mono] of sec.fields) {
            const value = flat[key];
            if (used.has(key) || value === undefined) continue;
            used.add(key);
            if (labels.has(label + '\u0000' + value)) continue; // alias with the same value
            labels.add(label + '\u0000' + value);
            rows.push({ key, label, value, mono, matched: matchedValues.has(value.toLowerCase()) });
        }
        if (rows.length) sections.push({ id: sec.id, title: sec.title, rows });
    }

    const other = Object.keys(flat).filter(k => !used.has(k)).sort();
    if (other.length) {
        sections.push({
            id: 'other', title: 'Other fields',
            rows: other.map(k => ({ key: k, label: k, value: flat[k], mono: true, matched: matchedValues.has(flat[k].toLowerCase()) })),
        });
    }
    return sections;
}

/** Case-insensitive filter over labels, keys and values. */
export function filterSections(sections: FieldSection[], query: string): FieldSection[] {
    const q = query.trim().toLowerCase();
    if (!q) return sections;
    return sections
        .map(s => ({ ...s, rows: s.rows.filter(r => r.label.toLowerCase().includes(q) || r.key.toLowerCase().includes(q) || r.value.toLowerCase().includes(q)) }))
        .filter(s => s.rows.length > 0);
}
