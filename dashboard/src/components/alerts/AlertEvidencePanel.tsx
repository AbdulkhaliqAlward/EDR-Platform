// AlertEvidencePanel — the triggering activity in analyst terms: what ran,
// from where, launched by whom, with what command line / script, and whether
// the binary is genuinely signed.
import { FileCode, ShieldCheck, ShieldQuestion, ShieldX, Terminal } from 'lucide-react';
import type { Alert } from '../../api/client';

const sigBadge = (status: string, signer: string) => {
    switch (status) {
        case 'microsoft':
        case 'trusted':
            return <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400"><ShieldCheck className="w-3.5 h-3.5" /> Signed{signer ? ` by ${signer}` : ''}</span>;
        case 'invalid':
            return <span className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400"><ShieldX className="w-3.5 h-3.5" /> Invalid signature (tampered or untrusted)</span>;
        case 'unsigned':
            return <span className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400"><ShieldQuestion className="w-3.5 h-3.5" /> Unsigned</span>;
        default:
            return <span className="text-slate-400">Unknown</span>;
    }
};

export function AlertEvidencePanel({ alert }: { alert: Alert }) {
    const ctx = (alert.context_data ?? {}) as Record<string, unknown>;
    const d = (ctx.data ?? {}) as Record<string, unknown>;
    const legacy = (alert.event_data ?? {}) as Record<string, unknown>;
    const s = (k: string): string => {
        const v = d[k] ?? ctx[k] ?? legacy[k];
        return v === undefined || v === null ? '' : String(v);
    };

    const script = s('script_block_text') || s('payload');
    const image = s('executable') || s('process_path');
    const rows: [string, string, boolean?][] = [
        ['Process', image || s('name') || s('process_name')],
        ['PID', s('pid')],
        ['Started', s('process_start_time') ? new Date(s('process_start_time')).toLocaleString() : ''],
        ['Command line', s('command_line'), true],
        ['Parent process', s('parent_executable') || s('parent_name')],
        ['Parent command line', s('parent_command_line'), true],
        ['User', s('user_name')],
        ['Integrity', [s('integrity_level'), s('is_elevated') === 'true' ? 'elevated' : ''].filter(Boolean).join(', ')],
        ['Original file name', s('original_file_name')],
        ['Product', [s('company'), s('product')].filter(Boolean).join(' — ')],
        ['SHA-256', s('sha256'), true],
        ['Target file', s('target_filename') || s('path'), true],
        ['Destination', [s('destination_hostname') || s('destination_ip'), s('destination_port')].filter(Boolean).join(':')],
        ['DNS query', s('query_name')],
        ['Registry key', s('target_object') || s('key_path'), true],
    ];
    const shown = rows.filter(([, v]) => v);
    if (shown.length === 0 && !script) return null;

    return (
        <div className="rounded-xl border border-slate-200 dark:border-slate-700 p-4 space-y-3">
            <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-indigo-500" />
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Triggering activity</span>
                {s('signature_status') && <span className="ml-auto text-xs">{sigBadge(s('signature_status'), s('signature_issuer'))}</span>}
            </div>
            {script && (
                <div className="rounded-lg bg-slate-900 p-3">
                    <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-1.5">
                        <Terminal className="w-3.5 h-3.5" />
                        PowerShell {s('action') === 'module' ? 'module log' : 'script block'}
                        {s('script_path') && <span className="normal-case font-normal text-slate-500 truncate">· {s('script_path')}</span>}
                        {Number(s('message_total')) > 1 && <span className="normal-case font-normal text-slate-500">· part {s('message_number')}/{s('message_total')}</span>}
                    </div>
                    <pre className="text-xs text-emerald-300 font-mono whitespace-pre-wrap break-all max-h-64 overflow-auto">{script}</pre>
                    {s('reassembled') === 'true' && <p className="text-[10px] text-slate-500 mt-1">Reassembled from PowerShell log fragments.</p>}
                    {s('truncated') === 'true' && <p className="text-[10px] text-slate-500 mt-1">Source telemetry was truncated by the collector.</p>}
                </div>
            )}
            <dl className="grid grid-cols-1 sm:grid-cols-[150px_1fr] gap-x-3 gap-y-1.5 text-xs">
                {shown.map(([label, value, mono]) => (
                    <div key={label} className="contents">
                        <dt className="text-slate-500">{label}</dt>
                        <dd className={`text-slate-800 dark:text-slate-200 break-all ${mono ? 'font-mono' : ''}`}>{value}</dd>
                    </div>
                ))}
            </dl>
        </div>
    );
}

export default AlertEvidencePanel;
