// AlertFieldsView — every collected event field, grouped, searchable and
// copyable. Matched detection fields are marked so the analyst sees exactly
// why the rule fired.
import { useMemo, useState } from 'react';
import { Check, ChevronDown, ChevronRight, Copy, Search, Target } from 'lucide-react';
import { filterSections, groupEventFields } from './alertFields';

function CopyButton({ value }: { value: string }) {
    const [done, setDone] = useState(false);
    const copy = async () => {
        try {
            await navigator.clipboard.writeText(value);
            setDone(true);
            setTimeout(() => setDone(false), 1200);
        } catch {
            /* clipboard unavailable (insecure context) */
        }
    };
    return (
        <button type="button" onClick={copy} title="Copy value" aria-label="Copy value"
            className="shrink-0 p-1 rounded text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-200/70 dark:hover:bg-slate-700 opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity">
            {done ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
    );
}

interface Props {
    context: unknown;
    matchedFields?: Record<string, unknown>;
}

export function AlertFieldsView({ context, matchedFields }: Props) {
    const [query, setQuery] = useState('');
    const [collapsed, setCollapsed] = useState<Record<string, boolean>>({ pipeline: true });
    const sections = useMemo(() => groupEventFields(context, matchedFields || {}), [context, matchedFields]);
    const shown = useMemo(() => filterSections(sections, query), [sections, query]);
    const total = sections.reduce((n, s) => n + s.rows.length, 0);

    if (total === 0) {
        return <p className="text-sm text-slate-500">No event fields were recorded for this alert.</p>;
    }

    return (
        <div className="space-y-3">
            <div className="relative">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                    type="search"
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                    placeholder={`Search ${total} fields…`}
                    aria-label="Search event fields"
                    className="w-full pl-9 pr-3 py-2 text-sm rounded-lg bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 outline-none"
                />
            </div>
            {shown.length === 0 && <p className="text-sm text-slate-500">No field matches “{query}”.</p>}
            {shown.map(sec => {
                const isCollapsed = !query && collapsed[sec.id];
                return (
                    <section key={sec.id} className="rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden">
                        <button
                            type="button"
                            onClick={() => setCollapsed(c => ({ ...c, [sec.id]: !c[sec.id] }))}
                            aria-expanded={!isCollapsed}
                            className="w-full flex items-center gap-2 px-3 py-2 bg-slate-50 dark:bg-slate-800/70 text-left"
                        >
                            {isCollapsed ? <ChevronRight className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                            <span className="text-xs font-bold uppercase tracking-wider text-slate-600 dark:text-slate-300">{sec.title}</span>
                            <span className="text-[10px] text-slate-400">{sec.rows.length}</span>
                        </button>
                        {!isCollapsed && (
                            <dl className="divide-y divide-slate-100 dark:divide-slate-800">
                                {sec.rows.map(r => (
                                    <div key={r.key} className={`group grid min-w-0 grid-cols-1 sm:grid-cols-[170px_minmax(0,1fr)] gap-x-3 gap-y-0.5 px-3 py-1.5 ${r.matched ? 'bg-amber-50/70 dark:bg-amber-900/10' : ''}`}>
                                        <dt className="text-xs text-slate-500 flex items-center gap-1 min-w-0" title={r.key}>
                                            {r.matched && <Target className="w-3 h-3 text-amber-500 shrink-0" aria-label="Matched by the rule" />}
                                            <span className="truncate">{r.label}</span>
                                        </dt>
                                        <dd className="flex items-start gap-1 min-w-0">
                                            <span dir="auto" className={`flex-1 min-w-0 text-xs text-slate-800 dark:text-slate-200 whitespace-pre-wrap break-all ${r.mono ? 'font-mono' : ''}`}>{r.value}</span>
                                            <CopyButton value={r.value} />
                                        </dd>
                                    </div>
                                ))}
                            </dl>
                        )}
                    </section>
                );
            })}
        </div>
    );
}

export default AlertFieldsView;
