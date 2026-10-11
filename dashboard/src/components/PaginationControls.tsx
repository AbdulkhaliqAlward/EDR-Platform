import { ChevronLeft, ChevronRight, ChevronsLeft } from 'lucide-react';
import { PAGE_SIZES, type PageInfo } from '../hooks/paginationState';

/**
 * Shared pager for every table: rows per page (10–100), "Showing X–Y [of N]",
 * page number, first/previous/next. Works for cursor lists (no exact total
 * required) and for client-side or offset lists (total known).
 */
export function PaginationControls({ info, page, count, busy, total, onNext, onPrevious, onSize, onFirst, label = 'rows' }: {
    info: PageInfo; page: number; count: number; busy?: boolean;
    total?: { value: number; capped: boolean };
    onNext: () => void; onPrevious: () => void; onSize: (value: number) => void;
    /** Jump back to page 1 (shown from page 3 on). */
    onFirst?: () => void;
    /** Noun used in the summary, e.g. "alerts". */
    label?: string;
}) {
    const start = count ? (page - 1) * info.limit + 1 : 0;
    const end = count ? start + count - 1 : 0;
    const pages = total && !total.capped ? Math.max(1, Math.ceil(total.value / info.limit)) : undefined;
    const btn = 'inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed';
    return <nav aria-label="Pagination" className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-slate-200 dark:border-slate-700 px-4 py-3 text-sm">
        <label className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-300">Rows per page
            <select aria-label="Rows per page" value={info.limit} disabled={busy} onChange={e => onSize(Number(e.target.value))} className="rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1 text-xs">
                {PAGE_SIZES.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
        </label>
        <span role="status" aria-live="polite" className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">
            {busy ? 'Loading…' : count ? `Showing ${start.toLocaleString()}–${end.toLocaleString()}` : `No ${label}`}
            {!busy && total ? ` of ${total.value.toLocaleString()}${total.capped ? '+' : ''}` : ''}
        </span>
        <div className="flex items-center gap-1.5">
            {onFirst && page > 2 && <button type="button" aria-label="First page" title="First page" disabled={busy} onClick={onFirst} className={btn}><ChevronsLeft className="w-3.5 h-3.5" /></button>}
            <button type="button" aria-label="Previous page" disabled={busy || !info.has_prev} onClick={onPrevious} className={btn}><ChevronLeft className="w-3.5 h-3.5" />Previous</button>
            <span className="px-1.5 text-xs text-slate-500 dark:text-slate-400 tabular-nums" aria-label="Current page">Page {page}{pages ? ` of ${pages}` : ''}</span>
            <button type="button" aria-label="Next page" disabled={busy || !info.has_next} onClick={onNext} className={btn}>Next<ChevronRight className="w-3.5 h-3.5" /></button>
        </div>
    </nav>;
}

export function NewItemsBanner({ count, onRefresh }: { count: number; onRefresh: () => void }) {
    if (!count) return null;
    return <button type="button" onClick={onRefresh} className="w-full rounded-lg border border-cyan-300 dark:border-cyan-800 bg-cyan-50 dark:bg-cyan-950/40 p-3 text-sm text-cyan-800 dark:text-cyan-200" aria-live="polite">
        {count >= 1000 ? '1,000+' : count} new or updated items — refresh first page
    </button>;
}
