import type { PageInfo } from '../hooks/paginationState';

export function PaginationControls({ info, page, count, busy, total, onNext, onPrevious, onSize }: {
    info: PageInfo; page: number; count: number; busy?: boolean;
    total?: { value: number; capped: boolean };
    onNext: () => void; onPrevious: () => void; onSize: (value: number) => void;
}) {
    const start = count ? (page - 1) * info.limit + 1 : 0;
    return <nav aria-label="Pagination" className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-200 dark:border-slate-700 p-4 text-sm">
        <label className="flex items-center gap-2 text-slate-600 dark:text-slate-300">Rows per page
            <select aria-label="Rows per page" value={info.limit} disabled={busy} onChange={e => onSize(Number(e.target.value))} className="rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 px-2 py-1">
                {[25, 50, 100].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
        </label>
        <span role="status" aria-live="polite" className="text-slate-500">{busy ? 'Loading…' : `Showing ${start}–${count ? start + count - 1 : 0}`}{total ? ` of ${total.value.toLocaleString()}${total.capped ? '+' : ''}` : ''}</span>
        <div className="flex gap-2">
            <button type="button" aria-label="Previous page" disabled={busy || !info.has_prev} onClick={onPrevious} className="btn btn-secondary disabled:opacity-40">Previous</button>
            <button type="button" aria-label="Next page" disabled={busy || !info.has_next} onClick={onNext} className="btn btn-secondary disabled:opacity-40">Next</button>
        </div>
    </nav>;
}

export function NewItemsBanner({ count, onRefresh }: { count: number; onRefresh: () => void }) {
    if (!count) return null;
    return <button type="button" onClick={onRefresh} className="w-full rounded-lg border border-cyan-300 dark:border-cyan-800 bg-cyan-50 dark:bg-cyan-950/40 p-3 text-sm text-cyan-800 dark:text-cyan-200" aria-live="polite">
        {count >= 1000 ? '1,000+' : count} new or updated items — refresh first page
    </button>;
}
