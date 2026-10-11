export interface PageInfo { limit: number; has_next: boolean; has_prev: boolean; next_cursor: string | null; prev_cursor: string | null }
export interface Paged<T> { data: T[]; page_info: PageInfo; total?: { value: number; capped: boolean } }
export const emptyPage = (limit = 25): PageInfo => ({ limit, has_next: false, has_prev: false, next_cursor: null, prev_cursor: null });
export function pageSearch(search: URLSearchParams, namespace = '') {
    if (!namespace) return search;
    const prefix = `${namespace}.`;
    return new URLSearchParams([...search].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => [key.slice(prefix.length), value]));
}
export function mergePageSearch(search: URLSearchParams, values: URLSearchParams, namespace = '') {
    if (!namespace) return values;
    const next = new URLSearchParams(search), prefix = `${namespace}.`;
    for (const key of [...next.keys()]) if (key.startsWith(prefix)) next.delete(key);
    for (const [key, value] of values) next.set(prefix + key, value);
    return next;
}
/** Rows-per-page choices for every table: at least 10, at most 100 (server cap). */
export const PAGE_SIZES = [10, 25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 25;
export function readPage(search: URLSearchParams) {
    const size = Number(search.get('limit'));
    const page = Number(search.get('page'));
    return { limit: (PAGE_SIZES as readonly number[]).includes(size) ? size : DEFAULT_PAGE_SIZE, cursor: search.get('cursor') || '', page: Number.isSafeInteger(page) ? Math.max(1, Math.min(1000000, page)) : 1 };
}
export function changeFilters(search: URLSearchParams, changes: Record<string, string | undefined>) {
    const next = new URLSearchParams(search);
    for (const [key, value] of Object.entries(changes)) { if (value !== undefined) next.set(key, value); else next.delete(key); }
    next.delete('cursor'); next.set('page', '1'); return next;
}
/** Back to page 1 keeping filters, sort and page size. */
export function firstPage(search: URLSearchParams) {
    const next = new URLSearchParams(search);
    next.delete('cursor'); next.set('page', '1'); return next;
}
export function changePage(search: URLSearchParams, info: PageInfo, direction: 'next' | 'prev') {
    const cursor = direction === 'next' ? info.next_cursor : info.prev_cursor;
    if (!cursor) return search;
    const next = new URLSearchParams(search);
    next.set('cursor', cursor); next.set('page', String(Math.max(1, readPage(search).page + (direction === 'next' ? 1 : -1))));
    return next;
}
