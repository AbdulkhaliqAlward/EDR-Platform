import { useCallback, useEffect, useMemo, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { mergePageSearch, pageSearch, readPage } from './paginationState';

/**
 * URL-synced page state for small server lists that take limit/offset (no
 * cursor). Fetch `limit + 1` rows: the extra row only tells whether a next
 * page exists. `controls(count, hasNext)` spreads into PaginationControls.
 */
export function useOffsetPageState({ namespace = '', resetKey = '', defaultLimit }: { namespace?: string; resetKey?: string; defaultLimit?: number } = {}) {
    const [urlSearch, setURLSearch] = useSearchParams();
    const search = useMemo(() => pageSearch(urlSearch, namespace), [urlSearch, namespace]);
    const parsed = readPage(search);
    const limit = search.has('limit') || !defaultLimit ? parsed.limit : defaultLimit;
    const page = parsed.page;
    const write = useCallback((changes: Record<string, string>, replace = false) => {
        setURLSearch(old => {
            const scoped = pageSearch(old, namespace);
            for (const [key, value] of Object.entries(changes)) scoped.set(key, value);
            return mergePageSearch(old, scoped, namespace);
        }, { replace });
    }, [namespace, setURLSearch]);
    const lastKey = useRef(resetKey);
    useEffect(() => {
        if (lastKey.current === resetKey) return;
        lastKey.current = resetKey;
        if (page !== 1) write({ page: '1' }, true);
    }, [resetKey, page, write]);
    return {
        limit, page, offset: (page - 1) * limit,
        controls: (count: number, hasNext: boolean) => ({
            info: { limit, has_prev: page > 1, has_next: hasNext, next_cursor: null, prev_cursor: null },
            page, count,
            onNext: () => write({ page: String(page + 1) }),
            onPrevious: () => write({ page: String(Math.max(1, page - 1)) }),
            onFirst: () => write({ page: '1' }),
            onSize: (size: number) => write({ limit: String(size), page: '1' }),
        }),
    };
}

/**
 * Pages an in-memory list (small configuration tables the server returns in
 * full: playbooks, automation rules, scripts, exceptions, sync history…).
 * Page and size live in the URL (optionally under a namespace) so reloads and
 * shared links keep the position. `resetKey` (filters/search/sort identity)
 * returns to page 1 when it changes. The result spreads into PaginationControls.
 */
export function useClientPagination<T>(rows: readonly T[], { namespace = '', resetKey = '' }: { namespace?: string; resetKey?: string } = {}) {
    const [urlSearch, setURLSearch] = useSearchParams();
    const search = useMemo(() => pageSearch(urlSearch, namespace), [urlSearch, namespace]);
    const { limit, page: requested } = readPage(search);
    const pages = Math.max(1, Math.ceil(rows.length / limit));
    // A shrinking list (deletes, filters) never leaves the view past the end.
    const page = Math.min(requested, pages);

    const write = useCallback((changes: Record<string, string>, replace = false) => {
        setURLSearch(old => {
            const scoped = pageSearch(old, namespace);
            for (const [key, value] of Object.entries(changes)) scoped.set(key, value);
            return mergePageSearch(old, scoped, namespace);
        }, { replace });
    }, [namespace, setURLSearch]);

    const lastKey = useRef(resetKey);
    useEffect(() => {
        if (lastKey.current === resetKey) return;
        lastKey.current = resetKey;
        if (requested !== 1) write({ page: '1' }, true);
    }, [resetKey, requested, write]);

    const pageRows = useMemo(() => rows.slice((page - 1) * limit, page * limit), [rows, page, limit]);
    return {
        pageRows,
        page,
        pages,
        controls: {
            info: { limit, has_prev: page > 1, has_next: page < pages, next_cursor: null, prev_cursor: null },
            page,
            count: pageRows.length,
            total: { value: rows.length, capped: false },
            onNext: () => write({ page: String(Math.min(pages, page + 1)) }),
            onPrevious: () => write({ page: String(Math.max(1, page - 1)) }),
            onFirst: () => write({ page: '1' }),
            onSize: (size: number) => write({ limit: String(size), page: '1' }),
        },
    };
}
