import { useCallback, useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { changeFilters, changePage, emptyPage, readPage, pageSearch, mergePageSearch, type Paged } from './paginationState';

const EMPTY_ROWS: never[] = [];

export function usePaginatedQuery<T>({ name, defaults = {}, fetchPage, enabled = true, namespace = '', scope = '', refreshFirstPage = 0 }: {
    name: string; defaults?: Record<string, string>; enabled?: boolean; namespace?: string; scope?: string;
    /** Poll interval (ms) applied only on the first page, and only while the tab is visible. */
    refreshFirstPage?: number;
    fetchPage: (params: Record<string, string>, signal: AbortSignal) => Promise<Paged<T>>;
}) {
    const [urlSearch, setURLSearch] = useSearchParams();
    const search = useMemo(() => pageSearch(urlSearch, namespace), [urlSearch, namespace]);
    const setSearch = useCallback((update: (old: URLSearchParams) => URLSearchParams, options?: { replace?: boolean }) => {
        setURLSearch(old => mergePageSearch(old, update(pageSearch(old, namespace)), namespace), options);
    }, [namespace, setURLSearch]);
    const [initialDefaults] = useState(defaults);
    const state = readPage(search);
    const params = useMemo(() => {
        const values: Record<string, string> = { ...initialDefaults, ...Object.fromEntries(search), limit: String(state.limit) };
        delete values.page;
        return values;
    }, [initialDefaults, search, state.limit]);
    // Persist default time bounds before issuing a request: reload/shared cursors
    // must carry the same filter identity as the first page.
    const missingDefaults = Object.keys(initialDefaults).some(key => !search.has(key));
    useEffect(() => {
        if (!missingDefaults) return;
        setSearch(previous => {
            const next = new URLSearchParams(previous);
            for (const [key, value] of Object.entries(initialDefaults)) if (!next.has(key)) next.set(key, value);
            return next;
        }, { replace: true });
    }, [initialDefaults, missingDefaults, setSearch]);
    const query = useQuery({
        queryKey: [name, 'page', scope, params],
        queryFn: ({ signal }) => fetchPage(params, signal),
        enabled: enabled && !missingDefaults,
        placeholderData: (previous, previousQuery) => previousQuery?.queryKey[2] === scope ? previous : undefined,
        staleTime: 30_000,
        // Older pages are never replaced under the analyst; hidden tabs do not poll.
        refetchInterval: refreshFirstPage > 0 && !params.cursor ? refreshFirstPage : false,
        refetchIntervalInBackground: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        retry: 1,
    });
    const info = query.data?.page_info ?? emptyPage(state.limit);
    const setFilters = useCallback((changes: Record<string, string | undefined>) => setSearch(old => changeFilters(old, changes)), [setSearch]);
    const canNavigate = query.isSuccess && !query.isFetching && !query.isPlaceholderData && !missingDefaults;
    const next = () => { if (canNavigate) setSearch(old => changePage(old, info, 'next')); };
    const previous = () => { if (canNavigate) setSearch(old => changePage(old, info, 'prev')); };
    return { ...query, ...state, params, info, rows: query.data?.data ?? EMPTY_ROWS, next, previous, setFilters,
        setPageSize: (limit: number) => setFilters({ limit: String(limit) }),
        reset: () => setFilters({}),
        busy: query.isFetching || missingDefaults,
    };
}
