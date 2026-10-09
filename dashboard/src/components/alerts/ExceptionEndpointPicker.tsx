import { useEffect, useState } from 'react';
import { Loader2, RefreshCw, Search } from 'lucide-react';
import { agentsApi, type Agent } from '../../api/client';
import { apiErrorMessage } from '../../api/apiError';

export interface ExceptionEndpoint { id: string; hostname: string }
interface Props {
    selected: ExceptionEndpoint | null;
    onChange: (endpoint: ExceptionEndpoint | null) => void;
    disabled: boolean;
    id: string;
}

/** Search server-side and paginate; never silently widen a missing endpoint to all endpoints. */
export function ExceptionEndpointPicker({ selected, onChange, disabled, id }: Props) {
    const [search, setSearch] = useState('');
    const [page, setPage] = useState(0);
    const [retry, setRetry] = useState(0);
    const [rows, setRows] = useState<Agent[]>([]);
    const [hasMore, setHasMore] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;
        const timer = window.setTimeout(() => {
            agentsApi.list({ search: search.trim() || undefined, limit: 20, offset: page * 20, sort_by: 'hostname', sort_order: 'asc' })
                .then(result => {
                    if (cancelled) return;
                    setRows(previous => {
                        const combined = page ? [...previous, ...(result.data || [])] : result.data || [];
                        return [...new Map(combined.map(agent => [agent.id, agent])).values()];
                    });
                    setHasMore(result.pagination.has_more);
                    setError(null);
                })
                .catch(err => { if (!cancelled) setError(apiErrorMessage(err, 'Could not load endpoints.')); })
                .finally(() => { if (!cancelled) setLoading(false); });
        }, 250);
        return () => { cancelled = true; window.clearTimeout(timer); };
    }, [search, page, retry]);

    const options: ExceptionEndpoint[] = selected && !rows.some(row => row.id === selected.id) ? [selected, ...rows] : rows;
    return (
        <div className="mt-3 min-w-0 space-y-2">
            <label htmlFor={`${id}-search`} className="sr-only">Search endpoints</label>
            <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-400" />
                <input id={`${id}-search`} className="input min-w-0 !pl-8" placeholder="Search hostname or IP address" value={search} disabled={disabled}
                    onChange={event => { setSearch(event.target.value); setPage(0); setRows([]); setHasMore(false); setError(null); setLoading(true); }} />
            </div>
            <label htmlFor={id} className="sr-only">Endpoint</label>
            <select id={id} className="input min-w-0" value={selected?.id || ''} disabled={disabled}
                onChange={event => onChange(options.find(endpoint => endpoint.id === event.target.value) || null)}>
                <option value="">Select an endpoint</option>
                {options.map(endpoint => <option key={endpoint.id} value={endpoint.id}>{endpoint.hostname || endpoint.id} · {endpoint.id.slice(0, 8)}</option>)}
            </select>
            {loading && <p role="status" className="flex items-center gap-1.5 text-xs text-slate-500"><Loader2 className="h-3 w-3 animate-spin" /> Loading endpoints…</p>}
            {error && <div role="alert" className="flex flex-wrap items-center gap-2 text-xs text-rose-600 dark:text-rose-400">
                <span>{error}</span><button type="button" disabled={disabled || loading} className="inline-flex items-center gap-1 underline"
                    onClick={() => { setLoading(true); setRetry(value => value + 1); }}><RefreshCw className="h-3 w-3" /> Retry endpoints</button>
            </div>}
            {!loading && !error && !rows.length && <p className="text-xs text-slate-500">No endpoints found. Change your search.</p>}
            {hasMore && <button type="button" disabled={disabled || loading || !!error} className="text-xs font-semibold text-indigo-600 disabled:opacity-50 dark:text-indigo-400"
                onClick={() => { setLoading(true); setPage(value => value + 1); }}>Load more endpoints</button>}
        </div>
    );
}
