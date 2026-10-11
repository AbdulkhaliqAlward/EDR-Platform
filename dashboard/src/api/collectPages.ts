import type { Paged } from '../hooks/paginationState';

// Only explicit exports use traversal. Interactive tables fetch one page.
// A bounded export fails rather than quietly presenting a partial dataset.
export async function collectPages<T>(fetchPage: (cursor?: string) => Promise<Paged<T>>, maximum = 10000): Promise<T[]> {
    const rows: T[] = [];
    const visited = new Set<string>();
    let cursor: string | undefined;
    do {
        const page = await fetchPage(cursor);
        if (rows.length + page.data.length > maximum) throw new Error(`Export exceeds ${maximum.toLocaleString()} records. Narrow the time range or filters.`);
        rows.push(...page.data);
        if (!page.page_info.has_next) return rows;
        const next = page.page_info.next_cursor;
        if (!next || visited.has(next)) throw new Error('Could not advance the export. Please retry.');
        if (rows.length === maximum) throw new Error(`Export exceeds ${maximum.toLocaleString()} records. Narrow the time range or filters.`);
        visited.add(next);
        cursor = next;
    } while (cursor);
    return rows;
}
