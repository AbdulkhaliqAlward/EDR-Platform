import { useEffect, useRef, useState } from 'react';

export function usePageSearch(params: Record<string, string>, setFilters: (changes: Record<string, string | undefined>) => void, field = 'search') {
    const committed = params[field] || '';
    const [draft, setDraft] = useState({ base: committed, value: committed });
    const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    // Navigation invalidates drafts and pending writes from the previous URL.
    useEffect(() => () => clearTimeout(timer.current), [committed]);
    const setValue = (value: string) => {
        setDraft({ base: committed, value });
        clearTimeout(timer.current);
        timer.current = setTimeout(() => setFilters({ [field]: value.trim() }), 300);
    };
    return [draft.base === committed ? draft.value : committed, setValue] as const;
}
