import { useEffect, useRef, useState } from 'react';

export function usePageFilters<T extends Record<string, string>>(params: Record<string, string>, defaults: T, commit: (changes: Record<string, string | undefined>) => void) {
    const current = Object.fromEntries(Object.keys(defaults).map(key => [key, params[key] ?? defaults[key]])) as T;
    const identity = JSON.stringify(current);
    const [draft, setDraft] = useState({ identity, values: current });
    const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const values = draft.identity === identity ? draft.values : current;
    useEffect(() => () => clearTimeout(timer.current), [identity]);
    const update = (next: T | ((old: T) => T)) => {
        const value = typeof next === 'function' ? next(values) : next;
        setDraft({ identity, values: value });
        clearTimeout(timer.current);
        timer.current = setTimeout(() => commit(value), 300);
    };
    return [values, update] as const;
}
