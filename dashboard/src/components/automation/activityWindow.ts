export interface ActivityWindow {
    from: string;
    through: string;
    afterAt: string;
    afterID: string;
}

export function createActivityWindow(from: string): ActivityWindow {
    return { from, through: '', afterAt: '', afterID: '' };
}

export function beginActivityWindow(window: ActivityWindow, through: string): void {
    if (!window.through) window.through = through;
}

// Advance only after a successful page. Keep the upper bound fixed across
// saturated batches, and overlap completed windows for delayed DB commits.
export function advanceActivityWindow<T extends { id: string }>(
    window: ActivityWindow, rows: T[], pageSize: number, timestamp: (row: T) => string,
): void {
    if (rows.length >= pageSize) {
        const last = rows[rows.length - 1];
        const at = timestamp(last);
        if (!at || !last.id || (at === window.afterAt && last.id === window.afterID)) {
            throw new Error('Activity cursor did not advance');
        }
        window.afterAt = at;
        window.afterID = last.id;
    } else {
        window.from = new Date(Math.max(Date.parse(window.from), Date.parse(window.through) - 60_000)).toISOString();
        window.through = '';
        window.afterAt = '';
        window.afterID = '';
    }
}
