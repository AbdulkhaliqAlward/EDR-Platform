/** A fixed window coalesces bursts without postponing refresh forever under steady traffic. */
export function createAlertRefresh(flush: () => void, interval = 1000) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let disposed = false;
    return {
        schedule() {
            if (disposed || timer !== undefined) return;
            timer = setTimeout(() => { timer = undefined; if (!disposed) flush(); }, interval);
        },
        dispose() { disposed = true; clearTimeout(timer); timer = undefined; },
    };
}
export function rememberAlert(ids: Set<string>, id: string, limit = 4096) {
    ids.add(id);
    while (ids.size > limit) ids.delete(ids.values().next().value!);
}
