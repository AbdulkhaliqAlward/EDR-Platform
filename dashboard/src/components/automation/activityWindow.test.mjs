import test from 'node:test';
import assert from 'node:assert/strict';
import { advanceActivityWindow, beginActivityWindow, createActivityWindow } from './activityWindow.ts';

test('saturated feed drains across batches without advancing its time bound', () => {
    const w = createActivityWindow('2026-10-09T00:00:00.000Z');
    beginActivityWindow(w, '2026-10-09T01:00:00.000Z');
    const rows = Array.from({ length: 650 }, (_, i) => ({ id: String(i).padStart(4, '0'), at: '2026-10-09T00:30:00.123456Z' }));
    for (let i = 0; i < 600; i += 200) {
        advanceActivityWindow(w, rows.slice(i, i + 200), 200, r => r.at);
    }
    assert.equal(w.afterID, '0599');
    beginActivityWindow(w, '2026-10-09T02:00:00.000Z');
    assert.equal(w.through, '2026-10-09T01:00:00.000Z');
    // An outage performs no successful advance; the next poll resumes at 599.
    assert.equal(w.afterID, '0599');
    advanceActivityWindow(w, rows.slice(600), 200, r => r.at);
    assert.equal(w.from, '2026-10-09T00:59:00.000Z');
    assert.equal(w.afterID, '');
    beginActivityWindow(w, '2026-10-09T02:00:00.000Z');
    assert.equal(w.through, '2026-10-09T02:00:00.000Z');
});

test('repeated cursor is rejected rather than silently skipping a saturated page', () => {
    const w = createActivityWindow('2026-10-09T00:00:00.000Z');
    beginActivityWindow(w, '2026-10-09T01:00:00.000Z');
    const rows = [{ id: 'a', at: '2026-10-09T00:30:00.000Z' }];
    advanceActivityWindow(w, rows, 1, r => r.at);
    assert.throws(() => advanceActivityWindow(w, rows, 1, r => r.at), /did not advance/);
    assert.equal(w.from, '2026-10-09T00:00:00.000Z');
});
