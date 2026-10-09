import assert from 'node:assert/strict';
import test from 'node:test';
import { createAlertRefresh, rememberAlert } from './alertRefresh.ts';

test('continuous events are batched without starving refresh or running after disposal', t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    let calls = 0;
    const refresh = createAlertRefresh(() => calls++);
    for (let i = 0; i < 60; i++) { refresh.schedule(); t.mock.timers.tick(50); }
    assert.equal(calls, 3);
    refresh.schedule(); refresh.dispose(); t.mock.timers.tick(2000);
    refresh.schedule(); t.mock.timers.tick(2000);
    assert.equal(calls, 3);
});
test('a long-running page keeps bounded alert identity and highlight sets', () => {
    const ids = new Set();
    for (let i = 0; i < 10_000; i++) rememberAlert(ids, String(i));
    assert.equal(ids.size, 4096); assert.ok(ids.has('9999')); assert.equal(ids.has('0'), false);
    rememberAlert(ids, '9999'); assert.equal(ids.size, 4096);
});
