import test from 'node:test';
import assert from 'node:assert/strict';
import { changeFilters, changePage, readPage, pageSearch, mergePageSearch } from './paginationState.ts';
import { collectPages } from '../api/collectPages.ts';

test('URL navigation preserves filters and round trips opaque forward/reverse cursors', () => {
    const initial = new URLSearchParams('severity=high&limit=50&date_from=2026-01-01');
    const info = { next_cursor: 'next/+==', prev_cursor: 'previous/+==' };
    const next = changePage(initial, info, 'next');
    assert.equal(readPage(new URLSearchParams(next.toString())).cursor, info.next_cursor);
    assert.equal(readPage(next).page, 2);
    const prev = changePage(next, info, 'prev');
    assert.equal(readPage(prev).page, 1);
    assert.equal(prev.get('severity'), 'high');
    for (const changes of [{ severity: 'low' }, { limit: '100' }, { order: 'asc' }, { search: 'backup' }]) {
        const reset = changeFilters(next, changes);
        assert.equal(readPage(reset).cursor, '');
        assert.equal(readPage(reset).page, 1);
    }
    assert.equal(initial.has('cursor'), false, 'does not mutate router state');
});

test('empty filters are explicit and malformed URL page numbers never produce NaN ranges', () => {
    assert.equal(changeFilters(new URLSearchParams('status=open'), { status: '' }).get('status'), '');
    for (const page of ['NaN', 'Infinity', '-1', '1.2']) assert.equal(readPage(new URLSearchParams({ page })).page, 1);
    for (const limit of ['1', '100000', 'abc']) assert.equal(readPage(new URLSearchParams({ limit })).limit, 25);
});

test('nested tables preserve other tables and route parameters during navigation', () => {
    const url = new URLSearchParams('tab=response&events.cursor=old&events.page=2&commands.cursor=other');
    const scoped = pageSearch(url, 'events');
    assert.equal(scoped.get('cursor'), 'old');
    assert.equal(scoped.has('tab'), false);
    const merged = mergePageSearch(url, changeFilters(scoped, { search: 'powershell' }), 'events');
    assert.equal(merged.get('tab'), 'response');
    assert.equal(merged.get('commands.cursor'), 'other');
    assert.equal(merged.get('events.page'), '1');
    assert.equal(merged.has('events.cursor'), false);
    assert.equal(merged.get('events.search'), 'powershell');
});

test('explicit exports exhaust cursor pages and reject truncation or broken navigation', async () => {
    const make = (data, next) => ({ data, page_info: { has_next: !!next, next_cursor: next } });
    assert.deepEqual(await collectPages(async cursor => cursor ? make([2], null) : make([1], 'second'), 2), [1,2]);
    await assert.rejects(collectPages(async () => make([1,2], 'second'), 2), /Narrow/);
    await assert.rejects(collectPages(async () => make([1], 'same'), 10), /advance/);
    await assert.rejects(collectPages(async () => ({ data: [], page_info: { has_next: true } })), /advance/);
});
