import assert from 'node:assert/strict';
import test from 'node:test';
import { buildExceptionInput, candidatesFromAlert, validateExceptionDraft } from './exceptionForm.ts';

const draft = (changes = {}) => ({ name: 'Approved backup', reason: 'Change 123', ruleScope: 'rule', ruleId: 'sigma-rule', hostScope: 'host', agentId: '12345678-1234-1234-1234-123456789012', expiryDays: '90', conditions: [{ field: 'Image', op: 'equals', value: 'C:\\Backup\\agent.exe', use: true }], ...changes });
const condition = (changes = {}) => ({ ...draft().conditions[0], ...changes });

test('specific and all endpoint scopes serialize without accidentally widening the draft', () => {
    assert.equal(buildExceptionInput(draft(), null).agent_id, draft().agentId);
    assert.equal(buildExceptionInput(draft({ hostScope: 'all' }), null).agent_id, undefined);
    assert.match(validateExceptionDraft(draft({ agentId: '' })), /Select the endpoint/);
});
test('all rules require an enabled exact anchor; disabled anchors do not qualify', () => {
    assert.equal(validateExceptionDraft(draft({ ruleScope: 'all' })), null);
    for (const conditions of [[condition({ op: 'contains' })], [condition({ use: false }), condition({ field: 'CommandLine', op: 'contains', value: '--backup' })]]) {
        assert.match(validateExceptionDraft(draft({ ruleScope: 'all', conditions })), /exact Image or Hashes/);
    }
});
test('enabled empty conditions are rejected instead of silently removed', () => {
    const conditions = [condition(), condition({ field: 'CommandLine', value: '  ' })];
    assert.match(validateExceptionDraft(draft({ conditions })), /Condition 2/);
    assert.throws(() => buildExceptionInput(draft({ conditions }), null), /Condition 2/);
    conditions[1].use = false;
    assert.equal(buildExceptionInput(draft({ conditions }), null).conditions.length, 1);
});
test('operators, wildcards, partial lengths, byte limits and control characters follow server validation', () => {
    for (const changes of [{ field: 'unknown' }, { op: 'regex' }, { value: 'C:\\*' }, { op: 'contains', value: '-c' }, { value: 'a\u0000b' }, { value: 'x'.repeat(1025) }]) {
        assert.ok(validateExceptionDraft(draft({ conditions: [condition(changes)] })));
    }
    for (const op of ['equals', 'startswith', 'endswith', 'contains']) {
        assert.equal(validateExceptionDraft(draft({ conditions: [condition({ op })] })), null);
    }
    assert.ok(validateExceptionDraft(draft({ name: 'ع'.repeat(128) })));
    assert.ok(validateExceptionDraft(draft({ reason: 'ع'.repeat(501) })));
    assert.ok(validateExceptionDraft(draft({ conditions: Array.from({ length: 11 }, () => condition()) })));
});
test('all expiry choices serialize correctly; invalid choices and empty drafts fail', () => {
    const now = Date.parse('2026-10-09T00:00:00Z');
    for (const days of [7, 30, 90, 365]) assert.equal(Date.parse(buildExceptionInput(draft({ expiryDays: String(days) }), null, now).expires_at), now + days * 86_400_000);
    assert.equal(buildExceptionInput(draft({ expiryDays: '0' }), null, now).expires_at, undefined);
    for (const change of [{ name: '' }, { reason: '' }, { ruleId: '' }, { conditions: [] }, { expiryDays: '500' }]) assert.ok(validateExceptionDraft(draft(change)));
});
test('alert evidence is suggested but not silently approved; secondary rule titles are not invented', () => {
    const alert = { id: 'source-alert', rule_id: 'primary', rule_title: 'Primary title', context_data: { data: { executable: 'C:\\Backup\\agent.exe', command_line: 'backup --nightly', sha256: 'abc' } } };
    const candidates = candidatesFromAlert(alert);
    assert.equal(candidates.find(c => c.field === 'Image').use, true);
    assert.equal(candidates.find(c => c.field === 'CommandLine').use, false);
    const input = buildExceptionInput(draft({ ruleId: 'secondary' }), alert);
    assert.equal(input.rule_id, 'secondary');
    assert.equal(input.rule_title, '');
    assert.equal(input.source_alert_id, 'source-alert');
});
test('legacy file-event evidence prefills Image, while a field with no value reports the actual missing value', () => {
    const candidates = candidatesFromAlert({ context_data: { data: { executable: '' } }, event_data: { image_path: 'C:\\Windows\\pwsh.exe' } });
    assert.equal(candidates.find(c => c.field === 'Image').value, 'C:\\Windows\\pwsh.exe');
    assert.match(validateExceptionDraft(draft({ conditions: [condition({ value: '' })] })), /Condition 1 \(Image\): enter the value/);
});
