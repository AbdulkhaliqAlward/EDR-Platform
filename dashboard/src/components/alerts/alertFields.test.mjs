import assert from 'node:assert/strict';
import test from 'node:test';
import { filterSections, flattenEvent, groupEventFields } from './alertFields.ts';

const processEvent = {
    event_type: 'process', event_id: 'e-1', timestamp: '2026-10-10T10:00:00Z', agent_id: 'a-1',
    source: { hostname: 'WS-01', ip_address: '10.0.0.5', os_type: 'windows' },
    _kafka_offset: 42,
    data: {
        action: 'process_creation', name: 'powershell.exe', executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        pid: 4242, ppid: 100, command_line: 'powershell -enc AAAA', parent_executable: 'C:\\Windows\\explorer.exe',
        parent_command_line: 'C:\\Windows\\explorer.exe', user_name: 'CORP\\bob', is_elevated: false,
        sha256: 'ab'.repeat(32), custom_collector_field: 'x', nested: { a: 1 },
    },
};

const ids = sections => sections.map(s => s.id);
const row = (sections, key) => sections.flatMap(s => s.rows).find(r => r.key === key);

test('every collected field is shown exactly once, grouped in order', () => {
    const sections = groupEventFields(processEvent);
    assert.deepEqual(ids(sections), ['event', 'process', 'parent', 'user', 'host', 'pipeline', 'other']);
    const all = sections.flatMap(s => s.rows.map(r => r.key));
    assert.equal(new Set(all).size, all.length, 'no field rendered twice');
    for (const key of Object.keys(flattenEvent(processEvent))) {
        assert.ok(all.includes(key) || key === 'name', `field ${key} must be visible`);
    }
    assert.equal(row(sections, 'process_name').value, 'powershell.exe', 'process events: name is the process');
    assert.equal(row(sections, 'is_elevated').value, 'false', 'false values are shown, not dropped');
    assert.equal(row(sections, 'nested').value, '{"a":1}');
    assert.equal(row(sections, 'hostname').value, 'WS-01');
});

test('file events: name is the file, never the process', () => {
    const sections = groupEventFields({ event_type: 'file', data: { name: 'evil.dll', path: 'C:\\x\\evil.dll', process_name: 'cmd.exe' } });
    assert.equal(sections.find(s => s.id === 'file').rows.find(r => r.key === 'name').value, 'evil.dll');
    assert.equal(row(sections, 'process_name').value, 'cmd.exe');
});

test('matched values are flagged and search filters across labels and values', () => {
    const sections = groupEventFields(processEvent, { CommandLine: 'powershell -enc AAAA' });
    assert.equal(row(sections, 'command_line').matched, true);
    assert.equal(row(sections, 'pid').matched, false);
    const found = filterSections(sections, 'explorer');
    assert.deepEqual(ids(found), ['parent']);
    assert.equal(filterSections(sections, '').length, sections.length);
});

test('script text is excluded from the table (shown as a block)', () => {
    const sections = groupEventFields({ event_type: 'powershell', data: { script_block_text: 'Get-Process', script_path: 'C:\\s.ps1' } });
    assert.equal(row(sections, 'script_block_text'), undefined);
    assert.equal(row(sections, 'script_path').value, 'C:\\s.ps1');
});
