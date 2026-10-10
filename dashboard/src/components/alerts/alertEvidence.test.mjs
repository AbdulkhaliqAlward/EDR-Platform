import assert from 'node:assert/strict';
import test from 'node:test';
import { alertEvidence, displaySnapshot, evidenceDate } from './alertEvidence.ts';

const fileAlert = (data = {}) => ({ context_data: { event_type: 'file', name: 'Utility.dll', data: { name: 'Utility.dll', path: 'C:\\Modules\\Utility.dll', process_name: 'unknown', process_path: '', ...data } } });

test('file target is never used as process identity, even with a polluted snapshot', () => {
    const alert = { ...fileAlert(), context_snapshot: { process_name: 'Utility.dll' } };
    const evidence = alertEvidence(alert);
    assert.equal(evidence.processName, '');
    assert.equal(evidence.image, '');
    assert.equal(evidence.target, 'C:\\Modules\\Utility.dll');
    assert.equal(displaySnapshot(alert).process_name, undefined);
    assert.equal(alert.context_snapshot.process_name, 'Utility.dll');
});

test('explicit actor aliases win over file name and empty executable', () => {
    const evidence = alertEvidence(fileAlert({ executable: '', process_path: 'C:\\Windows\\powershell.exe', process_name: 'powershell.exe' }));
    assert.equal(evidence.image, 'C:\\Windows\\powershell.exe');
    assert.equal(evidence.processName, 'powershell.exe');
});

test('legacy flat and nested process records remain supported without mislabeling their path as a target', () => {
    for (const event of [{ event_type: 'process', name: 'cmd.exe', path: 'C:\\cmd.exe' }, { event_type: 'process', data: { name: 'cmd.exe' } }]) {
        const evidence = alertEvidence({ event_data: event });
        assert.equal(evidence.processName, 'cmd.exe');
        assert.equal(evidence.target, '');
    }
});

test('missing fields are not filled from another event or scoring snapshot', () => {
    const alert = { ...fileAlert(), event_data: { process_path: 'C:\\other.exe' }, context_snapshot: { process_name: 'other.exe', process_path: 'C:\\other.exe' } };
    assert.equal(alertEvidence(alert).image, '');
    assert.equal(displaySnapshot(alert), alert.context_snapshot);
});

test('false and zero remain visible; malformed telemetry never becomes object text', () => {
    const evidence = alertEvidence(fileAlert({ is_elevated: false, pid: 0, executable: { value: 'bad' }, command_line: ['bad'] }));
    assert.equal(evidence.pick('is_elevated'), 'false');
    assert.equal(evidence.pick('pid'), '0');
    assert.equal(evidence.image, '');
    assert.equal(evidence.pick('command_line'), '');
    assert.equal(alertEvidence({ context_data: { data: null } }).image, '');
    assert.match(evidenceDate('garbled'), /Unavailable/);
    assert.equal(evidenceDate(''), '');
});
