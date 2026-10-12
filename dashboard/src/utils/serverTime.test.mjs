import test from 'node:test';
import assert from 'node:assert/strict';
import { formatInZone, zoneName, browserSkewMs, describeClockOffset } from './serverTime.ts';

const at = '2026-10-12T10:04:05Z';

test('times are rendered in the server display zone, not the browser zone', () => {
    const riyadh = formatInZone(at, { timezone: 'Asia/Riyadh', utc_offset_seconds: 10800 });
    assert.match(riyadh, /12 Oct 2026, 13:04:05 GMT\+3/);
    const utc = formatInZone(at, { timezone: 'UTC', utc_offset_seconds: 0 });
    assert.match(utc, /12 Oct 2026, 10:04:05 UTC/);
});

test('offset-only and unknown zones fall back to the numeric offset', () => {
    assert.equal(formatInZone(at, { timezone: '', utc_offset_seconds: 19800 }), '12 Oct 2026, 15:34:05 UTC+05:30');
    assert.equal(formatInZone(at, { timezone: 'Not/AZone', utc_offset_seconds: -3600 }), '12 Oct 2026, 09:04:05 UTC-01:00');
    assert.equal(zoneName({ timezone: '', utc_offset_seconds: 0 }), 'UTC');
    assert.equal(zoneName({ timezone: 'Asia/Riyadh', utc_offset_seconds: 10800 }), 'Asia/Riyadh');
});

test('invalid input is returned unchanged', () => {
    assert.equal(formatInZone('not a date', { timezone: 'UTC', utc_offset_seconds: 0 }), 'not a date');
});

test('browser skew uses the request midpoint', () => {
    // Browser 90 s behind: request sent at 1000, received at 1200 (browser ms).
    const server = new Date(1100 + 90_000).toISOString();
    assert.equal(browserSkewMs(server, 1000, 1200), 90_000);
    assert.equal(browserSkewMs('garbage', 0, 0), 0);
});

test('agent clock offsets are described in words', () => {
    assert.equal(describeClockOffset(312_000), '5m 12s behind the server');
    assert.equal(describeClockOffset(-7_200_000), '2h 0m ahead of the server');
    assert.equal(describeClockOffset(4_000), '4s behind the server');
});

test('agent location reads like an address and never invents geography', async () => {
    const { formatAgentLocation } = await import('./agentLocation.ts');
    assert.equal(formatAgentLocation({ network_scope: 'public', public_ip: '198.51.100.23', city: 'Riyadh', region: 'Riyadh Region', country: 'Saudi Arabia', country_code: 'SA' }),
        'Riyadh, Riyadh Region, Saudi Arabia (SA) · 198.51.100.23');
    assert.equal(formatAgentLocation({ network_scope: 'public', public_ip: '2001:db8::1', country: 'Sweden', country_code: 'SE' }), 'Sweden (SE) · 2001:db8::1');
    assert.equal(formatAgentLocation({ network_scope: 'private', public_ip: '172.31.5.9' }), 'Private network · 172.31.5.9');
    assert.equal(formatAgentLocation({ network_scope: 'unknown', public_ip: '203.0.113.7' }), 'Location unknown · 203.0.113.7');
    assert.equal(formatAgentLocation(undefined), '');
});
