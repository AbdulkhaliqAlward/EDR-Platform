// Real pages inside the app-shell container, against isolated HTTP fixtures:
// Endpoint Risk, Audit Logs, Script Library, Signatures (history + catalog),
// Vulnerability Management and Fleet Connectivity. Checks the shared pager
// (10/25/50/100 rows, Showing X–Y of N, next/previous/first), page-specific
// content fixes, and no horizontal overflow at 390/1280 in light and dark.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { chromium } from 'playwright';

process.env.VITE_CONNECTION_MANAGER_URL = '/fixture';
process.env.VITE_API_URL = '/fixture';
const root = fileURLToPath(new URL('../', import.meta.url));
const errors = [], requests = [];
const stamp = new Date(Date.now() - 3600000).toISOString();
const uuid = n => `00000000-0000-4000-8000-${String(n + 1).padStart(12, '0')}`;
const N = 37;
const cursorPage = (params, total, make) => {
    const limit = Number(params.limit || 25), start = Number(params.cursor || 0);
    const data = Array.from({ length: Math.max(0, Math.min(limit, total - start)) }, (_, i) => make(start + i));
    return { data, page_info: { limit, has_next: start + limit < total, has_prev: start > 0, next_cursor: start + limit < total ? String(start + limit) : null, prev_cursor: start > 0 ? String(Math.max(0, start - limit)) : null } };
};
const agent = n => ({ id: uuid(n), hostname: `fleet-host-${n}`, status: 'online', os_type: 'windows', health_score: 90, last_seen: new Date().toISOString(), ip_addresses: [`10.0.0.${n}`], tags: {}, metadata: {}, agent_version: '1.0', queue_depth: 0, events_dropped: 0 });
const screens = {
    risk: { module: '/src/pages/EndpointRisk.tsx', role: 'analyst', first: 'risk-host-0', label: 'endpoints' },
    audit: { module: '/src/pages/AuditLogs.tsx', role: 'admin', first: 'auditor-0', label: 'log entries' },
    scripts: { module: '/src/pages/automation/ScriptLibraryPage.tsx', named: 'ScriptLibraryPage', role: 'admin', first: 'Script 0', label: 'scripts' },
    signatures: { module: '/src/pages/settings/SignaturesManagement.tsx', role: 'admin', first: 'v100', label: 'syncs' },
    vuln: { module: '/src/pages/VulnerabilityManagement.tsx', role: 'admin', first: 'CVE-2026-0000', label: 'findings' },
    fleet: { module: '/src/pages/parity/paritySectionPages.tsx', named: 'ManagementNetworkPage', role: 'admin', first: 'fleet-host-0', label: 'endpoints' },
};
const plugin = {
    name: 'pagination-more-pages',
    resolveId(id) { if (id.startsWith('/more-page.js')) return '\0more-page'; },
    load(id) {
        if (id !== '\0more-page') return;
        const imports = Object.entries(screens).map(([key, s]) => `import ${s.named ? `{ ${s.named} as P_${key} }` : `P_${key}`} from '${s.module}';`).join('');
        const map = Object.keys(screens).map(key => `${key}:P_${key}`).join(',');
        const roles = JSON.stringify(Object.fromEntries(Object.entries(screens).map(([k, s]) => [k, s.role])));
        return `import React from 'react';import {createRoot} from 'react-dom/client';import {BrowserRouter} from 'react-router-dom';import {QueryClient,QueryClientProvider} from '@tanstack/react-query';import {ToastProvider} from '/src/components/Toast.tsx';import '/src/index.css';${imports}
        const screen=new URLSearchParams(location.search).get('screen');
        localStorage.setItem('user',JSON.stringify({role:${roles}[screen]}));
        const Page={${map}}[screen];
        const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
        createRoot(document.getElementById('root')).render(React.createElement(BrowserRouter,null,React.createElement(QueryClientProvider,{client},React.createElement(ToastProvider,null,
            React.createElement('main',{className:'flex-1 min-h-0 overflow-x-hidden overflow-y-auto'},React.createElement('div',{className:'xc-app-workspace w-full max-w-[1920px] mx-auto px-5 sm:px-8 lg:px-10 xl:px-12 py-6 lg:py-8'},React.createElement(Page)))))));`;
    },
    configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
            const url = new URL(req.url, 'http://fixture');
            const send = (value, status = 200) => { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(value)); };
            if (url.pathname === '/verify') { res.setHeader('Content-Type', 'text/html'); res.end(await server.transformIndexHtml('/verify', '<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/more-page.js"></script></body></html>')); return; }
            if (!url.pathname.startsWith('/fixture/')) return next();
            const params = Object.fromEntries(url.searchParams);
            requests.push({ path: url.pathname, params });
            const path = url.pathname.replace('/fixture/api/v1', '');
            if (path === '/alerts/endpoint-risk') return send({ data: Array.from({ length: N }, (_, n) => ({ agent_id: uuid(n), hostname: `risk-host-${n}`, os_type: 'windows', agent_status: 'online', total_alerts: 3, peak_risk_score: 99 - n, avg_risk_score: 60, critical_count: n < 5 ? 1 : 0, high_count: 1, medium_count: 1, open_count: 2, last_alert_at: stamp })), total: N, window_days: Number(params.window_days || 7) });
            if (path === '/audit/logs') return send(cursorPage(params, 63, n => ({ id: uuid(n), user_id: uuid(900), username: `auditor-${n}`, action: n % 2 ? 'playbook.run' : 'user_login', resource_type: n % 2 ? 'playbook_execution' : 'user', resource_id: uuid(n), result: n === 3 ? 'failure' : 'success', details: n % 2 ? `playbook Contain run on WS-${n}` : '', ip_address: `192.0.2.${n}`, timestamp: stamp })));
            if (path === '/response-scripts') return send({ data: Array.from({ length: N }, (_, n) => ({ id: uuid(n), name: `Script ${n}`, description: n === 7 ? 'needle description' : 'Collect diagnostics', cmd: `ipconfig /all`, timeout_seconds: 60, enabled: true, created_by: 'admin', updated_at: stamp, created_at: stamp })), total: N });
            if (path === '/commands/capabilities') return send({ custom_commands_enabled: false, command_approval_enabled: false, library_executables: ['ipconfig'] });
            if (path === '/signatures/stats') return send({ count: 63, max_version: 163, sources: { malwarebazaar: 63 } });
            if (path === '/signatures/sync-history') return send({ data: Array.from({ length: N }, (_, n) => ({ id: n + 1, generation: 100 + n, hashes_inserted: 10 * n, synced_at: stamp })) });
            if (path === '/signatures/catalog') return send(cursorPage(params, 63, n => ({ id: 1000 - n, sha256: String(n).padStart(64, 'a'), name: `Malware ${n}`, family: 'Emotet', severity: 'high', source: 'malwarebazaar', version: 1000 - n, first_seen: stamp })));
            if (path === '/vuln/findings') {
                const limit = Number(params.limit || 50), offset = Number(params.offset || 0), total = params.search === 'nomatch' ? 0 : 63;
                return send({ data: Array.from({ length: Math.max(0, Math.min(limit, total - offset)) }, (_, i) => ({ id: uuid(offset + i), agent_id: uuid(1), hostname: 'vuln-host', cve: `CVE-2026-${String(offset + i).padStart(4, '0')}`, title: 'Fixture finding', description: '', severity: 'high', status: 'open', source: 'scanner', package_name: 'openssl', installed_version: '1.0', fixed_version: '1.1', reference_url: '', kev_listed: false, detected_at: stamp })), pagination: { total, limit, offset } });
            }
            if (path === '/vuln/stats') return send({ data: { total: 63, open_count: 63, by_severity: { high: 63 }, by_status: { open: 63 }, kev_count: 0, affected_hosts: 1, top_cves: [], top_hosts: [] } });
            if (path === '/agents/stats') return send({ total: N, online: N, offline: 0, degraded: 0, pending: 0, suspended: 0 });
            if (path === '/agents') { const page = cursorPage(params, N, agent); return send({ ...page, pagination: { total: N, has_more: page.page_info.has_next } }); }
            send({ data: [], total: 0 });
        });
    },
};
const server = await createServer({ root, server: { host: '127.0.0.1', port: 0 }, plugins: [plugin] });
let browser;
const status = nav => nav.getByRole('status');
try {
    await server.listen(); const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
    browser = await chromium.launch({ channel: process.platform === 'win32' ? 'chrome' : undefined, headless: true });
    for (const [screen, cfg] of Object.entries(screens)) for (const width of [390, 1280]) for (const dark of [false, true]) {
        const page = await browser.newPage({ viewport: { width, height: 1000 } });
        page.setDefaultNavigationTimeout(60000); page.setDefaultTimeout(15000);
        page.on('pageerror', error => errors.push(`${screen}: ${error.message}`));
        await page.route('**/*', route => route.request().url().startsWith(origin) ? route.continue() : route.abort());
        await page.goto(`${origin}/verify?screen=${screen}`, { waitUntil: 'domcontentloaded' });
        await page.getByText(cfg.first, { exact: false }).first().waitFor();
        await page.evaluate(d => document.documentElement.classList.toggle('dark', d), dark);
        const nav = page.getByRole('navigation', { name: 'Pagination' }).first();
        const sizes = await nav.getByLabel('Rows per page').locator('option').allTextContents();
        assert.deepEqual(sizes, ['10', '25', '50', '100'], `${screen}: page sizes`);
        await nav.getByLabel('Rows per page').selectOption('10');
        await status(nav).filter({ hasText: /Showing 1–10/ }).waitFor();
        await nav.getByRole('button', { name: 'Next page' }).click();
        await status(nav).filter({ hasText: /Showing 11–20/ }).waitFor();
        await nav.getByRole('button', { name: 'Next page' }).click();
        await status(nav).filter({ hasText: /Showing 21–30/ }).waitFor();
        await nav.getByRole('button', { name: 'First page' }).click();
        await status(nav).filter({ hasText: /Showing 1–10/ }).waitFor();

        if (screen === 'risk') {
            assert.ok(requests.some(r => r.path.endsWith('/alerts/endpoint-risk') && r.params.window_days === '7'));
            await page.getByLabel('Activity window').selectOption('30');
            await page.waitForFunction(() => new URLSearchParams(location.search).get('window') === '30');
            assert.ok(requests.some(r => r.path.endsWith('/alerts/endpoint-risk') && r.params.window_days === '30'));
            assert.equal(await page.getByRole('link', { name: 'Open endpoint risk-host-0' }).getAttribute('href'), `/management/devices/${uuid(0)}`);
        }
        if (screen === 'audit') {
            await page.getByRole('columnheader', { name: 'Log ID' }).waitFor();
            await page.locator('table').getByText('Sign in', { exact: true }).first().waitFor();
            await page.locator('table').getByText('Playbook run', { exact: true }).first().waitFor();
            await page.getByText('playbook Contain run on WS-1').waitFor();
            await page.getByText('192.0.2.0').waitFor();
            assert.equal(await page.getByText('Delete logs').count(), 0);
        }
        if (screen === 'scripts') {
            await page.getByLabel('Search scripts').fill('needle');
            await page.getByText('Script 7', { exact: true }).waitFor();
            await status(nav).filter({ hasText: /Showing 1–1 of 1/ }).waitFor();
        }
        if (screen === 'signatures') {
            const catalogNav = page.getByRole('navigation', { name: 'Pagination' }).nth(1);
            await catalogNav.getByLabel('Rows per page').selectOption('10');
            await page.getByText('Malware 9', { exact: true }).waitFor();
            await catalogNav.getByRole('button', { name: 'Next page' }).click();
            await page.getByText('Malware 10', { exact: true }).waitFor();
            assert.ok(requests.some(r => r.path.endsWith('/signatures/catalog') && r.params.cursor === '10'));
            assert.ok(requests.some(r => r.path.endsWith('/signatures/sync-history') && r.params.limit === '200'));
        }
        if (screen === 'vuln') {
            assert.ok(requests.some(r => r.path.endsWith('/vuln/findings') && r.params.limit === '10' && r.params.offset === '10'), 'server offset paging');
            await status(nav).filter({ hasText: /of 63/ }).waitFor();
        }
        if (screen === 'fleet') {
            await page.getByLabel('Search fleet').fill('fleet-host-3');
            await page.getByText('fleet-host-3', { exact: true }).first().waitFor();
            await status(nav).filter({ hasText: /of [0-9]+$/ }).waitFor();
        }
        const offenders = await page.evaluate(() => [...document.querySelectorAll('button, input, select, a, nav, table, h1, h2')]
            .filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > window.innerWidth + 1 && getComputedStyle(e).position !== 'fixed'; })
            .filter(e => !e.closest('.overflow-x-auto, .overflow-auto')).slice(0, 5).map(e => `${e.tagName} ${(e.textContent || '').trim().slice(0, 30)}`));
        assert.deepEqual(offenders, [], `${screen} overflow at ${width} dark=${dark}`);
        await page.close();
    }
    assert.deepEqual(errors, []);
    console.log('PASS more pages (Endpoint Risk, Audit Logs, Script Library, Signatures, Vulnerability, Fleet Connectivity): 10/25/50/100 sizes, Showing X–Y, next/first, page-specific fixes, 390/1280 light/dark');
} catch (error) {
    console.error('Page errors:', errors);
    throw error;
} finally { await browser?.close(); await server.close(); }
