// Real Alerts page (inside the app shell main container) against an isolated HTTP fixture: keyset navigation,
// risk-score sort, current-page reload after a status change, list hostnames,
// detail fetch by ID, responsive light/dark. No live services are contacted.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { chromium } from 'playwright';

process.env.VITE_CONNECTION_MANAGER_URL = '/fixture';
process.env.VITE_API_URL = '/fixture';
const root = fileURLToPath(new URL('../', import.meta.url));
const errors = [], requests = [];
const base = Date.now() - 3600000;
const uuid = n => `00000000-0000-4000-8000-${String(n + 1).padStart(12, '0')}`;
const TOTAL = 63;
const risk = n => (n * 37) % 101;
const alertRow = (n, sort) => ({
    id: uuid(n), rule_id: `rule-${n}`, rule_title: `${sort === 'risk_score' ? 'Risk' : 'Fixture'} alert ${n}`,
    severity: 'high', status: 'open', agent_id: uuid(500), source_hostname: `Fixture host ${n}`,
    timestamp: new Date(base - n * 1000).toISOString(), created_at: new Date(base - n * 1000).toISOString(),
    last_seen_at: new Date(base - n * 1000).toISOString(), risk_score: risk(n), risk_level: 'high',
    mitre_tactics: [], mitre_techniques: [], event_count: 1, confidence: 0.9,
});
const plugin = {
    name: 'alerts-pagination-page',
    resolveId(id) { if (id === '/alerts-page.js') return '\0alerts-page'; },
    load(id) {
        if (id !== '\0alerts-page') return;
        return `import React from 'react';import {createRoot} from 'react-dom/client';import {BrowserRouter} from 'react-router-dom';import {QueryClient,QueryClientProvider} from '@tanstack/react-query';import {ToastProvider} from '/src/components/Toast.tsx';import Alerts from '/src/pages/Alerts.tsx';import '/src/index.css';
        localStorage.setItem('user',JSON.stringify({role:'analyst'}));
        const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
        createRoot(document.getElementById('root')).render(React.createElement(BrowserRouter,null,React.createElement(QueryClientProvider,{client},React.createElement(ToastProvider,null,React.createElement('main',{className:'flex-1 min-h-0 overflow-x-hidden overflow-y-auto'},React.createElement('div',{className:'xc-app-workspace w-full max-w-[1920px] mx-auto px-5 sm:px-8 lg:px-10 xl:px-12 py-6 lg:py-8'},React.createElement(Alerts)))))));`;
    },
    configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
            const url = new URL(req.url, 'http://fixture');
            const send = (value, status = 200) => { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(value)); };
            if (url.pathname === '/verify') { res.setHeader('Content-Type', 'text/html'); res.end(await server.transformIndexHtml('/verify', '<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/alerts-page.js"></script></body></html>')); return; }
            if (!url.pathname.startsWith('/fixture/')) return next();
            const params = Object.fromEntries(url.searchParams);
            requests.push({ method: req.method, path: url.pathname, params });
            const status = url.pathname.match(/\/sigma\/alerts\/([0-9a-f-]+)\/status$/);
            if (status && req.method === 'PATCH') { send({ id: status[1], status: 'acknowledged' }); return; }
            const detail = url.pathname.match(/\/sigma\/alerts\/([0-9a-f-]{36})$/);
            if (detail) {
                const n = Number(detail[1].slice(-12)) - 1;
                send({ ...alertRow(n), context_data: { event_type: 'process', data: { command_line: 'alert-detail-evidence.exe /full' }, source: { hostname: `Fixture host ${n}` } } });
                return;
            }
            if (url.pathname.endsWith('/sigma/alerts')) {
                const limit = Number(params.limit || 25), start = Number(params.cursor || 0);
                const data = Array.from({ length: Math.max(0, Math.min(limit, TOTAL - start)) }, (_, i) => alertRow(start + i, params.sort));
                send({ data, page_info: { limit, has_next: start + limit < TOTAL, has_prev: start > 0, next_cursor: start + limit < TOTAL ? String(start + limit) : null, prev_cursor: start > 0 ? String(Math.max(0, start - limit)) : null } });
                return;
            }
            send({ data: [], total: 0, pagination: { total: 0, has_more: false }, page_info: { limit: 25, has_next: false, has_prev: false, next_cursor: null, prev_cursor: null } });
        });
    },
};
const until = async (check, message, timeout = 10000) => {
    const end = Date.now() + timeout;
    while (!check()) { if (Date.now() > end) throw new Error(message); await new Promise(r => setTimeout(r, 50)); }
};
const listRequests = () => requests.filter(r => r.method === 'GET' && r.path.endsWith('/sigma/alerts'));
const server = await createServer({ root, server: { host: '127.0.0.1', port: 0 }, plugins: [plugin] });
let browser;
try {
    await server.listen(); const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
    browser = await chromium.launch({ channel: process.platform === 'win32' ? 'chrome' : undefined, headless: true });
    for (const width of [390, 1280]) for (const dark of [false, true]) {
        requests.length = 0;
        const page = await browser.newPage({ viewport: { width, height: 1000 } });
        page.setDefaultNavigationTimeout(60000); page.setDefaultTimeout(15000);
        page.on('pageerror', error => errors.push(error.message));
        await page.route('**/*', route => route.request().url().startsWith(origin) ? route.continue() : route.abort());
        await page.goto(`${origin}/verify`, { waitUntil: 'domcontentloaded' });
        await page.getByText('Fixture alert 0', { exact: true }).waitFor();
        await page.evaluate(d => document.documentElement.classList.toggle('dark', d), dark);

        // First page: creation-time keyset with the default 24h range persisted in the URL.
        const first = listRequests()[0].params;
        assert.equal(first.sort, 'created_at'); assert.equal(first.order, 'desc'); assert.equal(first.limit, '25');
        assert.ok(first.date_from && first.date_to); assert.equal(first.cursor, undefined);
        // The lightweight list still carries the hostname the table shows.
        await page.getByText('Fixture host 0', { exact: true }).first().waitFor();

        const nav = page.getByRole('navigation', { name: 'Pagination' });
        await nav.getByRole('button', { name: 'Next page' }).click();
        await page.getByText('Fixture alert 25', { exact: true }).waitFor();
        assert.equal(new URL(page.url()).searchParams.get('cursor'), '25');

        // A status change re-reads the SAME page (same cursor), it never jumps to page 1.
        const before = listRequests().length;
        await page.getByRole('row', { name: /Fixture alert 25\b/ }).getByTitle('Acknowledge').click();
        await page.waitForFunction(() => document.body.textContent.includes('Alert status updated'));
        await until(() => listRequests().length > before, 'current page was not reloaded after the status change');
        const reloads = listRequests().slice(before);
        assert.ok(reloads.every(r => r.params.cursor === '25'), 'status change navigated away from the current page');
        assert.ok(requests.some(r => r.method === 'PATCH' && r.path.endsWith(`/sigma/alerts/${uuid(25)}/status`)));
        assert.equal(new URL(page.url()).searchParams.get('cursor'), '25');

        // Details load the full record by ID.
        await page.getByText('Fixture alert 26', { exact: true }).click();
        await until(() => requests.some(r => r.path.endsWith(`/sigma/alerts/${uuid(26)}`)), 'detail was not fetched by ID');
        await page.keyboard.press('Escape');

        // Risk-score sort is a server keyset sort and restarts from page 1.
        await page.getByRole('button', { name: /^Risk/ }).first().click();
        await page.getByText('Risk alert 0', { exact: true }).waitFor();
        const sp = new URL(page.url()).searchParams;
        assert.equal(sp.get('sort'), 'risk_score'); assert.equal(sp.get('order'), 'desc'); assert.equal(sp.has('cursor'), false);
        assert.equal(listRequests().at(-1).params.sort, 'risk_score');
        await page.getByText('Risk score', { exact: true }).waitFor();
        await nav.getByRole('button', { name: 'Next page' }).click();
        await page.getByText('Risk alert 25', { exact: true }).waitFor();
        assert.equal(listRequests().at(-1).params.sort, 'risk_score');

        const offenders = await page.evaluate(() => [...document.querySelectorAll('button, input, select, a, nav, table, h1, h2')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > window.innerWidth + 1 && getComputedStyle(e).position !== 'fixed'; }).filter(e => !e.closest('.overflow-x-auto, .overflow-auto')).slice(0, 8).map(e => `${e.tagName}.${String(e.className).slice(0, 90)} right=${Math.round(e.getBoundingClientRect().right)} text=${(e.textContent || '').trim().slice(0, 40)}`));
        assert.deepEqual(offenders, [], `page overflow at ${width} dark=${dark}`);
        assert.equal(await nav.evaluate(e => e.scrollWidth <= e.clientWidth + 1), true, `pagination overflow at ${width} dark=${dark}`);
        await page.close();
    }
    assert.deepEqual(errors, []);
    console.log('PASS Alerts page: created_at keyset + URL cursor, list hostnames, status change reloads the same page, detail by ID, risk-score keyset sort, 390/1280 light/dark');
} catch (error) {
    console.error('Page errors:', errors);
    throw error;
} finally { await browser?.close(); await server.close(); }
