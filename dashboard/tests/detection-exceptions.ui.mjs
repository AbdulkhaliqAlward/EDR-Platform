// Real React components and platform CSS; all API calls stay on this disposable loopback fixture.
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('../', import.meta.url));
const artifacts = process.env.EDR_UI_ARTIFACT_DIR || join(tmpdir(), 'edr-exception-ui-verification');
await mkdir(artifacts, { recursive: true });
process.env.VITE_CONNECTION_MANAGER_URL = '/fixture';
process.env.VITE_API_URL = '/fixture';
const agents = Array.from({ length: 24 }, (_, index) => ({ id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`, hostname: `Workstation-${String(index + 1).padStart(2, '0')}`, status: 'online' }));
const alert = { id: '11111111-1111-4111-8111-111111111111', agent_id: agents[0].id, source_hostname: agents[0].hostname, rule_id: 'primary-rule', rule_title: 'Suspicious backup command', related_rule_ids: ['primary-rule', 'secondary-rule'], context_data: { data: { executable: 'C:\\Backup\\agent.exe', parent_executable: 'C:\\Windows\\System32\\services.exe', command_line: 'backup --nightly' } } };
const state = { items: [], saved: [], mutations: [], agentFailures: 0, createFailures: 0, statusFailures: 0, toggleFailures: 0, deleteFailures: 0, listFailures: 0, createDelay: 0, perfRequests: { alerts: 0, stats: 0 } };
const plugin = {
    name: 'isolated-detection-exceptions-test',
    resolveId(id) { if (id === 'virtual:exceptions-fixture' || id === '/fixture-entry.js') return 'virtual:exceptions-fixture'; },
    load(id) {
        if (id !== 'virtual:exceptions-fixture') return;
        return `import React,{useState} from 'react';import {createRoot} from 'react-dom/client';import {QueryClient,QueryClientProvider} from '@tanstack/react-query';import {ToastProvider} from '/src/components/Toast.tsx';import {useAlerts} from '/src/hooks/useAlerts.ts';import {useDashboard} from '/src/hooks/useDashboard.ts';import {Modal} from '/src/components/Modal.tsx';import {alertsApi} from '/src/api/client.ts';import {DetectionExceptionsPage} from '/src/pages/automation/DetectionExceptionsPage.tsx';import {CreateExceptionModal} from '/src/components/alerts/CreateExceptionModal.tsx';import '/src/index.css';
        localStorage.setItem('user',JSON.stringify({role:new URLSearchParams(location.search).get('role')||'admin'}));
        const alert=${JSON.stringify(alert)};
        function PerfAlerts(){const data=useAlerts();const [open,setOpen]=useState(false);return React.createElement(React.Fragment,null,React.createElement('output',{'data-testid':'perf-alerts'},data.alerts.length),React.createElement('button',{onClick:()=>{data.setSelectedAlert(alert);setOpen(true);}},'Open selected alert'),data.selectedAlert?React.createElement('span',null,'Alert still selected'):null,React.createElement(CreateExceptionModal,{isOpen:open,alert,onClose:()=>setOpen(false)}));}
        function PerfDashboard(){const data=useDashboard();return React.createElement('output',{'data-testid':'perf-dashboard'},data.liveAlerts.length);}
        const queryClient=new QueryClient({defaultOptions:{queries:{retry:false,staleTime:30000,refetchOnWindowFocus:false}}});
        function Perf(){const [mode,setMode]=useState('dashboard');return React.createElement(QueryClientProvider,{client:queryClient},React.createElement(ToastProvider,null,React.createElement('button',{onClick:()=>setMode('dashboard')},'Show dashboard'),React.createElement('button',{onClick:()=>setMode('alerts')},'Show alerts'),React.createElement('button',{onClick:()=>setMode('none')},'Leave pages'),mode==='dashboard'?React.createElement(PerfDashboard):mode==='alerts'?React.createElement(PerfAlerts):null));}
        function App(){const [open,setOpen]=useState(false);const params=new URLSearchParams(location.search);const props={isOpen:open,alert,onClose:()=>setOpen(false)};if(params.has('callback')){props.updateAlertStatus=false;props.onCreated=async(marked)=>{if(marked)await alertsApi.updateStatus(alert.id,'false_positive');};}const content=React.createElement(React.Fragment,null,React.createElement('button',{onClick:()=>setOpen(true)},'Open alert exception'),React.createElement(CreateExceptionModal,props));return params.has('alert')?React.createElement('main',{className:'p-6'},params.has('nested')?React.createElement(Modal,{isOpen:true,onClose:()=>{},title:'Alert details'},content):content):React.createElement('main',{className:'mx-auto max-w-6xl p-4'},React.createElement(DetectionExceptionsPage));}
        createRoot(document.getElementById('root')).render(React.createElement(new URLSearchParams(location.search).has('perf')?Perf:App));`;
    },
    configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
            const url = new URL(req.url, 'http://fixture');
            if (url.pathname === '/verify') {
                res.setHeader('Content-Type', 'text/html');
                res.end(await server.transformIndexHtml('/verify', '<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/fixture-entry.js"></script></body></html>'));
                return;
            }
            if (url.pathname === '/fixture-entry.js') {
                res.setHeader('Content-Type', 'application/javascript');
                res.end((await server.transformRequest('virtual:exceptions-fixture')).code);
                return;
            }
            if (!url.pathname.startsWith('/fixture/')) return next();
            let text = ''; for await (const chunk of req) text += chunk;
            const input = text ? JSON.parse(text) : {};
            const send = (body, status = 200) => { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(body)); };
            const fail = key => { if (state[key] > 0) { state[key]--; send({ message: `Fixture ${key} failure` }, 503); return true; } return false; };
            if (url.pathname === '/fixture/control') { Object.assign(state, input); send(state); return; }
            if (url.pathname === '/fixture/state') { send(state); return; }
            if (url.pathname.endsWith('/sigma/alerts') && req.method === 'GET') { state.perfRequests.alerts++; send({ alerts: [], total: 0 }); return; }
            if (url.pathname.endsWith('/sigma/stats/alerts')) { state.perfRequests.stats++; send({ total_alerts: 0, by_severity: {}, by_status: {} }); return; }
            if (url.pathname.includes('/sigma/stats/timeline')) { send({ data: [] }); return; }
            if (url.pathname.endsWith('/agents/stats')) { send({ total: 24 }); return; }
            if (url.pathname.endsWith('/agents')) {
                if (fail('agentFailures')) return;
                const search = (url.searchParams.get('search') || '').toLowerCase();
                if (search === 'workstation-01') await new Promise(resolve => setTimeout(resolve, 700));
                const rows = agents.filter(agent => agent.hostname.toLowerCase().includes(search));
                const offset = Number(url.searchParams.get('offset') || 0);
                send({ data: rows.slice(offset, offset + 20), pagination: { total: rows.length, has_more: offset + 20 < rows.length } }); return;
            }
            if (url.pathname.endsWith('/detection-exceptions') && req.method === 'GET') { if (!fail('listFailures')) send({ data: state.items }); return; }
            if (url.pathname.endsWith('/detection-exceptions') && req.method === 'POST') {
                if (fail('createFailures')) return;
                await new Promise(resolve => setTimeout(resolve, state.createDelay));
                const item = { ...input, id: `exception-${state.saved.length + 1}`, hostname: agents.find(agent => agent.id === input.agent_id)?.hostname || '', enabled: true, hit_count: 0, created_by: 'test-admin', created_at: new Date().toISOString() };
                state.saved.push(input); state.items.push(item); send({ data: item }, 201); return;
            }
            if (url.pathname.includes('/detection-exceptions/')) {
                const id = url.pathname.split('/').at(-1);
                if (req.method === 'PATCH') {
                    if (fail('toggleFailures')) return;
                    const item = state.items.find(item => item.id === id); Object.assign(item, input); state.mutations.push({ method: 'PATCH', id, input }); send({ data: item }); return;
                }
                if (req.method === 'DELETE') { if (fail('deleteFailures')) return; state.items = state.items.filter(item => item.id !== id); state.mutations.push({ method: 'DELETE', id }); send({}); return; }
            }
            if (url.pathname.includes('/alerts/') && req.method === 'GET') { send(alert); return; }
            if (url.pathname.includes('/alerts/')) { if (fail('statusFailures')) return; state.mutations.push({ method: req.method, input, kind: 'alert-status' }); send({ data: { ...alert, status: 'false_positive' } }); return; }
            send({ message: `Unmocked API request: ${req.method} ${url.pathname}` }, 500);
        });
    },
};
const server = await createServer({ root, server: { host: '127.0.0.1', port: 0, strictPort: true }, plugins: [plugin] });
let browser;
try {
    await server.listen();
    const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
    browser = await chromium.launch({ channel: process.env.EDR_UI_BROWSER_CHANNEL || (process.platform === 'win32' ? 'chrome' : undefined), headless: true });
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    page.setDefaultTimeout(10_000);
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => route.request().url().startsWith(origin) ? route.continue() : route.abort());
    const control = async patch => { const response = await fetch(`${origin}/fixture/control`, { method: 'POST', body: JSON.stringify(patch) }); assert.equal(response.status, 200); };
    const saved = async () => (await (await fetch(`${origin}/fixture/state`)).json());
    const dialog = () => page.getByRole('dialog');
    const create = () => dialog().getByRole('button', { name: 'Create exception', exact: true });
    const noOverflow = async () => {
        const dimensions = await dialog().evaluate(element => {
            const form = element.querySelector('form'); const box = element.getBoundingClientRect();
            return { overflow: form.scrollWidth > form.clientWidth + 1, outside: [...form.querySelectorAll('input,select,textarea,[data-condition-row]')].filter(node => { const rect = node.getBoundingClientRect(); return rect.width && (rect.left < box.left || rect.right > box.right + 1); }).map(node => node.id) };
        });
        assert.equal(dimensions.overflow, false); assert.deepEqual(dimensions.outside, []);
    };
    await page.goto(`${origin}/verify`);
    await page.getByText('No detection exceptions yet').waitFor();
    await page.getByRole('button', { name: 'New exception', exact: true }).click();
    await create().click(); await dialog().getByRole('alert').filter({ hasText: 'Enter a name' }).waitFor();
    await dialog().getByLabel('Name', { exact: true }).fill('Approved backup');
    await dialog().getByLabel('Sigma rule ID').fill('backup-rule');
    await dialog().getByLabel('Justification (audited)').fill('Approved change 123');
    await dialog().getByLabel('Value', { exact: true }).fill('C:\\Backup\\agent.exe');
    await dialog().getByRole('button', { name: 'Add condition' }).click();
    await create().click(); await dialog().getByRole('alert').filter({ hasText: 'Condition 2' }).waitFor();
    assert.equal((await saved()).saved.length, 0);
    await dialog().getByRole('button', { name: 'Remove condition 2' }).click();
    await control({ agentFailures: 1 });
    await dialog().getByLabel('Endpoint scope').selectOption('host');
    await create().click(); await dialog().getByRole('alert').filter({ hasText: 'Select the endpoint' }).waitFor();
    await dialog().getByRole('button', { name: 'Retry endpoints' }).click();
    await dialog().getByRole('button', { name: 'Load more endpoints' }).waitFor();
    await control({ agentFailures: 1 });
    await dialog().getByRole('button', { name: 'Load more endpoints' }).click();
    await dialog().getByRole('button', { name: 'Retry endpoints' }).waitFor();
    assert.equal(await dialog().getByRole('button', { name: 'Load more endpoints' }).isDisabled(), true);
    await dialog().getByRole('button', { name: 'Retry endpoints' }).click();
    await dialog().getByLabel('Endpoint', { exact: true }).selectOption(agents[20].id);
    await dialog().getByLabel('Search endpoints').fill('workstation-01');
    await page.waitForRequest(request => request.url().includes('search=workstation-01'));
    await dialog().getByLabel('Search endpoints').fill('workstation-24');
    await dialog().getByLabel('Endpoint', { exact: true }).selectOption(agents[23].id);
    await new Promise(resolve => setTimeout(resolve, 850));
    assert.equal(await dialog().getByLabel('Endpoint', { exact: true }).locator('option').filter({ hasText: 'Workstation-01' }).count(), 0);
    const fields = ['Image', 'ParentImage', 'CommandLine', 'ParentCommandLine', 'OriginalFileName', 'Hashes', 'User', 'IntegrityLevel', 'Company', 'Product', 'Description', 'CurrentDirectory', 'TargetFilename', 'ImageLoaded', 'TargetObject', 'Details', 'DestinationIp', 'DestinationHostname', 'DestinationPort', 'QueryName', 'PipeName', 'SourceImage', 'TargetImage', 'ScriptBlockText', 'Path'];
    for (const field of fields) { await dialog().getByLabel('Field', { exact: true }).selectOption(field); assert.equal(await dialog().getByLabel('Field', { exact: true }).inputValue(), field); }
    await dialog().getByLabel('Field', { exact: true }).selectOption('Image');
    for (const op of ['equals', 'startswith', 'endswith', 'contains']) { await dialog().getByLabel('Operator').selectOption(op); assert.equal(await dialog().getByLabel('Operator').inputValue(), op); }
    await dialog().getByLabel('Rule scope').selectOption('all');
    await create().click(); await dialog().getByRole('alert').filter({ hasText: 'All rules requires' }).waitFor();
    await dialog().getByLabel('Operator').selectOption('equals');
    for (const expiry of ['7', '30', '90', '365', '0']) { await dialog().getByLabel('Expires').selectOption(expiry); assert.equal(await dialog().getByLabel('Expires').inputValue(), expiry); }
    await dialog().getByLabel('Expires').selectOption('7');
    for (let index = 1; index < 10; index++) await dialog().getByRole('button', { name: 'Add condition' }).click();
    assert.equal(await dialog().getByRole('button', { name: 'Add condition' }).isDisabled(), true);
    for (let index = 10; index > 1; index--) await dialog().getByRole('button', { name: `Remove condition ${index}`, exact: true }).click();
    await dialog().getByLabel('Enable condition 1', { exact: true }).uncheck();
    await create().click(); await dialog().getByRole('alert').filter({ hasText: 'Enable at least' }).waitFor();
    await dialog().getByLabel('Enable condition 1', { exact: true }).check();
    await create().focus(); await page.keyboard.press('Tab');
    assert.equal(await dialog().evaluate(element => element.contains(document.activeElement)), true);
    for (const width of [320, 390, 768, 1280]) { await page.setViewportSize({ width, height: 1000 }); await noOverflow(); await dialog().locator('form').evaluate(form => { form.parentElement.scrollTop = 0; }); await page.screenshot({ path: join(artifacts, `exception-${width}.png`) }); }
    await page.evaluate(() => document.documentElement.classList.add('dark')); await page.waitForTimeout(350); await noOverflow(); await page.screenshot({ path: join(artifacts, 'exception-dark.png') });
    await page.evaluate(() => document.documentElement.classList.remove('dark'));
    await control({ createFailures: 1 });
    await create().click(); await dialog().getByRole('alert').filter({ hasText: 'Fixture createFailures failure' }).waitFor();
    assert.equal(await dialog().getByLabel('Name', { exact: true }).inputValue(), 'Approved backup');
    await control({ createDelay: 600 });
    await create().click();
    await dialog().locator('form').evaluate(form => { form.requestSubmit(); form.requestSubmit(); });
    assert.equal(await dialog().getByRole('button', { name: 'Close modal' }).isDisabled(), true);
    await page.keyboard.press('Escape'); assert.equal(await dialog().count(), 1);
    await page.getByRole('article', { name: 'Approved backup' }).waitFor();
    let current = await saved(); assert.equal(current.saved.length, 1); assert.equal(current.saved[0].agent_id, agents[23].id); assert.equal(current.saved[0].rule_id, ''); assert.equal(current.saved[0].conditions.length, 1);
    const article = () => page.getByRole('article', { name: 'Approved backup' });
    await control({ toggleFailures: 1 }); await article().getByRole('button', { name: 'Disable exception Approved backup' }).click();
    await page.getByRole('alert').filter({ hasText: 'Fixture toggleFailures failure' }).waitFor();
    assert.equal(await article().getByRole('button', { name: 'Disable exception Approved backup' }).getAttribute('aria-pressed'), 'true');
    await article().getByRole('button', { name: 'Disable exception Approved backup' }).click();
    await article().getByRole('button', { name: 'Enable exception Approved backup' }).waitFor();
    await page.getByLabel('Filter by state').selectOption('active'); await page.getByText('No matching exceptions').waitFor();
    await page.getByLabel('Filter by state').selectOption('disabled'); await article().waitFor();
    await page.getByLabel('Search exceptions').fill('does-not-exist'); await page.getByText('No matching exceptions').waitFor();
    await page.getByLabel('Search exceptions').fill('Backup'); await article().waitFor();
    await article().getByRole('button', { name: 'Enable exception Approved backup' }).click(); await page.getByText('No matching exceptions').waitFor();
    await page.getByLabel('Filter by state').selectOption('all'); await article().waitFor();
    await control({ listFailures: 1 }); await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Fixture listFailures failure' }).waitFor(); assert.equal(await article().count(), 1);
    await page.getByRole('button', { name: 'Refresh', exact: true }).click(); await page.getByRole('alert').waitFor({ state: 'hidden' });
    await article().getByRole('button', { name: 'Delete exception Approved backup' }).click(); await dialog().getByRole('button', { name: 'Cancel' }).click(); assert.equal(await article().count(), 1);
    await control({ deleteFailures: 1 }); await article().getByRole('button', { name: 'Delete exception Approved backup' }).click(); await dialog().getByRole('button', { name: 'Delete exception', exact: true }).click();
    await dialog().getByRole('alert').filter({ hasText: 'Fixture deleteFailures failure' }).waitFor();
    await dialog().getByRole('button', { name: 'Delete exception', exact: true }).click(); await page.getByText('No detection exceptions yet').waitFor();
    await page.getByRole('button', { name: 'New exception', exact: true }).click(); assert.equal(await dialog().getByLabel('Name', { exact: true }).inputValue(), ''); await page.keyboard.press('Escape'); await dialog().waitFor({ state: 'hidden' });
    await page.getByRole('button', { name: 'New exception', exact: true }).click(); await dialog().getByRole('button', { name: 'Close modal' }).click(); await dialog().waitFor({ state: 'hidden' });
    await page.getByRole('button', { name: 'New exception', exact: true }).click(); await dialog().getByRole('button', { name: 'Cancel' }).click(); await dialog().waitFor({ state: 'hidden' });
    await page.goto(`${origin}/verify?alert=1`); await page.getByRole('button', { name: 'Open alert exception' }).click();
    assert.equal(await dialog().getByLabel('Endpoint scope').inputValue(), 'host'); assert.equal(await dialog().getByLabel('Endpoint', { exact: true }).inputValue(), agents[0].id);
    await dialog().getByLabel('Sigma rule ID').selectOption('secondary-rule');
    await dialog().getByLabel('Justification (audited)').fill('Approved change 456');
    await control({ statusFailures: 1, createDelay: 0 });
    await create().click(); await dialog().getByRole('alert').filter({ hasText: 'follow-up update failed' }).waitFor();
    current = await saved(); const totalCreated = current.saved.length; assert.equal(current.saved.at(-1).rule_id, 'secondary-rule'); assert.equal(current.saved.at(-1).rule_title, '');
    assert.equal(await dialog().getByLabel('Name', { exact: true }).isDisabled(), true);
    await dialog().getByRole('button', { name: 'Retry follow-up update' }).click(); await dialog().waitFor({ state: 'hidden' }); assert.equal((await saved()).saved.length, totalCreated);
    await page.getByRole('button', { name: 'Open alert exception' }).click(); await dialog().getByLabel('Justification (audited)').fill('Approved change 789');
    await dialog().getByLabel('Also mark this alert as a false positive').uncheck(); await dialog().getByLabel('Endpoint scope').selectOption('all');
    const statusCount = (await saved()).mutations.filter(row => row.kind === 'alert-status').length;
    await create().click(); await dialog().waitFor({ state: 'hidden' }); current = await saved(); assert.equal(current.mutations.filter(row => row.kind === 'alert-status').length, statusCount); assert.equal(current.saved.at(-1).agent_id, undefined);
    await page.goto(`${origin}/verify?role=viewer`); await page.getByText('Read-only access.', { exact: false }).waitFor(); assert.equal(await page.getByRole('button', { name: 'New exception', exact: true }).count(), 0);
    await page.setViewportSize({ width: 390, height: 1000 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await page.screenshot({ path: join(artifacts, 'exceptions-page-mobile.png'), fullPage: true });
    current = await saved();
    await control({ items: [...current.items, { ...current.items[0], id: 'expired-fixture', name: 'Expired backup', expires_at: '2020-01-01T00:00:00Z', hit_count: 3 }] });
    await page.goto(`${origin}/verify`); await page.getByRole('article', { name: 'Expired backup', exact: true }).waitFor();
    await page.getByLabel('Filter by state').selectOption('expired');
    assert.equal(await page.getByRole('article').count(), 1);
    assert.equal(await page.getByRole('article', { name: 'Expired backup' }).getByRole('button', { name: /Enable|Disable/ }).count(), 0);
    await page.goto(`${origin}/verify?alert=1&callback=1`); await page.getByRole('button', { name: 'Open alert exception' }).click();
    await dialog().getByLabel('Justification (audited)').fill('Callback update test'); await control({ statusFailures: 1 });
    await create().click(); await dialog().getByRole('alert').filter({ hasText: 'follow-up update failed' }).waitFor();
    const callbackCreated = (await saved()).saved.length;
    await dialog().getByRole('button', { name: 'Retry follow-up update' }).click(); await dialog().waitFor({ state: 'hidden' }); assert.equal((await saved()).saved.length, callbackCreated);
    await page.goto(`${origin}/verify?alert=1&nested=1`); await page.getByRole('button', { name: 'Open alert exception' }).click();
    assert.equal(await dialog().count(), 2);
    assert.equal(await page.getByRole('dialog', { name: 'Create detection exception', exact: true }).count(), 1);
    await page.keyboard.press('Escape');
    assert.equal(await dialog().count(), 1);
    assert.equal(await page.evaluate(() => document.body.style.overflow), 'hidden');
    // Exercise the actual dashboard/alerts hooks and actual stream lifecycle with an in-memory socket.
    // Deliberately deliver close asynchronously so the old reconnect-after-unmount bug is observable.
    await page.addInitScript(() => {
        localStorage.setItem('auth_token', 'fixture-token');
        window.__testSockets = []; window.__allowSocketOpen = true;
        const NativeSocket = window.WebSocket;
        class TestSocket {
            static OPEN = 1; static CONNECTING = 0; static CLOSED = 3;
            readyState = 0;
            constructor(url, protocols) { if (!url.includes('/sigma/alerts/stream')) return new NativeSocket(url, protocols); window.__testSockets.push(this); queueMicrotask(() => { if (this.readyState === 0 && window.__allowSocketOpen) { this.readyState = 1; this.onopen?.({}); } }); }
            send() {}
            close() { this.readyState = 3; queueMicrotask(() => this.onclose?.({ code: 1000, reason: 'fixture close', wasClean: true })); }
        }
        window.WebSocket = TestSocket;
    });
    await control({ perfRequests: { alerts: 0, stats: 0 } });
    await page.goto(`${origin}/verify?perf=1`); await page.getByTestId('perf-dashboard').waitFor();
    await page.waitForFunction(() => window.__testSockets.some(socket => socket.readyState === 1));
    await page.waitForTimeout(500);
    const initialRequests = (await saved()).perfRequests;
    await page.waitForTimeout(3200);
    assert.deepEqual((await saved()).perfRequests, initialRequests, 'connected idle pages must not poll every second');
    await page.evaluate(async () => {
        for (let index = 0; index < 30; index++) {
            window.__testSockets.at(-1).onmessage?.({ data: JSON.stringify({ type: 'alert', data: { id: `perf-${index}`, timestamp: new Date().toISOString(), severity: 'medium' } }) });
            await new Promise(resolve => setTimeout(resolve, 50));
        }
    });
    await page.waitForTimeout(1200);
    const afterBurst = (await saved()).perfRequests;
    assert.ok(afterBurst.alerts - initialRequests.alerts >= 1 && afterBurst.alerts - initialRequests.alerts <= 3);
    assert.ok(Number(await page.getByTestId('perf-dashboard').textContent()) >= 20, 'batched stream alerts must reach the UI');
    for (let index = 0; index < 10; index++) {
        const mode = index % 2 === 0 ? 'alerts' : 'dashboard';
        await page.getByRole('button', { name: `Show ${mode}` }).click();
        await page.getByTestId(`perf-${mode}`).waitFor();
    }
    await page.getByRole('button', { name: 'Leave pages' }).click();
    const socketCount = await page.evaluate(() => window.__testSockets.length);
    await page.waitForTimeout(1400);
    assert.equal(await page.evaluate(() => window.__testSockets.length), socketCount, 'disposed sockets must not reconnect after navigation');
    assert.equal(await page.evaluate(() => window.__testSockets.filter(socket => socket.readyState !== 3).length), 0);
    await page.getByRole('button', { name: 'Show alerts' }).click(); await page.getByTestId('perf-alerts').waitFor();
    await page.waitForFunction(() => window.__testSockets.at(-1).readyState === 1);
    await page.getByRole('button', { name: 'Open selected alert' }).click(); await dialog().waitFor();
    await page.keyboard.press('Escape'); await dialog().waitFor({ state: 'hidden' });
    await page.getByText('Alert still selected', { exact: true }).waitFor();
    const beforeOffline = (await saved()).perfRequests.alerts;
    await page.evaluate(() => { window.__allowSocketOpen = false; const socket = window.__testSockets.at(-1); socket.readyState = 3; socket.onclose?.({ code: 1006, reason: 'fixture disconnect', wasClean: false }); });
    await page.waitForTimeout(5500);
    assert.ok((await saved()).perfRequests.alerts > beforeOffline, 'HTTP fallback must continue during a stream outage');
    await page.getByRole('button', { name: 'Leave pages' }).click();
    assert.equal(await page.evaluate(() => window.__testSockets.filter(socket => socket.readyState !== 3).length), 0);
    assert.deepEqual(errors, []);
    console.log(`PERF: no extra alert/stat requests in 3.2s connected idle; 30 streamed events caused ${afterBurst.alerts - initialRequests.alerts} list refreshes; 10 navigations left zero live sockets; disconnected HTTP fallback verified.`);
    console.log(`PASS: real UI controls, all fields/operators/expiries, endpoint search/pagination/races, validation, CRUD failures/retries, busy locking, partial success, reset, RBAC, light/dark and four responsive widths. Screenshots: ${artifacts}`);
} finally {
    await browser?.close();
    await server.close();
}
