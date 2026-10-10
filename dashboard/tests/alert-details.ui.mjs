// Isolated rendering of the real alert panel; never contacts an EDR service.
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { chromium } from 'playwright';

process.env.VITE_CONNECTION_MANAGER_URL = '/fixture';
process.env.VITE_API_URL = '/fixture';
const artifacts = join(tmpdir(), 'mitras-alert-details');
await mkdir(artifacts, { recursive: true });
const target = 'C:\\Program Files\\WindowsPowerShell\\Modules\\Microsoft.PowerShell.Commands.Utility\\Microsoft.PowerShell.Commands.Utility.dll';
const alert = {
    id: 'fixture-alert', rule_title: 'PowerShell Module File Created By Non-PowerShell Process', rule_id: 'fixture-rule',
    agent_id: 'fixture-agent', severity: 'medium', status: 'open', category: 'file_event', event_count: 8,
    confidence: 0.65, timestamp: '2026-10-10T13:43:00Z', created_at: '2026-10-10T13:43:00Z', updated_at: '2026-10-10T13:45:00Z',
    event_ids: ['fixture-event'], matched_fields: { TargetFilename: target },
    context_data: { event_type: 'file', event_id: 'fixture-event', _kafka_partition: 0, _kafka_offset: 0,
        data: { name: 'Microsoft.PowerShell.Commands.Utility.dll', path: target, pid: 35592, process_name: 'unknown', process_path: '', is_elevated: false, action: 'created' } },
    context_snapshot: { process_name: 'Microsoft.PowerShell.Commands.Utility.dll', lineage_suspicion: 'none', scored_at: '2026-10-10T13:45:00Z', missing_context_fields: ['process_path'] },
};
const plugin = {
    name: 'alert-details-fixture',
    resolveId(id) { if (id === 'virtual:alert-details') return id; },
    load(id) {
        if (id !== 'virtual:alert-details') return;
        return `import React from 'react';import {createRoot} from 'react-dom/client';import {MemoryRouter} from 'react-router-dom';import {QueryClient,QueryClientProvider} from '@tanstack/react-query';import {AlertDetailPanel} from '/src/components/alerts/AlertDetailPanel.tsx';import '/src/index.css';
        localStorage.setItem('user',JSON.stringify({role:'viewer'}));const alert=${JSON.stringify(alert)};
        if(location.search.includes('known'))Object.assign(alert.context_data.data,{process_name:'powershell.exe',process_path:'C:\\\\Windows\\\\powershell.exe',command_line:'Get-CimInstance Win32_LogicalDisk'});
        const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
        createRoot(document.getElementById('root')).render(React.createElement(QueryClientProvider,{client},React.createElement(MemoryRouter,null,React.createElement(AlertDetailPanel,{alert,isOpen:true,onClose:()=>{},onStatusChange:()=>{},inlineMode:true}))));`;
    },
    configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
            if (req.url.startsWith('/verify')) {
                res.setHeader('Content-Type', 'text/html');
                res.end(await server.transformIndexHtml('/verify', '<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><main id="root" style="max-width:680px;margin:auto"></main><script type="module" src="/@id/virtual:alert-details"></script></body></html>'));
            } else if (req.url.startsWith('/fixture/')) {
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(req.url.includes('settings') ? { enabled: false } : { data: [], executions: [] }));
            } else next();
        });
    },
};
const server = await createServer({ root: fileURLToPath(new URL('../', import.meta.url)), plugins: [plugin], server: { host: '127.0.0.1', port: 0 } });
let browser;
try {
    await server.listen();
    const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
    browser = await chromium.launch({ channel: process.platform === 'win32' ? 'chrome' : undefined, headless: true });
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => route.request().url().startsWith(origin) ? route.continue() : route.abort());
    const value = label => page.locator('dt').filter({ hasText: new RegExp(`^${label}$`) }).locator('xpath=following-sibling::dd[1]');
    for (const width of [390, 1280]) for (const dark of [false, true]) {
        await page.setViewportSize({ width, height: 1000 });
        await page.goto(`${origin}/verify`);
        await page.evaluate(dark => document.documentElement.classList.toggle('dark', dark), dark);
        await page.getByText('Process image (Image)', { exact: true }).waitFor();
        assert.equal(await value('Process name').innerText(), 'Not available');
        assert.equal(await value('Target path \\(TargetFilename\\)').innerText(), target);
        await page.getByRole('button', { name: 'Events', exact: true }).click();
        assert.equal(await value('Process name').innerText(), 'Not available');
        assert.equal(await page.getByText('false', { exact: true }).count(), 1);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'event panel overflows');
        await page.screenshot({ path: join(artifacts, `events-${width}-${dark ? 'dark' : 'light'}.png`), fullPage: true, animations: 'disabled' });
        await page.getByRole('button', { name: 'Show full JSON' }).click();
        await page.getByRole('button', { name: 'Hide full JSON' }).waitFor();
        await page.getByRole('button', { name: /Context/ }).click();
        await page.getByText('Lineage unavailable', { exact: true }).waitFor();
        await page.getByText('Burst data unavailable.', { exact: true }).waitFor();
        assert.equal(await page.getByText('Microsoft.PowerShell.Commands.Utility.dll', { exact: true }).count(), 0);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'context panel overflows');
    }
    await page.goto(`${origin}/verify?known`);
    await page.getByText('Process name', { exact: true }).waitFor();
    assert.equal(await value('Process name').innerText(), 'powershell.exe');
    assert.equal(await value('Command line').innerText(), 'Get-CimInstance Win32_LogicalDisk');
    assert.deepEqual(errors, []);
    console.log(`PASS: real alert panel, Summary/Events/Context, JSON toggle, missing/known process, 390/1280px light/dark. Screenshots: ${artifacts}`);
} finally {
    await browser?.close();
    await server.close();
}
