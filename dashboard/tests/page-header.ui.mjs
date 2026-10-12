import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from 'vite';
import ts from 'typescript';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('../', import.meta.url));
const errors = [];
const plugin = {
    name: 'page-header-fixture',
    resolveId(id) { if (id === '/header-fixture.js') return '\0header-fixture'; },
    load(id) {
        if (id !== '\0header-fixture') return;
        return ts.transpileModule(`import React,{useState} from 'react';import {createRoot} from 'react-dom/client';
        import PageHeader from '/src/components/PageHeader.tsx';import {BarChart3} from 'lucide-react';import '/src/index.css';
        function Fixture(){const [count,setCount]=useState(0),[open,setOpen]=useState(false),[range,setRange]=useState('24h');
        const button={className:'rounded-lg border border-slate-300 dark:border-slate-600 px-3 py-2 text-slate-900 dark:text-white'};
        return <main className="p-2 sm:p-6 space-y-6 bg-slate-50 dark:bg-slate-950 min-h-screen">
          <PageHeader eyebrow="Dashboards" title="Security Posture" icon={BarChart3}/>
          <PageHeader eyebrow="Managed Detection & Response" title="Incident Queue" icon={BarChart3} actions={<>
            <select aria-label="Range" value={range} onChange={e=>setRange(e.target.value)} className="rounded-lg p-2 border dark:bg-slate-800 dark:text-white"><option value="24h">24 hours</option><option value="7d">7 days</option></select>
            <button {...button} onClick={()=>setCount(n=>n+1)}>Refresh</button><button {...button} disabled>Unavailable action</button>
            <div className="relative"><button {...button} onClick={()=>setOpen(v=>!v)}>Export</button>{open&&<div role="menu" className="absolute right-0 top-full z-50 min-w-40 bg-white dark:bg-slate-800 border rounded-lg p-2"><button {...button} role="menuitem" onClick={()=>{setCount(n=>n+10);setOpen(false)}}>Download CSV</button></div>}</div>
          </>} />
          <output aria-label="Action result">{count}:{range}</output>
        </main>}
        createRoot(document.getElementById('root')).render(<Fixture/>);`, { compilerOptions: { jsx: ts.JsxEmit.React, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
    },
    configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
            if (req.url !== '/header-check') return next();
            res.setHeader('Content-Type', 'text/html');
            res.end(await server.transformIndexHtml('/header-check', '<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/header-fixture.js"></script></body></html>'));
        });
    },
};
const server = await createServer({ root, server: { host: '127.0.0.1', port: 0 }, plugins: [plugin] });
let browser;
try {
    await server.listen();
    const origin = `http://127.0.0.1:${server.httpServer.address().port}`;
    browser = await chromium.launch({ channel: process.platform === 'win32' ? 'chrome' : undefined, headless: true });
    for (const width of [390, 1280]) for (const dark of [false, true]) {
        const page = await browser.newPage({ viewport: { width, height: 1000 } });
        page.on('pageerror', error => errors.push(error.message));
        await page.route('**/*', route => route.request().url().startsWith(origin) ? route.continue() : route.abort());
        await page.goto(`${origin}/header-check`, { waitUntil: 'networkidle', timeout: 60000 });
        await page.evaluate(dark => document.documentElement.classList.toggle('dark', dark), dark);
        await page.getByRole('heading', { name: 'Incident Queue' }).waitFor({ timeout: 15000 });
        const headers = page.locator('[data-page-header]');
        assert.equal(await headers.count(), 2);
        assert.deepEqual(await headers.evaluateAll(nodes => nodes.map(n => n.className)), [await headers.first().getAttribute('class'), await headers.first().getAttribute('class')]);
        for (const header of await headers.all()) assert.ok(await header.evaluate(n => n.scrollWidth <= n.clientWidth + 1), `Header overflow at ${width}, dark=${dark}`);
        const actions = page.locator('[data-page-header-actions]');
        assert.equal(await actions.getByRole('button').count(), 3);
        assert.equal(await actions.getByRole('button', { name: 'Unavailable action' }).isDisabled(), true);
        await actions.getByRole('button', { name: 'Refresh', exact: true }).click();
        await actions.getByRole('combobox', { name: 'Range' }).selectOption('7d');
        assert.equal(await page.getByLabel('Action result').innerText(), '1:7d');
        await actions.getByRole('button', { name: 'Export', exact: true }).click();
        await page.getByRole('menuitem', { name: 'Download CSV' }).click();
        assert.equal(await page.getByLabel('Action result').innerText(), '11:7d');
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        await page.screenshot({ path: path.join(tmpdir(), `mitras-page-header-${width}-${dark ? 'dark' : 'light'}.png`), fullPage: true });
        await page.close();
    }
    assert.deepEqual(errors, []);
    console.log('PASS shared page header: matching cards, 390/1280 light/dark, contained actions, disabled state, select, refresh, export menu, no overflow.');
} finally {
    await browser?.close();
    await server.close();
}
