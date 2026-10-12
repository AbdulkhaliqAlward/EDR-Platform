// Actual production pages, isolated HTTP fixtures. No endpoint commands execute.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { chromium } from 'playwright';

process.env.VITE_CONNECTION_MANAGER_URL = '/fixture';
process.env.VITE_API_URL = '/fixture';
const root = fileURLToPath(new URL('../', import.meta.url));
const errors = [], requests = [];
let failures = 0;
const stamp = new Date(Date.now() - 3600000).toISOString();
const uuid = n => `00000000-0000-4000-8000-${String(n + 1).padStart(12, '0')}`;
const plugin = {
    name: 'pagination-production-pages',
    resolveId(id) { if (id === '/pagination-pages.js') return '\0pagination-pages'; },
    load(id) {
        if (id !== '\0pagination-pages') return;
        return `import React from 'react';import {createRoot} from 'react-dom/client';import {BrowserRouter} from 'react-router-dom';import {QueryClient,QueryClientProvider} from '@tanstack/react-query';import {ToastProvider} from '/src/components/Toast.tsx';import Endpoints from '/src/pages/Endpoints.tsx';import Rules from '/src/pages/Rules.tsx';import Events from '/src/pages/Events.tsx';import ActionCenter from '/src/pages/ActionCenter.tsx';import SecurityEvents from '/src/pages/SecurityEvents.tsx';import '/src/index.css';
        localStorage.setItem('user',JSON.stringify({role:new URLSearchParams(location.search).get('screen')==='security'?'security':'viewer'}));
        const Page={agents:Endpoints,rules:Rules,events:Events,commands:ActionCenter,security:SecurityEvents}[new URLSearchParams(location.search).get('screen')];
        const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
        createRoot(document.getElementById('root')).render(React.createElement(BrowserRouter,null,React.createElement(QueryClientProvider,{client},React.createElement(ToastProvider,null,React.createElement(Page)))));`;
    },
    configureServer(server) {
        server.middlewares.use(async (req,res,next) => {
            const url = new URL(req.url, 'http://fixture');
            const send = (value, status=200) => { res.statusCode=status;res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value)); };
            if (url.pathname === '/verify') { res.setHeader('Content-Type','text/html');res.end(await server.transformIndexHtml('/verify','<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/pagination-pages.js"></script></body></html>'));return; }
            if (!url.pathname.startsWith('/fixture/')) return next();
            const parts=[];for await(const part of req) parts.push(part);
            const body=parts.length?JSON.parse(Buffer.concat(parts).toString()):{};
            const params = req.method==='POST'?body:Object.fromEntries(url.searchParams);
            requests.push({path:url.pathname,params});
            if (/\/events\/[0-9a-f-]+$/.test(url.pathname)) { send({data:{id:url.pathname.split('/').at(-1),agent_id:uuid(0),event_type:'process',timestamp:stamp,raw:{proof:'complete-detail-evidence'}}});return; }
            if (/\/commands\/[0-9a-f-]+$/.test(url.pathname)) {send({data:{id:url.pathname.split('/').at(-1),agent_id:uuid(0),command_type:'scan_file',status:'completed',issued_at:stamp,parameters:{proof:'complete-detail-evidence'}}});return;}
            if (/\/security\/events\/[0-9a-f-]+$/.test(url.pathname)) {send({data:{id:url.pathname.split('/').at(-1),event_type:'login_failed',severity:'warning',created_at:stamp,description:'complete-detail-evidence',metadata:{proof:'full'}}});return;}
            const kind = url.pathname.endsWith('/commands')?'commands':url.pathname.endsWith('/security/events')?'security':url.pathname.endsWith('/events/search')?'events':url.pathname.endsWith('/sigma/rules')?'rules':url.pathname.endsWith('/agents')?'agents':null;
            if (!kind) {send({data:[],total:0,enabled:0,disabled:0,by_rule:{},by_severity:{}});return;}
            const search = (kind==='commands'?(params.agent_id===uuid(98)?'empty':params.agent_id===uuid(99)?'failure':''):kind==='security'?(params.severity==='critical'?'empty':params.severity==='info'?'failure':''):params.search) || body.filters?.find(f=>f.field==='event_type')?.value || '';
            if(search!=='failure') failures=0;
            if(search==='failure' && failures++<2) {send({error:{message:'fixture unavailable'}},503);return;}
            const limit=Number(params.limit||25),start=Number(params.cursor||0),total=search==='empty'?0:63;
            const data=Array.from({length:Math.max(0,Math.min(limit,total-start))},(_,i)=>{
                const n=start+i;
                return kind==='commands'?{id:uuid(n),agent_id:uuid(0),agent_hostname:`Fixture command ${n}`,command_type:'scan_file',status:'completed',issued_at:stamp,parameters:{}}:
                kind==='security'?{id:uuid(n),event_type:'login_failed',severity:'warning',description:`Fixture security ${n}`,created_at:stamp}:kind==='agents'?{id:uuid(n),hostname:`Fixture agent ${n}`,status:'online',os_type:'windows',health_score:90,last_seen:stamp,ip_addresses:[],tags:[],metadata:{},agent_version:'1.0'}:
                kind==='rules'?{id:uuid(n),title:`Fixture rule ${n}`,severity:'high',enabled:true,status:'stable',tags:[],mitre_tactics:[],mitre_techniques:[],created_at:stamp}:
                {id:uuid(n),agent_id:uuid(0),event_type:'process',severity:'high',timestamp:stamp,created_at:stamp,summary:`Fixture event ${n}`};
            });
            send({data,page_info:{limit,has_next:start+limit<total,has_prev:start>0,next_cursor:start+limit<total?String(start+limit):null,prev_cursor:start>0?String(Math.max(0,start-limit)):null},total:{value:total,capped:false},pagination:{total,limit,offset:start,has_more:start+limit<total}});
        });
    },
};
const server=await createServer({root,server:{host:'127.0.0.1',port:0},plugins:[plugin]});
let browser;
try {
    await server.listen();const origin=`http://127.0.0.1:${server.httpServer.address().port}`;
    browser=await chromium.launch({channel:process.platform==='win32'?'chrome':undefined,headless:true});
    for(const screen of ['agents','rules','events','commands','security']) for(const width of [390,1280]) for(const dark of [false,true]) {
        const page=await browser.newPage({viewport:{width,height:1000}});
        page.setDefaultNavigationTimeout(60000);page.setDefaultTimeout(15000);
        page.on('pageerror',error=>errors.push(`${screen}: ${error.message}`));
        await page.route('**/*',route=>route.request().url().startsWith(origin)?route.continue():route.abort());
        await page.goto(`${origin}/verify?screen=${screen}`,{waitUntil:'domcontentloaded'});
        const label={agents:'Fixture agent',rules:'Fixture rule',events:'Fixture event',commands:'Fixture command',security:'Fixture security'}[screen];
        const prefix=screen==='commands'?'commands.':'';
        await page.getByText(`${label} 0`,{exact:true}).first().waitFor();
        await page.evaluate(d=>document.documentElement.classList.toggle('dark',d),dark);
        const nav=page.getByRole('navigation',{name:'Pagination'});
        await nav.getByRole('button',{name:'Next page'}).click();
        await page.getByText(`${label} 25`,{exact:true}).first().waitFor();
        assert.equal(new URL(page.url()).searchParams.get(prefix+'cursor'),'25');
        await page.reload();await page.getByText(`${label} 25`,{exact:true}).first().waitFor();
        await nav.getByRole('button',{name:'Previous page'}).click();
        await page.getByText(`${label} 0`,{exact:true}).first().waitFor();
        await nav.getByLabel('Rows per page').selectOption('50');
        await page.getByText(`${label} 49`,{exact:true}).first().waitFor();
        await nav.getByRole('button',{name:'Next page'}).click();
        await page.getByText(`${label} 50`,{exact:true}).first().waitFor();
        if(screen==='events' || screen==='security') {
            await page.getByText(`${label} 50`,{exact:true}).click();
            await page.getByText(/complete-detail-evidence/).waitFor();
            await page.keyboard.press('Escape');
        }
        if(screen==='commands') {await page.getByTitle('Expand Details').first().click();await page.getByText(/complete-detail-evidence/).waitFor();await page.getByTitle('Collapse Details').first().click();}
        const input=screen==='security'?page.locator('select').nth(1):page.getByPlaceholder(screen==='agents'?'Search for devices':screen==='rules'?'Title, ID, or category…':screen==='commands'?'Filter by Agent ID...':'e.g. network, process, file');
        const change=async value=>screen==='security'?input.selectOption(value==='empty'?'critical':value==='failure'?'info':''):input.fill(screen==='commands'?(value==='empty'?uuid(98):value==='failure'?uuid(99):''):value);
        await change('empty');
        await page.waitForFunction(prefix=>new URLSearchParams(location.search).get(prefix+'page')==='1',prefix);
        await page.waitForFunction(()=>!document.body.textContent.includes('Fixture '));
        assert.equal(new URL(page.url()).searchParams.has(prefix+'cursor'),false);
        assert.equal(await nav.getByRole('button',{name:'Next page'}).isDisabled(),true);
        await change('failure');await page.getByRole('button',{name:/Retry/i}).click();
        await page.getByText(`${label} 0`,{exact:true}).first().waitFor();
        await change('');await page.getByText(`${label} 0`,{exact:true}).first().waitFor();
        assert.equal(await nav.evaluate(e=>e.scrollWidth<=e.clientWidth+1),true,`${screen} ${width} dark=${dark}`);
        const header = page.locator('[data-page-header]');
        assert.equal(await header.count(), 1, screen);
        assert.ok(await header.evaluate(e => e.scrollWidth <= e.clientWidth + 1), `header ${screen} ${width} dark=${dark}`);
        assert.ok(await header.getByRole('heading', { level: 1 }).isVisible());
        await page.close();
    }
    assert.deepEqual(errors,[]);
    assert.ok(requests.some(r=>r.path.includes('/events/') && r.path!=='/fixture/api/v1/events/search'));
    console.log('PASS actual Endpoints, Rules, Events, ActionCenter, SecurityEvents pages: 390/1280 light/dark, next/previous, size/filter reset, URL reload, full event detail, empty/error/recovery, pagination width');
} catch(error) {
    console.error('Page errors:',errors);
    for(const context of browser?.contexts() || []) for(const page of context.pages()) console.error('Fixture page:',await page.locator('body').innerText());
    throw error;
} finally {await browser?.close();await server.close();}
