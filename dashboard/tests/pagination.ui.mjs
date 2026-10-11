// Real shared hook/components against an isolated, delayed HTTP fixture.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import { chromium } from 'playwright';

const root = fileURLToPath(new URL('..', import.meta.url));
const errors = [];
const plugin = {
    name: 'pagination-fixture',
    resolveId(id) { if (id === '/fixture.js') return '\0pagination-fixture'; },
    load(id) {
        if (id !== '\0pagination-fixture') return;
        return `import React,{useState} from 'react';import {createRoot} from 'react-dom/client';
        import {BrowserRouter} from 'react-router-dom';import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
        import {usePaginatedQuery} from '/src/hooks/usePaginatedQuery.ts';import {PaginationControls} from '/src/components/PaginationControls.tsx';import '/src/index.css';
        function App(){const q=usePaginatedQuery({name:'fixture',defaults:{order:'desc'},fetchPage:async(params,signal)=>{const r=await fetch('/records?'+new URLSearchParams(params),{signal});if(!r.ok)throw Error('fixture');return r.json();}});
        const [detail,setDetail]=useState(null);return <main className="p-4 bg-white dark:bg-slate-900 dark:text-white min-h-screen">
          <label>Search<input aria-label="Search" value={q.params.search||''} onChange={e=>q.setFilters({search:e.target.value})}/></label>
          {q.isError?<div role="alert">Could not load records<button onClick={()=>q.refetch()}>Retry</button></div>:null}
          {!q.busy&&!q.rows.length?<p>No results for these filters</p>:null}
          <ul>{q.rows.map(row=><li key={row.id}><button onClick={async()=>setDetail(await(await fetch('/record/'+row.id)).json())}>{row.title}</button></li>)}</ul>
          <PaginationControls info={q.info} page={q.page} count={q.rows.length} busy={q.busy} onNext={q.next} onPrevious={q.previous} onSize={q.setPageSize}/>
          {detail?<div role="dialog" aria-label="Details"><pre>{JSON.stringify(detail)}</pre><button onClick={()=>setDetail(null)}>Close details</button></div>:null}
        </main>};const client=new QueryClient();createRoot(document.getElementById('root')).render(<BrowserRouter><QueryClientProvider client={client}><App/></QueryClientProvider></BrowserRouter>);`;
    },
    configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
            const url = new URL(req.url, 'http://fixture');
            const send = (data, code=200) => {res.statusCode=code;res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));};
            if (url.pathname === '/verify') {res.setHeader('Content-Type','text/html');res.end(await server.transformIndexHtml('/verify','<html><head><meta name="viewport" content="width=device-width,initial-scale=1"></head><body><div id="root"></div><script type="module" src="/fixture.js"></script></body></html>'));return;}
            if (url.pathname.startsWith('/record/')) {send({id:url.pathname.split('/').at(-1),raw:{full_payload:'detail-only evidence'}});return;}
            if (url.pathname !== '/records') return next();
            const search = url.searchParams.get('search') || '';
            if(search==='slow') await new Promise(resolve=>setTimeout(resolve,700));
            if(search==='fail') {send({error:'fixture'},503);return;}
            const limit=Number(url.searchParams.get('limit')||25), start=Number(url.searchParams.get('cursor')||0), total=search==='empty'?0:83;
            const data=Array.from({length:Math.max(0,Math.min(limit,total-start))},(_,i)=>({id:String(start+i),title:(search||'Record')+' '+(start+i)}));
            send({data,page_info:{limit,has_next:start+limit<total,has_prev:start>0,next_cursor:start+limit<total?String(start+limit):null,prev_cursor:start>0?String(Math.max(0,start-limit)):null}});
        });
    },
    // JSX in the virtual module is transformed explicitly below.
    async transform(code,id) { if(id==='\0pagination-fixture') {const {transformWithEsbuild}=await import('vite');return transformWithEsbuild(code,id,{loader:'jsx',jsx:'automatic'});} },
};
const server=await createServer({root,server:{host:'127.0.0.1',port:0},plugins:[plugin]});
let browser;
try {
    await server.listen();const origin=`http://127.0.0.1:${server.httpServer.address().port}`;
    browser=await chromium.launch({channel:process.platform==='win32'?'chrome':undefined,headless:true});
    for(const width of [390,1280]) for(const dark of [false,true]) {
        const page=await browser.newPage({viewport:{width,height:900}});page.on('pageerror',error=>errors.push(error.message));await page.route('**/*',route=>route.request().url().startsWith(origin)?route.continue():route.abort());
        await page.goto(origin+'/verify',{waitUntil:'domcontentloaded'});await page.getByRole('button',{name:'Record 0',exact:true}).waitFor();
        await page.evaluate(d=>document.documentElement.classList.toggle('dark',d),dark);
        const next=page.getByRole('button',{name:'Next page'}), prev=page.getByRole('button',{name:'Previous page'});
        assert.equal(await prev.isDisabled(),true);
        await next.click();await page.getByRole('button',{name:'Record 25',exact:true}).waitFor();assert.match(page.url(),/cursor=25/);
        await page.getByRole('button',{name:'Record 25',exact:true}).click();await page.getByRole('dialog').getByText(/detail-only evidence/).waitFor();await page.getByRole('button',{name:'Close details'}).click();
        await prev.click();await page.getByRole('button',{name:'Record 0',exact:true}).waitFor();
        await next.click();await page.getByRole('button',{name:'Record 25',exact:true}).waitFor();
        await page.getByLabel('Rows per page').selectOption('50');await page.getByRole('button',{name:'Record 49',exact:true}).waitFor();assert.equal(new URL(page.url()).searchParams.has('cursor'),false);
        await next.click();await page.getByRole('button',{name:'Record 50',exact:true}).waitFor();
        await page.getByLabel('Search',{exact:true}).fill('slow');await page.getByLabel('Search',{exact:true}).fill('fast');await page.getByRole('button',{name:'fast 0',exact:true}).waitFor();
        await page.waitForTimeout(800);assert.equal(await page.getByRole('button',{name:/^slow /}).count(),0);
        await page.reload();await page.getByRole('button',{name:'fast 0',exact:true}).waitFor();
        await page.getByLabel('Search',{exact:true}).fill('empty');await page.getByText('No results for these filters').waitFor();
        assert.equal(await page.getByRole('button',{name:'Next page'}).isDisabled(),true);
        const fits=await page.getByRole('navigation',{name:'Pagination'}).evaluate(e=>e.scrollWidth<=e.clientWidth+1);assert.equal(fits,true,`${width} dark=${dark}`);
        await page.close();
    }
    assert.deepEqual(errors,[]);console.log('PASS pagination: 390/1280, light/dark; next/previous, URL reload, size/filter reset, stale response, detail fetch, empty state');
} finally {await browser?.close();await server.close();}
