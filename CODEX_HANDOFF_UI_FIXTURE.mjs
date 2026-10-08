import {createServer} from 'file:///E:/D-10-5-26/D-10-5-26/graduation_project-final/final-EDR-Platform/dashboard/node_modules/vite/dist/node/index.js';
process.env.VITE_CONNECTION_MANAGER_URL='/mock';process.env.VITE_API_URL='/mock';
let setting={enabled:true,configured:true,locked:false};
let rule={id:'fixture-rule',name:'Exact technique response',description:'Mock rule',priority:5,auto_execute:false,enabled:true,playbook_id:'fixture-pb',trigger_conditions:{rule_ids:['sigma-test'],mitre_techniques:['T1059'],logic_operator:'OR'},cooldown_minutes:30};
let saved=[];
const root='E:/D-10-5-26/D-10-5-26/graduation_project-final/final-EDR-Platform/dashboard';
const server=await createServer({root,server:{host:'127.0.0.1',port:5173,strictPort:true},plugins:[{name:'codex-isolated-api-fixture',resolveId(id){if(id==='virtual:codex-preview')return id;},load(id){if(id==='virtual:codex-preview')return `import React from 'react';import {createRoot} from 'react-dom/client';import {BrowserRouter} from 'react-router-dom';import {QueryClient,QueryClientProvider} from '@tanstack/react-query';import {AutomationRulesPage} from '/src/pages/automation/AutomationRulesPage.tsx';import '/src/index.css';localStorage.setItem('user',JSON.stringify({role:'admin'}));createRoot(document.getElementById('root')).render(React.createElement(QueryClientProvider,{client:new QueryClient()},React.createElement(BrowserRouter,null,React.createElement(AutomationRulesPage))));`;},configureServer(s){s.middlewares.use(async(req,res,next)=>{
const url=req.url.split('?')[0];
if(url==='/verify'){res.setHeader('Content-Type','text/html');res.end(await s.transformIndexHtml('/verify', `<html><head></head><body><div id="root"></div><script type="module" src="/verify.tsx"></script></body></html>`));return;}
if(url==='/verify.tsx'){res.setHeader('Content-Type','application/javascript');const transformed=await s.transformRequest("virtual:codex-preview");res.end(transformed.code);return;}
if(!url.startsWith('/mock/')&&url!='/verify-state')return next();
let body='';for await(const chunk of req)body+=chunk;const input=body?JSON.parse(body):{};
let output={data:[],total:0};
if(url.endsWith('/automation/settings')){if(req.method==='PUT'){setting={...setting,enabled:input.enabled,configured:input.enabled};saved.push({kind:'settings',input});}output={data:setting};}
else if(url.endsWith('/automation/playbooks'))output={data:[{id:'fixture-pb',name:'Diagnostic fixture',category:'investigation',commands:[{type:'collect_logs'}],enabled:true}],total:1};
else if(url.endsWith('/automation/rules')||url.endsWith('/automation/rules/fixture-rule')){if(req.method==='PATCH'){rule={...rule,...input};saved.push({kind:'rule',input});output={data:rule};}else output={data:[rule],total:1};}
else if(url==='/verify-state')output={setting,rule,saved};
res.setHeader('Content-Type','application/json');res.end(JSON.stringify(output));
});}}]});await server.listen();console.log('Isolated automation UI fixture at http://127.0.0.1:5173/verify');