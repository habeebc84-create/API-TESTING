/* ============================================================
   CASTONE — Automated API Testing Using Fuzz Testing
   Module 1: API Configuration & Endpoint Management
   Module 2: Automated Fuzz Testing Engine
   Module 3: Vulnerability Detection & Reporting
   ============================================================ */
'use strict';

/* ---------- State ---------- */
const LS = { ep:'castone_endpoints', cases:'castone_cases', findings:'castone_findings', runs:'castone_runs', bugs:'castone_bugs' };
let endpoints = load(LS.ep, []);
let cases = load(LS.cases, []);
let findings = load(LS.findings, []);
let runs = load(LS.runs, []);
let bugs = load(LS.bugs, { age:true, sqli:true, crash:true, leak:true, slow:true, xss:true });
let selectedEpId = null;
let fuzzRunning = false;
let stopRequested = false;
let currentRunId = null;

function load(k, d){ try{ const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; }catch(e){ return d; } }
function save(k, v){ try{ localStorage.setItem(k, JSON.stringify(v)); }catch(e){} }
function persistAll(){ save(LS.ep,endpoints); save(LS.cases,cases); save(LS.findings,findings); save(LS.runs,runs); save(LS.bugs,bugs); }

/* ---------- Utils ---------- */
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2,8);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const clamp = (n,a,b) => Math.max(a, Math.min(b, n));
function toast(msg){ const t=$('toast'); t.textContent=msg; t.classList.add('show'); clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('show'),2600); }
function download(name, content, type){
  const blob = new Blob([content], {type:type||'text/plain'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href), 2000);
}
function csvCell(v){ v = String(v ?? ''); return /[",\n]/.test(v) ? '"' + v.replace(/"/g,'""') + '"' : v; }
function mulberry32(a){ return function(){ a|=0; a=a+0x6D2B79F5|0; let t=Math.imul(a^a>>>15,1|a); t=t+Math.imul(t^t>>>7,61|t)^t; return ((t^t>>>14)>>>0)/4294967296; }; }
function parseKV(text){
  const out = {};
  String(text||'').split('\n').forEach(line=>{
    line=line.trim(); if(!line) return;
    const i = line.indexOf(':'); const j = line.indexOf('=');
    // headers use "Key: Value", query uses "key=value" — accept both
    let sep = -1;
    if(i>0 && (j<0 || i<j)) sep=i; else if(j>0) sep=j;
    if(sep>0) out[line.slice(0,sep).trim()] = line.slice(sep+1).trim();
    else out[line] = '';
  });
  return out;
}
function buildUrl(base, queryObj){
  const q = Object.entries(queryObj||{}).filter(([,v])=>v!==undefined && v!==null && v!=='');
  if(!q.length) return base;
  const sep = base.includes('?') ? '&' : '?';
  return base + sep + q.map(([k,v])=>encodeURIComponent(k)+'='+encodeURIComponent(v)).join('&');
}
function fmtTime(ms){ if(ms==null) return '—'; return ms < 1000 ? Math.round(ms)+'ms' : (ms/1000).toFixed(2)+'s'; }
function statusClass(s){ if(s>=200&&s<300) return 'status-ok'; if(s>=400&&s<500) return 'status-warn'; if(s>=500) return 'status-err'; return ''; }

/* ---------- Demo Target API (built-in vulnerable simulator) ---------- */
const DEMO_PRODUCTS = [
  {id:1,name:'Wireless Mouse',price:25.99},{id:2,name:'Mechanical Keyboard',price:89.00},
  {id:3,name:'USB-C Hub',price:45.50},{id:4,name:'Monitor Stand',price:39.99},{id:5,name:'Webcam HD',price:59.00}
];
function demoDelay(){ return bugs.slow ? 30 + Math.random()*120 : 15 + Math.random()*40; }
function containsSpecial(s){
  return typeof s==='string' && (/[^\x20-\x7E]/.test(s) || s.length>5000);
}
function handleDemo(method, path, query, body){
  // body is object or null; query is object
  const b = body || {};
  const delay = demoDelay();
  const inputs = [...Object.values(b), ...Object.values(query || {})];
  const hasCrash = bugs.crash && inputs.some(containsSpecial);
  const hasLeak = bugs.leak && hasCrash;
  const hasSqli = bugs.sqli && inputs.some(v=>typeof v==='string' && /DROP TABLE|UNION SELECT|';--|OR\s+['"]?1['"]?\s*=\s*['"]?1/i.test(v));
  const hasXss = bugs.xss && inputs.some(v=>typeof v==='string' && /<script|<img|<svg|javascript:/i.test(v));

  if(hasCrash){
    return { status:500, timeMs: delay+40,
      body: hasLeak
        ? { error:'Internal Server Error', detail:'java.lang.NullPointerException at com.app.UserController.create(UserController.java:142) — DB connection pool exhausted. Query: SELECT * FROM users WHERE id=...', stack:'at com.app.UserController.create(UserController.java:142)\nat java.base/...' }
        : { error:'Internal Server Error' } };
  }
  if(path==='users' && (method==='POST'||method==='PUT'||method==='PATCH')){
    const name = b.name, age = b.age, email = b.email;
    // Proper validation only when bugs are fixed
    if(!bugs.age){
      if(typeof age!=='number' || isNaN(age) || age<0 || age>150) return {status:400,timeMs:delay,body:{error:'Validation failed: age must be a number between 0 and 150'}};
      if(typeof name!=='string' || !name.trim()) return {status:400,timeMs:delay,body:{error:'Validation failed: name is required'}};
      if(typeof email!=='string' || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return {status:400,timeMs:delay,body:{error:'Validation failed: invalid email format'}};
    } else {
      // Vulnerable: only checks presence loosely, accepts negative/huge ages, wrong types
      if(name===undefined || name===null || name==='') return {status:400,timeMs:delay,body:{error:'name is required'}};
      if(email===undefined || email===null || email==='') return {status:400,timeMs:delay,body:{error:'email is required'}};
      // age NOT validated (bug)
    }
    const resp = { id: Math.floor(Math.random()*9000)+1000, name, age, email, created:true };
    if(hasSqli) resp.debug = `Executed query: SELECT * FROM users WHERE name='${name}'`;
    if(hasXss) resp.rendered = `<div>Welcome, ${name}</div>`;
    if(bugs.slow && typeof age==='number' && age>100000) return {status:200,timeMs:2200,body:resp};
    return {status:201,timeMs:delay,body:resp};
  }
  if(path==='products' && method==='GET'){
    let page = parseInt(query.page,10); let limit = parseInt(query.limit,10);
    if(!bugs.age){ // reuse flag as "validation fixed" for demo simplicity
      if(isNaN(page)||page<1) return {status:400,timeMs:delay,body:{error:'page must be >= 1'}};
      if(isNaN(limit)||limit<1||limit>100) return {status:400,timeMs:delay,body:{error:'limit must be 1..100'}};
    }
    if(isNaN(page)) page=1; if(isNaN(limit)) limit=10;
    const start=(page-1)*limit;
    return {status:200,timeMs:delay,body:{page,limit,total:DEMO_PRODUCTS.length,items:DEMO_PRODUCTS.slice(start,start+limit)}};
  }
  if(path==='login' && method==='POST'){
    const u=b.username, p=b.password;
    if(!bugs.sqli){
      if(typeof u!=='string'||typeof p!=='string'||!u||!p) return {status:400,timeMs:delay,body:{error:'username and password required'}};
      if(u==='admin'&&p==='secret123') return {status:200,timeMs:delay,body:{token:'demo-jwt-token',user:u}};
      return {status:401,timeMs:delay,body:{error:'Invalid credentials'}};
    }
    if(u==='admin'&&p==='secret123') return {status:200,timeMs:delay,body:{token:'demo-jwt-token',user:u}};
    if(typeof u==='string' && /' OR '1'='1|OR 1=1/i.test(u)) return {status:200,timeMs:delay,body:{token:'demo-jwt-token',user:u,warning:'SQLi bypass succeeded (demo)'}};
    return {status:401,timeMs:delay,body:{error:'Invalid credentials'}};
  }
  if(path==='search' && method==='GET'){
    const q = query.q || '';
    if(hasCrash) return {status:500,timeMs:delay+40,body:{error:'Internal Server Error',detail:bugs.leak?'Elasticsearch query parse failure at SearchService.java:88':'Internal Server Error'}};
    const hits = DEMO_PRODUCTS.filter(p=>p.name.toLowerCase().includes(String(q).toLowerCase()));
    const resp = { q, count: hits.length, results: hits };
    if(hasSqli) resp.debug = `Query executed: SELECT * FROM products WHERE name LIKE '%${q}%'`;
    if(hasXss) resp.rendered = `<div>Results for: ${q}</div>`;
    return {status:200,timeMs:delay,body:resp};
  }
  return {status:404,timeMs:delay,body:{error:'Endpoint not found (demo API). Available: users, products, login, search'}};
}

/* ---------- HTTP executor (demo:// or real fetch with timeout) ---------- */
async function executeRequest(ep, bodyObj, queryObj, headersObj, timeoutMs){
  const start = performance.now();
  const timeout = timeoutMs || ep.timeout || 5000;
  const url = buildUrl(ep.url, queryObj);
  const headers = Object.assign({}, headersObj||{});
  // Auth
  if(ep.authType==='bearer' && ep.authValue) headers['Authorization'] = 'Bearer ' + ep.authValue;
  if(ep.authType==='basic' && ep.authValue) headers['Authorization'] = 'Basic ' + btoa(unescape(encodeURIComponent(ep.authValue)));
  if(ep.authType==='apikey' && ep.authValue) headers['X-API-Key'] = ep.authValue;
  const method = (ep.method||'GET').toUpperCase();
  const hasBody = !['GET','HEAD'].includes(method) && bodyObj!==null && bodyObj!==undefined;

  if(/^demo:\/\//i.test(ep.url)){
    const path = ep.url.replace(/^demo:\/\//i,'').split('?')[0].replace(/^\/+/,'');
    // simulate network latency
    await sleep(10 + Math.random()*30);
    const res = handleDemo(method, path, queryObj||{}, bodyObj);
    return { status:res.status, body:res.body, headers:{'content-type':'application/json','x-demo':'true'},
             timeMs: Math.round(performance.now()-start), error:null, url };
  }

  const ctrl = new AbortController();
  const timer = setTimeout(()=>ctrl.abort(), timeout);
  try{
    const opts = { method, headers, signal: ctrl.signal };
    if(hasBody){ opts.body = JSON.stringify(bodyObj); if(!headers['Content-Type'] && !headers['content-type']) headers['Content-Type']='application/json'; }
    const resp = await fetch(url, opts);
    const text = await resp.text();
    let parsed; try{ parsed = JSON.parse(text); }catch(e){ parsed = text; }
    const h = {}; resp.headers.forEach((v,k)=>h[k]=v);
    return { status: resp.status, body: parsed, headers: h, timeMs: Math.round(performance.now()-start), error:null, url };
  }catch(err){
    const isTimeout = err && err.name==='AbortError';
    return { status:0, body:null, headers:{}, timeMs: Math.round(performance.now()-start),
             error: isTimeout ? 'Timeout after '+timeout+'ms' : ('Network error: '+(err.message||err)), url };
  }finally{ clearTimeout(timer); }
}

/* ---------- Fuzz payload generation (Module 2) ---------- */
const RANDOM_STRINGS = ['hello','test','Alice','xyz','a','', '   ', 'null','undefined','true','0','-1','999999','Lorem ipsum dolor sit amet','😀','café','\u0000','\n\r\t','<b>bold</b>','"quoted"',"o'reilly",'back\\slash','%00','../etc/passwd','{json}','[array]'];
const SPECIAL_PAYLOADS = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users --", '<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'javascript:alert(1)', '<svg onload=alert(1)>', '😀😀😀', 'café naïve résumé', '\u202eRTL override', 'A'.repeat(500), '0'.repeat(100), '<!-- comment -->', '{{7*7}}', '${7*7}', '%3Cscript%3E'];
const BOUNDARY_NUMBERS = [-1, 0, 1, -100, 100, 150, 999999, 2147483647, -2147483648, 1.5, -0.5, 0.001, 1e10, NaN];
const TYPE_CONFUSION = ['abc', 'true', 'false', [], {}, [1,2,3], {nested:true}, '2024-13-45', '12.34.56', '@@@', '   ', 0, false, true];

function randomString(rng, len){
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-@.!';
  let s=''; const n = len || (3 + Math.floor(rng()*12));
  for(let i=0;i<n;i++) s += chars[Math.floor(rng()*chars.length)];
  return s;
}
function clone(o){ return JSON.parse(JSON.stringify(o)); }

function generateMutations(ep, strategies, rng, fuzzQuery, fuzzHeaders){
  // Returns array of {strategy, body, query, headers, field, value}
  const baseBody = ep.body && ep.body.trim() ? safeParse(ep.body) : null;
  const baseQuery = parseKV(ep.query);
  const baseHeaders = parseKV(ep.headers);
  const mutations = [];

  const bodyKeys = baseBody && typeof baseBody==='object' && !Array.isArray(baseBody) ? Object.keys(baseBody) : [];
  const queryKeys = Object.keys(baseQuery);
  const headerKeys = Object.keys(baseHeaders);

  function push(strategy, field, value, apply){
    const body = baseBody!==null ? clone(baseBody) : null;
    const query = Object.assign({}, baseQuery);
    const headers = Object.assign({}, baseHeaders);
    apply(body, query, headers);
    mutations.push({ strategy, field, value, body, query, headers });
  }

  // Helper to pick a field value generator based on original type
  function variantsFor(orig){
    const v = [];
    if(typeof orig==='number'){
      if(strategies.boundary) v.push(...BOUNDARY_NUMBERS.map(n=>({s:'boundary',val:n})));
      if(strategies.type) v.push(...TYPE_CONFUSION.slice(0,6).map(t=>({s:'type-confusion',val:t})));
      if(strategies.random) v.push({s:'random',val:Math.floor(rng()*100000)-5000},{s:'random',val:Math.round(rng()*1000)/100});
      if(strategies.null) v.push({s:'null/missing',val:null},{s:'null/missing',val:''});
      if(strategies.special) v.push({s:'special-chars',val:SPECIAL_PAYLOADS[Math.floor(rng()*SPECIAL_PAYLOADS.length)]});
    } else if(typeof orig==='string'){
      if(strategies.boundary) v.push({s:'boundary',val:''},{s:'boundary',val:'A'.repeat(1000)},{s:'boundary',val:'x'});
      if(strategies.null) v.push({s:'null/missing',val:null},{s:'null/missing',val:''},{s:'null/missing',val:undefined});
      if(strategies.type) v.push({s:'type-confusion',val:123},{s:'type-confusion',val:true},{s:'type-confusion',val:[]},{s:'type-confusion',val:{}});
      if(strategies.random) v.push({s:'random',val:randomString(rng)},{s:'random',val:randomString(rng,30)});
      if(strategies.special) v.push(...SPECIAL_PAYLOADS.slice(0,6).map(p=>({s:'special-chars',val:p})));
    } else if(typeof orig==='boolean'){
      if(strategies.random) v.push({s:'random',val:!orig},{s:'random',val:rng()>0.5});
      if(strategies.type) v.push({s:'type-confusion',val:'true'},{s:'type-confusion',val:1},{s:'type-confusion',val:0});
      if(strategies.null) v.push({s:'null/missing',val:null});
    } else if(Array.isArray(orig)){
      if(strategies.mutation) v.push({s:'mutation',val:[]},{s:'mutation',val:[null,null]},{s:'mutation',val:['x',123,null]});
      if(strategies.type) v.push({s:'type-confusion',val:'not-array'},{s:'type-confusion',val:123});
      if(strategies.null) v.push({s:'null/missing',val:null});
    } else if(orig && typeof orig==='object'){
      if(strategies.mutation) v.push({s:'mutation',val:{}},{s:'mutation',val:{a:1,b:2}});
      if(strategies.type) v.push({s:'type-confusion',val:'string'},{s:'type-confusion',val:42});
      if(strategies.null) v.push({s:'null/missing',val:null});
    } else { // null / undefined orig
      if(strategies.random) v.push({s:'random',val:randomString(rng)},{s:'random',val:Math.floor(rng()*1000)});
      if(strategies.null) v.push({s:'null/missing',val:null});
    }
    return v;
  }

  // Mutate body fields
  bodyKeys.forEach(key=>{
    variantsFor(baseBody[key]).forEach(({s,val})=>{
      push(s, 'body.'+key, val, (body)=>{
        if(val===undefined) delete body[key]; else body[key]=val;
      });
    });
  });

  // Whole-body mutations
  if(baseBody!==null && strategies.mutation){
    push('mutation','(whole body)','{}', (body)=>{ Object.keys(body).forEach(k=>delete body[k]); });
    push('mutation','(whole body)','[]', ()=>{});
    // fix: replace body with array — handled specially below
    const last = mutations[mutations.length-1]; last.body = [];
    push('mutation','(whole body)','null', ()=>{});
    mutations[mutations.length-1].body = null;
    push('mutation','(whole body)','"string"', ()=>{});
    mutations[mutations.length-1].body = 'just-a-string';
  }

  // Query param fuzzing
  if(fuzzQuery){
    const keys = queryKeys.length ? queryKeys : ['page','limit','q','id'];
    keys.forEach(key=>{
      const orig = baseQuery[key] !== undefined ? baseQuery[key] : '1';
      const vals = strategies.boundary ? ['-1','0','999999',''] : [];
      if(strategies.null) vals.push('null');
      if(strategies.type) vals.push('abc','true','[]');
      if(strategies.random) vals.push(String(Math.floor(rng()*10000)), randomString(rng,8));
      if(strategies.special) vals.push(SPECIAL_PAYLOADS[0], SPECIAL_PAYLOADS[3]);
      vals.forEach(val=> push('query-fuzz','query.'+key,val,(body,q)=>{ q[key]=val; }));
    });
  }

  // Header fuzzing
  if(fuzzHeaders){
    const keys = headerKeys.length ? headerKeys : ['X-Custom-Header'];
    keys.forEach(key=>{
      const vals = [randomString(rng,10), SPECIAL_PAYLOADS[3], 'A'.repeat(300), '', 'null'];
      vals.forEach(val=> push('header-fuzz','header.'+key,val,(body,q,h)=>{ h[key]=val; }));
    });
  }

  // If no body template, fuzz with a generic payload set
  if(baseBody===null && bodyKeys.length===0 && !['GET','HEAD'].includes((ep.method||'GET').toUpperCase())){
    const generic = [
      {s:'random',val:{name:randomString(rng),age:Math.floor(rng()*80),email:randomString(rng,6)+'@example.com'}},
      {s:'boundary',val:{name:'',age:-1,email:'invalid'}},
      {s:'null/missing',val:{}},
      {s:'special-chars',val:{name:SPECIAL_PAYLOADS[0],age:'abc',email:'x'}},
    ];
    generic.forEach(g=> mutations.push({strategy:g.s, field:'(body)', value:g.val, body:g.val, query:Object.assign({},baseQuery), headers:Object.assign({},baseHeaders)}));
  }

  // Shuffle deterministically with seed, then caller slices to count
  for(let i=mutations.length-1;i>0;i--){ const j=Math.floor(rng()*(i+1)); [mutations[i],mutations[j]]=[mutations[j],mutations[i]]; }
  return mutations;
}
function safeParse(text){ try{ return JSON.parse(text); }catch(e){ return null; } }

/* ---------- Analyzer (Module 3) ---------- */
function analyzeCase(c, ep){
  const out = [];
  const bodyText = JSON.stringify(c.responseBody ?? '');
  const inputText = JSON.stringify(c.input ?? '');
  const expected = ep.expected || 200;
  // Only flag acceptance when the generated value is plausibly invalid. A 2xx
  // for a valid boundary such as 0 or a normal string is not a validation bug.
  const mutated = c.mutatedValue;
  const invalidBoundary = c.strategy === 'boundary' && (
    (typeof mutated === 'number' && (mutated < 0 || mutated > 150 || !Number.isFinite(mutated))) ||
    (typeof mutated === 'string' && (mutated.length === 0 || mutated.length > 500))
  );
  const invalidQuery = c.strategy === 'query-fuzz' && (
    mutated === '-1' || mutated === '0' || mutated === '999999' || mutated === 'abc' || mutated === 'null' || mutated === '[]'
  );
  const invalidInput = ['null/missing','mutation','type-confusion'].includes(c.strategy) || invalidBoundary || invalidQuery;

  function add(severity, type, title, evidence, recommendation){
    out.push({ id: uid(), caseId: c.id, endpointId: ep.id, endpointName: ep.name, endpointUrl: ep.url,
      severity, type, title, evidence, recommendation, timestamp: new Date().toISOString() });
  }

  if(c.error){
    if(/Timeout/i.test(c.error)) add('High','Timeout','Request timeout', c.error + ' (input: '+inputText.slice(0,200)+')', 'Investigate slow queries / missing timeout handling. Add server-side timeouts and pagination limits.');
    else add('High','Connection Failure','Connection / network failure', c.error, 'Check API availability, CORS, DNS and firewall. Verify the endpoint URL and server status.');
    return out;
  }
  if(c.status>=500){
    add(c.status===500?'Critical':'High','Server Error (5xx)', 'Unexpected HTTP '+c.status+' server error',
      'Input '+inputText.slice(0,250)+' → HTTP '+c.status+' '+bodyText.slice(0,300),
      'Fix server-side crash. Add input validation before processing, null checks, and generic error handling. Return 4xx for bad input instead of 5xx.');
  }
  if(c.status===0) add('High','No Response','No HTTP response received','Status 0 / network failure','Check server availability and connectivity.');
  // Stack trace / internal leak
  if(/Exception|at com\.|at java\.|Traceback|NullPointer|SELECT .* FROM|Query:|stack/i.test(bodyText)){
    add('High','Information Disclosure','Internal details leaked in response', bodyText.slice(0,350), 'Never return stack traces or SQL queries to clients. Log details server-side and return a generic error message.');
  }
  // SQLi reflection
  if((/DROP TABLE|UNION SELECT|Executed query/i.test(bodyText) && /DROP TABLE|UNION SELECT|OR.*1.*=.*1/i.test(inputText)) || (/SQLi bypass succeeded/i.test(bodyText) && /OR.*1.*=.*1|UNION SELECT/i.test(inputText))){
    add('High','SQL Injection Risk','SQL payload reflected / executed', 'Input '+inputText.slice(0,200)+' → response contains SQL fragment: '+bodyText.slice(0,250), 'Use parameterized queries / prepared statements. Never concatenate user input into SQL. Validate and escape input.');
  }
  // XSS reflection
  if(/<script|<img|<svg|javascript:/i.test(bodyText) && /<script|<img|<svg|javascript:/i.test(inputText)){
    add('High','Cross-Site Scripting Risk','XSS payload reflected without encoding', 'Input '+inputText.slice(0,200)+' → response reflects markup: '+bodyText.slice(0,250), 'Output-encode user input (HTML-escape). Set Content-Security-Policy headers. Validate input with an allowlist.');
  }
  // Missing validation: invalid input accepted with 2xx
  if(invalidInput && c.status>=200 && c.status<300){
    add('Medium','Missing Validation','Invalid input accepted (HTTP '+c.status+')',
      'Fuzzed '+c.field+' = '+JSON.stringify(c.mutatedValue).slice(0,150)+' → HTTP '+c.status+' (expected 4xx)',
      'Add server-side validation: type checks, range checks (e.g. age 0–150), required fields, and format validation. Return 400 with a clear error for invalid input.');
  }
  // Status mismatch vs expected success, only for non-malformed normal requests.
  if(c.status && c.status!==expected && c.status<500 && !invalidInput){
    add('Low','Status Mismatch','Response status differs from expected', 'Expected '+expected+', got '+c.status, 'Verify the endpoint contract and update the expected status or fix the API response.');
  }
  // Inconsistent error format
  if(c.status>=400 && c.status<500){
    const hasErrorField = c.responseBody && typeof c.responseBody==='object' && ('error' in c.responseBody || 'message' in c.responseBody || 'detail' in c.responseBody);
    if(!hasErrorField) add('Low','Inconsistent Error Handling','Error response lacks standard error field', 'HTTP '+c.status+' body: '+bodyText.slice(0,250), 'Return consistent JSON errors, e.g. {"error": "...", "code": "..."}. Document error codes in the API spec.');
  }
  // Slow response
  if(c.timeMs>2000) add('Medium','Performance','Slow response ('+fmtTime(c.timeMs)+')', 'Input '+inputText.slice(0,200)+' took '+fmtTime(c.timeMs), 'Add pagination, indexing, caching and input size limits. Set server timeouts and rate limits.');
  return out;
}

/* ---------- Views ---------- */
function showView(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  $('view-'+name).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active', n.dataset.view===name));
  window.scrollTo({top:0,behavior:'smooth'});
  if(name==='dashboard') renderDashboard();
  if(name==='endpoints') renderEndpoints();
  if(name==='fuzz') renderFuzzTargets();
  if(name==='reports') renderReports();
  if(name==='demoapi') renderDemoView();
}

/* ---------- Module 1: Endpoints UI ---------- */
function newEndpoint(){
  selectedEpId = null;
  $('endpointForm').reset();
  $('f_id').value=''; $('f_timeout').value=5000; $('f_expected').value=200; $('f_method').value='POST';
  $('f_body').value='{"name":"Alice","age":25,"email":"alice@example.com"}';
  toggleAuthFields();
  $('editorTitle').textContent='New Endpoint'; $('btnDelete').style.display='none';
  $('connectResult').innerHTML='';
  renderEndpoints();
}
function editEndpoint(id){
  const ep = endpoints.find(e=>e.id===id); if(!ep) return;
  selectedEpId = id;
  $('f_id').value=ep.id; $('f_name').value=ep.name; $('f_method').value=ep.method; $('f_url').value=ep.url;
  $('f_timeout').value=ep.timeout; $('f_expected').value=ep.expected; $('f_desc').value=ep.desc||'';
  $('f_authType').value=ep.authType||'none'; $('f_authValue').value=ep.authValue||'';
  $('f_headers').value=Object.entries(ep.headers||{}).map(([k,v])=>k+': '+v).join('\n');
  $('f_query').value=Object.entries(ep.query||{}).map(([k,v])=>k+'='+v).join('\n');
  $('f_body').value=ep.body||'';
  $('editorTitle').textContent='Edit: '+ep.name; $('btnDelete').style.display='inline-block';
  toggleAuthFields(); renderEndpoints();
}
function toggleAuthFields(){
  const t=$('f_authType').value;
  $('authFieldWrap').style.display = t==='none' ? 'none':'block';
  $('authFieldLabel').textContent = t==='bearer'?'Bearer Token': t==='basic'?'Username:Password':'API Key Value';
}
function saveEndpoint(ev){
  ev.preventDefault();
  const body = $('f_body').value.trim();
  if(body){ try{ JSON.parse(body); }catch(e){ toast('⚠️ Request body is not valid JSON: '+e.message); return false; } }
  const data = {
    name: $('f_name').value.trim(), method: $('f_method').value, url: $('f_url').value.trim(),
    timeout: clamp(parseInt($('f_timeout').value,10)||5000, 500, 60000),
    expected: clamp(parseInt($('f_expected').value,10)||200, 100, 599),
    desc: $('f_desc').value.trim(), authType: $('f_authType').value, authValue: $('f_authValue').value.trim(),
    headers: parseKV($('f_headers').value), query: parseKV($('f_query').value), body
  };
  const id = $('f_id').value;
  if(id){ const i=endpoints.findIndex(e=>e.id===id); if(i>=0) endpoints[i]=Object.assign({},endpoints[i],data); }
  else { data.id=uid(); endpoints.unshift(data); selectedEpId=data.id; }
  persistAll(); renderEndpoints(); renderFuzzTargets(); updateSidebar();
  toast('✅ Endpoint saved');
  return false;
}
function deleteEndpoint(){
  const id=$('f_id').value; if(!id) return;
  if(!confirm('Delete this endpoint?')) return;
  endpoints=endpoints.filter(e=>e.id!==id);
  if(selectedEpId===id) selectedEpId=null;
  persistAll(); newEndpoint(); renderFuzzTargets(); updateSidebar();
  toast('🗑 Endpoint deleted');
}
async function validateConnectivity(){
  const url=$('f_url').value.trim();
  if(!url){ toast('Enter a URL first'); return; }
  const box=$('connectResult'); box.innerHTML='⏳ Checking connectivity…';
  const ep={ id:'tmp', name:$('f_name').value||'tmp', method:$('f_method').value, url,
    timeout:clamp(parseInt($('f_timeout').value,10)||5000,500,60000), expected:200,
    authType:$('f_authType').value, authValue:$('f_authValue').value,
    headers:parseKV($('f_headers').value), query:parseKV($('f_query').value), body:$('f_body').value };
  const res=await executeRequest(ep, safeParse(ep.body), ep.query, ep.headers, ep.timeout);
  if(res.error) box.innerHTML='<span class="badge fail">UNREACHABLE</span> '+esc(res.error)+' ('+fmtTime(res.timeMs)+')';
  else box.innerHTML='<span class="badge pass">REACHABLE</span> HTTP '+res.status+' in '+fmtTime(res.timeMs)+' — '+esc(ep.url);
}
function renderEndpoints(){
  const list=$('endpointList');
  $('endpointCountLabel').textContent = endpoints.length+' saved';
  $('navEndpointCount').textContent = endpoints.length;
  $('sideEndpoints').textContent = endpoints.length;
  $('statEndpoints').textContent = endpoints.length;
  if(!endpoints.length){ list.innerHTML='<p class="empty">No endpoints yet. Add one or import OpenAPI.</p>'; return; }
  list.innerHTML = endpoints.map(ep=>`
    <div class="ep-item ${ep.id===selectedEpId?'selected':''}" onclick="editEndpoint('${ep.id}')">
      <div class="ep-top"><span class="method ${ep.method.toLowerCase()}">${ep.method}</span><span class="ep-name">${esc(ep.name)}</span>
      <span class="tag">expect ${ep.expected}</span>${ep.authType&&ep.authType!=='none'?'<span class="tag">🔐 '+esc(ep.authType)+'</span>':''}</div>
      <div class="ep-url">${esc(ep.url)}</div>
      ${ep.desc?'<div class="ep-url" style="color:var(--muted2)">'+esc(ep.desc)+'</div>':''}
    </div>`).join('');
}

/* ---------- OpenAPI import ---------- */
function openOpenAPIPaste(){
  const text = prompt('Paste OpenAPI/Swagger JSON:');
  if(text) importOpenAPIText(text);
}
function importOpenAPIFile(ev){
  const f=ev.target.files[0]; if(!f) return;
  const r=new FileReader();
  r.onload=()=>{ try{ importOpenAPIText(r.result); }catch(e){ toast('❌ Could not parse file: '+e.message); } };
  r.readAsText(f); ev.target.value='';
}
function importOpenAPIText(text){
  let spec; try{ spec=JSON.parse(text); }catch(e){ toast('❌ Invalid JSON: '+e.message); return; }
  if(!spec || !spec.paths || typeof spec.paths!=='object'){
    toast('❌ No valid "paths" object found — import an OpenAPI/Swagger JSON spec'); return;
  }
  const swaggerBase = spec.host ? `${(spec.schemes && spec.schemes[0]) || 'https'}://${spec.host}${spec.basePath || ''}` : '';
  const base = (spec.servers && spec.servers[0] && spec.servers[0].url) || swaggerBase || 'https://api.example.com';
  const methods = new Set(['get','post','put','patch','delete']);
  let added=0;
  Object.entries(spec.paths).forEach(([path, pathItem])=>{
    if(!pathItem || typeof pathItem!=='object') return;
    Object.entries(pathItem).forEach(([method, op])=>{
      if(!methods.has(method) || !op || typeof op!=='object') return;
      let body='';
      const schema = op.requestBody?.content?.['application/json']?.schema || (op.parameters||[]).find(p=>p?.in==='body')?.schema;
      if(schema?.properties){
        const exampleValue = v => v.example ?? v.default ?? (Array.isArray(v.enum) ? v.enum[0] : undefined) ?? (v.type==='number'||v.type==='integer' ? 1 : v.type==='boolean' ? true : v.type==='array' ? [] : v.type==='object' ? {} : 'example');
        body=JSON.stringify(Object.fromEntries(Object.entries(schema.properties).map(([k,v])=>[k,exampleValue(v||{})])),null,2);
      }
      const query={}, pathValues={};
      const parameters=[...(pathItem.parameters||[]),...(op.parameters||[])];
      parameters.forEach(p=>{
        if(!p?.name) return;
        const schema=p.schema||p;
        const value=p.example ?? schema.default ?? (Array.isArray(schema.enum)?schema.enum[0]:undefined) ?? (schema.type==='number'||schema.type==='integer'?1:schema.type==='boolean'?true:'example');
        if(p.in==='query') query[p.name]=String(value);
        if(p.in==='path') pathValues[p.name]=String(value);
      });
      const resolvedPath=path.replace(/\{([^}]+)\}/g,(_match,name)=>encodeURIComponent(pathValues[name] ?? '1'));
      const hasPathParams=/\{[^}]+\}/.test(path);
      const expectedEntry=Object.keys(op.responses||{}).find(code=>/^2\d\d$/.test(code));
      const expected=expectedEntry ? Number(expectedEntry) : method==='post'?201:200;
      const description=[op.description||'',hasPathParams?'Path parameter values were initialized with examples (or 1); edit the URL to customize.':''].filter(Boolean).join(' ');
      endpoints.unshift({ id:uid(), name:(op.summary||op.operationId||method.toUpperCase()+' '+path),
        method:method.toUpperCase(), url: base.replace(/\/$/,'')+resolvedPath, timeout:5000, expected,
        desc:description, authType:'none', authValue:'', headers:{'Content-Type':'application/json'}, query, body });
      added++;
    });
  });
  if(!added){ toast('❌ No supported HTTP operations found in the OpenAPI paths'); return; }
  persistAll(); renderEndpoints(); renderFuzzTargets(); updateSidebar();
  toast('✅ Imported '+added+' endpoint(s) from OpenAPI');
}

/* ---------- Module 2: Fuzz runner ---------- */
function renderFuzzTargets(){
  const sel=$('fuzzTarget');
  const prev=sel.value;
  sel.innerHTML = endpoints.length
    ? endpoints.map(ep=>`<option value="${ep.id}">${esc(ep.method)} ${esc(ep.name)} — ${esc(ep.url)}</option>`).join('')
    : '<option value="">— No endpoints. Add one in Module 1 —</option>';
  if(prev && endpoints.some(e=>e.id===prev)) sel.value=prev;
  else if(selectedEpId && endpoints.some(e=>e.id===selectedEpId)) sel.value=selectedEpId;
}
function onFuzzTargetChange(){ selectedEpId=$('fuzzTarget').value||selectedEpId; renderEndpoints(); }
function getStrategies(){
  return { boundary:$('strat_boundary').checked, null:$('strat_null').checked, type:$('strat_type').checked,
           random:$('strat_random').checked, special:$('strat_special').checked, mutation:$('strat_mutation').checked };
}
async function runFuzz(){
  if(fuzzRunning) return;
  const ep = endpoints.find(e=>e.id===$('fuzzTarget').value) || endpoints[0];
  if(!ep){ toast('⚠️ Add an endpoint first (Module 1)'); showView('endpoints'); return; }
  const rawCount = parseInt($('fuzzCount').value,10);
  const rawDelay = parseInt($('fuzzDelay').value,10);
  const count = clamp(Number.isFinite(rawCount) ? rawCount : 30, 1, 500);
  const delay = clamp(Number.isFinite(rawDelay) ? rawDelay : 120, 0, 5000);
  const parsedSeed = parseInt($('fuzzSeed').value,10);
  const seed = Number.isFinite(parsedSeed) ? parsedSeed : 42;
  const rng = mulberry32(seed);
  const strategies = getStrategies();
  if(!Object.values(strategies).some(Boolean)){ toast('⚠️ Enable at least one strategy'); return; }

  const mutations = generateMutations(ep, strategies, rng, $('fuzzQuery').checked, $('fuzzHeaders').checked);
  // Iterations means requests sent, even when the finite mutation dictionary is smaller.
  if(!mutations.length){ toast('⚠️ No fuzzable inputs — add a body template or enable query/header fuzzing'); return; }
  const plan = Array.from({length:count}, (_, i) => clone(mutations[i % mutations.length]));

  fuzzRunning=true; stopRequested=false; currentRunId=uid();
  $('btnRunFuzz').style.display='none'; $('btnStopFuzz').style.display='inline-block';
  $('progressWrap').style.display='block';
  $('liveLog').innerHTML='';
  const runStart = new Date();
  let done=0, passed=0, failed=0;
  const runFindings=[];

  for(const m of plan){
    if(stopRequested) break;
    const res = await executeRequest(ep, m.body, m.query, m.headers, ep.timeout);
    const verdict = res.error ? 'fail' : (res.status>=500||res.status===0 ? 'fail' : (res.status>=200&&res.status<300 ? 'pass':'warn'));
    const c = { id:uid(), runId:currentRunId, endpointId:ep.id, endpointName:ep.name,
      strategy:m.strategy, field:m.field, mutatedValue:m.value, input:m.body, query:m.query,
      status:res.status, timeMs:res.timeMs, responseBody:res.body, error:res.error, verdict,
      timestamp:new Date().toISOString() };
    cases.unshift(c); if(cases.length>1000) cases=cases.slice(0,1000);
    const f = analyzeCase(c, ep);
    f.forEach(x=>{ findings.unshift(x); runFindings.push(x); });
    if(verdict==='pass') passed++; else if(verdict==='fail') failed++;
    done++;
    appendLog(c, f);
    $('progressFill').style.width = Math.round(done/plan.length*100)+'%';
    $('progressText').textContent = done+' / '+plan.length+'  •  '+passed+' pass • '+failed+' fail • '+runFindings.length+' findings';
    $('liveCount').textContent = done+' cases';
    if(delay) await sleep(delay);
  }

  runs.unshift({ id:currentRunId, endpointName:ep.name, endpointUrl:ep.url, total:done, passed, failed,
    findings:runFindings.length, seed, startedAt:runStart.toISOString(), finishedAt:new Date().toISOString() });
  if(runs.length>50) runs=runs.slice(0,50);
  persistAll(); renderCases(); renderReports(); renderDashboard(); updateSidebar();
  fuzzRunning=false;
  $('btnRunFuzz').style.display='inline-block'; $('btnStopFuzz').style.display='none';
  toast(stopRequested ? '⏹ Fuzz run stopped' : '✅ Fuzz run complete: '+done+' cases, '+runFindings.length+' findings');
  showView('reports');
}
function stopFuzz(){ stopRequested=true; }
function appendLog(c, f){
  const log=$('liveLog');
  if(log.querySelector('.empty')) log.innerHTML='';
  const div=document.createElement('div'); div.className='log-line';
  const st = c.error ? '<span class="status-err">ERR</span>' : '<span class="'+statusClass(c.status)+'">'+c.status+'</span>';
  const v = c.verdict==='pass' ? '<span class="badge pass">PASS</span>' : c.verdict==='fail' ? '<span class="badge fail">FAIL</span>' : '<span class="badge warn">WARN</span>';
  div.innerHTML = `<span>#${esc(c.strategy)}</span><span>${esc(c.field)}=${esc(JSON.stringify(c.mutatedValue)).slice(0,60)}</span>${st}<span>${fmtTime(c.timeMs)}</span>${v}${f.length?'<span class="badge high">'+f.length+' finding(s)</span>':''}`;
  log.prepend(div);
  while(log.children.length>120) log.lastChild.remove();
}
function renderCases(){
  const tb=$('casesBody');
  if(!cases.length){ tb.innerHTML='<tr><td colspan="7" class="empty">No test cases yet.</td></tr>'; return; }
  tb.innerHTML = cases.slice(0,200).map((c,i)=>`
    <tr>
      <td>${cases.length-i}</td>
      <td><span class="badge info">${esc(c.strategy)}</span></td>
      <td class="mono-sm">${esc(c.field)} = ${esc(JSON.stringify(c.mutatedValue)).slice(0,90)}</td>
      <td>${c.error?'<span class="status-err">ERR</span>':'<span class="'+statusClass(c.status)+'">'+c.status+'</span>'}</td>
      <td>${fmtTime(c.timeMs)}</td>
      <td>${c.verdict==='pass'?'<span class="badge pass">PASS</span>':c.verdict==='fail'?'<span class="badge fail">FAIL</span>':'<span class="badge warn">WARN</span>'}</td>
      <td><button class="btn btn-ghost btn-sm" onclick="viewCase('${c.id}')">View</button></td>
    </tr>`).join('');
}
function viewCase(id){
  const c=cases.find(x=>x.id===id); if(!c) return;
  $('modalTitle').textContent='Test Case — '+c.strategy;
  $('modalBody').innerHTML = `
    <p><b>Endpoint:</b> ${esc(c.endpointName)}<br><b>Field:</b> <code>${esc(c.field)}</code> = <code>${esc(JSON.stringify(c.mutatedValue))}</code><br>
    <b>Status:</b> ${c.error?esc(c.error):c.status} &nbsp; <b>Time:</b> ${fmtTime(c.timeMs)} &nbsp; <b>Verdict:</b> ${c.verdict}</p>
    <h4 style="margin-top:12px">Request body</h4><pre>${esc(JSON.stringify(c.input,null,2))}</pre>
    <h4>Response</h4><pre>${esc(JSON.stringify(c.responseBody,null,2) ?? c.error ?? '')}</pre>`;
  $('modalOverlay').classList.add('open');
}
function closeModal(){ $('modalOverlay').classList.remove('open'); }
function clearCases(){ if(!confirm('Clear all test cases? Findings are kept.')) return; cases=[]; persistAll(); renderCases(); updateSidebar(); toast('🧹 Test cases cleared'); }
async function replayFailures(){
  const failedCases = cases.filter(c=>c.verdict==='fail');
  if(!failedCases.length){ toast('No failed cases to replay'); return; }
  toast('🔁 Replaying '+failedCases.length+' failed case(s)…');
  let fixed=0;
  for(const c of failedCases.slice(0,50)){
    const ep=endpoints.find(e=>e.id===c.endpointId); if(!ep) continue;
    const res=await executeRequest(ep, c.input, c.query||{}, {}, ep.timeout);
    if(!res.error && res.status<500) fixed++;
    await sleep(60);
  }
  toast('🔁 Replay done: '+fixed+'/'+Math.min(failedCases.length,50)+' now pass (regression check)');
}

/* ---------- Module 3: Reports ---------- */
function renderReports(){
  const counts={Critical:0,High:0,Medium:0,Low:0};
  findings.forEach(f=>{ if(counts[f.severity]!==undefined) counts[f.severity]++; });
  $('sevCritical').textContent=counts.Critical; $('sevHigh').textContent=counts.High;
  $('sevMedium').textContent=counts.Medium; $('sevLow').textContent=counts.Low;
  $('navFindingCount').style.display = findings.length?'inline-block':'none';
  $('navFindingCount').textContent=findings.length;
  $('sideFindings').textContent=findings.length; $('statFindings').textContent=findings.length;

  // severity chart
  const sevMax=Math.max(1,...Object.values(counts));
  const sevColors={Critical:'#ef4444',High:'#f97316',Medium:'#eab308',Low:'#3b82f6'};
  $('sevChart').innerHTML = Object.entries(counts).map(([k,v])=>`
    <div class="bar-row"><span class="bar-label">${k}</span><div class="bar-track"><div class="bar-fill" style="width:${v/sevMax*100}%;background:${sevColors[k]}"></div></div><span class="bar-val">${v}</span></div>`).join('');

  // type chart
  const byType={}; findings.forEach(f=>byType[f.type]=(byType[f.type]||0)+1);
  const typeEntries=Object.entries(byType).sort((a,b)=>b[1]-a[1]);
  const typeMax=Math.max(1,...typeEntries.map(e=>e[1]));
  const typeColors=['#3b82f6','#8b5cf6','#06b6d4','#22c55e','#f97316','#ef4444','#eab308'];
  $('typeChart').innerHTML = typeEntries.length ? typeEntries.map(([k,v],i)=>`
    <div class="bar-row"><span class="bar-label">${esc(k)}</span><div class="bar-track"><div class="bar-fill" style="width:${v/typeMax*100}%;background:${typeColors[i%typeColors.length]}"></div></div><span class="bar-val">${v}</span></div>`).join('')
    : '<p class="empty">No findings yet.</p>';

  // filter types
  const ft=$('filterType'); const cur=ft.value;
  ft.innerHTML='<option value="">All types</option>'+typeEntries.map(([k])=>`<option ${k===cur?'selected':''}>${esc(k)}</option>`).join('');

  renderFindings(); renderSummary();
}
function renderFindings(){
  const sev=$('filterSeverity').value, type=$('filterType').value;
  const list=findings.filter(f=>(!sev||f.severity===sev)&&(!type||f.type===type));
  const tb=$('findingsBody');
  if(!list.length){ tb.innerHTML='<tr><td colspan="6" class="empty">No findings match the filter.</td></tr>'; return; }
  tb.innerHTML=list.slice(0,200).map(f=>`
    <tr>
      <td><span class="badge ${f.severity.toLowerCase()}">${f.severity}</span></td>
      <td><b>${esc(f.title)}</b><br><span class="muted">${esc(f.type)}</span></td>
      <td class="mono-sm">${esc(f.endpointName)}<br>${esc(f.endpointUrl)}</td>
      <td class="mono-sm">${esc(f.evidence).slice(0,220)}</td>
      <td style="min-width:200px">${esc(f.recommendation)}</td>
      <td><button class="btn btn-ghost btn-sm" onclick="viewFinding('${f.id}')">Details</button></td>
    </tr>`).join('');
}
function viewFinding(id){
  const f=findings.find(x=>x.id===id); if(!f) return;
  $('modalTitle').textContent=f.severity+' — '+f.title;
  $('modalBody').innerHTML=`
    <p><span class="badge ${f.severity.toLowerCase()}">${f.severity}</span> <b>${esc(f.type)}</b><br>
    <b>Endpoint:</b> ${esc(f.endpointName)} — <code>${esc(f.endpointUrl)}</code><br><b>Detected:</b> ${new Date(f.timestamp).toLocaleString()}</p>
    <h4 style="margin-top:12px">Evidence</h4><pre>${esc(f.evidence)}</pre>
    <h4>Recommendation</h4><p>${esc(f.recommendation)}</p>
    <p class="muted" style="margin-top:10px">Note: findings indicate potential issues and must be validated manually before treating them as confirmed vulnerabilities.</p>`;
  $('modalOverlay').classList.add('open');
}
function renderSummary(){
  const el=$('reportSummary');
  if(!cases.length){ el.innerHTML='<p class="empty">Run a fuzz test to generate a summary.</p>'; return; }
  const total=cases.length, passed=cases.filter(c=>c.verdict==='pass').length;
  const bySev={}; findings.forEach(f=>bySev[f.severity]=(bySev[f.severity]||0)+1);
  const topTypes=Object.entries(findings.reduce((a,f)=>{a[f.type]=(a[f.type]||0)+1;return a;},{})).sort((a,b)=>b[1]-a[1]).slice(0,5);
  el.innerHTML=`<div class="summary-box">
    <p><b>CASTONE API Fuzz Test Report</b> — ${new Date().toLocaleString()}</p>
    <h4>Overview</h4>
    <ul><li>Test cases executed: <b>${total}</b> (${passed} passed, ${total-passed} flagged)</li>
    <li>Total findings: <b>${findings.length}</b> — Critical: ${bySev.Critical||0}, High: ${bySev.High||0}, Medium: ${bySev.Medium||0}, Low: ${bySev.Low||0}</li>
    <li>Endpoints tested: ${[...new Set(cases.map(c=>c.endpointName))].join(', ')}</li></ul>
    <h4>Top finding types</h4><ul>${topTypes.map(([t,n])=>`<li>${esc(t)} — ${n} occurrence(s)</li>`).join('')||'<li>None</li>'}</ul>
    <h4>Recommendations</h4><ul>
      <li>Fix all Critical/High findings first (server errors, injection, disclosure).</li>
      <li>Add strict server-side validation and return 4xx for invalid input.</li>
      <li>Re-run fuzzing after fixes and use “Replay Failures” for regression testing.</li>
      <li>Integrate into CI/CD for continuous API robustness testing.</li></ul>
    <p class="muted">Disclaimer: automated fuzzing improves coverage but does not guarantee detection of every vulnerability. Validate findings manually.</p>
  </div>`;
}
function copySummary(){ navigator.clipboard?.writeText($('reportSummary').innerText).then(()=>toast('📋 Summary copied')); }

/* ---------- Dashboard ---------- */
function renderDashboard(){
  $('statTests').textContent=cases.length;
  $('sideTests').textContent=cases.length;
  const passed=cases.filter(c=>c.verdict==='pass').length;
  $('statPassRate').textContent=cases.length?Math.round(passed/cases.length*100)+'%':'—';
  // status distribution
  const byStatus={}; cases.forEach(c=>{ const k=c.error?'Network error':(c.status>=200&&c.status<300?'2xx Success':c.status>=400&&c.status<500?'4xx Client error':c.status>=500?'5xx Server error':'Other'); byStatus[k]=(byStatus[k]||0)+1; });
  const entries=Object.entries(byStatus);
  const max=Math.max(1,...entries.map(e=>e[1]));
  const colors={'2xx Success':'#22c55e','4xx Client error':'#eab308','5xx Server error':'#ef4444','Network error':'#f97316','Other':'#64748b'};
  $('dashChart').innerHTML = entries.length ? entries.map(([k,v])=>`
    <div class="bar-row"><span class="bar-label">${k}</span><div class="bar-track"><div class="bar-fill" style="width:${v/max*100}%;background:${colors[k]||'#3b82f6'}"></div></div><span class="bar-val">${v}</span></div>`).join('')
    : '<p class="empty">No test data yet. Run a fuzz test to see results here.</p>';
  // recent runs
  $('recentRuns').innerHTML = runs.length ? runs.slice(0,6).map(r=>`
    <div class="run-item"><span><b>${esc(r.endpointName)}</b><br><span class="muted">${new Date(r.startedAt).toLocaleString()} • seed ${r.seed}</span></span>
    <span>${r.total} cases • <span class="badge ${r.findings?'high':'pass'}">${r.findings} findings</span></span></div>`).join('')
    : '<p class="empty">No runs yet.</p>';
}
function updateSidebar(){ renderEndpoints(); renderDashboard(); renderReports(); }
function clearHistory(){ if(!confirm('Clear run history?')) return; runs=[]; persistAll(); renderDashboard(); toast('🧹 History cleared'); }
function quickStart(){
  loadDemoEndpoints();
  showView('fuzz');
  toast('⚡ Demo loaded — press “Start Fuzz Test”');
}

/* ---------- Exports ---------- */
function exportCasesCSV(){
  if(!cases.length) return toast('No cases to export');
  const rows=[['id','timestamp','endpoint','strategy','field','mutatedValue','status','timeMs','verdict','error']];
  cases.forEach(c=>rows.push([c.id,c.timestamp,c.endpointName,c.strategy,c.field,JSON.stringify(c.mutatedValue),c.status,c.timeMs,c.verdict,c.error||'']));
  download('castone-test-cases.csv', rows.map(r=>r.map(csvCell).join(',')).join('\n'), 'text/csv');
}
function exportCasesJSON(){ download('castone-test-cases.json', JSON.stringify(cases,null,2), 'application/json'); }
function exportFindingsCSV(){
  if(!findings.length) return toast('No findings to export');
  const rows=[['severity','type','title','endpoint','url','evidence','recommendation','timestamp']];
  findings.forEach(f=>rows.push([f.severity,f.type,f.title,f.endpointName,f.endpointUrl,f.evidence,f.recommendation,f.timestamp]));
  download('castone-findings-report.csv', rows.map(r=>r.map(csvCell).join(',')).join('\n'), 'text/csv');
}
function exportFindingsJSON(){ download('castone-findings-report.json', JSON.stringify(findings,null,2), 'application/json'); }
function exportAllData(){ download('castone-backup.json', JSON.stringify({endpoints,cases,findings,runs,bugs,exportedAt:new Date().toISOString()},null,2), 'application/json'); toast('⬇ Backup downloaded'); }

/* ---------- Demo API view ---------- */
function saveBugs(){
  bugs={ age:$('bug_age').checked, sqli:$('bug_sqli').checked, crash:$('bug_crash').checked,
         leak:$('bug_leak').checked, slow:$('bug_slow').checked, xss:$('bug_xss').checked };
  persistAll(); toast('🐛 Demo vulnerabilities updated');
}
function renderDemoView(){
  $('bug_age').checked=bugs.age; $('bug_sqli').checked=bugs.sqli; $('bug_crash').checked=bugs.crash;
  $('bug_leak').checked=bugs.leak; $('bug_slow').checked=bugs.slow; $('bug_xss').checked=bugs.xss;
  const sel=$('manualEndpoint');
  sel.innerHTML = endpoints.length ? endpoints.map(ep=>`<option value="${ep.id}">${esc(ep.method)} ${esc(ep.name)}</option>`).join('') : '<option value="">— Load demo endpoints first —</option>';
}
function loadDemoEndpoints(){
  const demo=[
    {id:'demo-users',name:'Create User (Demo)',method:'POST',url:'demo://users',timeout:5000,expected:201,desc:'Creates a user. Vulnerable to missing age validation, SQLi & XSS reflection.',authType:'none',authValue:'',headers:{'Content-Type':'application/json'},query:{},body:'{"name":"Alice","age":25,"email":"alice@example.com"}'},
    {id:'demo-products',name:'List Products (Demo)',method:'GET',url:'demo://products',timeout:5000,expected:200,desc:'Lists products with pagination.',authType:'none',authValue:'',headers:{},query:{page:'1',limit:'10'},body:''},
    {id:'demo-login',name:'Login (Demo)',method:'POST',url:'demo://login',timeout:5000,expected:200,desc:'Login with username/password. Vulnerable to SQLi bypass.',authType:'none',authValue:'',headers:{'Content-Type':'application/json'},query:{},body:'{"username":"admin","password":"secret123"}'},
    {id:'demo-search',name:'Search (Demo)',method:'GET',url:'demo://search',timeout:5000,expected:200,desc:'Search products by query string.',authType:'none',authValue:'',headers:{},query:{q:'mouse'},body:''},
  ];
  demo.forEach(d=>{ if(!endpoints.some(e=>e.id===d.id)) endpoints.unshift(d); });
  selectedEpId='demo-users';
  persistAll(); renderEndpoints(); renderFuzzTargets(); updateSidebar();
  toast('✅ Demo endpoints loaded ('+demo.length+')');
}
async function manualRequest(){
  const ep=endpoints.find(e=>e.id===$('manualEndpoint').value);
  if(!ep){ toast('Load demo endpoints first'); return; }
  const raw=$('manualBody').value.trim();
  let body=null, query={};
  if(raw){
    try{ const parsed=JSON.parse(raw); if(['GET','HEAD'].includes(ep.method)) query=parsed; else body=parsed; }
    catch(e){ raw.split('\n').forEach(l=>{ const i=l.indexOf('='); if(i>0) query[l.slice(0,i).trim()]=l.slice(i+1).trim(); }); }
  }
  const res=await executeRequest(ep, body, Object.assign({},ep.query,query), ep.headers, ep.timeout);
  $('manualResponse').textContent = '→ '+ep.method+' '+res.url+'\n← HTTP '+res.status+' ('+fmtTime(res.timeMs)+')\n\n'+JSON.stringify(res.body,null,2)+(res.error?'\n\nError: '+res.error:'');
}

/* ---------- Init ---------- */
function seedIfEmpty(){
  if(!endpoints.length) loadDemoEndpoints();
}
function init(){
  // restore bug toggles
  // ensure demo endpoints exist on first run
  seedIfEmpty();
  renderEndpoints(); renderFuzzTargets(); renderCases(); renderReports(); renderDashboard(); renderDemoView(); toggleAuthFields();
  updateSidebar();
  // keyboard: Esc closes modal
  document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeModal(); });
}
document.addEventListener('DOMContentLoaded', init);
