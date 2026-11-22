'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
function loadApp() {
  const elements = new Map();
  const document = {
    addEventListener() {},
    getElementById(id) { if (!elements.has(id)) elements.set(id, { textContent: '', innerHTML: '', classList: { add() {}, remove() {}, toggle() {} } }); return elements.get(id); },
    querySelectorAll() { return []; },
    createElement() { return { click() {}, style: {}, classList: { add() {} } }; }
  };
  const context = {
    document, localStorage: { getItem() { return null; }, setItem() {} },
    window: { scrollTo() {} }, navigator: {}, performance: { now: () => Date.now() },
    console, Date, Math, JSON, Object, Array, String, Number, Boolean, RegExp, Error,
    setTimeout, clearTimeout, setInterval, clearInterval, AbortController, AbortSignal,
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    unescape, encodeURIComponent, decodeURIComponent
  };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: 'app.js' });
  vm.runInContext('globalThis.testHooks = { get bugs(){ return bugs; }, set bugs(value){ bugs = value; } };', context);
  return context;
}

test('demo users accept a negative age in vulnerable mode and reject it after the fix', () => {
  const app = loadApp();
  const body = { name: 'Alice', age: -1, email: 'alice@example.com' };
  assert.equal(app.handleDemo('POST', 'users', {}, body).status, 201);
  app.testHooks.bugs.age = false;
  assert.equal(app.handleDemo('POST', 'users', {}, body).status, 400);
  assert.equal(app.handleDemo('POST', 'users', {}, { ...body, age: 25 }).status, 201);
});

test('query fuzz reaches the demo search API vulnerability paths', () => {
  const app = loadApp();
  const xss = app.handleDemo('GET', 'search', { q: '<script>alert(1)</script>' }, null);
  assert.equal(xss.status, 200);
  assert.match(xss.body.rendered, /<script>/);
  const crash = app.handleDemo('GET', 'search', { q: '😀' }, null);
  assert.equal(crash.status, 500);
});


test('SQL injection demo payload is detected and reflected independently of crash fuzzing', () => {
  const app = loadApp();
  const response = app.handleDemo('POST', 'login', {}, { username: "' OR '1'='1", password: 'x' });
  assert.equal(response.status, 200);
  assert.match(response.body.warning, /SQLi bypass succeeded/);
  const findings = app.analyzeCase({ id:'sqli1', strategy:'special-chars', field:'body.username', mutatedValue:"' OR '1'='1", input:{username:"' OR '1'='1"}, status:response.status, timeMs:20, responseBody:response.body, error:null }, {id:'login',name:'Login',url:'demo://login',expected:200});
  assert.ok(findings.some(f => f.type === 'SQL Injection Risk'));
});

test('mutation generation is deterministic for the same seed and honors strategies', () => {
  const app = loadApp();
  const endpoint = { body: '{"age":25,"name":"Alice"}', query: 'page=1', headers: 'X-Test: ok' };
  const strategies = { boundary:true, null:true, type:true, random:true, special:true, mutation:true };
  const a = app.generateMutations(endpoint, strategies, app.mulberry32(42), true, true);
  const b = app.generateMutations(endpoint, strategies, app.mulberry32(42), true, true);
  assert.ok(a.length > 30);
  assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)));
  assert.ok(a.some(m => m.strategy === 'query-fuzz'));
  assert.ok(a.some(m => m.strategy === 'header-fuzz'));
});

test('analyzer flags plausible invalid acceptance but not a valid zero boundary', () => {
  const app = loadApp();
  const ep = { id:'e1', name:'users', url:'demo://users', expected:201 };
  const base = { id:'c1', status:201, timeMs:20, responseBody:{ok:true}, input:{age:0}, error:null, endpointId:'e1' };
  assert.equal(app.analyzeCase({ ...base, strategy:'boundary', field:'body.age', mutatedValue:0 }, ep).some(f => f.type === 'Missing Validation'), false);
  assert.equal(app.analyzeCase({ ...base, strategy:'boundary', field:'body.age', mutatedValue:-1 }, ep).some(f => f.type === 'Missing Validation'), true);
});

test('analyzer reports server errors, information disclosure, and reflected XSS', () => {
  const app = loadApp();
  const ep = { id:'e1', name:'users', url:'demo://users', expected:201 };
  const findings = app.analyzeCase({ id:'c1', strategy:'special-chars', field:'body.name', mutatedValue:'<script>x</script>', input:{name:'<script>x</script>'}, status:500, timeMs:25, responseBody:{detail:'NullPointerException at com.example.User', rendered:'<script>x</script>'}, error:null }, ep);
  assert.ok(findings.some(f => f.type === 'Server Error (5xx)'));
  assert.ok(findings.some(f => f.type === 'Information Disclosure'));
  assert.ok(findings.some(f => f.type === 'Cross-Site Scripting Risk'));
});

test('missing-value analyzer safely renders undefined payloads instead of crashing', () => {
  const app = loadApp();
  const ep = { id:'e1', name:'users', url:'https://example.test/users', expected:200 };
  const findings = app.analyzeCase({ id:'c1', strategy:'null/missing', field:'body.name', mutatedValue:undefined, input:{}, status:200, timeMs:10, responseBody:{ok:true}, error:null }, ep);
  assert.ok(findings.some(f => f.type === 'Missing Validation'));
  assert.match(findings.find(f => f.type === 'Missing Validation').evidence, /undefined/);
});

test('mobile navigation exposes all views and accessible labels', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  assert.match(html, /<nav class="mobile-nav" aria-label="Main navigation">/);
  for (const view of ['dashboard','endpoints','fuzz','reports','demoapi','help']) {
    assert.match(html, new RegExp(`class="mobile-nav-item[^\"]*" data-view="${view}"`));
  }
});
