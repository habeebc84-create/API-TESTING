"use strict";
const $ = selector => document.querySelector(selector);
const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, character => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
})[character]);
const pretty = value => JSON.stringify(value, null, 2);
const methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const demos = [
  {id:"users", name:"Create user", method:"POST", path:"/users", body:{name:"Alex",age:24,active:true}, headers:{}, query:{}, auth:"None"},
  {id:"inventory", name:"Find inventory", method:"GET", path:"/inventory", body:{}, headers:{}, query:{limit:10}, auth:"None"}
];
let stored;
try { stored = JSON.parse(localStorage.getItem("castone-workbench") || "{}"); } catch { stored = {}; }
const state = {endpoints:stored.endpoints || demos, runs:stored.runs || [], view:"overview", endpoint:"users", report:"", busy:false, run:null};
const labels = {overview:"Overview", endpoints:"Endpoints", runner:"Test runner", reports:"Reports", docs:"Guide"};
const save = () => {
  try { localStorage.setItem("castone-workbench", JSON.stringify({endpoints:state.endpoints,runs:state.runs})); }
  catch { alert("Browser storage is unavailable or full. This session can still export results."); }
};
const stats = (label,value) => `<div class="card stat"><span>${label}</span><strong>${value}</strong></div>`;
const tag = text => `<span class="tag" data-value="${escapeHTML(text)}">${escapeHTML(text)}</span>`;
const options = (items, current) => items.map(([id,name]) => `<option value="${escapeHTML(id)}" ${id === current ? "selected" : ""}>${escapeHTML(name)}</option>`).join("");
const endpointOptions = () => options(state.endpoints.map(e => [e.id, `${e.method} ${e.path} · ${e.name}`]),state.endpoint);
const heading = (title,desc) => `<div class="heading"><div><h1>${title}</h1><p>${desc}</p></div></div>`;
const findings = run => run.cases.filter(item => item.severity);
const when = iso => new Date(iso).toLocaleString();
function overview(){
  const cases = state.runs.flatMap(run => run.cases);
  const endpoint = state.endpoints.find(item => item.id === state.endpoint) || state.endpoints[0];
  return `<div class="heading overview-heading"><div><h1>Overview</h1><p>Configure mock endpoints, run suites, and review responses.</p></div><button class="outline" data-view="endpoints">Manage endpoints</button></div>
  <section class="launch">
    <div class="launch-copy"><h2>Start a test run</h2><p>Check how an endpoint handles missing fields, boundary values, and unexpected types.</p>
    <button ${endpoint ? `data-launch="${escapeHTML(endpoint.id)}"` : 'data-view="endpoints"'}>${endpoint ? "Configure run" : "Add an endpoint"}</button></div>
    <div class="request-preview">${endpoint ? `<div class="preview-heading"><span>REQUEST PREVIEW</span><span>JSON</span></div><div class="preview-route">${tag(endpoint.method)} <code>${escapeHTML(endpoint.path)}</code></div><pre>${escapeHTML(pretty(requestData(endpoint).baseline))}</pre>` : '<div class="preview-heading">REQUEST PREVIEW</div><p class="preview-empty">Select a saved endpoint to preview a request.</p>'}</div>
  </section>
  <div class="stats-strip">${stats("Saved endpoints",state.endpoints.length)}${stats("Completed runs",state.runs.length)}${stats("Executed cases",cases.length)}${stats("Findings",cases.filter(item=>item.severity).length)}</div>
  <div class="activity">
    <section class="card"><div class="panel-head"><h2>Recent runs</h2>${state.runs.length ? '<button class="link-button" data-view="reports">All reports</button>' : ''}</div>
    ${state.runs.length ? `<div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Run time</th><th>Cases</th><th>Findings</th><th><span class="sr-only">Report</span></th></tr></thead><tbody>${state.runs.slice(0,6).map(r=>`<tr><td>${tag(r.endpoint.method)} <code>${escapeHTML(r.endpoint.path)}</code></td><td>${when(r.started)}</td><td>${r.cases.length}</td><td>${findings(r).length}</td><td><button class="link-button" data-report="${r.id}">Open</button></td></tr>`).join("")}</tbody></table></div>` : '<div class="empty activity-empty"><strong>No test runs yet</strong><span>Completed runs and findings will appear here.</span></div>'}</section>
    <section class="card"><div class="panel-head"><h2>Saved endpoints</h2></div>
    ${state.endpoints.length ? `<div class="endpoint-list">${state.endpoints.slice(0,5).map(item=>`<button class="endpoint-row" data-launch="${escapeHTML(item.id)}" aria-label="Configure run for ${escapeHTML(item.name)}">${tag(item.method)} <code>${escapeHTML(item.path)}</code><span>${escapeHTML(item.name)}</span></button>`).join("")}</div>` : '<p class="empty activity-empty">No endpoints saved.</p>'}</section>
  </div>`;
}
function endpoints(){
  const e = state.endpoints.find(item => item.id === state.endpoint) || {name:"",method:"POST",path:"",headers:{},query:{},body:{},auth:"None"};
  return `${heading("Endpoints","Save request configurations in this browser.")}<div class="grid two"><section class="card"><div class="bar"><h2>Saved endpoints</h2><button class="outline" id="new">New endpoint</button></div>
  <div class="table-wrap"><table><tbody>${state.endpoints.map(item=>`<tr><td>${tag(item.method)} ${escapeHTML(item.path)}</td><td><button class="outline" data-endpoint="${escapeHTML(item.id)}">${escapeHTML(item.name)}</button></td></tr>`).join("")}</tbody></table></div>
  <label class="field">Import OpenAPI JSON<input id="import" type="file" accept=".json,application/json"></label><p id="import-message" role="status"></p></section>
  <form class="card" id="endpoint-form"><h2>${e.id ? "Edit endpoint" : "New endpoint"}</h2><label class="field">Name<input name="name" required maxlength="80" value="${escapeHTML(e.name)}"></label>
  <div class="grid two"><label class="field">Method<select name="method">${options(methods.map(m=>[m,m]),e.method)}</select></label><label class="field">Mock path<input name="path" required placeholder="/users" value="${escapeHTML(e.path)}"></label></div>
  <label class="field">Authentication scheme<select name="auth">${options(["None","Bearer","API key","Basic"].map(m=>[m,m]),e.auth)}</select></label>
  ${["headers","query","body"].map(key=>`<label class="field">${{headers:"Headers",query:"Query parameters",body:"Request body"}[key]} (JSON object)<textarea name="${key}">${escapeHTML(pretty(e[key]))}</textarea></label>`).join("")}
  <p id="message" role="status"></p><div class="actions"><button>Save endpoint</button><button type="button" class="outline" id="check">Check configuration</button>${e.id ? '<button type="button" class="outline" id="delete">Delete</button>' : ""}</div></form></div>`;
}
function readEndpoint(){
  const data = new FormData($("#endpoint-form"));
  const name = data.get("name").trim(), path = data.get("path").trim();
  if (!name || !/^\/(?!\/)[^?#\s]*$/.test(path)) throw Error("Enter a name and a relative path such as /users.");
  const item = {id:state.endpoint || crypto.randomUUID(),name,path,method:data.get("method"),auth:data.get("auth")};
  for (const key of ["headers","query","body"]) {
    let value;
    try { value = JSON.parse(data.get(key) || "{}"); } catch { throw Error(`Enter valid JSON in ${key}.`); }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw Error(`${key} must be a JSON object.`);
    item[key] = value;
  }
  return item;
}
function requestData(endpoint){
  return ["GET","DELETE"].includes(endpoint.method) ? {location:"query",baseline:endpoint.query} : {location:"body",baseline:endpoint.body};
}
function suite(endpoint,count,seed){
  const {baseline} = requestData(endpoint);
  const fields = Object.keys(baseline);
  let rng = seed >>> 0;
  const next = () => (rng = (Math.imul(1664525,rng) + 1013904223) >>> 0);
  const variants = [
    ["Missing field",(_,obj,key)=>delete obj[key]], ["Null",()=>null], ["Empty string",()=>""],
    ["Zero",()=>0], ["Negative number",()=>-1], ["Large number",()=>Number.MAX_SAFE_INTEGER],
    ["Boolean",()=>Boolean(next()%2)], ["Nested object",()=>({sample:true})],
    ["Array",()=>[]], ["Unicode",()=>"Résumé • 東京"], ["Random text",()=>`sample-${next().toString(36)}`],
    ["Random number",()=>next()%1000], ["Long text",()=>"a".repeat(256)]
  ];
  return Array.from({length:count},(_,index)=>{
    const input = structuredClone(baseline);
    if (!index) return {label:"Baseline",input,expected:"2xx"};
    const field = fields[Math.floor((index-1)/variants.length)%fields.length] || "sample";
    const [label,mutate] = variants[(index-1)%variants.length];
    if (label === "Missing field") mutate(null,input,field);
    else Object.defineProperty(input,field,{value:mutate(),enumerable:true,configurable:true,writable:true});
    return {label:`${field} · ${label}`,input,expected:isValid(baseline,input) ? "2xx" : "4xx"};
  });
}
function isValid(baseline,input){
  return Object.keys(input).length === Object.keys(baseline).length && Object.entries(baseline).every(([key,value])=>{
    const field = input[key];
    if (!Object.hasOwn(input,key) || typeof field !== typeof value || Array.isArray(field) !== Array.isArray(value)) return false;
    if (typeof value === "string") return Boolean(field?.trim()) && field.length <= 128;
    if (typeof value === "number") return field >= 0 && field <= (key === "age" ? 120 : 10000);
    return (value === null) === (field === null);
  });
}
function simulate(endpoint,test,profile,timeout,index){
  const latency = profile === "faults" && index > 0 && index % 11 === 0 ? 1600 : 36 + (index*29)%109;
  const invalid = test.expected === "4xx";
  let status = invalid ? 422 : 200;
  if (profile === "faults" && invalid && index % 5 === 1) status = 500;
  if (profile === "faults" && invalid && index % 5 === 2) status = 200;
  if (latency > timeout) status = 0;
  const issue = status === 0 ? ["Medium","Timeout","Review slow operations and deadline handling."] :
    status >= 500 ? ["High","Server error","Validate input before passing it to application logic."] :
    invalid && status < 300 ? ["Medium","Invalid input accepted","Apply validation consistently to all request fields."] : [];
  const {location} = requestData(endpoint);
  return {...test,status,duration:Math.min(latency,timeout),severity:issue[0],finding:issue[1],recommendation:issue[2],
    request:{method:endpoint.method,path:endpoint.path,headers:endpoint.headers,query:endpoint.query,[location]:test.input,auth:endpoint.auth},
    response:status === 0 ? {error:"Simulated request timed out"} : status === 500 ? {error:"Simulated internal error"} : status === 422 ? {error:"Input failed validation"} : {ok:true}};
}
function caseTable(run,onlyFindings=false){
  const rows = run.cases.map((item,index)=>({item,index})).filter(({item})=>!onlyFindings || item.severity);
  return rows.length ? `<div class="table-wrap"><table><thead><tr><th>Case</th><th>Expected</th><th>Actual</th><th>Latency</th><th>Finding</th><th></th></tr></thead><tbody>${rows.map(({item,index})=>`<tr><td>${escapeHTML(item.label)}</td><td>${item.expected}</td><td>${tag(item.status || "Timeout")}</td><td>${item.duration} ms</td><td class="${item.severity ? "issue" : "ok"}">${escapeHTML(item.severity ? `${item.severity} · ${item.finding}` : "As expected")}</td><td><button class="outline" data-case="${index}" data-run="${run.id}">Details</button></td></tr>`).join("")}</tbody></table></div>` : '<div class="empty">No cases to display.</div>';
}
function runner(){
  return `${heading("Test runner","Run reproducible input suites against a built-in mock API.")}<div class="grid two"><form class="card" id="runner-form"><h2>Suite settings</h2><label class="field">Endpoint<select name="endpoint" required>${endpointOptions()}</select></label><label class="field">Mock behavior<select name="profile"><option value="faults">Simulated faults</option><option value="strict">Strict validation</option></select></label><div class="grid two"><label class="field">Cases<input name="count" type="number" min="1" max="100" value="16" required></label><label class="field">Seed<input name="seed" type="number" min="0" max="4294967295" value="42" required></label><label class="field">Timeout (ms)<input name="timeout" type="number" min="50" max="10000" value="1000" required></label><label class="field">Rate (cases/sec)<input name="rate" type="number" min="1" max="50" value="20" required></label></div>
  <button ${state.busy || !state.endpoints.length ? "disabled" : ""}>Run suite</button></form><section class="card"><h2>Execution progress</h2><div id="progress" aria-live="polite">${progress()}</div></section></div><section class="card"><h2>Executed cases</h2><div id="cases">${state.run ? caseTable(state.run) : '<div class="empty">Run a suite to see individual inputs and responses.</div>'}</div></section>`;
}
function progress(){
  const run = state.run;
  return run ? `<p>${state.busy ? "Running" : "Completed"} · ${run.cases.length} of ${run.settings.count} cases</p><progress value="${run.cases.length}" max="${run.settings.count}"></progress><div class="bar progress-footer"><span>${findings(run).length} findings</span>${state.busy ? "" : `<button class="link-button" data-report="${run.id}">Open report</button>`}</div>` : '<div class="empty">Choose an endpoint and run a suite to see progress here.</div>';
}
async function runSuite(settings, endpoint){
  if (state.busy || !endpoint) return;
  state.endpoint = endpoint.id;
  const run = {id:crypto.randomUUID(),started:new Date().toISOString(),endpoint:structuredClone(endpoint),settings,cases:[]};
  state.busy = true;
  state.run = run;
  const button = $("#runner-form button");
  if (button) button.disabled = true;
  for (const [index,test] of suite(endpoint,settings.count,settings.seed).entries()){
    await new Promise(resolve=>setTimeout(resolve,1000/settings.rate));
    run.cases.push(simulate(endpoint,test,settings.profile,settings.timeout,index));
    if (state.view === "runner") {
      $("#progress").innerHTML = progress();
      $("#cases").innerHTML = caseTable(run);
    }
  }
  state.busy = false;
  state.runs.unshift(run);
  state.report = run.id;
  save();
  render();
}
function reports(){
  const run = state.runs.find(item=>item.id===state.report) || state.runs[0];
  if (!run) return `${heading("Reports","Review simulated response anomalies and export test evidence.")}<div class="card empty">No completed runs yet.</div>`;
  state.report = run.id;
  const issues = findings(run);
  return `${heading("Reports","Review simulated response anomalies and export test evidence.")}<div class="card no-print" style="margin-top:18px"><label class="field">Test run<select id="run-select">${options(state.runs.map(r=>[r.id,`${r.endpoint.name} · ${when(r.started)}`]),run.id)}</select></label><div class="actions"><button id="csv">Export CSV</button><button id="pdf" class="outline">Print / Save PDF</button><button id="replay" class="outline" ${state.busy ? "disabled" : ""}>Replay suite</button></div></div>
  <div class="grid four">${stats("Cases",run.cases.length)}${stats("High findings",issues.filter(i=>i.severity==="High").length)}${stats("Medium findings",issues.filter(i=>i.severity==="Medium").length)}${stats("Average latency",Math.round(run.cases.reduce((sum,i)=>sum+i.duration,0)/run.cases.length)+" ms")}</div>
  <section class="card"><h2>Run summary</h2><p>${tag(run.endpoint.method)} <code>${escapeHTML(run.endpoint.path)}</code> · ${when(run.started)} · Seed ${run.settings.seed} · ${run.settings.profile === "faults" ? "Simulated faults" : "Strict validation"}</p><p>${issues.length ? "Review the mock findings below. Case details include the input, response, and recommended corrective action." : "All mock responses matched the expected status classes."}</p><h3>Findings</h3>${caseTable(run,true)}
  ${issues.length ? `<h3 style="margin-top:18px">Recommended fixes</h3><ul>${[...new Set(issues.map(i=>i.recommendation))].map(item=>`<li>${escapeHTML(item)}</li>`).join("")}</ul>` : ""}</section><section class="card" style="margin-top:16px"><h2>All cases</h2>${caseTable(run)}</section>`;
}
function docs(){
  return `${heading("Quick guide","A browser-based demo for the three CASTONE modules.")}<div class="grid three"><section class="card"><h2>Configure an endpoint</h2><p>Use a sample or save a mock path with JSON headers, query parameters, and body. Auth is recorded as a scheme. OpenAPI JSON import reads supported methods, paths and examples.</p></section><section class="card"><h2>Run an input suite</h2><p>The mock evaluates query values for GET and DELETE, and the JSON body for other methods. Strict validation models expected behavior. Simulated faults introduce server errors, invalid input acceptance and timeouts.</p></section><section class="card"><h2>Inspect and replay</h2><p>Review responses and recommendations in Reports. Replay uses the saved endpoint snapshot and seed. CSV includes request and response data. Use the browser print dialog to save as PDF.</p></section></div><section class="card"><h2>Data and timing</h2><p>Endpoint configurations and run history stay in this browser. Execution is local. All response codes and latency values come from the mock.</p></section>`;
}
function render(){
  $("#breadcrumb").textContent = `Workspace / ${labels[state.view]}`;
  document.querySelectorAll("nav button").forEach(button => button.setAttribute("aria-current",button.dataset.view===state.view ? "page" : "false"));
  $("#main").innerHTML = {overview,endpoints,runner,reports,docs}[state.view]();
  $("#main").querySelector("h1").tabIndex = -1;
}
function go(view){state.view=view;render();$("#main h1").focus({preventScroll:true});window.scrollTo(0,0);}
function exportCsv(run){
  const cell = value => {
    const text = String(value ?? "");
    return '"' + (/^[=+@\-\t\r\n]/.test(text) ? "'" : "") + text.replaceAll('"','""') + '"';
  };
  const lines = [["Method","Path","Case","Expected","Status","Latency (ms)","Severity","Finding","Recommendation","Request","Response"],
    ...run.cases.map(i=>[run.endpoint.method,run.endpoint.path,i.label,i.expected,i.status || "Timeout",i.duration,i.severity,i.finding,i.recommendation,JSON.stringify(i.request),JSON.stringify(i.response)])];
  const url = URL.createObjectURL(new Blob([lines.map(row=>row.map(cell).join(",")).join("\r\n")],{type:"text/csv;charset=utf-8"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = `castone-${run.id}.csv`;
  link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
document.addEventListener("click",event=>{
  const button = event.target.closest("button");
  if (!button) return;
  const {view,endpoint,report,run,launch,case:caseIndex} = button.dataset;
  if (view) go(view);
  if (launch) {state.endpoint=launch;go("runner");$('[name="endpoint"]').focus();}
  if (endpoint) {state.endpoint=endpoint;render();}
  if (report) {state.report=report;go("reports");}
  if (run) {
    const selected = state.runs.find(item=>item.id===run) || state.run;
    $("#detail-text").textContent = pretty(selected.cases[Number(caseIndex)]);
    $("#details").showModal();
  }
  if (button.id === "new") {state.endpoint="";render();$('[name="name"]').focus();}
  if (button.id === "check") {
    try {const item=readEndpoint(); $("#message").classList.remove("error");$("#message").textContent=`Mock ready · ${item.method} ${item.path}`;}
    catch(error) {$("#message").classList.add("error");$("#message").textContent=error.message;}
  }
  if (button.id === "delete" && confirm("Delete this saved endpoint? Existing run reports will be kept.")) {
    state.endpoints = state.endpoints.filter(item=>item.id!==state.endpoint);
    state.endpoint = state.endpoints[0]?.id || "";
    save();render();
  }
  if (["pdf","csv","replay"].includes(button.id)){
    const selected = state.runs.find(item=>item.id===state.report);
    if (button.id==="pdf") print();
    if (button.id==="csv") exportCsv(selected);
    if (button.id==="replay") {go("runner");runSuite(selected.settings,selected.endpoint);}
  }
});
document.addEventListener("submit",event=>{
  if (event.target.method === "dialog") return;
  event.preventDefault();
  if (event.target.id==="endpoint-form") {
    try {
      const item=readEndpoint(), exists=state.endpoints.some(e=>e.id===item.id);
      state.endpoints=exists ? state.endpoints.map(e=>e.id===item.id ? item : e) : [...state.endpoints,item];
      state.endpoint=item.id;save();render();$("#message").textContent="Endpoint saved.";
    } catch(error) {$("#message").classList.add("error");$("#message").textContent=error.message;}
  }
  if (event.target.id==="runner-form"){
    const data = new FormData(event.target);
    runSuite({seed:Number(data.get("seed")),count:Number(data.get("count")),timeout:Number(data.get("timeout")),rate:Number(data.get("rate")),profile:data.get("profile")},state.endpoints.find(item=>item.id===data.get("endpoint")));
  }
});
document.addEventListener("change",async event=>{
  if(event.target.id==="run-select"){state.report=event.target.value;render();}
  if(event.target.id!=="import" || !event.target.files.length) return;
  try {
    const spec=JSON.parse(await event.target.files[0].text());
    if(!spec.paths || typeof spec.paths!=="object") throw Error("Choose an OpenAPI or Swagger JSON document with a paths object.");
    const imported=[];
    for(const [path,definition] of Object.entries(spec.paths)){
      if(!path.startsWith("/") || path.startsWith("//") || !definition) continue;
      for(const method of methods){
        const operation=definition[method.toLowerCase()];
        if(!operation) continue;
        const media=operation.requestBody?.content?.["application/json"];
        const body=media?.example ?? media?.schema?.example ?? {};
        const query=Object.fromEntries([...(definition.parameters||[]),...(operation.parameters||[])].filter(parameter=>parameter.in==="query" && parameter.name).map(parameter=>[parameter.name,parameter.example ?? parameter.schema?.default ?? parameter.default ?? "sample"]));
        imported.push({id:crypto.randomUUID(),name:String(operation.summary || operation.operationId || path),path,method,body:body && typeof body==="object" && !Array.isArray(body) ? body : {},query,headers:{},auth:"None"});
      }
    }
    if(!imported.length) throw Error("The file contains no supported REST operations.");
    state.endpoints.push(...imported);state.endpoint=imported[0].id;save();render();
    $("#import-message").textContent=`Imported ${imported.length} endpoints.`;
  } catch(error){if($("#import-message")) $("#import-message").textContent=error.message;}
});
render();
