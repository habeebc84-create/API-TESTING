# CASTONE — Automated API Testing Tool Using Fuzz Testing

> **Automated API Testing Using Fuzz Testing** is a software testing approach designed to evaluate the reliability, robustness, and security of Application Programming Interfaces (APIs). Traditional testing uses predefined inputs, whereas fuzz testing generates random, invalid, unexpected, and boundary-value inputs to identify defects.

This repository implements the complete **CASTONE 3-Module** system described in the project presentation:

| Module | Name | What it does |
|--------|------|--------------|
| **1** | API Configuration & Endpoint Management | Add/manage REST endpoints, headers, query params, bodies, authentication, OpenAPI import, connectivity validation |
| **2** | Automated Fuzz Testing Engine | Generates random, malformed, boundary-value & mutated inputs; executes requests with timeouts & rate limits; records everything |
| **3** | Vulnerability Detection & Reporting | Detects 5xx, timeouts, missing validation, injection & info leaks; classifies severity; exports CSV / JSON / PDF reports |

---

## 🚀 Quick Start (no install needed)

**Option A — Open directly:** open `index.html` in any modern browser. Everything runs client-side. The built-in **Demo Target API** (`demo://users`, `demo://products`, `demo://login`, `demo://search`) lets you demo fuzzing instantly with intentional vulnerabilities you can toggle on/off.

**Option B — Local server (recommended):**
```bash
npx serve .          # or
python3 -m http.server 8000
```
Then open http://localhost:8000

**Option C — Deploy to Vercel (1-click):**
Push this repo to GitHub and import it in [Vercel](https://vercel.com). No build step required — `vercel.json` is included. Your app will be live at `https://<project>.vercel.app`.

**Option D — CORS-free real-API testing:** run the optional proxy so browser CORS doesn't block real APIs:
```bash
npm install                              # one-time
npm run proxy                           # loopback proxy on http://127.0.0.1:3001
```
Then set an endpoint URL to `http://127.0.0.1:3001/proxy?url=<URL-encoded-target-url>`. Example: `http://127.0.0.1:3001/proxy?url=https%3A%2F%2Fapi.example.com%2Fusers`. The proxy binds to loopback, limits browser origins by default, and forwards custom headers and fuzzed query parameters to the target. Add trusted UI origins with `CASTONE_ALLOWED_ORIGINS` if needed (comma-separated, e.g. `CASTONE_ALLOWED_ORIGINS=https://your-preview.example npm run proxy`).

---

## 🎯 60-Second Demo Script (for presentations)

1. **Dashboard → Quick Start Demo** — loads 4 demo endpoints.
2. **Demo Target API** — show the 6 vulnerability toggles (all ON).
3. **Fuzz Engine** — select *Create User (Demo)*, 30 iterations, seed 42 → **Start Fuzz Test**.
4. **Findings & Reports** — show Critical/High findings (500 crash, SQLi, XSS, missing validation) with evidence + recommendations.
5. Turn **all vulnerabilities OFF**, re-run fuzzing → findings drop to ~0. This demonstrates fix verification & regression testing.
6. **Export CSV / Print-PDF** for the report slide.

---

## 🧪 Module 2 — Fuzzing Strategies

| Strategy | Example (for `age` field) |
|----------|---------------------------|
| Boundary values | `-1, 0, 1, 150, 999999, 2147483647` |
| Null / missing / empty | `null`, `""`, field removed |
| Type confusion | `"abc"`, `true`, `[]`, `{}` for a number |
| Random values | random strings, numbers, booleans |
| Special chars / injection | `' OR '1'='1`, `<script>alert(1)</script>`, emoji, 500-char strings |
| JSON mutation | `{}`, `[]`, `null`, whole-body replacement |

Each case records: **input, HTTP status, response body, execution time, verdict, and detected anomalies** — fully reproducible via the seed.

## 📊 Module 3 — Detection Rules

| Rule | Severity |
|------|----------|
| HTTP 5xx server error | Critical / High |
| Timeout / connection failure | High |
| Stack trace / SQL leaked in response | High |
| SQLi / XSS payload reflected | High |
| Invalid input accepted with 2xx (missing validation) | Medium |
| Slow response (>2s) | Medium |
| Inconsistent error format | Low |
| Status mismatch vs expected | Low |

> ⚠️ The proposed system improves test automation and input coverage. It does **not guarantee detection of every vulnerability**; findings must be validated manually. Only test APIs you own or have permission to test.

---

## 📁 Project Structure

```
index.html      — App UI (Dashboard, Module 1/2/3 views, Demo API, Help)
style.css       — Dark modern theme (responsive, print-ready)
app.js          — All logic: store, Demo API simulator, fuzz engine, analyzer, reports
server.js       — Optional loopback-only CORS proxy for real APIs (Node 18+, Express)
package.json    — Optional proxy dependencies and run script
vercel.json     — Vercel deployment config (static, no build)
```

All data (endpoints, cases, findings, runs, and demo bug toggles) is stored in the browser's `localStorage`. Use **Dashboard → Export All Data** to back up as JSON. Run the built-in checks with `npm test`.

## 🔌 Testing Real APIs

1. **Module 1 → New Endpoint** — enter URL, method, headers, auth (Bearer / Basic / API Key), JSON body template.
2. **Validate Connectivity** — confirms reachability & latency.
3. **Import OpenAPI** — paste or upload a Swagger/OpenAPI JSON spec; endpoints are auto-created.
4. **Module 2** — configure iterations, delay, seed & strategies → run.
5. **Module 3** — review findings, filter by severity, export CSV/JSON or print to PDF.

> Browser note: some real APIs block cross-origin requests (CORS). The Demo API always works. For CORS-blocked APIs, use `npm run proxy` (Option D above). The proxy runs on your own machine; browser-based cloud previews cannot reach your machine's `localhost` service.

## 🔮 Future Scope

- AI-assisted analysis: explain failures & suggest fixes
- Coverage-guided fuzzing: prioritize inputs exploring new API behavior
- CI/CD integration: run during builds/deployments
- Advanced auth testing with authorized test accounts
- Regression replay of previously detected failures *(already included)*
- Real-time dashboard & metrics *(already included)*
- GraphQL & multi-format support
- Smart test generation from schemas & response feedback

## 📚 References

1. Atlidakis, V., Godefroid, P., and Polishchuk, M. (2019). *RESTler: Stateful REST API Fuzzing.* IEEE/ACM ICSE.
2. OWASP Foundation. *Web Security Testing Guide.*
3. *RESTLess: Enhancing State-of-the-Art REST API Fuzzing With LLMs.* IEEE Transactions on Services Computing, 2024.
4. Microsoft. *RESTler Fuzzer* — GitHub repository.

## 📄 Presentation Slides

The 12-slide deck (Introduction → Thank You) maps 1:1 to this app: Slides 6–8 = Modules 1–3, Slide 10 = Future Scope, Slide 11 = References. Use the in-app **Help** view and **Executive Summary** for live-demo talking points.
