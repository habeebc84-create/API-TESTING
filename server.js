/*
 * Optional, loopback-only CORS proxy for APIs you are authorized to test.
 * Run: npm install && npm run proxy
 * Target format: http://127.0.0.1:3001/proxy?url=https%3A%2F%2Fapi.example.com%2Fusers
 * Node 18+ provides the native fetch implementation used below.
 */
'use strict';
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = Number(process.env.PORT || 3001);
const HOST = process.env.HOST || '127.0.0.1';
const allowedOrigins = new Set(['http://localhost:8000','http://127.0.0.1:8000','http://localhost:8080','http://127.0.0.1:8080', ...(process.env.CASTONE_ALLOWED_ORIGINS || '').split(',')].map(s => s.trim()).filter(Boolean));
const allowedMethods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const blockedHeaders = new Set(['host', 'content-length', 'connection', 'transfer-encoding', 'accept-encoding', 'origin', 'referer']);

app.disable('x-powered-by');
app.use(cors({
  origin(origin, callback) {
    // No-Origin clients (curl/scripts) are allowed; browser origins must be explicitly trusted.
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CASTONE proxy. Add it to CASTONE_ALLOWED_ORIGINS.'));
  },
  methods: [...allowedMethods],
  allowedHeaders: true,
  maxAge: 600
}));
app.use(express.json({ limit: '1mb', strict: false }));

app.all('/proxy', async (req, res) => {
  const targetValue = typeof req.query.url === 'string' ? req.query.url : '';
  if (!targetValue) return res.status(400).json({ error: 'Missing ?url= target parameter' });
  if (!allowedMethods.has(req.method)) return res.status(405).json({ error: 'HTTP method is not supported by this proxy' });

  let target;
  try {
    target = new URL(targetValue);
    if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Only http and https targets are supported');
    if (target.username || target.password) throw new Error('Put credentials in the Authorization header, not the URL');
  } catch (error) {
    return res.status(400).json({ error: 'Invalid target URL: ' + error.message });
  }

  // Query parameters added to the proxy URL by CASTONE (including fuzzed values)
  // are forwarded to the upstream target, not left on the proxy request.
  for (const [key, value] of Object.entries(req.query)) {
    if (key === 'url') continue;
    for (const item of Array.isArray(value) ? value : [value]) target.searchParams.set(key, String(item));
  }

  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (!blockedHeaders.has(key.toLowerCase()) && value !== undefined) headers[key] = value;
  }
  const options = { method: req.method, headers, redirect: 'manual', signal: AbortSignal.timeout(60000) };
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && req.body !== undefined) {
    options.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  }

  try {
    const upstream = await fetch(target, options);
    const bytes = Buffer.from(await upstream.arrayBuffer());
    const contentType = upstream.headers.get('content-type');
    if (contentType) res.setHeader('content-type', contentType);
    const cacheControl = upstream.headers.get('cache-control');
    if (cacheControl) res.setHeader('cache-control', cacheControl);
    res.status(upstream.status).send(bytes);
  } catch (error) {
    const status = error.name === 'TimeoutError' || error.name === 'AbortError' ? 504 : 502;
    res.status(status).json({ error: status === 504 ? 'Upstream request timed out' : 'Proxy request failed: ' + error.message });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true, service: 'castone-proxy' }));
app.use((error, _req, res, next) => {
  if (error.message && error.message.startsWith('Origin not allowed')) return res.status(403).json({ error: error.message });
  return next(error);
});
app.listen(PORT, HOST, () => console.log(`CASTONE proxy listening on http://${HOST}:${PORT}`));
