import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { Agent, fetch } from 'undici';
import { WebSocketServer, WebSocket } from 'ws';
import { safeLookup, assertHostAllowed } from './safe.js';
import {
  toProxy, parseProxyUrl, rewriteHtml, rewriteCss, rewriteJs,
  rewriteRefresh, rewriteLinkHeader, rewriteSetCookie,
} from './rewrite.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const ACCESS_KEY = process.env.ACCESS_KEY || '';
// Tor Browser (Firefox ESR on Windows) user agent. Set USER_AGENT=off to pass the visitor's own UA through,
// or USER_AGENT=<any string> to use your own.
const UA_ENV = process.env.USER_AGENT;
const SPOOF_UA = UA_ENV === 'off' ? null : (UA_ENV || 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0');
const DEBUG = process.env.DEBUG_PROXY === '1';
const MAX_BODY_IN = 50 * 1024 * 1024;
const MAX_REWRITE = 15 * 1024 * 1024;

const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'));
const RUNTIME_JS = fs.readFileSync(path.join(__dirname, 'runtime.js'));

const dispatcher = new Agent({
  connect: { lookup: safeLookup, timeout: 10_000 },
  headersTimeout: 30_000,
  maxHeaderSize: 1024 * 1024, // YouTube etc. send >16KB of headers (UND_ERR_HEADERS_OVERFLOW)
  bodyTimeout: 0,
});

/* ----------------------------------------------------------------- helpers */

const parseCookies = (h = '') =>
  Object.fromEntries(h.split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));

const isHttps = (req) => (req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https';
const authToken = () => crypto.createHmac('sha256', ACCESS_KEY).update('pl-auth').digest('hex');
const safeEq = (a, b) => { const A = Buffer.from(a), B = Buffer.from(b); return A.length === B.length && crypto.timingSafeEqual(A, B); };

function isAuthed(req) {
  if (!ACCESS_KEY) return true;
  const t = parseCookies(req.headers.cookie).__pl_key;
  return !!t && safeEq(t, authToken());
}

function page(res, status, title, body) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(`<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>${title}</title>
<body style="font:16px system-ui;background:#0f1115;color:#e6e6e6;display:grid;place-items:center;min-height:100vh;margin:0"><main style="max-width:560px;padding:24px"><h1 style="font-size:20px">${title}</h1>${body}</main>`);
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

async function readBody(req, limit) {
  const chunks = []; let n = 0;
  for await (const c of req) { n += c.length; if (n > limit) throw Object.assign(new Error('Request body too large'), { status: 413 }); chunks.push(c); }
  return Buffer.concat(chunks);
}

function decode(buf, ct) {
  let label = (/charset=["']?([\w-]+)/i.exec(ct) || [])[1];
  if (!label) label = (/<meta[^>]+charset=["']?([\w-]+)/i.exec(buf.subarray(0, 2048).toString('latin1')) || [])[1] || 'utf-8';
  try { return new TextDecoder(label).decode(buf); } catch { return new TextDecoder('utf-8').decode(buf); }
}

function kindOf(ct, dest) {
  const t = ct.split(';')[0].trim().toLowerCase();
  if (t === 'text/html' || t === 'application/xhtml+xml') return 'html';
  if (t === 'text/css') return 'css';
  if (/^(application|text)\/(x-)?(javascript|ecmascript|jscript)$/.test(t)) return /worker/.test(dest) ? 'jsworker' : 'js';
  return null;
}

/** Real origin hint for root-relative URLs that escaped the /p/ prefix. */
function originHint(req) {
  const ref = req.headers.referer;
  if (ref) {
    try { const u = new URL(ref); const p = parseProxyUrl(u.pathname); if (p) return `${p.scheme}/${p.url.host}`; } catch { /* ignore */ }
  }
  return parseCookies(req.headers.cookie).__pl_o || null;
}

const DROP_RES = new Set([
  'content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'strict-transport-security', 'alt-svc', 'report-to', 'nel', 'clear-site-data', 'public-key-pins',
  'expect-ct', 'permissions-policy', 'content-encoding', 'content-length', 'transfer-encoding',
  'connection', 'keep-alive', 'set-cookie', 'location', 'refresh', 'link', 'referrer-policy',
  'service-worker-allowed', 'origin-agent-cluster', 'document-policy',
]);
const DROP_REQ = new Set([
  'host', 'connection', 'content-length', 'accept-encoding', 'forwarded', 'via', 'x-real-ip',
  'cdn-loop', 'rndr-id', 'true-client-ip', 'priority', 'upgrade-insecure-requests', 'te',
]);

function upstreamHeaders(req, target) {
  const h = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (DROP_REQ.has(k) || k.startsWith('x-forwarded-') || k.startsWith('x-render') || k.startsWith('cf-') || k.startsWith('sec-fetch-')) continue;
    if (SPOOF_UA && (k.startsWith('sec-ch-ua') || k === 'user-agent')) continue; // Chrome client hints would contradict a Firefox UA
    if (k === 'cookie') continue;
    h.set(k, Array.isArray(v) ? v.join(', ') : v);
  }
  if (SPOOF_UA) h.set('user-agent', SPOOF_UA);
  const cookies = (req.headers.cookie || '').split(/;\s*/).filter((c) => c && !/^__pl_(o|key)=/.test(c)).map((c) => c.replace(/^__plh-/, '__Host-'));
  if (cookies.length) h.set('cookie', cookies.join('; '));
  // Origin/Referer must look like the real site, not the proxy.
  const fix = (v) => { try { const u = new URL(v); const p = parseProxyUrl(u.pathname + u.search); return p ? p.url.href : v; } catch { return v; } };
  if (req.headers.referer) h.set('referer', fix(req.headers.referer));
  if (req.headers.origin && req.headers.origin !== 'null') {
    const ref = req.headers.referer && parseProxyUrl((() => { try { return new URL(req.headers.referer).pathname; } catch { return ''; } })());
    h.set('origin', ref ? ref.url.origin : target.origin);
  }
  return h;
}

/* ----------------------------------------------------------------- proxy */

async function proxy(req, res, p, urlObj) {
  const target = p.url;
  if (!/^https?:$/.test(target.protocol)) return page(res, 400, 'Bad request', '<p>Only http(s) targets are supported here.</p>');
  if (!p.hasPath) { res.writeHead(302, { location: req.url.replace(/^(\/p\/[a-z]+\/[^/?#]+)/, '$1/') }); return res.end(); }
  if (target.host === req.headers.host) return page(res, 400, 'Loop detected', '<p>That URL points back at this proxy.</p>');
  try { assertHostAllowed(target.hostname); } catch (e) { return page(res, 403, 'Blocked', `<p>${esc(e.message)}</p>`); }

  const method = req.method;
  const body = (method === 'GET' || method === 'HEAD') ? undefined : await readBody(req, MAX_BODY_IN);
  const ac = new AbortController();
  res.on('close', () => ac.abort());

  let up;
  try {
    up = await fetch(target.href, {
      method, body, headers: upstreamHeaders(req, target), dispatcher,
      redirect: 'manual',            // we hand every redirect back to the browser, rewritten
      signal: ac.signal,
    });
  } catch (e) {
    const cause = e.cause || e;
    console.error(`[upstream error] ${method} ${target.href.slice(0, 200)} -> ${cause.code || cause.message}`);
    if (cause.code === 'PL_BLOCKED') return page(res, 403, 'Blocked', `<p>${esc(cause.message)}</p>`);
    if (ac.signal.aborted) return;
    return page(res, 502, 'Could not reach site', `<p>${esc(target.host)}: ${esc(cause.code || cause.message)}</p>`);
  }

  if (DEBUG && (up.status >= 400)) console.warn(`[upstream ${up.status}] ${method} ${target.href.slice(0, 200)}`);
  const https = isHttps(req);
  const out = {};
  const set = (k, v) => { out[k] = v; };
  for (const [k, v] of up.headers) if (!DROP_RES.has(k)) set(k, v);

  // 1) HTTP redirects: Location on 3xx (and 201 etc.) is resolved against the *upstream* URL
  const loc = up.headers.get('location');
  if (loc) set('location', toProxy(loc, target.href));
  // 2) Refresh header
  const refresh = up.headers.get('refresh');
  if (refresh) set('refresh', rewriteRefresh(refresh, target.href));
  // 3) Link headers (preload etc.)
  const link = up.headers.get('link');
  if (link) set('link', rewriteLinkHeader(link, target.href));
  // cookies: scoped to this origin by path
  const cookies = up.headers.getSetCookie().map((c) => rewriteSetCookie(c, p.scheme, target.host, https));
  set('referrer-policy', 'same-origin');

  const ct = up.headers.get('content-type') || '';
  const kind = kindOf(ct, req.headers['sec-fetch-dest'] || '');
  const bodyless = method === 'HEAD' || [101, 204, 205, 304].includes(up.status) || !up.body;
  const cl = Number(up.headers.get('content-length') || 0);

  if (kind && !bodyless && (!cl || cl <= MAX_REWRITE)) {
    const buf = Buffer.from(await up.arrayBuffer());
    if (buf.length <= MAX_REWRITE) {
      let text = decode(buf, ct);
      if (kind === 'html') {
        text = rewriteHtml(text, target.href);
        cookies.push(`__pl_o=${p.scheme}/${target.host}; Path=/; SameSite=Lax${https ? '; Secure' : ''}`);
      } else if (kind === 'css') text = rewriteCss(text, target.href);
      else if (kind === 'js') text = rewriteJs(text, target.href);
      else if (kind === 'jsworker') text = rewriteJs(text, target.href, { rewriteLocation: false });
      set('content-type', ct.replace(/;?\s*charset=[^;]*/i, '') + '; charset=utf-8');
      if (cookies.length) out['set-cookie'] = cookies;
      res.writeHead(up.status, out);
      return res.end(text);
    }
    if (cookies.length) out['set-cookie'] = cookies;
    res.writeHead(up.status, out);
    return res.end(buf);
  }

  // everything else is streamed untouched
  if (!up.headers.get('content-encoding') && cl) set('content-length', String(cl));
  if (cookies.length) out['set-cookie'] = cookies;
  res.writeHead(up.status, out);
  if (bodyless) return res.end();
  const stream = Readable.fromWeb(up.body);
  stream.on('error', () => res.destroy());
  stream.pipe(res);
}

/* ---------------------------------------------------------------- server */

async function handle(req, res) {
  const u = new URL(req.url, 'http://x');

  if (u.pathname === '/healthz') { res.writeHead(200); return res.end('ok'); }

  if (ACCESS_KEY) {
    const key = u.searchParams.get('key');
    if (key && safeEq(Buffer.from(key).toString('hex'), Buffer.from(ACCESS_KEY).toString('hex'))) {
      res.writeHead(302, {
        'set-cookie': `__pl_key=${authToken()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${isHttps(req) ? '; Secure' : ''}`,
        location: '/',
      });
      return res.end();
    }
    if (!isAuthed(req)) {
      return page(res, 401, 'Access key required',
        '<form method=get action=/><input name=key type=password autofocus placeholder="access key" style="padding:10px;border-radius:8px;border:1px solid #333;background:#181b22;color:inherit"> <button style="padding:10px 14px;border-radius:8px;border:0;background:#4f7cff;color:#fff">Enter</button></form>');
    }
  }

  if (u.pathname === '/' || u.pathname === '/index.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(INDEX_HTML);
  }
  if (u.pathname === '/__pl/runtime.js') {
    res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-cache' });
    return res.end(RUNTIME_JS);
  }
  if (u.pathname === '/__pl/rw' && req.method === 'POST') {
    const code = (await readBody(req, 2 * 1024 * 1024)).toString('utf8');
    let base = 'http://invalid/';
    try { base = new URL(req.headers['x-pl-base']).href; } catch { /* default */ }
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    return res.end(rewriteJs(code, base));
  }
  if (u.pathname === '/go') {
    let v = (u.searchParams.get('url') || '').trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) v = 'https://' + v;
    const dest = toProxy(v, v);
    res.writeHead(302, { location: dest });
    return res.end();
  }

  const p = parseProxyUrl(req.url);
  if (p) return proxy(req, res, p, u);

  // Root-relative URL that escaped the /p/ prefix (e.g. built in a script we couldn't see). Re-route it.
  const hint = originHint(req);
  if (hint) { res.writeHead(307, { location: `/p/${hint}${req.url}`, 'cache-control': 'no-store' }); return res.end(); }
  return page(res, 404, 'Not found', '<p>Go to the <a style="color:#7aa2ff" href="/">start page</a> and enter a URL.</p>');
}

const server = http.createServer({ maxHeaderSize: 128 * 1024 }, (req, res) => { // big cookies from the browser
  handle(req, res).catch((e) => {
    console.error(e);
    if (!res.headersSent) page(res, e.status || 500, 'Proxy error', `<p>${esc(e.message)}</p>`);
    else res.destroy();
  });
});

/* ------------------------------------------------------------- websockets */

server.on('upgrade', (req, socket, head) => {
  const fail = (code = 400) => { socket.write(`HTTP/1.1 ${code} Error\r\nConnection: close\r\n\r\n`); socket.destroy(); };
  if (!isAuthed(req)) return fail(401);
  const p = parseProxyUrl(req.url);
  if (!p) return fail(404);
  const t = p.url;
  const proto = { ws: 'ws:', wss: 'wss:', http: 'ws:', https: 'wss:' }[p.scheme];
  try { assertHostAllowed(t.hostname); } catch { return fail(403); }
  if (t.host === req.headers.host) return fail(400);
  t.protocol = proto;

  const protocols = (req.headers['sec-websocket-protocol'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  const headers = {
    origin: `${proto === 'wss:' ? 'https' : 'http'}://${t.host}`,
    'user-agent': SPOOF_UA || req.headers['user-agent'] || '',
  };
  const cookies = (req.headers.cookie || '').split(/;\s*/).filter((c) => c && !/^__pl_(o|key)=/.test(c)).map((c) => c.replace(/^__plh-/, '__Host-'));
  if (cookies.length) headers.cookie = cookies.join('; ');

  const upstream = new WebSocket(t.href, protocols, { headers, lookup: safeLookup, handshakeTimeout: 15_000 });
  upstream.on('error', () => { if (!socket.destroyed && socket.writable) fail(502); });
  upstream.on('open', () => {
    const wss = new WebSocketServer({ noServer: true, handleProtocols: () => upstream.protocol || false });
    wss.handleUpgrade(req, socket, head, (client) => {
      client.on('message', (d, bin) => { if (upstream.readyState === WebSocket.OPEN) upstream.send(d, { binary: bin }); });
      upstream.on('message', (d, bin) => { if (client.readyState === WebSocket.OPEN) client.send(d, { binary: bin }); });
      const code = (c) => (c >= 1000 && c <= 4999 && ![1004, 1005, 1006, 1015].includes(c) ? c : 1000);
      client.on('close', (c) => upstream.close(code(c)));
      upstream.on('close', (c) => client.close(code(c)));
      client.on('error', () => upstream.terminate());
      upstream.on('error', () => client.terminate());
    });
  });
});

server.listen(PORT, () => console.log(`proxy listening on :${PORT}${ACCESS_KEY ? ' (access key required)' : ' (NO access key set)'}`));
