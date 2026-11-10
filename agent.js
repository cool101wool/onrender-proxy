#!/usr/bin/env node
// Run this on the computer whose internet connection you want to share:
//
//     npm install
//     node agent.js https://your-app.onrender.com
//
// It opens a small page on THIS computer only (127.0.0.1) where you press "Allow sharing" and set a PIN.
// Another computer then enters that PIN on the proxy's start page and browses through this connection.
// Nothing is shared until you press the button, and you can stop at any time.
import http from 'node:http';
import crypto from 'node:crypto';
import { exec } from 'node:child_process';
import { Agent, fetch } from 'undici';
import { WebSocket } from 'ws';
import { safeLookup, assertHostAllowed } from './safe.js';
import { frame } from './exit.js';

const args = process.argv.slice(2);
const opt = (n) => { const i = args.indexOf('--' + n); return i >= 0 ? (args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : true) : undefined; };
const SERVER = (args.find((a) => /^https?:\/\//.test(a)) || process.env.PROXY_URL || '').replace(/\/+$/, '');
if (!SERVER) {
  console.error('Usage: node agent.js https://your-app.onrender.com [--port 8123]\n' +
    '  Advanced (skips the button; running this IS your consent): --arm --pin 123456 --key ACCESS_KEY [--minutes 60]');
  process.exit(1);
}
const CTL_PORT = Number(opt('port')) || 8123;
const CTL = crypto.randomBytes(16).toString('hex'); // only the page we open knows this

// Same rule as the server: never let a remote viewer reach this computer's LAN / localhost.
const dispatcher = new Agent({ connect: { lookup: safeLookup, timeout: 10_000 }, headersTimeout: 30_000, maxHeaderSize: 1024 * 1024, bodyTimeout: 0 });

const state = { status: 'idle', msg: '', viewers: 0, reqs: 0, expiresAt: 0, recent: [] };
let ws = null, cfg = null, stopping = true, retries = 0, expiryTimer = null, pingTimer = null, retryTimer = null;
const inflight = new Map(); // id -> { ac }
const bodies = new Map();   // id -> { msg, chunks }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const authToken = (key) => crypto.createHmac('sha256', key).update('pl-auth').digest('hex');

/* --------------------------------------------------------------- tunnel */

function start(c) {
  if (!/^\d{4,8}$/.test(c.pin || '')) throw new Error('The PIN must be 4 to 8 digits');
  if (!c.key) throw new Error('Enter the access key you set on the server');
  stop();
  cfg = { ...c, minutes: Math.min(Math.max(parseInt(c.minutes, 10) || 60, 1), 480) };
  cfg.expiresAt = Date.now() + cfg.minutes * 60_000;
  stopping = false; retries = 0;
  state.status = 'connecting'; state.msg = ''; state.reqs = 0; state.viewers = 0; state.recent = [];
  state.expiresAt = cfg.expiresAt;
  expiryTimer = setTimeout(() => { setIdle('Sharing time ran out'); stop(); }, cfg.minutes * 60_000);
  // Pinging the public URL also keeps a free Render instance from spinning down while you share.
  pingTimer = setInterval(() => { fetch(SERVER + '/healthz').then((r) => r.arrayBuffer()).catch(() => {}); }, 4 * 60_000);
  connect();
}

function setIdle(msg = '') { state.status = 'idle'; state.msg = msg; state.viewers = 0; }

function stop() {
  stopping = true;
  clearTimeout(expiryTimer); clearInterval(pingTimer); clearTimeout(retryTimer);
  for (const { ac } of inflight.values()) ac.abort();
  inflight.clear(); bodies.clear();
  if (ws) { try { ws.close(1000, 'stopped'); } catch { /* ignore */ } ws = null; }
  if (state.status !== 'error') setIdle(state.msg);
}

function fatal(msg) { state.status = 'error'; state.msg = msg; stop(); }

function connect() {
  const sock = new WebSocket(SERVER.replace(/^http/, 'ws') + '/__pl/agent', {
    headers: { 'x-pl-auth': authToken(cfg.key) }, maxPayload: 32 * 1024 * 1024, handshakeTimeout: 20_000,
  });
  ws = sock;
  let accepted = false;

  sock.on('unexpected-response', (_req, res) => {
    fatal(res.statusCode === 401 ? 'The access key is wrong' : res.statusCode === 403 ? 'The server has no ACCESS_KEY set, so sharing is disabled' : `Server answered ${res.statusCode}`);
  });
  sock.on('open', () => sock.send(JSON.stringify({ t: 'hello', pin: cfg.pin, minutes: Math.max(1, Math.ceil((cfg.expiresAt - Date.now()) / 60_000)) })));
  sock.on('message', (data, isBinary) => {
    if (isBinary) return onFrame(data);
    let m; try { m = JSON.parse(data.toString()); } catch { return; }
    if (m.t === 'ready') { accepted = true; retries = 0; state.status = 'active'; state.msg = ''; }
    else if (m.t === 'reject') {
      if (m.code === 'in_use' && retries > 0) return; // our own stale connection is still being cleaned up; retry
      fatal(m.reason || 'Rejected by the server');
    } else if (m.t === 'viewers') { state.viewers = m.n; }
    else if (m.t === 'expired') { setIdle('Sharing time ran out'); stop(); }
    else if (m.t === 'req') onReq(m);
    else if (m.t === 'cancel') { inflight.get(m.id)?.ac.abort(); bodies.delete(m.id); }
  });
  sock.on('close', () => {
    if (ws !== sock) return;
    for (const { ac } of inflight.values()) ac.abort();
    inflight.clear(); bodies.clear();
    if (stopping || state.status === 'error') return;
    state.status = 'connecting'; state.msg = 'Connection lost, retrying...'; state.viewers = 0;
    retries++;
    retryTimer = setTimeout(connect, Math.min(2000 * retries, 20_000));
  });
  sock.on('error', () => { /* close handler retries */ });
}

/* ----------------------------------------------------------- requests */

function onReq(m) {
  if (m.hasBody) bodies.set(m.id, { msg: m, chunks: [] });
  else run(m, undefined);
}
function onFrame(buf) {
  const id = buf.readUInt32BE(0), flag = buf[4], b = bodies.get(id);
  if (!b) return;
  if (flag === 0) b.chunks.push(Buffer.from(buf.subarray(5)));
  else { bodies.delete(id); run(b.msg, Buffer.concat(b.chunks)); }
}

const sendJson = (o) => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(o)); };
async function sendFrame(id, flag, payload) {
  while (ws && ws.bufferedAmount > 8 * 1024 * 1024) await sleep(20);
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(frame(id, flag, payload));
}

async function run(m, body) {
  const ac = new AbortController();
  inflight.set(m.id, { ac });
  try {
    const u = new URL(m.url);
    if (!/^https?:$/.test(u.protocol)) throw Object.assign(new Error('Only http(s) is allowed'), { code: 'PL_BLOCKED' });
    assertHostAllowed(u.hostname);
    state.reqs++;
    state.recent.unshift(`${m.method} ${u.host}`); state.recent.length = Math.min(state.recent.length, 8);

    const up = await fetch(u.href, { method: m.method, headers: new Headers(m.headers), body, dispatcher, redirect: 'manual', signal: ac.signal });

    const enc = up.headers.has('content-encoding'); // undici already decoded the body
    const headers = [];
    for (const [k, v] of up.headers) {
      if (k === 'set-cookie' || k === 'content-encoding' || (k === 'content-length' && enc)) continue;
      headers.push([k, v]);
    }
    for (const c of up.headers.getSetCookie()) headers.push(['set-cookie', c]);
    const bodyless = m.method === 'HEAD' || [101, 204, 205, 304].includes(up.status) || !up.body;
    sendJson({ t: 'res', id: m.id, status: up.status, headers, hasBody: !bodyless });
    if (!bodyless) {
      for await (const chunk of up.body) { if (ac.signal.aborted) break; await sendFrame(m.id, 0, Buffer.from(chunk)); }
      if (!ac.signal.aborted) await sendFrame(m.id, 1);
    }
  } catch (e) {
    if (!ac.signal.aborted) {
      const cause = e.cause || e;
      sendJson({ t: 'err', id: m.id, code: cause.code || e.code || 'PL_REMOTE', message: cause.message || String(cause) });
    }
  } finally { inflight.delete(m.id); }
}

/* ------------------------------------------------ local control page */

const PAGE = `<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Share this computer</title>
<style>
:root{--bg:#0f1115;--fg:#e6e6e6;--muted:#8b93a1;--card:#181b22;--line:#2a2f3a;--accent:#4f7cff;--ok:#3ecf8e;--bad:#ff6b6b}
@media (prefers-color-scheme:light){:root{--bg:#f6f7f9;--fg:#14161a;--muted:#5d6675;--card:#fff;--line:#dfe3ea}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;padding:16px}
main{width:100%;max-width:520px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px}
h1{font-size:20px;margin:0 0 4px}p{color:var(--muted);margin:0 0 16px}label{display:block;font-size:14px;color:var(--muted);margin:12px 0 4px}
input,select{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font:inherit}
button{margin-top:16px;padding:12px 18px;border-radius:10px;border:0;background:var(--accent);color:#fff;font:inherit;cursor:pointer;width:100%}
button.stop{background:var(--bad)}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.st{padding:10px 12px;border-radius:10px;border:1px solid var(--line);margin-bottom:6px}.ok{color:var(--ok)}.bad{color:var(--bad)}
ul{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:14px}.hide{display:none}
</style>
<main>
<h1>Share this computer's internet</h1>
<p>While sharing, a computer that knows your PIN can browse the web through this connection, and sites will see <b>this</b> computer's IP address. It cannot reach your local network.</p>
<div id=st class=st>Not sharing</div>
<div id=idle>
  <label for=key>Access key (the ACCESS_KEY you set on Render)</label><input id=key type=password autocomplete=off>
  <label for=pin>PIN to give the other computer (4 to 8 digits)</label><input id=pin inputmode=numeric maxlength=8 autocomplete=off placeholder="e.g. 482915">
  <label for=min>Stop sharing automatically after</label>
  <select id=min><option value=30>30 minutes<option value=60 selected>1 hour<option value=240>4 hours<option value=480>8 hours</select>
  <button id=go>Allow sharing</button>
</div>
<div id=busy class=hide><button id=halt class=stop>Stop sharing</button><ul id=recent></ul></div>
</main>
<script>
var T=location.hash.slice(1),$=function(i){return document.getElementById(i)};
function api(p,b){return fetch(p,{method:b?'POST':'GET',headers:{'x-ctl':T,'content-type':'application/json'},body:b?JSON.stringify(b):undefined}).then(function(r){return r.json()})}
$('go').onclick=function(){api('/start',{key:$('key').value,pin:$('pin').value,minutes:$('min').value}).then(function(r){if(r.error)$('st').innerHTML='<span class=bad>'+r.error+'</span>'})};
$('halt').onclick=function(){api('/stop',{})};
function fmt(ms){var s=Math.max(0,Math.round(ms/1000));return Math.floor(s/60)+'m '+('0'+s%60).slice(-2)+'s'}
function tick(){api('/status').then(function(s){
  var busy=s.status==='active'||s.status==='connecting';
  $('idle').classList.toggle('hide',busy);$('busy').classList.toggle('hide',!busy);
  var t=s.status==='active'?'<b class=ok>Sharing</b> &middot; '+s.viewers+' computer'+(s.viewers==1?'':'s')+' connected &middot; '+s.reqs+' requests &middot; stops in '+fmt(s.expiresAt-Date.now())
   :s.status==='connecting'?'Connecting… '+(s.msg||''):s.status==='error'?'<span class=bad>'+s.msg+'</span>':'Not sharing'+(s.msg?' ('+s.msg+')':'');
  $('st').innerHTML=t;$('recent').innerHTML=(s.recent||[]).map(function(x){return '<li>'+x.replace(/</g,'&lt;')+'</li>'}).join('');
}).catch(function(){$('st').textContent='Agent not running'})}
tick();setInterval(tick,1000);
</script></html>`;

const hostOk = (req) => new RegExp(`^(127\\.0\\.0\\.1|localhost):${CTL_PORT}$`).test(req.headers.host || '');

http.createServer(async (req, res) => {
  if (!hostOk(req)) { res.writeHead(403); return res.end(); } // blocks DNS-rebinding
  if (req.method === 'GET' && req.url === '/') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); return res.end(PAGE); }
  if (req.headers['x-ctl'] !== CTL) { res.writeHead(403); return res.end('{}'); }  // blocks other websites/pages
  const send = (o, c = 200) => { res.writeHead(c, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (req.url === '/status') return send({ ...state });
  if (req.url === '/start' && req.method === 'POST') {
    let b = ''; for await (const c of req) b += c;
    try { start(JSON.parse(b)); return send({ ok: true }); } catch (e) { return send({ error: e.message }, 400); }
  }
  if (req.url === '/stop' && req.method === 'POST') { stop(); setIdle(''); return send({ ok: true }); }
  res.writeHead(404); res.end('{}');
}).listen(CTL_PORT, '127.0.0.1', () => {
  const url = `http://127.0.0.1:${CTL_PORT}/#${CTL}`;
  console.log(`\nAgent for ${SERVER}\nOpen this page on THIS computer and press "Allow sharing":\n  ${url}\n`);
  if (opt('arm')) {
    try { start({ pin: String(opt('pin')), key: opt('key') || process.env.ACCESS_KEY, minutes: opt('minutes') }); console.log('Sharing armed from the command line.'); }
    catch (e) { console.error(e.message); process.exit(1); }
  } else if (!opt('no-open')) {
    const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start ""' : 'xdg-open';
    exec(`${cmd} "${url}"`, () => {});
  }
}).on('error', (e) => { console.error(e.code === 'EADDRINUSE' ? `Port ${CTL_PORT} is busy. Use --port <number>.` : e.message); process.exit(1); });

process.on('SIGINT', () => { stop(); process.exit(0); });
