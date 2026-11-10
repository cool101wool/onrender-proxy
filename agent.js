#!/usr/bin/env node
// Helper for "share this computer's internet". No npm install needed, just Node 22 or newer.
//
//   node agent.js https://your-app.onrender.com ABCD-EFGH            share this computer's normal internet
//   node agent.js https://your-app.onrender.com ABCD-EFGH --tor      share Tor Browser's connection (keep it open)
//   node agent.js https://your-app.onrender.com ABCD-EFGH --socks 127.0.0.1:9150   any SOCKS5 proxy
//
// Get the code by opening  https://your-app.onrender.com/share  in a browser, setting a PIN and pressing
// "Allow sharing". Stop with Ctrl+C or the Stop button in the browser.
import https from 'node:https';
import http from 'node:http';
import dns from 'node:dns';
import net from 'node:net';
import zlib from 'node:zlib';
import tls from 'node:tls';

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf('--' + n); return i < 0 ? undefined : (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true); };
const [serverArg, codeArg] = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--socks');
let SOCKS = null; // { host, port } when traffic should leave through a SOCKS5 proxy (Tor)
if (typeof WebSocket === 'undefined') { console.error('This helper needs Node 22 or newer (you have ' + process.version + ').'); process.exit(1); }
if (!/^https?:\/\//.test(serverArg || '') || !codeArg) {
  console.error('Usage: node agent.js https://your-app.onrender.com ABCD-EFGH [--tor | --socks 127.0.0.1:9150]\n(open /share on your site in a browser to get the code)');
  process.exit(1);
}
const SERVER = serverArg.replace(/\/+$/, '');
const WS_URL = SERVER.replace(/^http/, 'ws') + '/__pl/agent';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1'; // testing only

/* ---- never let a remote viewer reach this computer's own network ---- */
function privV4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19)) || a >= 224;
}
function privV6(ip) {
  const l = ip.toLowerCase();
  if (l === '::' || l === '::1') return true;
  if (l.startsWith('::ffff:')) {
    const r = l.slice(7);
    if (net.isIPv4(r)) return privV4(r);
    const m = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(r);
    return m ? privV4(`${parseInt(m[1], 16) >> 8}.${parseInt(m[1], 16) & 255}.${parseInt(m[2], 16) >> 8}.${parseInt(m[2], 16) & 255}`) : true;
  }
  return /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || l.startsWith('ff') || l.startsWith('64:ff9b') || l.startsWith('2001:db8');
}
const isPrivate = (ip) => (net.isIPv4(ip) ? privV4(ip) : net.isIPv6(ip) ? privV6(ip) : true);
const blocked = (h) => Object.assign(new Error(`Blocked: ${h} is a private or internal address`), { code: 'PL_BLOCKED' });
function assertHost(hostname) {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (ALLOW_PRIVATE) return;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) throw blocked(h);
  if (net.isIP(h) && isPrivate(h)) throw blocked(h);
}
function safeLookup(hostname, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err);
    const ok = ALLOW_PRIVATE ? addrs : addrs.filter((a) => !isPrivate(a.address));
    if (!ok.length) return cb(blocked(hostname));
    if (options && options.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}

/* ------------------------------------------------ SOCKS5 (Tor Browser / tor) */
// Hostnames are sent to the proxy unresolved, so DNS happens on the Tor side (no DNS leak, .onion works,
// and the proxy's exit can't reach this computer's LAN).
const SOCKS_ERR = { 1: 'general SOCKS failure', 2: 'connection not allowed by Tor', 3: 'network unreachable', 4: 'host unreachable',
  5: 'connection refused', 6: 'TTL expired', 7: 'command not supported', 8: 'address type not supported', 0xf0: 'onion service descriptor not found',
  0xf1: 'onion service descriptor invalid', 0xf2: 'onion service introduction failed', 0xf3: 'onion service rendezvous failed', 0xf4: 'onion service needs authentication' };
function ipv6Bytes(ip) {
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  const groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  const b = Buffer.alloc(16);
  groups.forEach((g, i) => b.writeUInt16BE(parseInt(g, 16) || 0, i * 2));
  return b;
}
function socksConnect(proxy, host, port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxy.port, proxy.host);
    let buf = Buffer.alloc(0), step = 0, done = false;
    const fail = (e) => { if (done) return; done = true; sock.destroy(); reject(e); };
    sock.setTimeout(60_000, () => fail(Object.assign(new Error('The SOCKS proxy timed out'), { code: 'ETIMEDOUT' })));
    sock.on('error', fail);
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (step === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 5 || buf[1] !== 0) return fail(new Error('The SOCKS proxy did not accept the connection'));
        buf = buf.subarray(2); step = 1;
        const ip = net.isIP(host.replace(/^\[|\]$/g, ''));
        const bare = host.replace(/^\[|\]$/g, '');
        const addr = ip === 4 ? Buffer.from([1, ...bare.split('.').map(Number)])
          : ip === 6 ? Buffer.concat([Buffer.from([4]), ipv6Bytes(bare)])
          : Buffer.concat([Buffer.from([3, Buffer.byteLength(host)]), Buffer.from(host)]);
        const pb = Buffer.alloc(2); pb.writeUInt16BE(port);
        sock.write(Buffer.concat([Buffer.from([5, 1, 0]), addr, pb]));
      }
      if (step === 1) {
        if (buf.length < 5) return;
        const len = buf[3] === 1 ? 10 : buf[3] === 4 ? 22 : 7 + buf[4];
        if (buf.length < len) return;
        if (buf[1] !== 0) return fail(Object.assign(new Error('Tor: ' + (SOCKS_ERR[buf[1]] || 'error ' + buf[1])), { code: 'SOCKS_' + buf[1] }));
        done = true; sock.removeListener('data', onData); sock.removeListener('error', fail); sock.setTimeout(0);
        if (buf.length > len) sock.unshift(buf.subarray(len));
        resolve(sock);
      }
    };
    sock.on('data', onData);
  });
}
class SocksHttpAgent extends http.Agent {
  createConnection(o, cb) { socksConnect(SOCKS, o.host || o.hostname, +o.port || 80).then((s) => cb(null, s), cb); }
}
class SocksHttpsAgent extends https.Agent {
  createConnection(o, cb) {
    const host = o.host || o.hostname;
    socksConnect(SOCKS, host, +o.port || 443).then((s) => {
      const t = tls.connect({ socket: s, servername: net.isIP(host) ? undefined : host, ALPNProtocols: ['http/1.1'] });
      t.once('secureConnect', () => cb(null, t));
      t.once('error', cb);
    }, cb);
  };
}
const canConnect = (host, port) => new Promise((r) => {
  const s = net.connect(port, host); s.setTimeout(1500, () => { s.destroy(); r(false); });
  s.on('connect', () => { s.destroy(); r(true); }); s.on('error', () => r(false));
});
if (flag('socks')) {
  const m = /^(.*):(\d+)$/.exec(String(flag('socks')));
  if (!m) { console.error('Use --socks host:port, for example --socks 127.0.0.1:9150'); process.exit(1); }
  SOCKS = { host: m[1], port: Number(m[2]) };
} else if (flag('tor')) {
  for (const port of [9150, 9050]) if (await canConnect('127.0.0.1', port)) { SOCKS = { host: '127.0.0.1', port }; break; } // Tor Browser, then the tor service
  if (!SOCKS) { console.error('Could not find Tor on this computer. Open Tor Browser and leave it running, then try again (or pass --socks host:port).'); process.exit(1); }
}

/* ---------------------------------------------------------------- state */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(new Date().toLocaleTimeString(), ...a);
const httpsAgent = SOCKS ? new SocksHttpsAgent({ keepAlive: true, maxSockets: 32 }) : new https.Agent({ keepAlive: true, maxSockets: 32 });
const httpAgent = SOCKS ? new SocksHttpAgent({ keepAlive: true, maxSockets: 32 }) : new http.Agent({ keepAlive: true, maxSockets: 32 });

let ws = null, resume = null, expiresAt = 0, stopping = false, attempts = 0, everReady = false, reqs = 0;
const inflight = new Map(); // id -> AbortController
const bodies = new Map();   // id -> { msg, chunks }

function frame(id, flag, payload) {
  const h = Buffer.alloc(5);
  h.writeUInt32BE(id, 0); h[4] = flag;
  return payload && payload.length ? Buffer.concat([h, payload]) : h;
}
const sendJson = (o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
async function sendFrame(id, flag, payload) {
  while (ws && ws.bufferedAmount > 8 * 1024 * 1024) await sleep(20);
  if (ws && ws.readyState === 1) ws.send(frame(id, flag, payload));
}

/* ------------------------------------------------------------- tunnel */
function connect() {
  const url = resume ? `${WS_URL}?resume=${encodeURIComponent(resume)}` : `${WS_URL}?code=${encodeURIComponent(codeArg)}`;
  const sock = new WebSocket(url);
  sock.binaryType = 'arraybuffer';
  ws = sock;

  sock.addEventListener('message', (e) => {
    if (typeof e.data !== 'string') return onFrame(Buffer.from(e.data));
    let m; try { m = JSON.parse(e.data); } catch { return; }
    if (m.t === 'ready') {
      everReady = true; attempts = 0; resume = m.resume; expiresAt = m.expiresAt;
      log(`Sharing is ON. Stops at ${new Date(expiresAt).toLocaleTimeString()}. Press Ctrl+C to stop.`);
    } else if (m.t === 'viewers') log(`${m.n} computer${m.n === 1 ? '' : 's'} connected`);
    else if (m.t === 'stop' || m.t === 'expired') { log(`Sharing ended (${m.why || m.t}).`); shutdown(0); }
    else if (m.t === 'req') onReq(m);
    else if (m.t === 'cancel') { inflight.get(m.id)?.abort(); bodies.delete(m.id); }
  });
  let handled = false;
  const down = async () => { // fires for failed handshakes ('error' only) as well as dropped connections ('close')
    if (handled || ws !== sock || stopping) return;
    handled = true;
    for (const ac of inflight.values()) ac.abort();
    inflight.clear(); bodies.clear();
    attempts++;
    if (!everReady) {
      // Is the server itself reachable? If yes, the code is the problem. If not it may just be waking up (Render free plan).
      const up = await fetch(SERVER + '/healthz', { signal: AbortSignal.timeout(90_000) }).then((r) => r.ok).catch(() => false);
      if (stopping) return;
      if (up || attempts >= 25) {
        console.error(up ? 'The server refused the code. It may have expired (10 minutes) or been used already. Create a new one on the /share page.'
          : 'Could not reach the server.');
        return shutdown(1);
      }
    } else if (Date.now() > expiresAt) { log('Sharing time ran out.'); return shutdown(0); }
    log(everReady ? 'Connection lost, retrying...' : 'Server not ready yet (it may be waking up), retrying...');
    setTimeout(connect, Math.min(3000 * attempts, 15_000));
  };
  sock.addEventListener('close', down);
  sock.addEventListener('error', down);
}

function shutdown(code) {
  stopping = true;
  for (const ac of inflight.values()) ac.abort();
  try { ws?.close(1000, 'bye'); } catch { /* ignore */ }
  setTimeout(() => process.exit(code), 200);
}
process.on('SIGINT', () => { log('Stopping...'); shutdown(0); });

/* ----------------------------------------------------------- requests */
function onReq(m) {
  if (m.hasBody) bodies.set(m.id, { msg: m, chunks: [] });
  else run(m, undefined);
}
function onFrame(buf) {
  if (buf.length < 5) return;
  const id = buf.readUInt32BE(0), flag = buf[4], b = bodies.get(id);
  if (!b) return;
  if (flag === 0) b.chunks.push(buf.subarray(5));
  else { bodies.delete(id); run(b.msg, Buffer.concat(b.chunks)); }
}

function doRequest(m, body, ac) {
  return new Promise((resolve, reject) => {
    const u = new URL(m.url);
    if (!/^https?:$/.test(u.protocol)) return reject(blocked(u.host));
    try { assertHost(u.hostname); } catch (e) { return reject(e); }
    const headers = {};
    for (const [k, v] of m.headers) {
      const l = k.toLowerCase();
      if (['host', 'content-length', 'connection', 'accept-encoding', 'transfer-encoding'].includes(l)) continue;
      headers[l] = headers[l] ? headers[l] + (l === 'cookie' ? '; ' : ', ') + v : v;
    }
    headers['accept-encoding'] = 'gzip, deflate, br';
    if (body && body.length) headers['content-length'] = String(body.length);
    const tls = u.protocol === 'https:';
    const req = (tls ? https : http).request({
      hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || undefined, path: u.pathname + u.search,
      method: m.method, headers, lookup: safeLookup, agent: tls ? httpsAgent : httpAgent, timeout: SOCKS ? 90_000 : 30_000, // Tor circuits are slower
    }, resolve); // no redirect following: the browser handles each hop through the proxy
    req.on('timeout', () => req.destroy(Object.assign(new Error('Timed out'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    ac.signal.addEventListener('abort', () => req.destroy(), { once: true });
    if (body && body.length) req.write(body);
    req.end();
  });
}

async function run(m, body) {
  const ac = new AbortController();
  inflight.set(m.id, ac);
  try {
    const res = await doRequest(m, body, ac);
    reqs++;
    const enc = (res.headers['content-encoding'] || '').toLowerCase();
    let stream = res;
    if (enc === 'gzip' || enc === 'x-gzip') stream = res.pipe(zlib.createGunzip());
    else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
    else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());
    if (stream !== res) stream.on('error', () => res.destroy());

    const headers = [];
    for (let i = 0; i < res.rawHeaders.length; i += 2) {
      const k = res.rawHeaders[i], l = k.toLowerCase();
      if (['set-cookie', 'content-encoding', 'transfer-encoding', 'connection', 'keep-alive'].includes(l)) continue;
      if (l === 'content-length' && enc) continue; // body was decoded
      headers.push([k, res.rawHeaders[i + 1]]);
    }
    for (const c of res.headers['set-cookie'] || []) headers.push(['set-cookie', c]);
    const bodyless = m.method === 'HEAD' || [101, 204, 205, 304].includes(res.statusCode);
    sendJson({ t: 'res', id: m.id, status: res.statusCode, headers, hasBody: !bodyless });
    if (bodyless) { res.resume(); return; }
    for await (const chunk of stream) { if (ac.signal.aborted) break; await sendFrame(m.id, 0, chunk); }
    if (!ac.signal.aborted) await sendFrame(m.id, 1);
  } catch (e) {
    if (!ac.signal.aborted) sendJson({ t: 'err', id: m.id, code: e.code || 'PL_REMOTE', message: e.message });
  } finally { inflight.delete(m.id); }
}

/* Pinging our own public URL also keeps a free Render instance awake while sharing. */
setInterval(() => { fetch(SERVER + '/healthz').then((r) => r.arrayBuffer()).catch(() => {}); }, 4 * 60_000); // also keeps the process alive

log(SOCKS ? `Traffic will leave through SOCKS5 at ${SOCKS.host}:${SOCKS.port} (Tor). Keep Tor Browser open.` : 'Traffic will leave through this computer\'s normal internet connection.');
log(`Connecting to ${SERVER} ...`);
connect();
