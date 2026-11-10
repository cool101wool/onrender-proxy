// "Exit via another computer" mode.
//
//   Computer A (shares its internet)  --tunnel-->  this server  <--HTTPS--  Computer B (browses)
//
// 1. On A, open /share in a browser, set a PIN and press "Allow sharing". That creates an *offer* with a
//    one-time pairing code (browser consent).
// 2. A runs `node agent.js <server> <code>`; the helper claims the offer and opens the tunnel.
// 3. B enters the PIN on the start page. B's proxied requests are then executed by A's helper, so sites see A's IP.
// Requires ACCESS_KEY.
//
// Tunnel protocol (WebSocket):
//   text frames (JSON):  ready / stop / expired / viewers (server->agent), req / res / err / cancel
//   binary frames:       [uint32 request-id][uint8 flag: 0=data, 1=end][payload]
import crypto from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';

const TEN_MIN = 10 * 60 * 1000;
const SESSION_MS = 12 * 60 * 60 * 1000;
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const norm = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

export function createExit(d) {
  const enabled = !!d.ACCESS_KEY;
  const secret = crypto.randomBytes(32);
  const pinKey = (pin) => crypto.createHmac('sha256', secret).update(String(pin)).digest('hex');

  const offers = new Map();    // id -> offer
  const byCode = new Map();    // normalised pairing code -> offer (until claimed)
  const byResume = new Map();  // resume token -> offer (after claimed)
  const hosts = new Map();     // pinKey -> host (helper currently connected)
  const sessions = new Map();  // viewer token -> { host, exp }
  const fails = new Map();     // ip -> { n, t }
  const hits = [];             // global failed-PIN timestamps
  let lockUntil = 0;

  const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 * 1024 });

  const json = (res, status, obj, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
    res.end(JSON.stringify(obj));
  };
  const clientIp = (req) =>
    req.headers['cf-connecting-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
  const setCookie = (req, name, v, maxAge) =>
    `${name}=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${d.isHttps(req) ? '; Secure' : ''}`;
  const readJson = async (req) => { try { return JSON.parse((await d.readBody(req, 2048)).toString()) || {}; } catch { return {}; } };
  const isJsonReq = (req) => (req.headers['content-type'] || '').split(';')[0] === 'application/json';
  const pinTaken = (key) => hosts.has(key) || [...offers.values()].some((o) => o.pinKey === key);

  /* --------------------------------------------------------------- offers */

  function endOffer(offer, why) {
    if (offer.ended) return;
    offer.ended = true;
    clearTimeout(offer.pendingTimer); clearTimeout(offer.timer);
    offers.delete(offer.id);
    if (offer.code) byCode.delete(offer.code);
    if (offer.resume) byResume.delete(offer.resume);
    if (offer.ws) {
      try { offer.ws.send(JSON.stringify({ t: 'stop', why })); } catch { /* gone */ }
      try { offer.ws.close(1000, 'stopped'); } catch { /* gone */ }
    }
    if (offer.host) closeHost(offer.host);
  }

  function closeHost(host) {
    if (host.closed) return;
    host.closed = true;
    if (hosts.get(host.key) === host) hosts.delete(host.key);
    for (const t of host.sessions) sessions.delete(t);
    host.sessions.clear();
    for (const e of [...host.inflight.values()]) e.err({ message: 'The remote computer disconnected', code: 'PL_REMOTE_OFFLINE' });
    host.inflight.clear();
  }

  const notifyViewers = (host) => {
    if (host.ws.readyState === WebSocket.OPEN) host.ws.send(JSON.stringify({ t: 'viewers', n: host.sessions.size }));
  };

  function onAgent(ws, offer) {
    if (offer.ws && offer.ws !== ws) { try { offer.ws.terminate(); } catch { /* gone */ } } // helper reconnecting
    const host = { ws, key: offer.pinKey, offer, inflight: new Map(), blocked: new Set(), nextId: 0, sessions: new Set(), closed: false, stats: offer.stats };
    offer.ws = ws; offer.host = host;
    hosts.set(host.key, host);
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    ws.send(JSON.stringify({ t: 'ready', expiresAt: offer.expiresAt, resume: offer.resume }));

    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        if (data.length < 5) return;
        const e = host.inflight.get(data.readUInt32BE(0));
        if (!e) return;
        if (data[4] === 0) e.data(data.subarray(5)); else e.end();
        return;
      }
      let m;
      try { m = JSON.parse(data.toString()); } catch { return; }
      const e = host.inflight.get(m.id);
      if (!e) return;
      if (m.t === 'res') e.res(m); else if (m.t === 'err') e.err(m);
    });
    ws.on('close', () => {
      closeHost(host);
      if (offer.host === host) { offer.host = null; offer.ws = null; } // offer stays so the helper can resume
    });
    ws.on('error', () => { /* handled by close */ });
  }

  // Drop dead helpers (Render's proxy silently kills idle sockets) and expired viewer sessions.
  setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.isAlive) { ws.terminate(); continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch { /* closing */ }
    }
    const now = Date.now();
    for (const [t, s] of sessions) if (s.exp < now) { sessions.delete(t); s.host.sessions.delete(t); notifyViewers(s.host); }
  }, 30_000).unref();

  function handleAgentUpgrade(req, socket, head) {
    const fail = (code, msg) => { socket.write(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`); socket.destroy(); };
    if (!enabled) return fail(403, 'Forbidden');
    const q = new URL(req.url, 'http://x').searchParams;
    let offer = null;
    const code = norm(q.get('code'));
    const resume = q.get('resume');
    if (code) {
      offer = byCode.get(code);
      if (offer && !offer.ended) { // first connection: the code is single use
        byCode.delete(code); offer.code = null;
        clearTimeout(offer.pendingTimer);
        offer.claimed = true;
        offer.expiresAt = Date.now() + offer.minutes * 60_000;
        offer.timer = setTimeout(() => endOffer(offer, 'expired'), offer.minutes * 60_000);
        offer.resume = crypto.randomBytes(24).toString('hex');
        byResume.set(offer.resume, offer);
      } else offer = null;
    } else if (resume) {
      offer = byResume.get(resume) || null;
    }
    if (!offer || offer.ended) return fail(401, 'Unauthorized');
    wss.handleUpgrade(req, socket, head, (ws) => onAgent(ws, offer));
  }

  /* ----------------------------------------------------------------- HTTP */

  function getExit(req) {
    const t = d.parseCookies(req.headers.cookie).__pl_exit;
    if (!t) return null;
    const s = sessions.get(t);
    if (!s || s.exp < Date.now() || s.host.closed) { sessions.delete(t); return { gone: true }; }
    return s;
  }

  const myOffer = (req) => offers.get(d.parseCookies(req.headers.cookie).__pl_offer || '') || null;

  function offerStatus(req) {
    const o = myOffer(req);
    if (!o) return { state: d.parseCookies(req.headers.cookie).__pl_offer ? 'ended' : 'none' };
    const base = { recent: o.recent, reqs: o.stats.reqs, viewers: o.host ? o.host.sessions.size : 0 };
    if (!o.claimed) return { ...base, state: 'waiting', code: o.display, codeExpiresAt: o.created + TEN_MIN };
    return { ...base, state: o.host ? 'active' : 'reconnecting', expiresAt: o.expiresAt };
  }

  async function route(req, res, u) {
    const p = u.pathname;

    /* --- computer B: use someone's connection --- */
    if (p === '/__pl/exit/status') {
      const s = getExit(req);
      json(res, 200, { enabled, connected: !!(s && !s.gone), offline: !!(s && s.gone) });
      return true;
    }
    if (p === '/__pl/exit/off') {
      const t = d.parseCookies(req.headers.cookie).__pl_exit;
      const s = t && sessions.get(t);
      if (s) { sessions.delete(t); s.host.sessions.delete(t); notifyViewers(s.host); }
      res.writeHead(302, { location: '/', 'set-cookie': setCookie(req, '__pl_exit', '', 0) });
      res.end();
      return true;
    }
    if (p === '/__pl/exit/connect' && req.method === 'POST') {
      if (!enabled) { json(res, 403, { ok: false, error: 'This mode is disabled until ACCESS_KEY is set on the server' }); return true; }
      if (!isJsonReq(req)) { json(res, 415, { ok: false, error: 'Bad request' }); return true; }
      const now = Date.now();
      if (now < lockUntil) { json(res, 429, { ok: false, error: 'Too many wrong PINs. Try again in a few minutes' }); return true; }
      const ip = clientIp(req);
      let f = fails.get(ip);
      if (!f || now - f.t > TEN_MIN) f = { n: 0, t: now };
      if (f.n >= 5) { json(res, 429, { ok: false, error: 'Too many wrong PINs from your address. Try again later' }); return true; }

      const pin = String((await readJson(req)).pin || '');
      const host = /^\d{4,8}$/.test(pin) ? hosts.get(pinKey(pin)) : null;
      if (!host || host.closed) {
        f.n++; fails.set(ip, f);
        while (hits.length && now - hits[0] > TEN_MIN) hits.shift();
        hits.push(now);
        if (hits.length >= 15) lockUntil = now + TEN_MIN;
        json(res, 401, { ok: false, error: 'Wrong PIN, or no computer is sharing right now' });
        return true;
      }
      fails.delete(ip);
      const old = d.parseCookies(req.headers.cookie).__pl_exit;
      if (old && sessions.has(old)) { sessions.get(old).host.sessions.delete(old); sessions.delete(old); }
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, { host, exp: now + SESSION_MS });
      host.sessions.add(token);
      notifyViewers(host);
      json(res, 200, { ok: true }, { 'set-cookie': setCookie(req, '__pl_exit', token, SESSION_MS / 1000) });
      return true;
    }

    /* --- computer A: offer to share (driven by /share in the browser) --- */
    if (p === '/__pl/exit/offer' && req.method === 'GET') { json(res, 200, { enabled, ...offerStatus(req) }); return true; }

    if (p === '/__pl/exit/offer' && req.method === 'POST') {
      if (!enabled) { json(res, 403, { ok: false, error: 'Set ACCESS_KEY on the server to enable sharing' }); return true; }
      if (!isJsonReq(req)) { json(res, 415, { ok: false, error: 'Bad request' }); return true; }
      const b = await readJson(req);
      const pin = String(b.pin || '');
      if (!/^\d{4,8}$/.test(pin)) { json(res, 400, { ok: false, error: 'The PIN must be 4 to 8 digits' }); return true; }
      const minutes = Math.min(Math.max(parseInt(b.minutes, 10) || 60, 5), 480);
      const prev = myOffer(req);
      if (prev) endOffer(prev, 'replaced');
      if (pinTaken(pinKey(pin))) { json(res, 409, { ok: false, error: 'That PIN is already in use. Choose a different one' }); return true; }
      if (offers.size >= 20) { json(res, 429, { ok: false, error: 'Too many active shares' }); return true; }

      let raw = '';
      for (const x of crypto.randomBytes(8)) raw += ALPHABET[x % ALPHABET.length];
      const offer = {
        id: crypto.randomBytes(16).toString('hex'), code: raw, display: `${raw.slice(0, 4)}-${raw.slice(4)}`,
        pinKey: pinKey(pin), minutes, created: Date.now(), claimed: false, expiresAt: 0, resume: null,
        host: null, ws: null, ended: false, stats: { reqs: 0 }, recent: [],
      };
      offer.pendingTimer = setTimeout(() => endOffer(offer, 'unclaimed'), TEN_MIN); // code must be used within 10 min
      offers.set(offer.id, offer); byCode.set(raw, offer);
      json(res, 200, { ok: true, ...offerStatus({ headers: { cookie: `__pl_offer=${offer.id}` } }) },
        { 'set-cookie': setCookie(req, '__pl_offer', offer.id, 86400) });
      return true;
    }

    if (p === '/__pl/exit/offer/stop' && req.method === 'POST') {
      const o = myOffer(req);
      if (o) endOffer(o, 'stopped from the browser');
      json(res, 200, { ok: true });
      return true;
    }
    return false;
  }

  /* ------------------------------------------- run a request on computer A */

  function remoteFetch(host, { method, url, headers, body }, signal) {
    return new Promise((resolve, reject) => {
      if (host.closed || host.ws.readyState !== WebSocket.OPEN) {
        return reject(Object.assign(new Error('The remote computer is offline'), { code: 'PL_REMOTE_OFFLINE' }));
      }
      const id = (host.nextId = (host.nextId + 1) >>> 0 || 1);
      let ctrl, settled = false;
      const resume = () => { host.blocked.delete(id); if (!host.blocked.size) host.ws._socket?.resume(); };

      const stream = new ReadableStream({
        start(c) { ctrl = c; },
        pull() { resume(); },
        cancel() { cancelRemote(); },
      }, new ByteLengthQueuingStrategy({ highWaterMark: 4 * 1024 * 1024 }));

      const finish = () => { host.inflight.delete(id); resume(); signal?.removeEventListener('abort', onAbort); };
      function cancelRemote() {
        if (!host.inflight.has(id)) return;
        finish();
        if (host.ws.readyState === WebSocket.OPEN) host.ws.send(JSON.stringify({ t: 'cancel', id }));
      }
      function onAbort() {
        const e = Object.assign(new Error('aborted'), { code: 'ABORT_ERR' });
        cancelRemote();
        if (!settled) reject(e); else try { ctrl.error(e); } catch { /* closed */ }
      }

      host.inflight.set(id, {
        res(m) {
          settled = true;
          const h = new Headers();
          for (const [k, v] of m.headers) h.append(k, v);
          if (!m.hasBody) finish();
          resolve(new Response(m.hasBody ? stream : null, { status: m.status, headers: h }));
        },
        data(buf) {
          try { ctrl.enqueue(Buffer.from(buf)); } catch { return; }
          if (ctrl.desiredSize <= 0) { host.blocked.add(id); host.ws._socket?.pause(); }
        },
        end() { finish(); try { ctrl.close(); } catch { /* already closed */ } },
        err(m) {
          finish();
          const e = Object.assign(new Error(m.message || 'Remote request failed'), { code: m.code || 'PL_REMOTE' });
          if (!settled) reject(e); else try { ctrl.error(e); } catch { /* closed */ }
        },
      });

      signal?.addEventListener('abort', onAbort, { once: true });
      host.stats.reqs++;
      try {
        const o = host.offer;
        o.recent.unshift(`${method} ${new URL(url).host}`);
        o.recent.length = Math.min(o.recent.length, 10);
      } catch { /* ignore */ }
      const hasBody = !!(body && body.length);
      host.ws.send(JSON.stringify({ t: 'req', id, method, url, headers, hasBody }));
      if (hasBody) {
        const CH = 256 * 1024;
        for (let o = 0; o < body.length; o += CH) host.ws.send(frame(id, 0, body.subarray(o, o + CH)));
        host.ws.send(frame(id, 1));
      }
    });
  }

  return { enabled, route, handleAgentUpgrade, getExit, remoteFetch };
}

export function frame(id, flag, payload) {
  const h = Buffer.alloc(5);
  h.writeUInt32BE(id, 0);
  h[4] = flag;
  return payload && payload.length ? Buffer.concat([h, payload]) : h;
}
