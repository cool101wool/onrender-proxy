// "Exit via another computer" mode.
//
//   Computer A (shares its internet)  --WebSocket-->  this server  <--HTTPS--  Computer B (browses)
//
// A runs agent.js, presses a button and sets a PIN. B enters the PIN on the start page. From then on B's
// proxied requests are executed by A's agent, so sites see A's IP address. Requires ACCESS_KEY.
//
// Tunnel protocol (WebSocket):
//   text frames  (JSON):  hello / ready / reject / viewers / expired / req / res / err / cancel
//   binary frames:        [uint32 request-id][uint8 flag: 0=data, 1=end][payload]
import crypto from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';

const TEN_MIN = 10 * 60 * 1000;
const SESSION_MS = 12 * 60 * 60 * 1000;

export function createExit(d) {
  const enabled = !!d.ACCESS_KEY;
  const secret = crypto.randomBytes(32);
  const pinKey = (pin) => crypto.createHmac('sha256', secret).update(String(pin)).digest('hex');

  const hosts = new Map();     // pinKey -> host
  const sessions = new Map();  // token  -> { host, exp }
  const fails = new Map();     // ip     -> { n, t }
  const hits = [];             // timestamps of failed PIN attempts (global)
  let lockUntil = 0;

  const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 * 1024 });

  const json = (res, status, obj, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
    res.end(JSON.stringify(obj));
  };
  const clientIp = (req) =>
    req.headers['cf-connecting-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
  const cookie = (req, v, maxAge) =>
    `__pl_exit=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${d.isHttps(req) ? '; Secure' : ''}`;

  /* ------------------------------------------------------------ host side */

  function closeHost(host) {
    if (host.closed) return;
    host.closed = true;
    clearTimeout(host.timer);
    if (hosts.get(host.key) === host) hosts.delete(host.key);
    for (const t of host.sessions) sessions.delete(t);
    host.sessions.clear();
    for (const e of [...host.inflight.values()]) e.err({ message: 'The remote computer disconnected', code: 'PL_REMOTE_OFFLINE' });
    host.inflight.clear();
  }

  const notifyViewers = (host) => {
    if (host.ws.readyState === WebSocket.OPEN) host.ws.send(JSON.stringify({ t: 'viewers', n: host.sessions.size, reqs: host.stats.reqs }));
  };

  function onAgent(ws) {
    let host = null;
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    const helloTimer = setTimeout(() => ws.close(1008, 'hello timeout'), 10_000);
    const reject = (code, reason) => { ws.send(JSON.stringify({ t: 'reject', code, reason })); ws.close(1000, 'rejected'); };

    ws.on('message', (data, isBinary) => {
      if (!host) {
        let m;
        try { m = JSON.parse(data.toString()); } catch { return ws.close(1008); }
        if (isBinary || m.t !== 'hello') return ws.close(1008);
        clearTimeout(helloTimer);
        const pin = String(m.pin || '');
        if (!/^\d{4,8}$/.test(pin)) return reject('bad_pin', 'The PIN must be 4 to 8 digits');
        const key = pinKey(pin);
        if (hosts.has(key)) return reject('in_use', 'That PIN is already in use. Choose a different one');
        const minutes = Math.min(Math.max(parseInt(m.minutes, 10) || 60, 1), 480);
        host = { ws, key, inflight: new Map(), blocked: new Set(), nextId: 0, sessions: new Set(), closed: false,
          stats: { reqs: 0 }, expires: Date.now() + minutes * 60_000 };
        host.timer = setTimeout(() => { try { ws.send(JSON.stringify({ t: 'expired' })); } catch { /* gone */ } ws.close(1000, 'expired'); }, minutes * 60_000);
        hosts.set(key, host);
        ws.send(JSON.stringify({ t: 'ready', expiresAt: host.expires }));
        return;
      }
      if (isBinary) {
        const id = data.readUInt32BE(0), flag = data[4];
        const e = host.inflight.get(id);
        if (!e) return;
        if (flag === 0) e.data(data.subarray(5)); else e.end();
        return;
      }
      let m;
      try { m = JSON.parse(data.toString()); } catch { return; }
      const e = host.inflight.get(m.id);
      if (!e) return;
      if (m.t === 'res') e.res(m); else if (m.t === 'err') e.err(m);
    });
    ws.on('close', () => { clearTimeout(helloTimer); if (host) closeHost(host); });
    ws.on('error', () => { /* handled by close */ });
  }

  // Drop dead agents (Render's proxy silently kills idle sockets) and expired sessions.
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
    const tok = req.headers['x-pl-auth'];
    if (!tok || !d.safeEq(String(tok), d.authToken())) return fail(401, 'Unauthorized');
    wss.handleUpgrade(req, socket, head, onAgent);
  }

  /* ------------------------------------------------------- viewer (B) side */

  function getExit(req) {
    const t = d.parseCookies(req.headers.cookie).__pl_exit;
    if (!t) return null;
    const s = sessions.get(t);
    if (!s || s.exp < Date.now() || s.host.closed) { sessions.delete(t); return { gone: true }; }
    return s;
  }

  async function route(req, res, u) {
    const p = u.pathname;

    if (p === '/__pl/exit/status') {
      const s = getExit(req);
      json(res, 200, { enabled, connected: !!(s && !s.gone), offline: !!(s && s.gone) });
      return true;
    }

    if (p === '/__pl/exit/off') {
      const t = d.parseCookies(req.headers.cookie).__pl_exit;
      const s = t && sessions.get(t);
      if (s) { sessions.delete(t); s.host.sessions.delete(t); notifyViewers(s.host); }
      res.writeHead(302, { location: '/', 'set-cookie': cookie(req, '', 0) });
      res.end();
      return true;
    }

    if (p === '/__pl/exit/connect' && req.method === 'POST') {
      if (!enabled) { json(res, 403, { ok: false, error: 'This mode is disabled until ACCESS_KEY is set on the server' }); return true; }
      if ((req.headers['content-type'] || '').split(';')[0] !== 'application/json') { json(res, 415, { ok: false, error: 'Bad request' }); return true; }
      const now = Date.now();
      if (now < lockUntil) { json(res, 429, { ok: false, error: 'Too many wrong PINs. Try again in a few minutes' }); return true; }
      const ip = clientIp(req);
      let f = fails.get(ip);
      if (!f || now - f.t > TEN_MIN) f = { n: 0, t: now };
      if (f.n >= 5) { json(res, 429, { ok: false, error: 'Too many wrong PINs from your address. Try again later' }); return true; }

      let pin = '';
      try { pin = String(JSON.parse((await d.readBody(req, 1024)).toString()).pin || ''); } catch { /* empty */ }
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
      json(res, 200, { ok: true }, { 'set-cookie': cookie(req, token, SESSION_MS / 1000) });
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
