# render-proxy

A web proxy for Render. URLs look like `/p/<scheme>/<host>/<path>`, e.g. `/p/https/example.com/a?b=1`.

## Deploy

1. Push this folder to a GitHub repo.
2. Render → New → Web Service (or Blueprint, `render.yaml` is included). Build: `npm install --omit=dev`, start: `node server.js`, health check: `/healthz`.
3. **Set `ACCESS_KEY`** in Environment. Without it anyone who finds the URL can use your proxy. Visit `https://your-app.onrender.com/?key=YOURKEY` once per browser.

## Redirect coverage

| Mechanism | How it's handled |
|---|---|
| HTTP 301/302/303/307/308 `Location` (relative, absolute, protocol-relative, any status that sends Location) | Upstream is fetched with `redirect: manual`; `Location` is resolved against the upstream URL and rewritten. Browser follows every hop through the proxy; 307/308 keep method + body natively |
| `Refresh:` response header | Rewritten |
| `<meta http-equiv=refresh>` (static, inside `<noscript>`, JS-created, `.content=` set later) | Rewritten server-side, in `setAttribute`/property setters, and by a MutationObserver |
| `location.href=`, `location=`, `assign`, `replace`, `window/document/top/parent/self.location` | JS is parsed (acorn AST) and `location` references become a shim, `__pl.location`, that navigates through the proxy and reports the real URL |
| Inline `onclick=` handlers, `javascript:` URLs, `setTimeout("string")`, `new Function`, dynamically-created `<script>` text | Rewritten (server-side, or via `/__pl/rw` for strings created at runtime) |
| `window.open`, `history.pushState/replaceState`, `navigation.navigate`, `<a>` clicks, form submit (static, `form.submit()`, `formaction`) | Patched / attributes rewritten |
| `fetch`, XHR, `sendBeacon`, `EventSource`, `Worker`, WebSocket | URLs rewritten; WebSockets are tunnelled (`/p/wss/...`) |
| ES module `import`/`export ... from`/`import()`, import maps | Specifiers rewritten |
| `<base href>`, `srcset`, CSS `url()`/`@import`, `<iframe srcdoc>`, `Link:` headers | Rewritten |
| Anything that still produces a root-relative URL (`/foo`) on the proxy origin | Re-routed with a 307 using Referer / `__pl_o` cookie |
| Service workers, speculation rules, preconnect | Blocked / removed |

## Browse through another computer's internet (exit mode)

Use this when sites block Render's datacenter IP (captchas, "unusual traffic") and you want them to see a home/office connection instead.

```
Computer A (shares its connection)  --tunnel-->  your Render app  <--  Computer B (browses)
```

1. Set `ACCESS_KEY` on Render (this mode is disabled without it).
2. **On computer A** (needs Node 20+): unzip this project, run `npm install`, then `node agent.js https://YOUR-APP.onrender.com`. A page opens on A at `127.0.0.1`. Enter the access key, choose a **PIN (4 to 8 digits)** and a time limit, and press **Allow sharing**. Nothing is shared until you press it, and **Stop sharing** ends it immediately.
3. **On computer B**: open the proxy start page, expand *Use another computer's internet connection*, enter the PIN, press Connect. All browsing now goes out from A. *Disconnect* switches back to Render's own connection.

Safety: A's agent refuses localhost / private / LAN addresses, so B can never reach A's home network. The PIN is rate-limited (5 wrong tries per 10 min per address, global lockout after 15). Sharing auto-stops after the chosen time. A's page lists the sites being requested. While A is offline B gets an error page, never a silent fallback to Render's IP.
Limits: WebSockets are not tunnelled in this mode; B must re-enter the PIN if A restarts; keep the agent's terminal open.
Headless use (running the command is your consent): `node agent.js URL --arm --pin 123456 --key ACCESS_KEY --minutes 60`.

## Keepalive

Render's free plan sleeps an instance after ~15 minutes without traffic. The server pings its own public URL (`RENDER_EXTERNAL_URL`, set by Render) every ~10 minutes, and the agent pings it every 4 minutes while sharing. Disable with `KEEPALIVE=off`. One free service running 24/7 uses about 744 of Render's 750 free instance hours per month, so don't run several free services at once.

## Security notes

- Private/loopback/link-local addresses are refused, checked at connect time (defeats DNS rebinding).
- CSP / X-Frame-Options / HSTS / COOP etc. are stripped from proxied responses so rewriting works.
- All proxied sites share one origin, so they are **not isolated from each other** (cookies are path-scoped per site, but localStorage and same-origin JS are shared). Don't log into sensitive accounts through it.

## Known limits

Direct `eval()` code and heavily obfuscated `window["loc"+"ation"]` tricks can't be rewritten; SVG documents aren't rewritten; `postMessage` origin checks inside sites see the proxy origin; DRM/video players that pin origins may fail. `ALLOW_PRIVATE=1` disables the SSRF guard and exists only for local testing. `USER_AGENT` (default: Tor Browser's, `off` to pass yours through) applies to Render's own connection; exit mode always uses the browser's real headers. `DEBUG_PROXY=1` logs upstream 4xx/5xx.
