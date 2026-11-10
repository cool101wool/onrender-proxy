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

## Security notes

- Private/loopback/link-local addresses are refused, checked at connect time (defeats DNS rebinding).
- CSP / X-Frame-Options / HSTS / COOP etc. are stripped from proxied responses so rewriting works.
- All proxied sites share one origin, so they are **not isolated from each other** (cookies are path-scoped per site, but localStorage and same-origin JS are shared). Don't log into sensitive accounts through it.

## Known limits

Direct `eval()` code and heavily obfuscated `window["loc"+"ation"]` tricks can't be rewritten; SVG documents aren't rewritten; `postMessage` origin checks inside sites see the proxy origin; DRM/video players that pin origins may fail. `ALLOW_PRIVATE=1` disables the SSRF guard and exists only for local testing.
