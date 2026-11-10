// URL / HTML / CSS / JS rewriting. Everything that can point the browser somewhere
// (or move it somewhere) is routed back through /p/<scheme>/<host>/<path>.
import * as cheerio from 'cheerio';
import * as acorn from 'acorn';

const SKIP = /^(?:data|blob|javascript|mailto|tel|about|sms|file|chrome|view-source):/i;
export const RUNTIME_SRC = '/__pl/runtime.js';

/* ------------------------------------------------------------------ URLs */

export function encodeProxy(u) {
  return `/p/${u.protocol.slice(0, -1)}/${u.host}${u.pathname}${u.search}${u.hash}`;
}

export function toProxy(raw, base) {
  if (raw == null) return raw;
  const s = String(raw).trim();
  if (!s || s[0] === '#' || SKIP.test(s)) return raw;
  if (/^\/p\/(https?|wss?)\/[^/]/.test(s)) return raw; // already proxied
  let u;
  try { u = new URL(s, base); } catch { return raw; }
  if (!/^(https?|wss?):$/.test(u.protocol)) return raw;
  return encodeProxy(u);
}

const PROXY_RE = /^\/p\/(https?|wss?)\/([^/?#]+)(\/[^?#]*)?(\?[^#]*)?/;
export function parseProxyUrl(pathAndQuery) {
  const m = PROXY_RE.exec(pathAndQuery);
  if (!m) return null;
  try {
    return { scheme: m[1], hasPath: m[3] != null, url: new URL(`${m[1]}://${m[2]}${m[3] || '/'}${m[4] || ''}`) };
  } catch { return null; }
}

/** `Refresh: 5; url=/x` and <meta http-equiv=refresh content="..."> */
export function rewriteRefresh(content, base) {
  const m = /^(\s*[\d.]+\s*)(?:[;,\s]\s*(?:url\s*=\s*)?['"]?(.*?)['"]?\s*)?$/is.exec(content || '');
  if (!m || !m[2]) return content;
  return `${m[1].trim()}; url=${toProxy(m[2], base)}`;
}

export function rewriteSrcset(v, base) {
  return String(v).split(/(?<=\s[\d.]+[wx])\s*,\s*|,\s+/).map((part) => {
    const t = part.trim();
    if (!t) return t;
    const i = t.search(/\s/);
    return i < 0 ? toProxy(t, base) : toProxy(t.slice(0, i), base) + t.slice(i);
  }).join(', ');
}

export function rewriteLinkHeader(v, base) {
  return v.replace(/<([^>]*)>/g, (_, u) => `<${toProxy(u, base)}>`);
}

/** Per-origin cookie isolation via cookie Path; strip Domain/SameSite so it works on our single origin. */
export function rewriteSetCookie(sc, scheme, host, https) {
  const parts = sc.split(';');
  let first = parts.shift();
  if (/^\s*__Host-/.test(first)) first = first.replace('__Host-', '__plh-'); // __Host- forbids non-root Path
  const kept = [first];
  for (const p of parts) {
    const k = p.trim().split('=')[0].toLowerCase();
    if (['domain', 'path', 'samesite', 'partitioned'].includes(k)) continue;
    if (k === 'secure' && !https) continue;
    kept.push(p);
  }
  kept.push(`Path=/p/${scheme}/${host}/`);
  return kept.join(';');
}

/* ------------------------------------------------------------------- CSS */

export function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)([^'")]*?)\1\s*\)/gi, (m, q, u) => `url(${q}${toProxy(u, base)}${q})`)
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => `@import ${q}${toProxy(u, base)}${q}`);
}

/* -------------------------------------------------------------------- JS */
// AST based so we never touch strings/comments/property names.
//   window.location / top.location / document.location / bare `location`  ->  __pl.location
//   import 'https://x/y.js', import('/y.js'), export ... from '...'        ->  proxied specifiers
// __pl.location is a shim (see runtime.js) whose setters/assign/replace navigate through the proxy.

const WINDOWISH = new Set(['window', 'self', 'top', 'parent', 'globalThis', 'document', 'frames', 'opener']);
const SKIP_KEYS = new Set(['type', 'start', 'end', 'loc', 'range']);

function propName(m) {
  if (!m.computed && m.property.type === 'Identifier') return m.property.name;
  if (m.computed && m.property.type === 'Literal' && typeof m.property.value === 'string') return m.property.value;
  return null;
}
function isWindowish(n) {
  if (!n) return false;
  if (n.type === 'Identifier') return WINDOWISH.has(n.name);
  if (n.type === 'MemberExpression') {
    const p = propName(n);
    return p != null && WINDOWISH.has(p) && isWindowish(n.object);
  }
  return false;
}
function nonRef(parent, key) {
  switch (parent.type) {
    case 'MemberExpression': return key === 'property' && !parent.computed;
    case 'Property': case 'MethodDefinition': case 'PropertyDefinition': return key === 'key' && !parent.computed;
    case 'LabeledStatement': case 'BreakStatement': case 'ContinueStatement': return key === 'label';
    case 'ExportSpecifier': case 'MetaProperty': return true;
    default: return false;
  }
}
function collectDecl(node, ctx) {
  if (!node || typeof node.type !== 'string') return;
  if (node.type === 'Identifier') { if (node.name === 'location') ctx.declared = true; return; }
  for (const k of Object.keys(node)) {
    if (SKIP_KEYS.has(k)) continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach((c) => collectDecl(c, ctx));
    else if (v && typeof v.type === 'string') collectDecl(v, ctx);
  }
}
const FUNCS = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);
const NAMED = new Set(['FunctionDeclaration', 'FunctionExpression', 'ClassDeclaration', 'ClassExpression']);

function needsSpecifierRewrite(v) {
  return typeof v === 'string' && (v.startsWith('/') || /^[a-z][a-z0-9+.-]*:/i.test(v));
}

function visitChild(parent, key, child, ctx) {
  if (!child || typeof child.type !== 'string') return;
  if (
    (parent.type === 'VariableDeclarator' && key === 'id') ||
    (FUNCS.has(parent.type) && key === 'params') ||
    (parent.type === 'CatchClause' && key === 'param') ||
    (NAMED.has(parent.type) && key === 'id') ||
    /^Import(Default|Namespace)?Specifier$/.test(parent.type) ||
    (parent.type === 'AssignmentExpression' && key === 'left' && /Pattern$/.test(child.type))
  ) { collectDecl(child, ctx); return; }
  if (child.type === 'Identifier') {
    if (child.name === 'location' && !nonRef(parent, key)) ctx.edits.push({ s: child.start, e: child.end, t: '__pl.location', bare: true });
    return;
  }
  if (child.type === 'Property' && child.shorthand) {
    if (parent.type === 'ObjectPattern') { collectDecl(child, ctx); return; }
    if (child.key.name === 'location') ctx.edits.push({ s: child.start, e: child.end, t: 'location: __pl.location', bare: true });
    return;
  }
  walk(child, ctx);
}

function walk(node, ctx) {
  switch (node.type) {
    case 'MemberExpression':
      if (propName(node) === 'location' && isWindowish(node.object)) {
        ctx.edits.push({ s: node.start, e: node.end, t: '__pl.location' });
        return;
      }
      break;
    case 'ImportDeclaration': case 'ExportAllDeclaration': case 'ExportNamedDeclaration': case 'ImportExpression': {
      const src = node.source;
      if (src && src.type === 'Literal' && needsSpecifierRewrite(src.value)) {
        ctx.edits.push({ s: src.start, e: src.end, t: JSON.stringify(toProxy(src.value, ctx.base)) });
      }
      break;
    }
  }
  for (const k of Object.keys(node)) {
    if (SKIP_KEYS.has(k)) continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach((c) => visitChild(node, k, c, ctx));
    else if (v && typeof v.type === 'string') visitChild(node, k, v, ctx);
  }
}

export function rewriteJs(code, base, { rewriteLocation = true } = {}) {
  if (!code || code.length > 4_000_000) return code;
  if (!/location|import|export/.test(code)) return code;
  let ast;
  const opts = { ecmaVersion: 'latest', allowReturnOutsideFunction: true, allowHashBang: true };
  try { ast = acorn.parse(code, { ...opts, sourceType: 'script' }); }
  catch {
    try { ast = acorn.parse(code, { ...opts, sourceType: 'module' }); }
    catch { return code; }
  }
  const ctx = { edits: [], declared: false, base };
  walk(ast, ctx);
  let edits = ctx.edits.filter((e) => rewriteLocation || e.t.startsWith('"'));
  if (ctx.declared) edits = edits.filter((e) => !e.bare);
  if (!edits.length) return code;
  edits.sort((a, b) => b.s - a.s);
  let out = code;
  for (const e of edits) out = out.slice(0, e.s) + e.t + out.slice(e.e);
  return out;
}

/* ------------------------------------------------------------------ HTML */

const URL_ATTRS = ['href', 'src', 'action', 'formaction', 'poster', 'cite', 'background', 'codebase', 'longdesc', 'manifest', 'xlink:href'];
const JS_TYPE = /^(?:|module|(?:text|application)\/(?:x-)?(?:javascript|ecmascript|jscript)|text\/jsx?)$/i;

export function rewriteHtml(html, docUrl, depth = 0) {
  const $ = cheerio.load(html, { scriptingEnabled: false }, true);

  // <base> changes how relative URLs resolve, so honour it for rewriting, then proxy it too.
  let base = docUrl;
  const baseHref = $('base[href]').first().attr('href');
  if (baseHref) { try { base = new URL(baseHref, docUrl).href; } catch { /* keep */ } }

  const rewriteChildrenText = (el, fn) => {
    for (const c of el.children || []) if (typeof c.data === 'string') c.data = fn(c.data);
  };

  $('*').each((_, el) => {
    const a = el.attribs;
    if (!a) return;
    const tag = el.name;

    for (const n of URL_ATTRS) {
      if (a[n] == null) continue;
      if (/^\s*javascript:/i.test(a[n])) a[n] = 'javascript:' + rewriteJs(a[n].replace(/^\s*javascript:/i, ''), base);
      else a[n] = toProxy(a[n], base);
    }
    if (tag === 'object' && a.data != null) a.data = toProxy(a.data, base);
    if (a.srcset != null) a.srcset = rewriteSrcset(a.srcset, base);
    if (a.imagesrcset != null) a.imagesrcset = rewriteSrcset(a.imagesrcset, base);
    if (a.ping != null) a.ping = a.ping.split(/\s+/).map((u) => toProxy(u, base)).join(' ');
    if (a.style != null) a.style = rewriteCss(a.style, base);
    if (a.integrity != null) delete a.integrity; // content is rewritten, SRI would fail
    for (const n of Object.keys(a)) {
      if (n.length > 2 && n.startsWith('on')) a[n] = rewriteJs(a[n], base); // inline handlers: onclick="location=..."
    }
    if (tag === 'iframe' && a.srcdoc != null && depth < 2) a.srcdoc = rewriteHtml(a.srcdoc, base, depth + 1);

    if (tag === 'meta') {
      const he = (a['http-equiv'] || '').toLowerCase();
      if (he === 'refresh' && a.content != null) a.content = rewriteRefresh(a.content, base);
      else if (he === 'content-security-policy' || (a.name || '').toLowerCase() === 'referrer') $(el).remove();
    } else if (tag === 'link') {
      const rel = (a.rel || '').toLowerCase();
      if (/\b(preconnect|dns-prefetch|serviceworker)\b/.test(rel)) $(el).remove();
    } else if (tag === 'style') {
      rewriteChildrenText(el, (t) => rewriteCss(t, base));
    } else if (tag === 'script') {
      const type = (a.type || '').trim();
      if (type === 'speculationrules') { $(el).remove(); return; }
      if (type === 'importmap') {
        rewriteChildrenText(el, (t) => {
          try {
            const j = JSON.parse(t);
            const fix = (m) => { for (const k of Object.keys(m || {})) m[k] = toProxy(m[k], base); };
            fix(j.imports);
            for (const s of Object.keys(j.scopes || {})) fix(j.scopes[s]);
            return JSON.stringify(j);
          } catch { return t; }
        });
      } else if (a.src == null && JS_TYPE.test(type)) {
        rewriteChildrenText(el, (t) => rewriteJs(t, base));
      }
    }
  });

  $('head').prepend(`<script src="${RUNTIME_SRC}"></script>`);
  return $.html();
}
