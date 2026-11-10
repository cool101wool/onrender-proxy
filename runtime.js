/* Injected first into every proxied HTML page.
 * Makes JS-driven navigation, network calls and DOM-created URLs go through the proxy
 * and makes the page believe it lives at the real URL. */
(function () {
  'use strict';
  if (window.__pl) return;

  var RealLoc = window.location;
  var ORIGIN = RealLoc.origin;
  var PROXIED = /^\/p\/(https?|wss?)\/[^\/]/;
  var SKIP = /^(?:data|blob|javascript|mailto|tel|about|sms):/i;
  var oGetAttr = Element.prototype.getAttribute;
  var oSetAttr = Element.prototype.setAttribute;
  var xhrOpen = XMLHttpRequest.prototype.open;
  var xhrSend = XMLHttpRequest.prototype.send;
  var baseGet = Object.getOwnPropertyDescriptor(Node.prototype, 'baseURI').get;

  /* ---------- URL helpers ---------- */
  function parseReal(p) {
    var m = /^\/p\/(https?|wss?)\/([^\/?#]+)(\/[^?#]*)?(\?[^#]*)?(#.*)?$/.exec(p);
    if (!m) return null;
    try { return new URL(m[1] + '://' + m[2] + (m[3] || '/') + (m[4] || '') + (m[5] || '')); } catch (e) { return null; }
  }
  function unprox(v) {
    if (typeof v !== 'string' || !v) return v;
    try {
      var u = new URL(v, RealLoc.href);
      if (u.origin === ORIGIN) { var r = parseReal(u.pathname + u.search + u.hash); if (r) return r.href; }
    } catch (e) {}
    return v;
  }
  function curReal() { return parseReal(RealLoc.pathname + RealLoc.search + RealLoc.hash) || new URL(RealLoc.href); }
  function realBase() { return unprox(baseGet.call(document)); }
  function proxify(u, base) {
    if (u == null) return u;
    if (u instanceof URL) u = u.href;
    var s = String(u), t = s.trim();
    if (!t || t.charAt(0) === '#' || SKIP.test(t) || PROXIED.test(t)) return s;
    var abs;
    try { abs = new URL(t, base || realBase()); } catch (e) { return s; }
    if (abs.origin === ORIGIN) return s;
    if (!/^(https?|wss?):$/.test(abs.protocol)) return s;
    return '/p/' + abs.protocol.slice(0, -1) + '/' + abs.host + abs.pathname + abs.search + abs.hash;
  }
  function cookiePath() { var r = curReal(); return '/p/' + r.protocol.slice(0, -1) + '/' + r.host + '/'; }

  /* ---------- JS rewrite via server (for eval-like strings) ---------- */
  var needsRw = /location|import\b/;
  function rw(code) {
    if (typeof code !== 'string' || !needsRw.test(code)) return code;
    try {
      var x = new XMLHttpRequest();
      xhrOpen.call(x, 'POST', '/__pl/rw', false);
      x.setRequestHeader('X-PL-Base', realBase());
      xhrSend.call(x, code);
      if (x.status === 200) return x.responseText;
    } catch (e) {}
    return code;
  }
  function rwJsUrl(v) { return /^\s*javascript:/i.test(v) ? 'javascript:' + rw(v.replace(/^\s*javascript:/i, '')) : null; }

  /* ---------- location shim ---------- */
  function navigate(u, replace) {
    var p = proxify(u);
    if (replace) RealLoc.replace(p); else RealLoc.assign(p);
  }
  var shim = {};
  function def(n, g, s) { Object.defineProperty(shim, n, { get: g, set: s, enumerable: true, configurable: true }); }
  ['protocol', 'host', 'hostname', 'port', 'pathname', 'search'].forEach(function (n) {
    def(n, function () { return curReal()[n]; }, function (v) { var u = curReal(); u[n] = v; navigate(u.href); });
  });
  def('origin', function () { return curReal().origin; });
  def('hash', function () { return RealLoc.hash; }, function (v) { RealLoc.hash = v; });
  def('href', function () { return curReal().href; }, function (v) { navigate(v); });
  shim.assign = function (u) { navigate(u); };
  shim.replace = function (u) { navigate(u, true); };
  shim.reload = function () { RealLoc.reload(); };
  shim.toString = function () { return curReal().href; };
  shim.valueOf = shim.toString;
  Object.defineProperty(shim, 'ancestorOrigins', { get: function () { return RealLoc.ancestorOrigins; } });
  Object.defineProperty(shim, Symbol.toPrimitive, { value: function () { return curReal().href; } });

  var PL = {};
  Object.defineProperty(PL, 'location', { get: function () { return shim; }, set: function (v) { navigate(v); }, enumerable: true });
  PL.proxify = proxify; PL.unprox = unprox; PL.rw = rw;
  Object.defineProperty(window, '__pl', { value: PL, configurable: false });

  /* ---------- attributes / properties ---------- */
  var URLA = { href: 1, src: 1, action: 1, formaction: 1, poster: 1, background: 1, 'xlink:href': 1, data: 1 };
  function srcsetRw(v) {
    return String(v).split(/(?<=\s[\d.]+[wx])\s*,\s*|,\s+/).map(function (p) {
      p = p.trim(); var i = p.search(/\s/);
      return i < 0 ? proxify(p) : proxify(p.slice(0, i)) + p.slice(i);
    }).join(', ');
  }
  function cssRw(v) { return String(v).replace(/url\(\s*(['"]?)([^'")]*?)\1\s*\)/gi, function (m, q, u) { return 'url(' + q + proxify(u) + q + ')'; }); }
  function refreshRw(c) {
    var m = /^(\s*[\d.]+\s*)(?:[;,\s]\s*(?:url\s*=\s*)?['"]?(.*?)['"]?\s*)?$/i.exec(c || '');
    return (m && m[2]) ? m[1].trim() + '; url=' + proxify(m[2]) : c;
  }
  function fixAttr(el, n, v) {
    v = String(v);
    if (URLA[n]) {
      if (n === 'data' && el.tagName !== 'OBJECT') return v;
      return rwJsUrl(v) || proxify(v);
    }
    if (n === 'srcset' || n === 'imagesrcset') return srcsetRw(v);
    if (n === 'style') return cssRw(v);
    if (n === 'integrity') return '';
    if (n.length > 2 && n.charAt(0) === 'o' && n.charAt(1) === 'n') return rw(v);
    if (n === 'content' && el.tagName === 'META' && /refresh/i.test(oGetAttr.call(el, 'http-equiv') || '')) return refreshRw(v);
    return v;
  }
  Element.prototype.setAttribute = function (n, v) { return oSetAttr.call(this, n, fixAttr(this, String(n).toLowerCase(), v)); };
  Element.prototype.getAttribute = function (n) {
    var v = oGetAttr.call(this, n), l = String(n).toLowerCase();
    return (URLA[l] && v && PROXIED.test(v)) ? unprox(v) : v;
  };
  var oSetNS = Element.prototype.setAttributeNS;
  Element.prototype.setAttributeNS = function (ns, n, v) {
    var l = String(n).toLowerCase();
    if (l === 'xlink:href' || l === 'href') v = proxify(v);
    return oSetNS.call(this, ns, n, v);
  };

  function patchProp(C, name, fix) {
    if (!window[C]) return;
    var proto = window[C].prototype, d = Object.getOwnPropertyDescriptor(proto, name);
    if (!d || !d.set || !d.configurable) return;
    Object.defineProperty(proto, name, {
      configurable: true, enumerable: d.enumerable,
      get: function () { return unprox(d.get.call(this)); },
      set: function (v) { d.set.call(this, (fix || function (x) { return rwJsUrl(String(x)) || proxify(x); })(v)); }
    });
  }
  [['HTMLAnchorElement', 'href'], ['HTMLAreaElement', 'href'], ['HTMLLinkElement', 'href'], ['HTMLBaseElement', 'href'],
   ['HTMLImageElement', 'src'], ['HTMLScriptElement', 'src'], ['HTMLIFrameElement', 'src'], ['HTMLFrameElement', 'src'],
   ['HTMLEmbedElement', 'src'], ['HTMLObjectElement', 'data'], ['HTMLMediaElement', 'src'], ['HTMLSourceElement', 'src'],
   ['HTMLTrackElement', 'src'], ['HTMLVideoElement', 'poster'], ['HTMLFormElement', 'action'],
   ['HTMLInputElement', 'src'], ['HTMLInputElement', 'formAction'], ['HTMLButtonElement', 'formAction']
  ].forEach(function (p) { patchProp(p[0], p[1]); });
  patchProp('HTMLImageElement', 'srcset', srcsetRw);
  patchProp('HTMLSourceElement', 'srcset', srcsetRw);
  patchProp('HTMLLinkElement', 'imageSrcset', srcsetRw);

  ['origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search'].forEach(function (n) {
    ['HTMLAnchorElement', 'HTMLAreaElement'].forEach(function (C) {
      var proto = window[C].prototype, d = Object.getOwnPropertyDescriptor(proto, n);
      if (!d || !d.get) return;
      Object.defineProperty(proto, n, { configurable: true, enumerable: true, set: d.set,
        get: function () { try { return new URL(this.href)[n]; } catch (e) { return d.get.call(this); } } });
    });
  });

  // <meta http-equiv=refresh>.content assigned from script
  (function () {
    var d = Object.getOwnPropertyDescriptor(HTMLMetaElement.prototype, 'content');
    if (!d || !d.set) return;
    Object.defineProperty(HTMLMetaElement.prototype, 'content', { configurable: true, enumerable: true, get: d.get,
      set: function (v) { d.set.call(this, /refresh/i.test(oGetAttr.call(this, 'http-equiv') || '') ? refreshRw(String(v)) : v); } });
  })();

  // dynamically created inline <script>
  ['text', 'textContent'].forEach(function (n) {
    var d = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, n) || Object.getOwnPropertyDescriptor(Node.prototype, n);
    if (!d || !d.set) return;
    Object.defineProperty(HTMLScriptElement.prototype, n, { configurable: true, enumerable: true, get: d.get,
      set: function (v) {
        var t = (oGetAttr.call(this, 'type') || '').toLowerCase();
        d.set.call(this, (!t || /javascript|ecmascript|module/.test(t)) ? rw(String(v)) : v);
      } });
  });

  /* ---------- HTML strings (innerHTML, document.write, ...) ---------- */
  var ATTRS = ['href', 'src', 'action', 'formaction', 'poster', 'background', 'data', 'srcset', 'imagesrcset', 'style', 'integrity', 'content', 'xlink:href'];
  function fixEl(el) {
    if (!el || el.nodeType !== 1) return;
    for (var i = 0; i < ATTRS.length; i++) {
      var n = ATTRS[i], v = oGetAttr.call(el, n);
      if (v == null) continue;
      if (n === 'content') { if (el.tagName !== 'META') continue; }
      var nv = fixAttr(el, n, v);
      if (nv !== v) oSetAttr.call(el, n, nv);
    }
    var at = el.attributes;
    for (var j = 0; j < at.length; j++) {
      var an = at[j].name;
      if (an.length > 2 && an.charAt(0) === 'o' && an.charAt(1) === 'n') { var o = at[j].value, r = rw(o); if (r !== o) oSetAttr.call(el, an, r); }
    }
  }
  function fixTree(root) {
    if (root.nodeType === 1) fixEl(root);
    var all = root.querySelectorAll ? root.querySelectorAll('*') : [];
    for (var i = 0; i < all.length; i++) fixEl(all[i]);
  }
  function rwHtml(h) {
    if (typeof h !== 'string' || h.indexOf('<') < 0) return h;
    var tpl = document.createElement('template');
    tplSet.call(tpl, h);
    fixTree(tpl.content);
    return tplGet.call(tpl);
  }
  var innerD = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  var tplSet = innerD.set, tplGet = innerD.get;
  Object.defineProperty(Element.prototype, 'innerHTML', { configurable: true, enumerable: true, get: innerD.get,
    set: function (v) { innerD.set.call(this, rwHtml(v)); } });
  var outerD = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
  if (outerD) Object.defineProperty(Element.prototype, 'outerHTML', { configurable: true, enumerable: true, get: outerD.get,
    set: function (v) { outerD.set.call(this, rwHtml(v)); } });
  if (window.ShadowRoot) {
    var sd = Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML');
    if (sd) Object.defineProperty(ShadowRoot.prototype, 'innerHTML', { configurable: true, enumerable: true, get: sd.get,
      set: function (v) { sd.set.call(this, rwHtml(v)); } });
  }
  var oIAH = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function (pos, h) { return oIAH.call(this, pos, rwHtml(h)); };
  ['write', 'writeln'].forEach(function (n) {
    var o = Document.prototype[n];
    Document.prototype[n] = function () { var a = Array.prototype.slice.call(arguments).map(rwHtml); return o.apply(this, a); };
  });
  var oPFS = DOMParser.prototype.parseFromString;
  DOMParser.prototype.parseFromString = function (s, t) { return oPFS.call(this, /html/.test(t) ? rwHtml(s) : s, t); };

  /* ---------- network ---------- */
  var oFetch = window.fetch;
  if (oFetch) window.fetch = function (input, init) {
    if (typeof input === 'string' || input instanceof URL) input = proxify(input);
    return oFetch.call(this, input, init);
  };
  window.Request = new Proxy(window.Request, { construct: function (t, a, nt) {
    if (typeof a[0] === 'string' || a[0] instanceof URL) a[0] = proxify(a[0]);
    return Reflect.construct(t, a, nt);
  } });
  XMLHttpRequest.prototype.open = function (m, u) { var a = Array.prototype.slice.call(arguments); a[1] = proxify(u); return xhrOpen.apply(this, a); };
  var ru = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, 'responseURL');
  if (ru) Object.defineProperty(XMLHttpRequest.prototype, 'responseURL', { configurable: true, get: function () { return unprox(ru.get.call(this)); } });
  var rd = Object.getOwnPropertyDescriptor(Response.prototype, 'url');
  if (rd) Object.defineProperty(Response.prototype, 'url', { configurable: true, get: function () { return unprox(rd.get.call(this)); } });
  if (navigator.sendBeacon) { var ob = navigator.sendBeacon; navigator.sendBeacon = function (u, d) { return ob.call(this, proxify(u), d); }; }
  if (window.EventSource) window.EventSource = new Proxy(window.EventSource, { construct: function (t, a, nt) { a[0] = proxify(a[0]); return Reflect.construct(t, a, nt); } });
  ['Worker', 'SharedWorker'].forEach(function (C) {
    if (window[C]) window[C] = new Proxy(window[C], { construct: function (t, a, nt) { a[0] = proxify(a[0]); return Reflect.construct(t, a, nt); } });
  });
  window.WebSocket = new Proxy(window.WebSocket, { construct: function (t, a, nt) {
    var p = proxify(a[0]);
    if (p.charAt(0) === '/') a[0] = (RealLoc.protocol === 'https:' ? 'wss://' : 'ws://') + RealLoc.host + p;
    return Reflect.construct(t, a, nt);
  } });
  if (navigator.serviceWorker) {
    try { navigator.serviceWorker.register = function () { return Promise.reject(new DOMException('Service workers are disabled by the proxy', 'SecurityError')); }; } catch (e) {}
  }

  /* ---------- navigation entry points ---------- */
  var oOpen = window.open;
  window.open = function (u) { var a = Array.prototype.slice.call(arguments); if (u != null && u !== '') a[0] = proxify(u); return oOpen.apply(this, a); };
  ['pushState', 'replaceState'].forEach(function (n) {
    var o = History.prototype[n];
    History.prototype[n] = function (s, t, u) { return o.call(this, s, t, u == null ? u : proxify(u)); };
  });
  if (window.Navigation && Navigation.prototype.navigate) {
    var oNav = Navigation.prototype.navigate;
    Navigation.prototype.navigate = function (u, o) { return oNav.call(this, proxify(u), o); };
  }
  var oSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () { fixEl(this); return oSubmit.apply(this, arguments); };
  document.addEventListener('submit', function (e) { fixEl(e.target); if (e.submitter) fixEl(e.submitter); }, true);
  function clickFix(e) {
    var t = e.target; if (!t || !t.closest) return;
    var a = t.closest('a[href],area[href]'); if (a) fixEl(a);
  }
  document.addEventListener('click', clickFix, true);
  document.addEventListener('auxclick', clickFix, true);

  // window.postMessage target origins refer to the real origin, which no longer matches
  var oPM = window.postMessage;
  window.postMessage = function (m, o, t) {
    if (typeof o === 'string' && o !== '/') o = '*';
    else if (o && typeof o === 'object' && o.targetOrigin && o.targetOrigin !== '/') o = Object.assign({}, o, { targetOrigin: '*' });
    return oPM.call(this, m, o, t);
  };

  // eval-like string execution
  ['setTimeout', 'setInterval'].forEach(function (n) {
    var o = window[n];
    window[n] = function (f) { if (typeof f === 'string') arguments[0] = rw(f); return o.apply(this, arguments); };
  });
  window.Function = new Proxy(Function, {
    construct: function (t, a, nt) { if (a.length) a[a.length - 1] = rw(String(a[a.length - 1])); return Reflect.construct(t, a, nt); },
    apply: function (t, th, a) { if (a.length) a[a.length - 1] = rw(String(a[a.length - 1])); return Reflect.apply(t, th, a); }
  });

  /* ---------- document identity ---------- */
  function docProp(proto, name, fn) {
    var d = Object.getOwnPropertyDescriptor(proto, name);
    if (d && d.configurable) Object.defineProperty(proto, name, { configurable: true, enumerable: d.enumerable, get: function () { return fn(d.get.call(this)); } });
  }
  docProp(Document.prototype, 'URL', function () { return curReal().href; });
  docProp(Document.prototype, 'documentURI', function () { return curReal().href; });
  docProp(Document.prototype, 'domain', function () { return curReal().hostname; });
  docProp(Document.prototype, 'referrer', function (v) { return unprox(v); });
  docProp(Node.prototype, 'baseURI', function (v) { return unprox(v); });
  try { var od = Object.getOwnPropertyDescriptor(window, 'origin'); if (od && od.configurable) Object.defineProperty(window, 'origin', { configurable: true, get: function () { return curReal().origin; } }); } catch (e) {}

  var cd = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  Object.defineProperty(Document.prototype, 'cookie', { configurable: true, enumerable: true,
    get: function () {
      return cd.get.call(this).split(/;\s*/).filter(function (c) { return !/^__pl_/.test(c); }).join('; ').replace(/(^|; )__plh-/g, '$1__Host-');
    },
    set: function (v) {
      var parts = String(v).split(';');
      var out = [parts.shift().replace(/^\s*__Host-/, '__plh-')];
      parts.forEach(function (p) { var k = p.trim().split('=')[0].toLowerCase(); if (['domain', 'path', 'samesite', 'partitioned'].indexOf(k) < 0) out.push(p); });
      out.push('Path=' + cookiePath());
      cd.set.call(this, out.join(';'));
    } });

  /* ---------- safety net: anything that still slipped through ---------- */
  new MutationObserver(function (muts) {
    for (var i = 0; i < muts.length; i++) {
      var m = muts[i];
      if (m.type === 'attributes') { fixEl(m.target); continue; }
      for (var j = 0; j < m.addedNodes.length; j++) { var n = m.addedNodes[j]; if (n.nodeType === 1) fixTree(n); }
    }
  }).observe(document, { subtree: true, childList: true, attributes: true,
    attributeFilter: ['href', 'src', 'action', 'formaction', 'poster', 'data', 'srcset', 'content'] });
})();
