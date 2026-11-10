// SSRF protection: the proxy must never be usable to reach private/internal addresses.
import dns from 'node:dns';
import net from 'node:net';

const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1'; // test only

function isPrivateV4(ip) {
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateV6(ip) {
  const l = ip.toLowerCase();
  if (l === '::' || l === '::1') return true;
  if (l.startsWith('::ffff:')) {
    const rest = l.slice(7);
    if (net.isIPv4(rest)) return isPrivateV4(rest);
    const m = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(rest);
    if (m) {
      const hi = parseInt(m[1], 16), lo = parseInt(m[2], 16);
      return isPrivateV4(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    return true;
  }
  return /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || l.startsWith('ff') ||
    l.startsWith('64:ff9b') || l.startsWith('2001:db8');
}

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateV4(ip);
  if (net.isIPv6(ip)) return isPrivateV6(ip);
  return true;
}

/** Throws for hostnames/IP literals that are obviously internal. DNS results are checked in safeLookup. */
export function assertHostAllowed(hostname) {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (ALLOW_PRIVATE) return;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') || h.endsWith('.local')) {
    throw blocked(h);
  }
  if (net.isIP(h) && isPrivateIp(h)) throw blocked(h);
}

function blocked(h) {
  const e = new Error(`Blocked: ${h} is a private or internal address`);
  e.code = 'PL_BLOCKED';
  return e;
}

/** dns.lookup replacement that refuses private results (defeats DNS rebinding too, since it runs at connect time). */
export function safeLookup(hostname, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err);
    const ok = ALLOW_PRIVATE ? addrs : addrs.filter((a) => !isPrivateIp(a.address));
    if (!ok.length) return cb(blocked(hostname));
    if (options && options.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}
