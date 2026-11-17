/**
 * TASK-047: real certificate probe. One TLS handshake per registered hostname (SNI = hostname).
 *
 * Verification is NEVER bypassed in the result: the socket is opened with rejectUnauthorized=false only so that a broken
 * chain can still be READ and REPORTED, and the verdict comes from socket.authorized / authorizationError (which include the
 * chain and hostname checks). An unauthorized certificate is returned as `trusted: false` with the reason, never as valid.
 * SSRF: only hostnames (no IP literals, no ports other than 443 unless injected by tests); names that resolve to
 * loopback/private/link-local space are refused. Running this against the internet is a deployment decision (CERT_EXPIRY_PROBE=1).
 */
import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function isPrivateAddress(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (v === 6) {
    const x = ip.toLowerCase();
    return x === '::1' || x === '::' || x.startsWith('fe80') || x.startsWith('fc') || x.startsWith('fd') || (x.startsWith('::ffff:') && isPrivateAddress(x.slice(7)));
  }
  return true;
}

/**
 * Returns { ok:false, error } (unreachable / refused) or { ok:true, trusted, authorizationError, validFrom, validTo, daysLeft,
 * issuer, subject, san, protocol }. Never throws.
 */
export async function probeTls(hostname, { port = 443, timeoutMs = 8000, connect = tls.connect, lookup = (h) => dns.lookup(h, { all: true }), allowPrivate = false, now = () => new Date() } = {}) {
  const host = String(hostname ?? '').trim().toLowerCase();
  if (!HOSTNAME.test(host) || net.isIP(host)) return { ok: false, error: 'HOSTNAME_INVALID' };
  let address = null;
  if (!allowPrivate) {
    try {
      const addrs = await lookup(host);
      const list = (Array.isArray(addrs) ? addrs : [addrs]).map((a) => a.address ?? a);
      if (list.length === 0) return { ok: false, error: 'DNS_NO_ADDRESS' };
      if (list.some(isPrivateAddress)) return { ok: false, error: 'ADDRESS_REFUSED' };
      address = list[0];
    } catch {
      return { ok: false, error: 'DNS_FAILED' };
    }
  }
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      try {
        socket?.destroy();
      } catch {
        /* already closed */
      }
      resolve(value);
    };
    let socket;
    try {
      // Pin the connection to the address that passed the private-range check (no second lookup).
      socket = connect({ host: address ?? host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs, ALPNProtocols: ['http/1.1'] }, () => {
        const cert = socket.getPeerCertificate();
        if (!cert || !cert.valid_to) return finish({ ok: false, error: 'NO_CERTIFICATE' });
        const validTo = new Date(cert.valid_to);
        const validFrom = new Date(cert.valid_from);
        const trusted = socket.authorized === true;
        finish({
          ok: true,
          trusted,
          authorizationError: trusted ? null : String(socket.authorizationError ?? 'UNKNOWN').slice(0, 120),
          validFrom,
          validTo,
          daysLeft: Math.floor((validTo.getTime() - now().getTime()) / 86400000),
          issuer: String(cert.issuer?.O ?? cert.issuer?.CN ?? '').slice(0, 120),
          subject: String(cert.subject?.CN ?? '').slice(0, 253),
          san: String(cert.subjectaltname ?? '').slice(0, 500),
          protocol: socket.getProtocol?.() ?? null,
        });
      });
    } catch {
      return resolve({ ok: false, error: 'CONNECT_FAILED' });
    }
    socket.setTimeout?.(timeoutMs, () => finish({ ok: false, error: 'TIMEOUT' }));
    socket.on('error', (e) => finish({ ok: false, error: String(e?.code ?? 'CONNECT_FAILED').slice(0, 60) }));
  });
}
