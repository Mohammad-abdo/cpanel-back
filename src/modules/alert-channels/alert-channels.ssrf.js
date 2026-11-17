import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { AppError } from '../../common/errors/app-error.js';

/** True when an IPv4/IPv6 literal is loopback, private, link-local, CGNAT, multicast, reserved or unspecified. */
export function isPrivateAddress(ip) {
  const kind = isIP(ip);
  if (kind === 4) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }
  if (kind === 6) {
    const v = ip.toLowerCase().replace(/^\[|\]$/g, '');
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
    if (mapped) return isPrivateAddress(mapped[1]);
    const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(v);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1], 16);
      const lo = parseInt(mappedHex[2], 16);
      return isPrivateAddress(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    if (v === '::' || v === '::1') return true;
    const first = parseInt(v.split(':')[0] || '0', 16);
    return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00 || v.startsWith('64:ff9b:') || v.startsWith('2001:db8:');
  }
  return true; // not an IP: caller must never treat it as public
}

const blocked = (code, msg) => new AppError(422, code, msg);

/**
 * Validates an outbound URL: https only, no credentials, no private IP literals, optional host allow-list and
 * (after DNS resolution) every resolved address must be public. Returns the parsed URL and resolved addresses.
 */
export async function assertSafeUrl(raw, { allowHosts = null, lookup = (h) => dnsLookup(h, { all: true, verbatim: true }) } = {}) {
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    throw blocked('URL_INVALID', 'URL is not valid');
  }
  if (url.protocol !== 'https:') throw blocked('URL_NOT_HTTPS', 'Only https URLs are allowed');
  if (url.username || url.password) throw blocked('URL_CREDENTIALS', 'URLs with embedded credentials are not allowed');
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) {
    throw blocked('URL_HOST_BLOCKED', 'Host is not allowed');
  }
  if (allowHosts && !allowHosts.some((h) => host === h || host.endsWith(`.${h}`))) {
    throw blocked('URL_HOST_NOT_ALLOWED', 'Host is not on the allow-list for this channel type');
  }
  if (isIP(host)) {
    if (isPrivateAddress(host)) throw blocked('URL_PRIVATE_ADDRESS', 'Private, loopback and link-local addresses are blocked');
    return { url, addresses: [host] };
  }
  let records;
  try {
    records = await lookup(host);
  } catch {
    throw blocked('URL_DNS_FAILED', 'Host could not be resolved');
  }
  const addresses = (Array.isArray(records) ? records : [records]).map((r) => (typeof r === 'string' ? r : r.address));
  if (!addresses.length) throw blocked('URL_DNS_FAILED', 'Host could not be resolved');
  if (addresses.some(isPrivateAddress)) throw blocked('URL_PRIVATE_ADDRESS', 'Host resolves to a private, loopback or link-local address');
  return { url, addresses };
}

/**
 * fetch with the SSRF guard, a timeout, no redirect following (a 3xx is a failure, so a public host cannot bounce
 * the request to a private one) and a response-size cap. Residual risk: DNS can change between the check and the
 * connect (rebinding); mitigated by https-only plus fixed allow-listed hosts for Telegram/Slack/Discord.
 */
export async function safeFetch(rawUrl, { method = 'POST', headers = {}, body, timeoutMs = 8000, maxBytes = 64 * 1024, allowHosts = null, fetchImpl = globalThis.fetch, lookup } = {}) {
  const { url } = await assertSafeUrl(rawUrl, { allowHosts, ...(lookup ? { lookup } : {}) });
  const res = await fetchImpl(url.toString(), { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  if (res.status >= 300 && res.status < 400) throw blocked('REDIRECT_BLOCKED', 'Redirects are not followed');
  let size = 0;
  try {
    const reader = res.body?.getReader?.();
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value?.length ?? 0;
        if (size > maxBytes) {
          await reader.cancel();
          break;
        }
      }
    }
  } catch {
    /* body is irrelevant; the status decides */
  }
  return { status: res.status, ok: res.status >= 200 && res.status < 300 };
}
