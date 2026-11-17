/**
 * TASK-047: Cloudflare DNS client (fetch based, no dependency).
 *
 * SSRF: the base URL is a constant; callers can only pass path parameters, which are validated and URL-encoded. Redirects are refused.
 * Secrets: the API token lives only in this closure and in the Authorization header. It is never part of an error message,
 * a log line or a returned value (toJSON/inspect are masked). Real calls are NOT_RUN without an Owner-supplied token.
 */
import { AppError } from '../../common/errors/app-error.js';

export const CLOUDFLARE_BASE_URL = 'https://api.cloudflare.com/client/v4';
export const CF_RECORD_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'TXT']);
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{20,128}$/;
const ZONE_ID_PATTERN = /^[0-9a-f]{32}$/;
const RECORD_ID_PATTERN = /^[0-9a-f]{32}$/;
const PROXIABLE = new Set(['A', 'AAAA', 'CNAME']);

export const isValidCloudflareToken = (token) => TOKEN_PATTERN.test(String(token ?? ''));
export const maskToken = (token) => (token ? `${String(token).slice(0, 4)}...[masked]` : '[none]');

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms));

function view(r) {
  return { id: r.id, type: r.type, name: r.name, content: r.content, ttl: r.ttl, proxied: Boolean(r.proxied) };
}

export function createCloudflareClient({
  token,
  fetchImpl = globalThis.fetch,
  sleep = defaultSleep,
  maxRetries = 3,
  baseDelayMs = 500,
  maxDelayMs = 20_000,
  /** Client-side pacing so a burst of changes stays far below Cloudflare's global rate limit. */
  minIntervalMs = 250,
  timeoutMs = 15_000,
  now = () => Date.now(),
} = {}) {
  if (!isValidCloudflareToken(token)) throw new AppError(422, 'DNS_TOKEN_INVALID', 'The Cloudflare API token has an invalid format');
  if (typeof fetchImpl !== 'function') throw new AppError(500, 'FETCH_UNAVAILABLE', 'fetch is not available');
  let lastAt = 0;
  const scrub = (text) => String(text ?? '').split(token).join('[masked]').slice(0, 300);

  async function pace() {
    const wait = lastAt + minIntervalMs - now();
    if (wait > 0) await sleep(wait);
    lastAt = now();
  }

  /** method + path (+query) -> Cloudflare `result`. Retries 429 always, 5xx and network errors only for idempotent methods. */
  async function request(method, path, { query, body } = {}) {
    const url = new URL(`${CLOUDFLARE_BASE_URL}${path}`);
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
    if (url.origin !== 'https://api.cloudflare.com') throw new AppError(500, 'DNS_URL_REJECTED', 'Refusing to call a non-Cloudflare host');
    const idempotent = method !== 'POST';
    let attempt = 0;
    for (;;) {
      await pace();
      let res;
      try {
        res = await fetchImpl(url.toString(), {
          method,
          redirect: 'error',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (error) {
        if (idempotent && attempt < maxRetries) {
          await sleep(Math.min(maxDelayMs, baseDelayMs * 2 ** attempt));
          attempt += 1;
          continue;
        }
        throw new AppError(502, 'DNS_PROVIDER_UNREACHABLE', `Cloudflare request failed: ${scrub(error?.name)}`);
      }
      if (res.status === 429 || (res.status >= 500 && idempotent)) {
        if (attempt < maxRetries) {
          const retryAfter = Number(res.headers?.get?.('retry-after'));
          const delay = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : baseDelayMs * 2 ** attempt;
          attempt += 1;
          await sleep(Math.min(maxDelayMs, delay));
          continue;
        }
      }
      let json = null;
      try {
        json = await res.json();
      } catch {
        /* non JSON error body */
      }
      if (!res.ok || json?.success === false) {
        const codes = (json?.errors ?? []).map((e) => e?.code).filter((c) => Number.isInteger(c));
        const code = res.status === 401 || res.status === 403 ? 'DNS_TOKEN_REJECTED' : res.status === 429 ? 'DNS_RATE_LIMITED' : 'DNS_PROVIDER_FAILED';
        throw new AppError(502, code, `Cloudflare answered HTTP ${res.status}${codes.length ? ` (codes ${codes.join(',')})` : ''}`);
      }
      return { result: json?.result, info: json?.result_info ?? null };
    }
  }

  const zoneId = (id) => {
    if (!ZONE_ID_PATTERN.test(String(id))) throw new AppError(422, 'DNS_ZONE_INVALID', 'Zone id is invalid');
    return id;
  };

  const payload = ({ type, name, content, ttl, proxied }) => {
    if (!CF_RECORD_TYPES.includes(type)) throw new AppError(422, 'DNS_TYPE_UNSUPPORTED', `Record type ${type} is not supported`);
    const wantsProxy = Boolean(proxied) && PROXIABLE.has(type);
    return {
      type,
      name,
      content: type === 'TXT' ? String(content) : String(content).trim(),
      // Cloudflare requires ttl 1 (automatic) for proxied records.
      ttl: wantsProxy ? 1 : Number.isInteger(ttl) && ttl >= 60 ? ttl : 300,
      ...(PROXIABLE.has(type) ? { proxied: wantsProxy } : {}),
    };
  };

  const client = {
    async verifyToken() {
      const { result } = await request('GET', '/user/tokens/verify');
      return { active: result?.status === 'active' };
    },
    /** Exact-name zone lookup. Returns null when the token cannot see it. */
    async findZone(name) {
      const { result } = await request('GET', '/zones', { query: { name, per_page: 1 } });
      const z = (result ?? []).find((r) => r?.name === name);
      return z ? { id: z.id, name: z.name, status: z.status } : null;
    },
    async listRecords(zone, { type, name, page = 1, perPage = 100 } = {}) {
      const { result, info } = await request('GET', `/zones/${zoneId(zone)}/dns_records`, { query: { type, name, page, per_page: perPage } });
      return { records: (result ?? []).map(view), totalPages: info?.total_pages ?? 1 };
    },
    /**
     * Idempotent: A/AAAA/CNAME keep one record per name+type (updated in place; unchanged = no write).
     * TXT allows several values per name (ACME), so it is matched by exact content.
     */
    async upsertRecord(zone, input) {
      const body = payload(input);
      const { records } = await client.listRecords(zone, { type: body.type, name: body.name });
      const existing = body.type === 'TXT' ? records.find((r) => r.content === body.content) : records[0];
      if (!existing) {
        const { result } = await request('POST', `/zones/${zoneId(zone)}/dns_records`, { body });
        return { action: 'created', record: view(result) };
      }
      const same = existing.content === body.content && existing.ttl === body.ttl && (body.proxied === undefined || existing.proxied === body.proxied);
      if (same) return { action: 'unchanged', record: existing };
      const { result } = await request('PUT', `/zones/${zoneId(zone)}/dns_records/${encodeURIComponent(existing.id)}`, { body });
      return { action: 'updated', record: view(result) };
    },
    /** Removes every record matching type+name (+content when given). Removing nothing is a success (idempotent). */
    async deleteRecord(zone, { type, name, content }) {
      const { records } = await client.listRecords(zone, { type, name });
      const targets = records.filter((r) => content === undefined || content === null || r.content === content);
      for (const r of targets) {
        if (!RECORD_ID_PATTERN.test(String(r.id))) throw new AppError(502, 'DNS_PROVIDER_FAILED', 'Provider returned an unexpected record id');
        await request('DELETE', `/zones/${zoneId(zone)}/dns_records/${encodeURIComponent(r.id)}`);
      }
      return { removed: targets.length };
    },
    toJSON: () => ({ provider: 'cloudflare', token: maskToken(token) }),
    toString: () => `CloudflareClient(${maskToken(token)})`,
    [Symbol.for('nodejs.util.inspect.custom')]: () => `CloudflareClient(${maskToken(token)})`,
  };
  return client;
}
