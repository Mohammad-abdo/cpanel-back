import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { AppError } from '../../common/errors/app-error.js';
import { isPrivateAddress } from '../alert-channels/alert-channels.ssrf.js';

/** Allowed check intervals (seconds). Minimum 30. */
export const INTERVAL_SEC_VALUES = [30, 60, 120, 300, 600, 1800, 3600];

const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|UptimeMonitor|UptimeCheck/i;
const schemaRequired = () =>
  new AppError(501, 'SCHEMA_REQUIRED', 'Uptime monitors are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');
const MAX_CHECKS_KEPT = 100;
const MAX_REDIRECTS = 5;
const BODY_LIMIT = 1024 * 1024;
const USER_AGENT = 'nodeteam-uptime/1.0';

const TICK_GRACE_MS = 500;
const MAX_PARALLEL_CHECKS = 10;

/** "200-399" or "200,204,301-302" into a matcher. */
export function parseExpectedStatus(spec) {
  const parts = String(spec)
    .replace(/\s+/g, '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (!parts.length) throw new Error('Expected status is empty');
  const ranges = parts.map((p) => {
    const m = p.match(/^(\d{3})(?:-(\d{3}))?$/);
    if (!m) throw new Error(`"${p}" is not a status code or range like 200-399`);
    const lo = Number(m[1]);
    const hi = Number(m[2] ?? m[1]);
    if (lo < 100 || hi > 599 || lo > hi) throw new Error(`"${p}" is not a valid status range`);
    return [lo, hi];
  });
  return (code) => ranges.some(([lo, hi]) => code >= lo && code <= hi);
}

function blocked(code, msg) {
  return new AppError(422, code, msg);
}

function hostBlocked(hostname) {
  const host = String(hostname).toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) return true;
  if (isIP(host)) return isPrivateAddress(host);
  return false;
}

/** http(s) only; rejects private hosts and names that resolve to private addresses. */
export async function isPublicHttpUrl(
  raw,
  { lookup = (h) => dnsLookup(h, { all: true, verbatim: true }) } = {},
) {
  let url;
  try {
    url = new URL(String(raw).trim());
  } catch {
    throw blocked('URL_INVALID', 'URL is not valid');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw blocked('URL_NOT_HTTP', 'Only http and https URLs are allowed');
  if (url.username || url.password) throw blocked('URL_CREDENTIALS', 'URLs with embedded credentials are not allowed');
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (hostBlocked(host)) throw blocked('URL_HOST_BLOCKED', 'Host is not allowed');
  if (isIP(host)) {
    if (isPrivateAddress(host)) throw blocked('URL_PRIVATE_ADDRESS', 'Private, loopback and link-local addresses are blocked');
    return url.href;
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
  return url.href;
}

function describeCheckError(error) {
  const e = error;
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError') return 'Timed out';
  const code = e?.cause?.code;
  const known = {
    ENOTFOUND: 'DNS lookup failed (domain not found)',
    EAI_AGAIN: 'DNS lookup failed (temporary)',
    ECONNREFUSED: 'Connection refused',
    ECONNRESET: 'Connection reset',
    ETIMEDOUT: 'Connection timed out',
  };
  return (code && known[code]) || e?.cause?.message || e?.message || 'Request failed';
}

async function readLimitedBody(res) {
  if (!res.body?.getReader) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value?.length ?? 0;
    if (size >= BODY_LIMIT) {
      await reader.cancel().catch(() => undefined);
      break;
    }
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function performCheck(target, { fetchImpl = globalThis.fetch, lookup } = {}) {
  const started = Date.now();
  try {
    const matches = parseExpectedStatus(target.expectedStatus);
    const signal = AbortSignal.timeout(target.timeoutMs);
    let url = target.url;
    let res;
    for (let hop = 0; ; hop++) {
      res = await fetchImpl(url, {
        method: target.method,
        redirect: 'manual',
        signal,
        headers: { 'user-agent': USER_AGENT, accept: '*/*' },
      });
      const location = res.headers.get('location');
      if (res.status < 300 || res.status >= 400 || !location) break;
      if (hop >= MAX_REDIRECTS) throw new Error('Too many redirects');
      await res.body?.cancel?.().catch(() => undefined);
      url = await isPublicHttpUrl(new URL(location, url).href, lookup ? { lookup } : {});
    }
    let keywordFound = true;
    if (target.keyword && target.method === 'GET') {
      const text = await readLimitedBody(res);
      keywordFound = text.includes(target.keyword);
    } else {
      await res.body?.cancel?.().catch(() => undefined);
    }
    const responseMs = Math.max(0, Math.round(Date.now() - started));
    if (!matches(res.status)) {
      return { ok: false, statusCode: res.status, responseMs, error: `Unexpected status ${res.status}` };
    }
    if (!keywordFound) {
      return { ok: false, statusCode: res.status, responseMs, error: `Page does not contain "${target.keyword}"` };
    }
    return { ok: true, statusCode: res.status, responseMs, error: null };
  } catch (error) {
    if (error instanceof AppError) throw error;
    const msg = describeCheckError(error).slice(0, 300);
    return { ok: false, statusCode: null, responseMs: null, error: msg };
  }
}

function view(row) {
  if (!row) return null;
  return {
    id: row.id,
    projectId: row.projectId,
    name: row.name,
    url: row.url,
    method: row.method,
    intervalSec: row.intervalSec,
    timeoutMs: row.timeoutMs,
    expectedStatus: row.expectedStatus,
    keyword: row.keyword,
    failureThreshold: row.failureThreshold,
    enabled: row.enabled,
    status: row.status,
    lastCheckedAt: row.lastCheckedAt,
    lastStatusCode: row.lastStatusCode,
    lastResponseMs: row.lastResponseMs,
    lastError: row.lastError,
    consecutiveFailures: row.consecutiveFailures,
    failingSince: row.failingSince,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function createUptimeService({
  prisma,
  fetchImpl = globalThis.fetch,
  lookup,
  now = () => new Date(),
} = {}) {
  const inFlight = new Set();
  const delegate = (name) => {
    const d = prisma?.[name];
    if (!d) throw schemaRequired();
    return d;
  };

  const guard = async (fn) => {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (STALE.test(String(e?.message))) throw schemaRequired();
      throw e;
    }
  };

  function requireActor(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
  }

  async function assertProject(projectId) {
    if (projectId == null) return;
    const p = await guard(() => prisma.project.findUnique({ where: { id: projectId }, select: { id: true } }));
    if (!p) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
  }

  async function getRow(id) {
    const row = await guard(() => delegate('uptimeMonitor').findUnique({ where: { id } }));
    if (!row) throw new AppError(404, 'UPTIME_NOT_FOUND', 'Uptime monitor not found');
    return row;
  }

  function applyEnabledFlags(patch, row) {
    if (patch.enabled === false) {
      patch.status = 'paused';
      patch.consecutiveFailures = 0;
      patch.failingSince = null;
    } else if (patch.enabled === true && row.status === 'paused') {
      patch.status = 'unknown';
    }
    return patch;
  }

  async function trimChecks(monitorId) {
    const stale = await guard(() =>
      delegate('uptimeCheck').findMany({
        where: { monitorId },
        orderBy: { checkedAt: 'desc' },
        skip: MAX_CHECKS_KEPT,
        select: { id: true },
      }),
    );
    if (stale.length) {
      await guard(() => delegate('uptimeCheck').deleteMany({ where: { id: { in: stale.map((s) => s.id) } } }));
    }
  }

  async function recordCheck(monitor, result, at) {
    const data = {
      lastCheckedAt: at,
      lastStatusCode: result.statusCode,
      lastResponseMs: result.responseMs,
      lastError: result.error,
    };
    if (monitor.enabled) {
      if (result.ok) {
        data.status = 'up';
        data.consecutiveFailures = 0;
        data.failingSince = null;
      } else {
        const failures = monitor.consecutiveFailures + 1;
        data.consecutiveFailures = failures;
        data.failingSince = monitor.failingSince ?? at;
        if (failures >= monitor.failureThreshold) data.status = 'down';
      }
    }
    const updated = await guard(() => delegate('uptimeMonitor').update({ where: { id: monitor.id }, data }));
    const check = await guard(() =>
      delegate('uptimeCheck').create({
        data: {
          monitorId: monitor.id,
          checkedAt: at,
          ok: result.ok,
          statusCode: result.statusCode,
          responseMs: result.responseMs,
          error: result.error,
        },
      }),
    );
    await trimChecks(monitor.id);
    return { monitor: view(updated), check };
  }

  return {
    async list(actor, { projectId } = {}) {
      requireActor(actor);
      const where = projectId ? { projectId } : {};
      const rows = await guard(() => delegate('uptimeMonitor').findMany({ where, orderBy: { createdAt: 'desc' } }));
      return rows.map(view);
    },

    async get(id, actor) {
      requireActor(actor);
      return view(await getRow(id));
    },

    async create(body, actor) {
      requireActor(actor);
      const url = await isPublicHttpUrl(body.url, lookup ? { lookup } : {});
      await assertProject(body.projectId ?? null);
      const name = body.name?.trim() || new URL(url).hostname;
      const row = await guard(() =>
        delegate('uptimeMonitor').create({
          data: {
            name,
            url,
            method: body.method ?? 'GET',
            intervalSec: Number(body.intervalSec ?? 60),
            timeoutMs: body.timeoutMs ?? 10000,
            expectedStatus: String(body.expectedStatus ?? '200-399').replace(/\s+/g, ''),
            keyword: body.keyword?.trim() || null,
            failureThreshold: body.failureThreshold ?? 2,
            enabled: body.enabled ?? true,
            projectId: body.projectId ?? null,
            status: 'unknown',
          },
        }),
      );
      return view(row);
    },

    async update(id, body, actor) {
      requireActor(actor);
      const row = await getRow(id);
      const data = {};
      if (body.name != null) data.name = body.name.trim();
      if (body.url != null) data.url = await isPublicHttpUrl(body.url, lookup ? { lookup } : {});
      if (body.method != null) data.method = body.method;
      if (body.intervalSec != null) data.intervalSec = Number(body.intervalSec);
      if (body.timeoutMs != null) data.timeoutMs = body.timeoutMs;
      if (body.expectedStatus != null) {
        parseExpectedStatus(body.expectedStatus);
        data.expectedStatus = body.expectedStatus.replace(/\s+/g, '');
      }
      if (body.keyword !== undefined) data.keyword = body.keyword?.trim() || null;
      if (body.failureThreshold != null) data.failureThreshold = body.failureThreshold;
      if (body.enabled !== undefined) data.enabled = body.enabled;
      if (body.projectId !== undefined) {
        await assertProject(body.projectId);
        data.projectId = body.projectId;
      }
      const interval = data.intervalSec ?? row.intervalSec;
      const timeout = data.timeoutMs ?? row.timeoutMs;
      if (timeout > interval * 1000) throw new AppError(422, 'TIMEOUT_TOO_LONG', 'Timeout must not exceed the check interval');
      applyEnabledFlags(data, row);
      const updated = await guard(() => delegate('uptimeMonitor').update({ where: { id }, data }));
      return view(updated);
    },

    async remove(id, actor) {
      requireActor(actor);
      await getRow(id);
      await guard(() => delegate('uptimeMonitor').delete({ where: { id } }));
      return { id, deleted: true };
    },

    async executeCheck(monitor, at = now()) {
      await isPublicHttpUrl(monitor.url, lookup ? { lookup } : {});
      const result = await performCheck(
        {
          url: monitor.url,
          method: monitor.method === 'HEAD' ? 'HEAD' : 'GET',
          timeoutMs: monitor.timeoutMs,
          expectedStatus: monitor.expectedStatus,
          keyword: monitor.keyword,
        },
        { fetchImpl, ...(lookup ? { lookup } : {}) },
      );
      return recordCheck(monitor, result, at);
    },

    async checkNow(id, actor) {
      requireActor(actor);
      const monitor = await getRow(id);
      return this.executeCheck(monitor);
    },

    /** Runs due enabled monitors (used by the in-process job scheduler). */
    async tick(at = now()) {
      const ts = at instanceof Date ? at.getTime() : Number(at);
      const monitors = await guard(() => delegate('uptimeMonitor').findMany({ where: { enabled: true } }));
      const due = monitors.filter((m) => {
        if (inFlight.has(m.id)) return false;
        if (!m.lastCheckedAt) return true;
        return ts - m.lastCheckedAt.getTime() >= m.intervalSec * 1000 - TICK_GRACE_MS;
      });
      const room = Math.max(0, MAX_PARALLEL_CHECKS - inFlight.size);
      await Promise.all(
        due.slice(0, room).map(async (m) => {
          inFlight.add(m.id);
          try {
            const fresh = await guard(() => delegate('uptimeMonitor').findUnique({ where: { id: m.id } }));
            if (fresh?.enabled) await this.executeCheck(fresh, at instanceof Date ? at : new Date(ts));
          } catch {
            /* single monitor failure must not stop the tick */
          } finally {
            inFlight.delete(m.id);
          }
        }),
      );
      return { due: due.length, started: Math.min(due.length, room) };
    },
  };
}