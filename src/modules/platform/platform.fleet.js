import { STALE_AFTER_MS } from '../agents/agents.service.js';

/**
 * Synthetic budgets used by the tests. They are engineering limits, NOT measured production budgets:
 * real load measurements on real VPS fleets are NOT_RUN.
 */
export const LOAD_BUDGET = Object.freeze({ maxPageSize: 500, probeConcurrency: 10, probeTimeoutMs: 5000, retryAttempts: 5, backoffBaseMs: 1000, backoffMaxMs: 60000 });

/** connected -> degraded -> offline. A silent agent never reports as healthy. */
export function connectionState(lastSeenAt, at = new Date(), revokedAt = null) {
  if (revokedAt) return 'revoked';
  if (!lastSeenAt) return 'never_connected';
  const age = at.getTime() - new Date(lastSeenAt).getTime();
  if (age <= STALE_AFTER_MS / 3) return 'connected';
  if (age <= STALE_AFTER_MS) return 'degraded';
  return 'offline';
}

/** Exponential backoff with full jitter. rng is injectable for deterministic tests. */
export function computeBackoff(attempt, { baseMs = LOAD_BUDGET.backoffBaseMs, maxMs = LOAD_BUDGET.backoffMaxMs, rng = Math.random } = {}) {
  const ceiling = Math.min(maxMs, baseMs * 2 ** Math.max(0, attempt));
  return Math.floor(rng() * ceiling);
}

export async function retry(fn, { attempts = LOAD_BUDGET.retryAttempts, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), rng, baseMs, maxMs } = {}) {
  let lastError;
  for (let i = 0; i < attempts; i += 1) {
    try {
      return await fn(i);
    } catch (err) {
      lastError = err;
      if (i < attempts - 1) await sleep(computeBackoff(i, { rng, baseMs, maxMs }));
    }
  }
  throw lastError;
}

/** Run tasks with a hard concurrency cap. Each task is isolated: one failure never rejects the batch. */
export async function mapSettled(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  async function lane() {
    while (next < items.length) {
      const i = next++;
      try {
        results[i] = { status: 'fulfilled', value: await worker(items[i]) };
      } catch (err) {
        results[i] = { status: 'rejected', reason: err };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, lane));
  return results;
}

const withTimeout = (promise, ms) =>
  new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout')), ms);
    promise.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });

/**
 * Read-only fleet view. There is deliberately no stop/restart path here: if the control plane or this
 * dashboard fails, applications on the VPS keep running and agents keep buffering (required.md section 16).
 */
export function createFleetService({ prisma, now = () => new Date(), adapters = null, probeTimeoutMs = LOAD_BUDGET.probeTimeoutMs }) {
  return {
    async overview({ limit, cursor }) {
      const rows = await prisma.server.findMany({
        where: { archivedAt: null },
        take: Math.min(limit, LOAD_BUDGET.maxPageSize) + 1,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        orderBy: { id: 'asc' },
        include: { agent: { select: { lastSeenAt: true, revokedAt: true } } },
      });
      const pageSize = Math.min(limit, LOAD_BUDGET.maxPageSize);
      const page = rows.slice(0, pageSize);
      const items = page.map((s) => ({ id: s.id, alias: s.alias, connection: connectionState(s.agent?.lastSeenAt, now(), s.agent?.revokedAt) }));
      const counts = {};
      for (const i of items) counts[i.connection] = (counts[i.connection] ?? 0) + 1;
      return { items, counts, nextCursor: rows.length > pageSize ? page[page.length - 1].id : null };
    },

    /** Probe many servers with bounded concurrency and per-server timeouts. Failures are reported, not thrown. */
    async probe({ serverIds }) {
      const results = await mapSettled(serverIds, LOAD_BUDGET.probeConcurrency, async (id) => {
        const r = await withTimeout(adapters.fleet.probe(id), probeTimeoutMs);
        return { id, state: r.reachable ? 'ok' : 'unreachable', latencyMs: r.latencyMs ?? null };
      });
      return results.map((r, i) => (r.status === 'fulfilled' ? r.value : { id: serverIds[i], state: r.reason?.message === 'timeout' ? 'timeout' : 'error' }));
    },
  };
}
