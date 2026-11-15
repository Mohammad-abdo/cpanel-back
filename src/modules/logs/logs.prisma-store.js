import { AppError } from '../../common/errors/app-error.js';
import { createInMemoryLogStore, levelRank } from './logs.store.js';
import { redactText, redactDeep } from './logs.redaction.js';

const MAX_MESSAGE = 8000;
const MAX_STACK = 16000;
const LEVELS = ['debug', 'info', 'warn', 'error', 'fatal'];

/**
 * Durable log store behind the same port as createInMemoryLogStore. Writes go to the LogEntry table
 * (write-through) and to a small hot buffer that keeps the synchronous query()/subscribe()/matches()
 * contract used by live streaming and monitoring. History reads use the async queryDurable().
 * Redaction is re-applied here, so nothing unredacted is ever persisted even if a caller skips it.
 */
export function createPrismaLogStore(prisma, { hotEntries = 2000 } = {}) {
  const hot = createInMemoryLogStore({ maxEntries: hotEntries });
  const listeners = new Set();
  const model = () => {
    const m = prisma?.logEntry;
    if (!m) throw new AppError(501, 'SCHEMA_REQUIRED', 'LogEntry table is not migrated yet (run prisma migrate deploy and generate)');
    return m;
  };

  const toRow = (e) => ({
    projectId: e.labels?.projectId ?? '',
    serverId: e.labels?.serverId ?? null,
    environmentId: e.labels?.environmentId ?? null,
    source: String(e.labels?.sourceId ?? e.labels?.kind ?? 'unknown').slice(0, 191),
    kind: e.labels?.kind ?? null,
    severity: e.level,
    message: redactText(String(e.message ?? '')).slice(0, MAX_MESSAGE),
    requestId: e.requestId ?? null,
    traceId: e.traceId ?? null,
    deploymentId: e.deploymentId ?? null,
    stack: e.stack ? redactText(String(e.stack)).slice(0, MAX_STACK) : null,
    fieldsJson: e.fields ? redactDeep(e.fields) : undefined,
    occurredAt: new Date(e.ts),
  });

  const fromRow = (r) => ({
    seq: r.seq,
    ts: r.occurredAt,
    level: r.severity,
    message: r.message,
    stack: r.stack,
    requestId: r.requestId,
    traceId: r.traceId,
    deploymentId: r.deploymentId,
    fields: r.fieldsJson ?? null,
    labels: {
      projectId: r.projectId,
      environmentId: r.environmentId ?? undefined,
      serverId: r.serverId ?? undefined,
      kind: r.kind ?? undefined,
      sourceId: r.source,
    },
  });

  function toWhere(f) {
    const where = {};
    if (f.projectId) where.projectId = f.projectId;
    if (f.environmentId) where.environmentId = f.environmentId;
    if (f.serverId) where.serverId = f.serverId;
    if (f.kind) where.kind = f.kind;
    if (f.sourceId) where.source = f.sourceId;
    if (f.level) where.severity = f.level;
    else if (f.minLevel) where.severity = { in: LEVELS.filter((l) => levelRank(l) >= levelRank(f.minLevel)) };
    if (f.requestId) where.requestId = f.requestId;
    if (f.traceId) where.traceId = f.traceId;
    if (f.deploymentId) where.deploymentId = f.deploymentId;
    if (f.from || f.to) where.occurredAt = { ...(f.from && { gte: f.from }), ...(f.to && { lte: f.to }) };
    if (f.q) where.OR = [{ message: { contains: f.q } }, { stack: { contains: f.q } }];
    return where;
  }

  return {
    matches: hot.matches,

    async append(batch) {
      const m = model();
      const stored = [];
      for (const e of batch) {
        const row = await m.create({ data: toRow(e) });
        stored.push({ ...e, message: row.message, stack: row.stack, seq: row.seq });
      }
      for (const e of stored) {
        // Feed the hot buffer without re-assigning seq: append then patch the stored copy.
        const [copy] = hot.append([e]);
        copy.seq = e.seq;
        listeners.forEach((fn) => fn(e));
      }
      return stored;
    },

    /** Synchronous recent-window read (hot buffer) for monitoring and stream replay. */
    query(filter, opts) {
      return hot.query(filter, opts);
    },

    /** Durable read, newest first; beforeSeq pages backwards, afterSeq replays oldest first. */
    async queryDurable(filter, { limit = 100, beforeSeq, afterSeq } = {}) {
      const where = toWhere(filter);
      if (afterSeq !== undefined) where.seq = { gt: afterSeq };
      else if (beforeSeq !== undefined) where.seq = { lt: beforeSeq };
      const rows = await model().findMany({
        where,
        orderBy: { seq: afterSeq !== undefined ? 'asc' : 'desc' },
        take: limit,
      });
      return rows.map(fromRow);
    },

    /** Retention: delete entries older than `days`. Intended to be called by a worker. */
    async pruneOlderThan(days, now = new Date()) {
      if (!Number.isFinite(days) || days <= 0) throw new AppError(400, 'INVALID_RETENTION', 'days must be a positive number');
      const cutoff = new Date(now.getTime() - days * 86400000);
      const res = await model().deleteMany({ where: { occurredAt: { lt: cutoff } } });
      return { deleted: res.count, cutoff };
    },

    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },

    get size() {
      return hot.size;
    },
  };
}
