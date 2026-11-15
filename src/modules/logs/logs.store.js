const LEVEL_RANK = { debug: 0, info: 1, warn: 2, error: 3, fatal: 4 };
export const levelRank = (level) => LEVEL_RANK[level] ?? 1;

/**
 * Log store port. REQUIRES DECISION: Loki (required.md section 4) vs a MySQL table. Until decided this
 * bounded in-memory store is the default so the gateway, redaction and tenancy rules are testable.
 * Raw bodies are redacted before they ever reach append().
 */
export function createInMemoryLogStore({ maxEntries = 20000 } = {}) {
  const entries = [];
  const listeners = new Set();
  let seq = 0;

  /** Pure label/filter matcher shared by search, export and live streaming. */
  function matches(entry, f) {
    const l = entry.labels;
    if (f.projectId && l.projectId !== f.projectId) return false;
    if (f.environmentId && l.environmentId !== f.environmentId) return false;
    if (f.serverId && l.serverId !== f.serverId) return false;
    if (f.kind && l.kind !== f.kind) return false;
    if (f.sourceId && l.sourceId !== f.sourceId) return false;
    if (f.minLevel && levelRank(entry.level) < levelRank(f.minLevel)) return false;
    if (f.level && entry.level !== f.level) return false;
    if (f.requestId && entry.requestId !== f.requestId) return false;
    if (f.traceId && entry.traceId !== f.traceId) return false;
    if (f.deploymentId && entry.deploymentId !== f.deploymentId) return false;
    if (f.from && entry.ts < f.from) return false;
    if (f.to && entry.ts > f.to) return false;
    if (f.q && !`${entry.message}\n${entry.stack ?? ''}`.toLowerCase().includes(f.q.toLowerCase())) return false;
    return true;
  }

  return {
    matches,

    append(batch) {
      const stored = batch.map((e) => ({ ...e, seq: ++seq }));
      entries.push(...stored);
      if (entries.length > maxEntries) entries.splice(0, entries.length - maxEntries);
      for (const e of stored) listeners.forEach((fn) => fn(e));
      return stored;
    },

    /** Newest first. `beforeSeq` pages backwards, `afterSeq` is used for reconnect replay (oldest first). */
    query(filter, { limit = 100, beforeSeq, afterSeq } = {}) {
      if (afterSeq !== undefined) {
        return entries.filter((e) => e.seq > afterSeq && matches(e, filter)).slice(0, limit);
      }
      const out = [];
      for (let i = entries.length - 1; i >= 0 && out.length < limit; i -= 1) {
        const e = entries[i];
        if (beforeSeq !== undefined && e.seq >= beforeSeq) continue;
        if (matches(e, filter)) out.push(e);
      }
      return out;
    },

    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },

    get size() {
      return entries.length;
    },
  };
}
