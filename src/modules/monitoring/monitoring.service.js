import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';

/**
 * Metrics live in Prometheus; this service returns metadata + latest health snapshots only.
 */
export function createMonitoringService({ prisma, now = () => new Date() }) {
  const scope = createScope({ prisma, now });
  return {
    /** Fleet averages (1/5/30/60 minute buckets by range) from stored snapshots (interim; Prometheus replaces this later). */
    async fleet({ hours }, actor) {
      const since = new Date(now().getTime() - hours * 3600 * 1000);
      const idClause = await scope.serverClause(actor);
      const rows = await prisma.serverSnapshot.findMany({
        where: { capturedAt: { gte: since }, ...(idClause ? { serverId: idClause } : {}) },
        orderBy: { capturedAt: 'asc' },
        take: 20000,
      });
      const bucketMs = (hours <= 1 ? 1 : hours <= 6 ? 5 : hours <= 24 ? 30 : 60) * 60000;
      const buckets = new Map();
      for (const r of rows) {
        const s = r.summaryJson;
        if (!s) continue;
        const key = Math.floor(new Date(r.capturedAt).getTime() / bucketMs) * bucketMs;
        const b = buckets.get(key) ?? { n: 0, cpu: 0, mem: 0 };
        b.n += 1;
        b.cpu += s.cpuPercent;
        b.mem += s.memPercent;
        buckets.set(key, b);
      }
      return [...buckets.entries()].map(([t, b]) => ({
        at: new Date(t).toISOString(),
        cpuPercent: Math.round((b.cpu / b.n) * 10) / 10,
        memPercent: Math.round((b.mem / b.n) * 10) / 10,
      }));
    },

    async getServerHealth(serverId, actor) {
      await scope.requireServer(actor, serverId, 'SERVER_NOT_FOUND', 'Server not found');
      const server = await prisma.server.findUnique({ where: { id: serverId } });
      if (!server) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');

      const latest = await prisma.healthCheck.findFirst({
        where: { resourceType: 'server', resourceId: serverId },
        orderBy: { checkedAt: 'desc' },
      });

      return {
        serverId,
        alias: server.alias,
        status: server.status,
        latestHealth: latest,
        metricsStore: 'prometheus',
      };
    },
  };
}
