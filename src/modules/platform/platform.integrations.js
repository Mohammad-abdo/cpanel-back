import { STALE_AFTER_MS } from '../agents/agents.service.js';

const present = (v) => Boolean(v && String(v).trim());

/**
 * Read-only integration status. Computed from existing adapters, database counts and environment
 * presence flags only. Secret values are never read into the response.
 * Each item: { name, status: ok | degraded | down | not_configured | unknown, detail, checkedAt }.
 */
export function createIntegrationsService({ prisma, adapters, now = () => new Date(), env = process.env }) {
  return {
    async list() {
      const checkedAt = now().toISOString();
      const items = [];
      const add = (name, status, detail) => items.push({ name, status, detail, checkedAt });

      try {
        await prisma.user.count({ where: { id: '00000000-0000-0000-0000-000000000000' } });
        add('database', 'ok', 'MySQL reachable through Prisma');
      } catch {
        add('database', 'down', 'Database query failed');
      }

      try {
        const h = await adapters.wazuh.health();
        add('wazuh', h.connected ? 'ok' : 'down', `${h.connected ? 'Connected' : 'Not connected'}${adapters.simulated ? ' (simulated adapter)' : ''}`);
      } catch {
        add('wazuh', 'down', 'Source unavailable');
      }

      try {
        const [total, last] = await Promise.all([
          prisma.logEntry.count(),
          prisma.logEntry.findFirst({ orderBy: { occurredAt: 'desc' }, select: { occurredAt: true } }),
        ]);
        add('log_store', total > 0 ? 'ok' : 'degraded', `${total} stored entries${last ? `, newest ${new Date(last.occurredAt).toISOString()}` : ''}`);
      } catch {
        add('log_store', 'down', 'Log table not reachable');
      }

      try {
        const agents = await prisma.serverAgent.findMany({ where: { revokedAt: null }, select: { lastSeenAt: true } });
        const fresh = agents.filter((a) => a.lastSeenAt && now().getTime() - new Date(a.lastSeenAt).getTime() <= STALE_AFTER_MS).length;
        const status = agents.length === 0 ? 'not_configured' : fresh === agents.length ? 'ok' : fresh === 0 ? 'down' : 'degraded';
        add('agents', status, `${fresh} of ${agents.length} enrolled agents reported in the last ${Math.round(STALE_AFTER_MS / 60000)} minutes`);
      } catch {
        add('agents', 'unknown', 'Agent registry not reachable');
      }

      add('queue_redis', present(env.REDIS_URL) ? 'ok' : 'not_configured', present(env.REDIS_URL) ? 'REDIS_URL is set (connection not probed)' : 'REDIS_URL is not set');
      add('backup_encryption', present(env.BACKUP_ENCRYPTION_KEY) ? 'ok' : 'not_configured', present(env.BACKUP_ENCRYPTION_KEY) ? 'Key is present' : 'BACKUP_ENCRYPTION_KEY is not set');

      try {
        const schedules = await prisma.reportSchedule.findMany({ select: { enabled: true, cron: true, definition: { select: { code: true } } }, take: 100 });
        const enabled = schedules.filter((s) => s.enabled);
        add('scheduler', enabled.length ? 'ok' : 'not_configured', `${enabled.length} enabled report schedule(s) of ${schedules.length}${enabled.length ? `: ${enabled.slice(0, 5).map((s) => `${s.definition.code} ${s.cron}`).join(', ')}` : ''}`);
      } catch {
        add('scheduler', 'unknown', 'Schedule registry not reachable');
      }
      return items;
    },
  };
}
