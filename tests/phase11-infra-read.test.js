import { describe, expect, it, vi } from 'vitest';
import { createServersService } from '../src/modules/servers/servers.service.js';
import { fleetReadQuerySchema } from '../src/modules/servers/servers.validator.js';
import { createIntegrationsService } from '../src/modules/platform/platform.integrations.js';
import { createMembersService } from '../src/modules/members/members.service.js';
import { createFirewallService } from '../src/modules/firewall/firewall.service.js';

const OWNER = { id: '11111111-1111-4111-8111-111111111111', isOwner: true };
const SERVER = '22222222-2222-4222-8222-222222222222';

describe('fleet read endpoints (servers module)', () => {
  it('validates the query and rejects unknown keys', () => {
    expect(fleetReadQuerySchema.parse({}).limit).toBe(500);
    expect(() => fleetReadQuerySchema.parse({ serverId: 'x' })).toThrow();
    expect(() => fleetReadQuerySchema.parse({ extra: 1 })).toThrow();
  });

  it('lists services without metaJson and filters by server', async () => {
    const findMany = vi.fn(async () => [{ id: 's1', serverId: SERVER, name: 'nginx', manager: 'systemd', state: 'running', metaJson: { secret: 'x' }, server: { id: SERVER, alias: 'a' } }]);
    const svc = createServersService({ prisma: { serverService: { findMany } } });
    const rows = await svc.services({ serverId: SERVER, limit: 10 }, OWNER);
    expect(rows[0]).not.toHaveProperty('metaJson');
    expect(findMany.mock.calls[0][0].where.serverId).toBe(SERVER);
  });

  it('lists ports and runtimes read-only', async () => {
    const prisma = {
      serverPort: { findMany: vi.fn(async () => [{ id: 'p', port: 22, proto: 'tcp' }]) },
      project: { findMany: vi.fn(async () => [{ id: 'pr', name: 'n', slug: 'n', type: 'node', status: 'active', server: { id: SERVER, alias: 'a' }, runtime: { runtime: 'node 24', processManager: 'pm2' }, environments: [] }]) },
    };
    const svc = createServersService({ prisma });
    expect(await svc.ports({ limit: 5 }, OWNER)).toHaveLength(1);
    const rt = await svc.runtimes(OWNER);
    expect(rt[0].runtime.processManager).toBe('pm2');
  });
});

describe('integrations status', () => {
  const prisma = {
    user: { count: vi.fn(async () => 0) },
    logEntry: { count: vi.fn(async () => 3), findFirst: vi.fn(async () => ({ occurredAt: new Date() })) },
    serverAgent: { findMany: vi.fn(async () => [{ lastSeenAt: new Date() }, { lastSeenAt: null }]) },
    reportSchedule: { findMany: vi.fn(async () => []) },
  };
  it('reports statuses from presence flags and never echoes secret values', async () => {
    const svc = createIntegrationsService({
      prisma,
      adapters: { simulated: true, wazuh: { health: async () => ({ connected: true }) } },
      env: { BACKUP_ENCRYPTION_KEY: 'super-secret-value' },
    });
    const items = await svc.list();
    const by = Object.fromEntries(items.map((i) => [i.name, i]));
    expect(by.wazuh.status).toBe('ok');
    expect(by.agents.status).toBe('degraded');
    expect(by.queue_redis.status).toBe('not_configured');
    expect(by.backup_encryption.status).toBe('ok');
    expect(by.scheduler.status).toBe('not_configured');
    expect(JSON.stringify(items)).not.toContain('super-secret-value');
  });

  it('degrades to down when the adapter throws', async () => {
    const svc = createIntegrationsService({ prisma, adapters: { wazuh: { health: async () => { throw new Error('x'); } } }, env: {} });
    expect((await svc.list()).find((i) => i.name === 'wazuh').status).toBe('down');
  });
});

describe('team analytics', () => {
  it('requires Owner', async () => {
    const svc = createMembersService({ prisma: {} });
    await expect(svc.analytics({}, { id: 'u', isOwner: false })).rejects.toMatchObject({ status: 403 });
  });
});

describe('firewall history', () => {
  it('reads only firewall audit events and exposes the diff', async () => {
    const prisma = {
      auditEvent: { findMany: vi.fn(async () => [{ id: 'a', action: 'firewall.change', result: 'success', resourceId: SERVER, afterJson: { diff: ['+ allow 443/tcp from any'] } }]) },
      server: { findMany: vi.fn(async () => [{ id: SERVER, alias: 'demo' }]) },
    };
    const svc = createFirewallService({ prisma });
    const rows = await svc.history({ limit: 10 }, OWNER);
    expect(prisma.auditEvent.findMany.mock.calls[0][0].where.action).toEqual({ startsWith: 'firewall.change' });
    expect(rows[0]).toMatchObject({ serverAlias: 'demo', diff: ['+ allow 443/tcp from any'] });
  });
});
