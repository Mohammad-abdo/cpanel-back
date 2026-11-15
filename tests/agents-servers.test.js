import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { createAgentsService, statusFromSummary } from '../src/modules/agents/agents.service.js';
import { createServersService } from '../src/modules/servers/servers.service.js';
import { createMonitoringService } from '../src/modules/monitoring/monitoring.service.js';
import { reportBodySchema } from '../src/modules/agents/agents.validator.js';

const sha = (v) => createHash('sha256').update(v).digest('hex');
const NOW = new Date('2026-11-15T12:00:00Z');
const now = () => NOW;
const SID = '00000000-0000-4000-8000-000000000001';
const AID = '00000000-0000-4000-8000-0000000000aa';

describe('statusFromSummary', () => {
  it('maps the worst resource to healthy/warning/critical', () => {
    expect(statusFromSummary({ cpuPercent: 10, memPercent: 20, diskPercent: 30 })).toBe('healthy');
    expect(statusFromSummary({ cpuPercent: 10, memPercent: 85, diskPercent: 30 })).toBe('warning');
    expect(statusFromSummary({ cpuPercent: 10, memPercent: 20, diskPercent: 97 })).toBe('critical');
  });
});

describe('agent enrollment', () => {
  const tx = () => ({
    agentEnrollment: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) },
    serverAgent: { deleteMany: vi.fn(), create: vi.fn() },
    server: { update: vi.fn() },
  });

  it('rejects unknown, used and expired tokens', async () => {
    for (const row of [null, { usedAt: NOW, expiresAt: new Date(NOW.getTime() + 1000) }, { usedAt: null, expiresAt: new Date(NOW.getTime() - 1) }]) {
      const prisma = { agentEnrollment: { findUnique: vi.fn().mockResolvedValue(row) } };
      await expect(createAgentsService({ prisma, now }).enroll({ token: 'x'.repeat(30) })).rejects.toMatchObject({ code: 'ENROLLMENT_INVALID' });
    }
  });

  it('issues a key once and stores only its hash', async () => {
    const t = tx();
    const prisma = {
      agentEnrollment: { findUnique: vi.fn().mockResolvedValue({ id: 'e', serverId: SID, usedAt: null, expiresAt: new Date(NOW.getTime() + 1000) }) },
      serverAgent: { findFirst: vi.fn().mockResolvedValue(null) },
      $transaction: (fn) => fn(t),
    };
    const out = await createAgentsService({ prisma, now }).enroll({ token: 'x'.repeat(30) });
    const stored = t.serverAgent.create.mock.calls[0][0].data.certFingerprint;
    expect(stored).toBe(sha(out.agentKey));
    expect(stored).not.toBe(out.agentKey);
  });

  it('refuses a token claimed concurrently', async () => {
    const t = tx();
    t.agentEnrollment.updateMany.mockResolvedValue({ count: 0 });
    const prisma = {
      agentEnrollment: { findUnique: vi.fn().mockResolvedValue({ id: 'e', serverId: SID, usedAt: null, expiresAt: new Date(NOW.getTime() + 1000) }) },
      serverAgent: { findFirst: vi.fn().mockResolvedValue(null) },
      $transaction: (fn) => fn(t),
    };
    await expect(createAgentsService({ prisma, now }).enroll({ token: 'x'.repeat(30) })).rejects.toMatchObject({ code: 'ENROLLMENT_INVALID' });
  });
  it('returns 409 for a server with an active agent and leaves the token unclaimed', async () => {
    const t = tx();
    const prisma = {
      agentEnrollment: { findUnique: vi.fn().mockResolvedValue({ id: 'e', serverId: SID, usedAt: null, expiresAt: new Date(NOW.getTime() + 1000) }) },
      serverAgent: { findFirst: vi.fn().mockResolvedValue({ id: 'a', serverId: SID, revokedAt: null }) },
      $transaction: (fn) => fn(t),
    };
    await expect(createAgentsService({ prisma, now }).enroll({ token: 'x'.repeat(30) })).rejects.toMatchObject({ status: 409, code: 'AGENT_ALREADY_ENROLLED' });
    expect(t.agentEnrollment.updateMany).not.toHaveBeenCalled();
    expect(t.serverAgent.create).not.toHaveBeenCalled();
  });
});

describe('agent authentication', () => {
  const svc = (agent) => createAgentsService({ prisma: { serverAgent: { findUnique: vi.fn().mockResolvedValue(agent) } }, now });

  it('accepts matching credentials', async () => {
    const agent = { id: 'a', serverId: SID, certFingerprint: sha('secret'), revokedAt: null };
    await expect(svc(agent).authenticate(`Agent ${AID}.secret`)).resolves.toBe(agent);
  });

  it('rejects wrong key, revoked agent, unknown agent and malformed header', async () => {
    const good = { certFingerprint: sha('secret'), revokedAt: null };
    await expect(svc(good).authenticate(`Agent ${AID}.wrong`)).rejects.toMatchObject({ code: 'AGENT_AUTH_INVALID' });
    await expect(svc({ ...good, revokedAt: NOW }).authenticate(`Agent ${AID}.secret`)).rejects.toMatchObject({ code: 'AGENT_AUTH_INVALID' });
    await expect(svc(null).authenticate(`Agent ${AID}.secret`)).rejects.toMatchObject({ code: 'AGENT_AUTH_INVALID' });
    await expect(svc(good).authenticate('Bearer abc')).rejects.toMatchObject({ code: 'AGENT_AUTH_REQUIRED' });
  });
});

describe('agent report', () => {
  it('stores snapshot and derives server status', async () => {
    const t = {
      serverSnapshot: { create: vi.fn() },
      serverService: { deleteMany: vi.fn(), createMany: vi.fn() },
      serverPort: { deleteMany: vi.fn(), createMany: vi.fn() },
      server: { update: vi.fn() },
      serverAgent: { update: vi.fn() },
    };
    const input = reportBodySchema.parse({ cpuPercent: 40, memPercent: 90, diskPercent: 50, services: [{ name: 'nginx', manager: 'nginx' }], ports: [{ port: 80, proto: 'tcp' }] });
    const out = await createAgentsService({ prisma: { $transaction: (fn) => fn(t) }, now }).report({ id: 'a', serverId: SID }, input);
    expect(out.status).toBe('warning');
    expect(t.server.update).toHaveBeenCalledWith({ where: { id: SID }, data: { status: 'warning' } });
    expect(t.serverService.createMany).toHaveBeenCalled();
  });

  it('validator rejects out-of-range values and unknown keys', () => {
    expect(reportBodySchema.safeParse({ cpuPercent: 120, memPercent: 1, diskPercent: 1 }).success).toBe(false);
    expect(reportBodySchema.safeParse({ cpuPercent: 1, memPercent: 1, diskPercent: 1, extra: 1 }).success).toBe(false);
  });
});

describe('servers service', () => {
  it('only Owner registers servers and issues tokens', async () => {
    const svc = createServersService({ prisma: {}, now });
    await expect(svc.create({ alias: 'a1' }, { id: 'u', isOwner: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.issueEnrollment(SID, { id: 'u', isOwner: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('stores only the token hash when issuing enrollment', async () => {
    const create = vi.fn();
    const prisma = { server: { findUnique: vi.fn().mockResolvedValue({ id: SID, archivedAt: null }) }, agentEnrollment: { create } };
    const out = await createServersService({ prisma, now }).issueEnrollment(SID, { id: 'u', isOwner: true });
    expect(create.mock.calls[0][0].data.tokenHash).toBe(sha(out.token));
    expect(new Date(out.expiresAt).getTime()).toBe(NOW.getTime() + 3600000);
  });

  it('reports offline for silent agents and unknown without an agent; hides credentials', async () => {
    const rows = [
      { id: '1', alias: 'a', status: 'healthy', agent: { lastSeenAt: new Date(NOW.getTime() - 10 * 60000), revokedAt: null }, snapshots: [] },
      { id: '2', alias: 'b', status: 'healthy', agent: { lastSeenAt: new Date(NOW.getTime() - 1000), revokedAt: null }, snapshots: [{ summaryJson: { cpuPercent: 5 } }] },
      { id: '3', alias: 'c', status: 'unknown', agent: null, snapshots: [] },
    ];
    const findMany = vi.fn().mockResolvedValue(rows);
    const out = await createServersService({ prisma: { server: { findMany } }, now }).list({ limit: 10 });
    expect(out.map((s) => s.status)).toEqual(['offline', 'healthy', 'unknown']);
    expect(out[1].latest).toEqual({ cpuPercent: 5 });
    expect(JSON.stringify(findMany.mock.calls[0][0])).not.toContain('certFingerprint');
  });
});

describe('monitoring fleet', () => {
  it('averages snapshots into buckets', async () => {
    const at = (m) => new Date(`2026-11-15T11:${m}:00Z`);
    const rows = [
      { capturedAt: at('05'), summaryJson: { cpuPercent: 10, memPercent: 40 } },
      { capturedAt: at('35'), summaryJson: { cpuPercent: 30, memPercent: 60 } },
    ];
    const out = await createMonitoringService({ prisma: { serverSnapshot: { findMany: vi.fn().mockResolvedValue(rows) } }, now }).fleet({ hours: 168 });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ cpuPercent: 20, memPercent: 50 });
  });
});
