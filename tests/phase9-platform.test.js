import { describe, expect, it, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { LOAD_BUDGET, computeBackoff, connectionState, createFleetService, mapSettled, retry } from '../src/modules/platform/platform.fleet.js';
import { MAX_FAILED_ATTEMPTS, createEmergencyService } from '../src/modules/platform/platform.emergency.js';
import { createPlatformController } from '../src/modules/platform/platform.controller.js';
import { createSimulatedAdapters } from '../src/modules/platform/platform.adapters.js';
import { sha256 } from '../src/modules/platform/platform.crypto.js';
import { STALE_AFTER_MS } from '../src/modules/agents/agents.service.js';
import { APPROVER, DEV, KEY, OWNER, U } from './phase6-helpers.js';

const NOW = new Date('2026-06-01T12:00:00Z');
const CODE = 'offline-recovery-code-0001';

describe('fleet: connection state and resilience', () => {
  it('classifies connected, degraded, offline, never connected and revoked', () => {
    const ago = (ms) => new Date(NOW.getTime() - ms);
    expect(connectionState(ago(1000), NOW)).toBe('connected');
    expect(connectionState(ago(STALE_AFTER_MS / 2), NOW)).toBe('degraded');
    expect(connectionState(ago(STALE_AFTER_MS * 2), NOW)).toBe('offline');
    expect(connectionState(null, NOW)).toBe('never_connected');
    expect(connectionState(ago(1), NOW, ago(5))).toBe('revoked');
  });
  it('backoff grows exponentially, is capped and jittered', () => {
    const max = (n) => computeBackoff(n, { rng: () => 0.999999 });
    expect(max(0)).toBeLessThan(1000);
    expect(max(3)).toBeGreaterThan(max(1));
    expect(max(30)).toBeLessThanOrEqual(LOAD_BUDGET.backoffMaxMs);
    expect(computeBackoff(5, { rng: () => 0 })).toBe(0);
  });
  it('retries with backoff then succeeds, or throws the last error', async () => {
    const sleep = vi.fn(async () => {});
    let n = 0;
    await expect(retry(async () => { if (++n < 3) throw new Error('flaky'); return 'ok'; }, { sleep, rng: () => 0.5 })).resolves.toBe('ok');
    expect(sleep).toHaveBeenCalledTimes(2);
    await expect(retry(async () => { throw new Error('dead'); }, { attempts: 3, sleep })).rejects.toThrow('dead');
  });
  it('mapSettled isolates failures and respects the concurrency cap', async () => {
    let live = 0;
    let peak = 0;
    const res = await mapSettled(Array.from({ length: 50 }, (_, i) => i), 5, async (i) => {
      live += 1; peak = Math.max(peak, live);
      await new Promise((r) => setTimeout(r, 1));
      live -= 1;
      if (i % 10 === 0) throw new Error('x');
      return i;
    });
    expect(peak).toBeLessThanOrEqual(5);
    expect(res.filter((r) => r.status === 'rejected')).toHaveLength(5);
    expect(res.filter((r) => r.status === 'fulfilled')).toHaveLength(45);
  });
});

describe('fleet: many servers', () => {
  const servers = Array.from({ length: 1200 }, (_, i) => ({ id: U(1000 + i), alias: `vps-${i}`, archivedAt: null, agent: { lastSeenAt: i % 3 === 0 ? new Date(NOW - 60 * 60 * 1000) : new Date(NOW - 1000), revokedAt: null } }));
  const prisma = {
    server: {
      findMany: vi.fn(async ({ take, skip = 0, cursor }) => {
        const start = cursor ? servers.findIndex((s) => s.id === cursor.id) + skip : 0;
        return servers.slice(start, start + take);
      }),
    },
  };
  const svc = createFleetService({ prisma, now: () => NOW, adapters: createSimulatedAdapters(), probeTimeoutMs: 20 });

  it('paginates 1200 servers without duplicates, capped at the page budget', async () => {
    const seen = new Set();
    let cursor;
    let pages = 0;
    do {
      const page = await svc.overview({ limit: 500, cursor });
      page.items.forEach((i) => seen.add(i.id));
      cursor = page.nextCursor;
      pages += 1;
    } while (cursor);
    expect(seen.size).toBe(1200);
    expect(pages).toBe(3);
    const big = await svc.overview({ limit: 100000 });
    expect(big.items.length).toBeLessThanOrEqual(LOAD_BUDGET.maxPageSize);
  });
  it('reports offline servers per state without hiding them', async () => {
    const page = await svc.overview({ limit: 300 });
    expect(page.counts.offline).toBe(100);
    expect(page.counts.connected).toBe(200);
  });
  it('probes with outage, timeout and error isolated per server (synthetic, not a measured budget)', async () => {
    const adapters = createSimulatedAdapters();
    adapters.fleet.probe = vi.fn(async (id) => {
      if (id === U(1)) return { reachable: false };
      if (id === U(2)) throw new Error('conn reset');
      if (id === U(3)) return new Promise(() => {});
      return { reachable: true, latencyMs: 4 };
    });
    const f = createFleetService({ prisma, now: () => NOW, adapters, probeTimeoutMs: 20 });
    const ids = [U(1), U(2), U(3), ...servers.slice(0, 200).map((s) => s.id)];
    const t0 = Date.now();
    const out = await f.probe({ serverIds: ids });
    expect(Date.now() - t0).toBeLessThan(2000);
    expect(out.slice(0, 3).map((o) => o.state)).toEqual(['unreachable', 'error', 'timeout']);
    expect(out.slice(3).every((o) => o.state === 'ok')).toBe(true);
  });
  it('is read-only: the fleet service exposes no stop or restart operation', () => {
    expect(Object.keys(svc).sort()).toEqual(['overview', 'probe']);
  });
});

describe('emergency Owner (break-glass)', () => {
  function setup({ hash = sha256(CODE), events = [] } = {}) {
    const store = [...events];
    const prisma = {
      auditEvent: {
        findMany: vi.fn(async ({ where }) => store.filter((e) => where.action.in.includes(e.action) && e.result === where.result).sort((a, b) => b.occurredAt - a.occurredAt).slice(0, 1)),
        count: vi.fn(async ({ where }) => store.filter((e) => e.action === where.action && e.result === where.result && e.occurredAt >= where.occurredAt.gte).length),
      },
      user: { count: vi.fn(async () => 1) },
      backupRun: { findFirst: vi.fn(async () => null) },
    };
    const auditService = { record: vi.fn(async (e) => { store.push({ ...e, afterJson: e.after, occurredAt: new Date(NOW.getTime() + store.length) }); }) };
    return { store, prisma, auditService, svc: createEmergencyService({ prisma, now: () => NOW, auditService, recoveryCodeHash: () => hash }) };
  }
  const body = { reason: 'primary approver unreachable during outage', recoveryCode: CODE, minutes: 30 };

  it('activates for the Owner with the correct recovery code, audited with an expiry', async () => {
    const t = setup();
    const r = await t.svc.activate(body, OWNER);
    expect(r.active).toBe(true);
    expect(new Date(r.expiresAt).getTime()).toBe(NOW.getTime() + 30 * 60000);
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'platform.breakglass.activate', result: 'success' }));
    expect((await t.svc.status()).active).toBe(true);
    await expect(t.svc.activate(body, OWNER)).rejects.toMatchObject({ code: 'BREAKGLASS_ACTIVE' });
  });
  it('rejects non-owners, wrong codes and unconfigured systems; never logs the code', async () => {
    const t = setup();
    await expect(t.svc.activate(body, DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    await expect(t.svc.activate(body, APPROVER)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.activate(body, null)).rejects.toMatchObject({ status: 401 });
    await expect(t.svc.activate({ ...body, recoveryCode: 'wrong-wrong-wrong-0000' }, OWNER)).rejects.toMatchObject({ code: 'RECOVERY_CODE_INVALID' });
    expect(JSON.stringify(t.store)).not.toContain(CODE);
    expect(JSON.stringify(t.store)).not.toContain('wrong-wrong');
    await expect(setup({ hash: '' }).svc.activate(body, OWNER)).rejects.toMatchObject({ code: 'BREAKGLASS_NOT_CONFIGURED' });
  });
  it('locks after repeated failures even for the correct code', async () => {
    const t = setup();
    for (let i = 0; i < MAX_FAILED_ATTEMPTS; i += 1) await t.svc.activate({ ...body, recoveryCode: 'wrong-wrong-wrong-0000' }, OWNER).catch(() => {});
    await expect(t.svc.activate(body, OWNER)).rejects.toMatchObject({ code: 'BREAKGLASS_LOCKED' });
  });
  it('expires and can be ended early by the Owner only', async () => {
    const past = { action: 'platform.breakglass.activate', result: 'success', actorId: OWNER.id, afterJson: { expiresAt: new Date(NOW - 1000).toISOString() }, occurredAt: new Date(NOW - 5000) };
    expect((await setup({ events: [past] }).svc.status()).active).toBe(false);
    const t = setup();
    await t.svc.activate(body, OWNER);
    await expect(t.svc.deactivate({}, DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    await t.svc.deactivate({ note: 'resolved' }, OWNER);
    expect((await t.svc.status()).active).toBe(false);
    await expect(t.svc.deactivate({}, OWNER)).rejects.toMatchObject({ code: 'BREAKGLASS_NOT_ACTIVE' });
  });
  it('readiness never reports unknowns as passed', async () => {
    const r = await setup().svc.readiness({ encryptionKey: () => KEY });
    expect(r.ready).toBe(false);
    const byName = Object.fromEntries(r.checks.map((c) => [c.name, c.status]));
    expect(byName.owner_account_exists).toBe('pass');
    expect(byName.backup_encryption_key_configured).toBe('pass');
    expect(byName.verified_backup_exists).toBe('fail');
    expect(byName.offsite_control_plane_restore_drill).toBe('unknown');
    expect(byName.approved_rpo_rto).toBe('unknown');
    const bad = await setup({ hash: '' }).svc.readiness({ encryptionKey: () => '' });
    expect(bad.checks.find((c) => c.name === 'backup_encryption_key_configured').status).toBe('fail');
  });
  it('controller restricts fleet probe and readiness to the Owner', async () => {
    const c = createPlatformController({ platformService: {}, fleet: { probe: vi.fn(async () => []) }, emergency: { readiness: vi.fn(async () => ({})) } });
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    await expect(c.fleetProbe({ user: DEV, validated: { body: {} } }, res)).rejects.toMatchObject({ status: 403 });
    await expect(c.readiness({ user: DEV }, res)).rejects.toMatchObject({ status: 403 });
    await c.readiness({ user: OWNER }, res);
    expect(res.status).toHaveBeenCalledWith(200);
  });
});

describe('platform routes fail closed without a session', () => {
  it('rejects every platform, break-glass and fleet route with 401', async () => {
    const { platformRouter } = await import('../src/modules/platform/platform.routes.js');
    const app = express();
    app.use(express.json());
    app.use('/p', platformRouter);
    app.use((err, req, res, next) => res.status(err.status ?? 500).json({ error: { code: err.code } })); // eslint-disable-line no-unused-vars
    for (const [m, path] of [['get', '/p/approvals'], ['get', '/p/fleet'], ['get', '/p/readiness'], ['get', '/p/break-glass'], ['post', '/p/break-glass/activate'], ['post', '/p/fleet/probe']]) {
      const res = await request(app)[m](path).send({});
      expect(res.status, path).toBe(401);
    }
  }, 30000);
});

describe('platform approval decisions (security test findings)', () => {
  it('checks permission before revealing whether a request exists or its state', async () => {
    const { createPlatformService } = await import('../src/modules/platform/platform.service.js');
    const { makeApprovalPrisma, makeRbac, DEV } = await import('./phase6-helpers.js');
    const prisma = makeApprovalPrisma();
    const platform = createPlatformService({ prisma, rbac: makeRbac([]), auditService: { record: vi.fn() } });
    const consumed = await prisma.approvalRequest.create({ data: { status: 'consumed', requesterId: 'x', resourceType: 'domain', resourceId: 'd' } });
    for (const id of [consumed.id, '00000000-0000-4000-8000-000000000000']) {
      await expect(platform.decide(id, { decision: 'approve' }, DEV)).rejects.toMatchObject({ status: 403 });
    }
  });
  it('lists and decides platform approvals only, never operation approvals', async () => {
    const { createPlatformService } = await import('../src/modules/platform/platform.service.js');
    const { makeApprovalPrisma, makeRbac, OWNER } = await import('./phase6-helpers.js');
    const prisma = makeApprovalPrisma();
    const platform = createPlatformService({ prisma, rbac: makeRbac([]), auditService: { record: vi.fn() } });
    const op = await prisma.approvalRequest.create({ data: { status: 'pending', operationJobId: 'job-1', requesterId: 'x', resourceType: 'project', resourceId: 'p' } });
    await platform.list({ status: 'pending', limit: 10 }, OWNER);
    expect(prisma.approvalRequest.findMany).toHaveBeenCalledWith(expect.objectContaining({ where: { operationJobId: null, status: 'pending' } }));
    await expect(platform.decide(op.id, { decision: 'approve' }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_FOUND' });
  });
});
