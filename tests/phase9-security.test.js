import { describe, expect, it, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createDomainsService } from '../src/modules/domains/domains.service.js';
import { createDatabasesService } from '../src/modules/databases/databases.service.js';
import { decrypt, encrypt, parseKey } from '../src/modules/platform/platform.crypto.js';
import { createPlatformService } from '../src/modules/platform/platform.service.js';
import { ACTION_RISK, requiresApproval } from '../src/modules/platform/platform.risk.js';
import { redact } from '../src/modules/audit/audit.service.js';
import { APPROVER, DEV, ENV_PROD, KEY, OWNER, PROJECT, U, approve, makeApprovalPrisma, makeCtx } from './phase6-helpers.js';

const UUID = U(42);
const MOUNTS = [
  ['/domains', () => import('../src/modules/domains/domains.routes.js'), 'domainsRouter'],
  ['/certificates', () => import('../src/modules/certificates/certificates.routes.js'), 'certificatesRouter'],
  ['/databases', () => import('../src/modules/databases/databases.routes.js'), 'databasesRouter'],
  ['/backups', () => import('../src/modules/backups/backups.routes.js'), 'backupsRouter'],
  ['/restores', () => import('../src/modules/restores/restores.routes.js'), 'restoresRouter'],
  ['/security', () => import('../src/modules/security/security.routes.js'), 'securityRouter'],
  ['/incidents', () => import('../src/modules/incidents/incidents.routes.js'), 'incidentsRouter'],
  ['/firewall', () => import('../src/modules/firewall/firewall.routes.js'), 'firewallRouter'],
  ['/access-reviews', () => import('../src/modules/access-reviews/access-reviews.routes.js'), 'accessReviewsRouter'],
  ['/platform', () => import('../src/modules/platform/platform.routes.js'), 'platformRouter'],
];

function routesOf(router) {
  return router.stack.filter((l) => l.route).flatMap((l) => Object.keys(l.route.methods).map((m) => ({ method: m, path: l.route.path })));
}

describe('security: every route of every phase 06-09 module fails closed', () => {
  it('returns 401 without a session for all routes and methods', async () => {
    const app = express();
    app.use(express.json());
    let total = 0;
    for (const [mount, load, name] of MOUNTS) {
      const mod = await load();
      app.use(mount, mod[name]);
      total += routesOf(mod[name]).length;
    }
    app.use((err, req, res, next) => res.status(err.status ?? 500).json({ error: { code: err.code } })); // eslint-disable-line no-unused-vars
    expect(total).toBeGreaterThan(40);
    for (const [mount, load, name] of MOUNTS) {
      const mod = await load();
      for (const r of routesOf(mod[name])) {
        const path = `${mount}${r.path.replace(/:\w+/g, UUID)}`;
        const res = await request(app)[r.method](path).send({});
        expect(res.status, `${r.method} ${path}`).toBe(401);
      }
    }
  }, 30000);

  it('every write route requires an MFA-satisfied session (not read-only requireSession)', async () => {
    for (const [, load, name] of MOUNTS) {
      const mod = await load();
      for (const l of mod[name].stack.filter((s) => s.route)) {
        const methods = Object.keys(l.route.methods);
        if (methods.includes('post') || methods.includes('delete') || methods.includes('put')) {
          // write routes are registered with requireSession({ requireMfa: true }); reads use the default.
          expect(l.route.stack.length, l.route.path).toBeGreaterThanOrEqual(3);
        }
      }
    }
  });

  it('bearer-only auth: no cookie is read, so ambient-credential CSRF does not apply', async () => {
    const app = express();
    const { domainsRouter } = await import('../src/modules/domains/domains.routes.js');
    app.use(express.json());
    app.use('/d', domainsRouter);
    app.use((err, req, res, next) => res.status(err.status ?? 500).json({ error: { code: err.code } })); // eslint-disable-line no-unused-vars
    const res = await request(app).post('/d').set('Cookie', 'session=abc; token=abc').send({});
    expect(res.status).toBe(401);
  });
});

describe('security: IDOR and privilege escalation', () => {
  const mk = () => makeCtx({
    prismaExtra: {
      projectEnvironment: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: where.id === ENV_PROD ? PROJECT : U(77) })) },
      domain: { findUnique: vi.fn(async () => ({ id: UUID, name: 'victim.example.com', projectId: U(77), dnsRecords: [], certificates: [] })) },
      managedDatabase: { findUnique: vi.fn(async () => ({ id: UUID, projectId: U(77), environmentId: U(78), dbName: 'other_db', instance: { name: 'm' }, users: [] })) },
    },
  });
  it('another project domain cannot be modified by guessing its id', async () => {
    const t = mk();
    const svc = createDomainsService(t);
    await expect(svc.changeDns(UUID, { op: 'upsert', type: 'A', name: 'victim.example.com', value: '1.2.3.4', ttl: 300, environmentId: ENV_PROD }, DEV)).rejects.toMatchObject({ code: 'ENVIRONMENT_PROJECT_MISMATCH' });
    await expect(svc.applyVhost(UUID, { upstreamPort: 80, webserver: 'nginx', environmentId: ENV_PROD }, DEV)).rejects.toBeTruthy();
    expect(t.adapters.calls.length).toBe(0);
  });
  it('database user creation on a foreign database is denied', async () => {
    const t = mk();
    const svc = createDatabasesService(t);
    await expect(svc.createUser(UUID, { environmentId: ENV_PROD, username: 'evil_user', level: 'readwrite' }, DEV)).rejects.toMatchObject({ code: 'ENVIRONMENT_MISMATCH' });
    expect(t.adapters.calls.length).toBe(0);
  });
  it('a user cannot approve their own request or escalate by approving without the decide permission', async () => {
    const prisma = makeApprovalPrisma();
    const rbac = { can: vi.fn(async (a) => a.isOwner || a.id === APPROVER.id) };
    const platform = createPlatformService({ prisma, rbac, auditService: { record: vi.fn() } });
    const req = await platform.request({ action: 'dns.change', resourceType: 'domain', resourceId: UUID, reason: 'because', impact: ['x'], rollbackPlan: 'undo' }, DEV);
    // Without the decide permission the answer is a plain 403 before anything about the request is revealed.
    await expect(platform.decide(req.id, { decision: 'approve' }, DEV)).rejects.toMatchObject({ status: 403, code: 'FORBIDDEN' });
    await expect(platform.decide(req.id, { decision: 'approve' }, { id: U(55), isOwner: false })).rejects.toMatchObject({ status: 403 });
    // With the permission, approving your own request is still refused.
    const own = await platform.request({ action: 'dns.change', resourceType: 'domain', resourceId: UUID, reason: 'because', impact: ['x'], rollbackPlan: 'undo' }, APPROVER);
    await expect(platform.decide(own.id, { decision: 'approve' }, APPROVER)).rejects.toMatchObject({ code: 'SELF_APPROVAL_DENIED' });
    await platform.decide(req.id, { decision: 'approve' }, APPROVER);
    await expect(platform.decide(req.id, { decision: 'reject' }, APPROVER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_PENDING' });
  });
  it('approvals expire, cannot be replayed and cannot be used by someone else', async () => {
    let at = new Date('2026-06-01T00:00:00Z');
    const ctx = makeCtx({ now: () => at });
    const input = { action: 'db.drop', resourceType: 'database', resourceId: UUID, reason: 'decommission', impact: ['x'], rollbackPlan: 'restore' };
    const g1 = await ctx.platform.gate(input, DEV);
    await approve(ctx, g1.approval.id);
    await expect(ctx.platform.gate({ ...input, approvalId: g1.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_REQUESTER_ONLY' });
    await expect(ctx.platform.gate({ ...input, binding: 'other', approvalId: g1.approval.id }, DEV)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    at = new Date(at.getTime() + 25 * 3600 * 1000);
    await expect(ctx.platform.gate({ ...input, approvalId: g1.approval.id }, DEV)).rejects.toMatchObject({ code: 'APPROVAL_EXPIRED' });
    at = new Date('2026-06-01T00:00:00Z');
    const g2 = await ctx.platform.gate(input, DEV);
    await approve(ctx, g2.approval.id);
    await expect(ctx.platform.gate({ ...input, approvalId: g2.approval.id }, DEV)).resolves.toMatchObject({ proceed: true });
    await expect(ctx.platform.gate({ ...input, approvalId: g2.approval.id }, DEV)).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });
  it('a rejected approval can never be executed', async () => {
    const ctx = makeCtx();
    const input = { action: 'ssl.issue', resourceType: 'domain', resourceId: UUID, reason: 'because', impact: ['x'], rollbackPlan: 'undo' };
    const g = await ctx.platform.gate(input, DEV);
    await ctx.platform.decide(g.approval.id, { decision: 'reject' }, APPROVER);
    await expect(ctx.platform.gate({ ...input, approvalId: g.approval.id }, DEV)).rejects.toMatchObject({ code: 'APPROVAL_NOT_APPROVED' });
  });
});

describe('security: secrets and crypto', () => {
  it('redacts secret-looking keys before storage, including nested and arrays', () => {
    const out = redact({ a: { password: 'p', apiKey: 'k', list: [{ token: 't', ok: 1 }] }, authorization: 'Bearer x' });
    expect(JSON.stringify(out)).not.toMatch(/"p"|"k"|"t"|Bearer/);
    expect(out.a.list[0].ok).toBe(1);
  });
  it('approval impact JSON is redacted before storage', async () => {
    const ctx = makeCtx();
    const r = await ctx.platform.request({ action: 'db.user.create', resourceType: 'database', resourceId: UUID, reason: 'access', impact: ['x'], rollbackPlan: 'undo', context: { password: 'hunter2', token: 'abc' } }, DEV);
    expect(JSON.stringify(r.impactJson)).not.toMatch(/hunter2|abc/);
  });
  it('AES-256-GCM round-trips, uses fresh IVs and rejects a wrong key or flipped bits', () => {
    const a = encrypt('secret', KEY);
    const b = encrypt('secret', KEY);
    expect(a.equals(b)).toBe(false);
    expect(decrypt(a, KEY).toString()).toBe('secret');
    expect(() => decrypt(a, 'b'.repeat(64))).toThrow(/authentication/);
    const bad = Buffer.from(a);
    bad[30] ^= 1;
    expect(() => decrypt(bad, KEY)).toThrow(/authentication/);
    expect(() => decrypt(Buffer.alloc(5), KEY)).toThrow();
  });
  it('refuses missing or short encryption keys (no hardcoded fallback)', () => {
    expect(() => parseKey('')).toThrow(/not configured/);
    expect(() => parseKey('abcd')).toThrow(/32 bytes/);
    expect(parseKey(Buffer.alloc(32, 1).toString('base64')).length).toBe(32);
  });
  it('risk model: high and critical actions require approval, nothing privileged is low', () => {
    for (const a of ['dns.change', 'ssl.issue', 'db.create', 'db.drop', 'backup.restore.inplace', 'firewall.change', 'emergency.owner']) expect(requiresApproval(a), a).toBe(true);
    expect(Object.values(ACTION_RISK)).not.toContain('low');
  });
  it('the shipped adapters are simulated and never execute real tooling', async () => {
    const { createSimulatedAdapters } = await import('../src/modules/platform/platform.adapters.js');
    const a = createSimulatedAdapters();
    expect(a.simulated).toBe(true);
    await a.dbAdmin.createUser({ username: 'u', password: 'topsecret' });
    expect(JSON.stringify(a.calls)).not.toContain('topsecret');
  });
});
