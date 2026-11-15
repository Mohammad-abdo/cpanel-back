import { describe, expect, it, vi } from 'vitest';
import { evaluate, createFirewallService, MAX_WINDOW_MS } from '../src/modules/firewall/firewall.service.js';
import { classifyGrant, createAccessReviewsService } from '../src/modules/access-reviews/access-reviews.service.js';
import { applyBodySchema } from '../src/modules/firewall/firewall.validator.js';
import { APPROVER, DEV, OWNER, U, approve, makeCtx, makeRbac } from './phase6-helpers.js';

const NOW = new Date('2026-06-01T10:00:00Z');
const SERVER = U(5);
const win = { windowStart: '2026-06-01T09:00:00.000Z', windowEnd: '2026-06-01T11:00:00.000Z' };
const allow80 = { op: 'allow', port: 80, proto: 'tcp', source: 'any' };

function fwSetup(grants = []) {
  const ctx = makeCtx({ now: () => NOW, grants, prismaExtra: { server: { findUnique: vi.fn(async () => ({ id: SERVER, archivedAt: null })) } } });
  return { ...ctx, svc: createFirewallService(ctx) };
}
const body = (over = {}) => ({ changes: [allow80], ...win, reason: 'open web', rollbackNote: 'delete the rule', ...over });

describe('firewall: evaluation', () => {
  const cur = [{ action: 'allow', port: 22, proto: 'tcp', source: 'any' }];
  it('flags lockout when SSH would be removed or denied', () => {
    expect(evaluate(cur, [{ op: 'delete', port: 22, proto: 'tcp', source: 'any' }]).problems[0].code).toBe('LOCKOUT_RISK');
    expect(evaluate(cur, [{ op: 'deny', port: 22, proto: 'tcp', source: 'any' }]).problems[0].code).toBe('LOCKOUT_RISK');
    expect(evaluate(cur, [allow80]).problems).toEqual([]);
  });
  it('rejects exposing database ports to any source and lists shared-service impact', () => {
    expect(evaluate(cur, [{ op: 'allow', port: 3306, proto: 'tcp', source: 'any' }]).problems[0].code).toBe('SENSITIVE_EXPOSURE');
    expect(evaluate(cur, [{ op: 'allow', port: 3306, proto: 'tcp', source: '10.0.0.5' }]).problems).toEqual([]);
    expect(evaluate(cur, [allow80]).impact[0]).toMatch(/every site/);
  });
  it('validator rejects bad sources and extra keys', () => {
    expect(applyBodySchema.safeParse({ ...body(), changes: [{ ...allow80, source: 'evil;rm' }] }).success).toBe(false);
    expect(applyBodySchema.safeParse({ ...body(), extra: 1 }).success).toBe(false);
  });
});

describe('firewall: apply', () => {
  it('previews without applying', async () => {
    const t = fwSetup();
    const p = await t.svc.preview(SERVER, { changes: [allow80] }, OWNER);
    expect(p.safe).toBe(true);
    expect(t.adapters.calls.some((c) => c.name === 'fw.apply')).toBe(false);
  });
  it('binds the maintenance window to the approval (scope-isolation remediation 2)', async () => {
    const t = fwSetup();
    const first = await t.svc.apply(SERVER, body(), OWNER);
    await approve(t, first.approval.id);
    const shifted = { windowStart: '2026-06-01T08:00:00.000Z', windowEnd: '2026-06-01T11:30:00.000Z' };
    await expect(t.svc.apply(SERVER, body({ ...shifted, approvalId: first.approval.id }), OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
  });
  it('needs approval; approved change applies; approval is single use and bound to the change set', async () => {
    const t = fwSetup();
    const first = await t.svc.apply(SERVER, body(), OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(first.approval.impactJson.riskTier).toBe('high');
    await approve(t, first.approval.id);
    await expect(t.svc.apply(SERVER, body({ changes: [{ ...allow80, port: 8080 }], approvalId: first.approval.id }), OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    const done = await t.svc.apply(SERVER, body({ approvalId: first.approval.id }), OWNER);
    expect(done.applied).toBe(true);
    await expect(t.svc.apply(SERVER, body({ approvalId: first.approval.id }), OWNER)).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });
  it('touching SSH is critical risk but still blocked if it would lock out', async () => {
    const t = fwSetup();
    await expect(t.svc.apply(SERVER, body({ changes: [{ op: 'delete', port: 22, proto: 'tcp', source: 'any' }] }), OWNER)).rejects.toMatchObject({ code: 'LOCKOUT_RISK' });
    const first = await t.svc.apply(SERVER, body({ changes: [{ op: 'allow', port: 22, proto: 'tcp', source: '203.0.113.7' }] }), OWNER);
    expect(first.approval.impactJson.riskTier).toBe('critical');
  });
  it('enforces the maintenance window', async () => {
    const t = fwSetup();
    await expect(t.svc.apply(SERVER, body({ windowStart: '2026-06-01T12:00:00.000Z', windowEnd: '2026-06-01T13:00:00.000Z' }), OWNER)).rejects.toMatchObject({ code: 'OUTSIDE_MAINTENANCE_WINDOW' });
    await expect(t.svc.apply(SERVER, body({ windowStart: '2026-06-01T00:00:00.000Z', windowEnd: '2026-06-01T11:00:00.000Z' }), OWNER)).rejects.toMatchObject({ code: 'WINDOW_INVALID' });
    expect(MAX_WINDOW_MS).toBe(14400000);
  });
  it('rolls back automatically when the server becomes unreachable (isolated lockout)', async () => {
    const t = fwSetup();
    const first = await t.svc.apply(SERVER, body(), OWNER);
    await approve(t, first.approval.id);
    t.adapters.fleet.probe = vi.fn(async () => ({ reachable: false }));
    await expect(t.svc.apply(SERVER, body({ approvalId: first.approval.id }), OWNER)).rejects.toMatchObject({ code: 'LOCKOUT_ROLLED_BACK' });
    expect(t.adapters.calls.some((c) => c.name === 'fw.rollback')).toBe(true);
  });
  it('denies unauthorized maintenance and wrong-server grants', async () => {
    const t = fwSetup([{ userId: DEV.id, permissionKey: 'server.firewall.update', resourceId: U(99), environmentId: null }]);
    await expect(t.svc.apply(SERVER, body(), DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.preview(SERVER, { changes: [allow80] }, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.apply(SERVER, body(), null)).rejects.toMatchObject({ status: 401 });
  });
  it('blocks self approval of a firewall change', async () => {
    const t = fwSetup();
    const first = await t.svc.apply(SERVER, body(), OWNER);
    await expect(t.platform.decide(first.approval.id, { decision: 'approve' }, OWNER)).rejects.toMatchObject({ code: 'SELF_APPROVAL_DENIED' });
    await expect(t.svc.apply(SERVER, body({ approvalId: first.approval.id }), OWNER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_APPROVED' });
    void APPROVER;
  });
});

describe('access reviews', () => {
  const AT = new Date('2026-06-01T00:00:00Z');
  const grant = (id, userId, over = {}) => ({ id, userId, permissionCode: 'domain.create', resourceType: 'project', resourceId: U(10), environmentId: U(12), grantedById: U(1), expiresAt: null, user: { id: userId, status: 'active', disabledAt: null }, ...over });
  function arSetup(grants) {
    const store = new Map();
    const prisma = {
      resourceGrant: { findMany: vi.fn(async () => grants) },
      accessReview: {
        create: vi.fn(async ({ data }) => { const r = { id: U(400), ...data }; store.set(r.id, r); return r; }),
        findUnique: vi.fn(async ({ where }) => store.get(where.id) ?? null),
        update: vi.fn(async ({ where, data }) => Object.assign(store.get(where.id), data)),
        findMany: vi.fn(async () => [...store.values()]),
      },
    };
    const rbacBase = makeRbac([{ userId: DEV.id, permissionKey: 'platform.access.review', resourceId: 'platform', environmentId: null }]);
    const rbac = { ...rbacBase, revoke: vi.fn(async () => ({})) };
    const auditService = { record: vi.fn() };
    return { prisma, rbac, auditService, store, svc: createAccessReviewsService({ prisma, rbac, auditService, now: () => AT }) };
  }
  const period = { periodStart: '2026-03-01T00:00:00.000Z', periodEnd: '2026-06-01T00:00:00.000Z' };

  it('classifies stale, disabled-user, high-risk-no-expiry and ownerless grants', () => {
    expect(classifyGrant(grant('g', 'u', { expiresAt: new Date('2026-01-01') }), { status: 'active' }, AT)).toContain('stale_expired_not_revoked');
    expect(classifyGrant(grant('g', 'u'), { status: 'disabled', disabledAt: AT }, AT)).toContain('disabled_user_active_grant');
    expect(classifyGrant(grant('g', 'u', { permissionCode: 'ssl.issue' }), { status: 'active' }, AT)).toContain('high_risk_no_expiry');
    expect(classifyGrant(grant('g', 'u', { grantedById: null }), { status: 'active' }, AT)).toContain('no_grantor_on_record');
    expect(classifyGrant(grant('g', 'u'), { status: 'active' }, AT)).toEqual([]);
  });
  it('snapshots grants, revokes on decision, and completes only when everything is decided', async () => {
    const g1 = grant(U(501), U(7), { expiresAt: new Date('2026-01-01') });
    const g2 = grant(U(502), U(8));
    const t = arSetup([g1, g2]);
    const review = await t.svc.start(period, DEV);
    expect(review.findingsJson.items).toHaveLength(2);
    await expect(t.svc.complete(review.id, DEV)).rejects.toMatchObject({ code: 'REVIEW_INCOMPLETE' });
    await t.svc.decide(review.id, { decisions: [{ grantId: g1.id, decision: 'revoke' }] }, DEV);
    expect(t.rbac.revoke).toHaveBeenCalledWith(g1.id, DEV);
    await expect(t.svc.complete(review.id, DEV)).rejects.toMatchObject({ code: 'REVIEW_INCOMPLETE' });
    await t.svc.decide(review.id, { decisions: [{ grantId: g2.id, decision: 'keep', note: 'still needed' }] }, DEV);
    expect((await t.svc.complete(review.id, DEV)).status).toBe('completed');
    await expect(t.svc.decide(review.id, { decisions: [{ grantId: g2.id, decision: 'keep' }] }, DEV)).rejects.toMatchObject({ code: 'REVIEW_NOT_OPEN' });
  });
  it('forbids self review and deciding on own grants', async () => {
    const mine = grant(U(503), DEV.id);
    const t = arSetup([mine]);
    await expect(t.svc.start({ ...period, subjectUserId: DEV.id }, DEV)).rejects.toMatchObject({ code: 'SELF_REVIEW_DENIED' });
    const review = await t.svc.start(period, DEV);
    await expect(t.svc.decide(review.id, { decisions: [{ grantId: mine.id, decision: 'keep' }] }, DEV)).rejects.toMatchObject({ code: 'SELF_REVIEW_DENIED' });
    expect((await t.svc.complete(review.id, DEV)).status).toBe('completed');
  });
  it('denies unauthorized users, foreign grants and a different reviewer', async () => {
    const t = arSetup([grant(U(504), U(7))]);
    await expect(t.svc.start(period, { id: U(9), isOwner: false })).rejects.toMatchObject({ status: 403 });
    const review = await t.svc.start(period, DEV);
    await expect(t.svc.decide(review.id, { decisions: [{ grantId: U(999), decision: 'keep' }] }, DEV)).rejects.toMatchObject({ code: 'GRANT_NOT_IN_REVIEW' });
    await expect(t.svc.decide(review.id, { decisions: [{ grantId: U(504), decision: 'keep' }] }, APPROVER)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.start({ periodStart: period.periodEnd, periodEnd: period.periodStart }, DEV)).rejects.toMatchObject({ code: 'PERIOD_INVALID' });
  });
});
