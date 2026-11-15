import { describe, expect, it, vi } from 'vitest';
import { rateLimit } from '../src/common/middleware/rate-limit.js';
import { createAuthService } from '../src/modules/auth/auth.service.js';
import { createAuditService } from '../src/modules/audit/audit.service.js';
import { createPlatformService } from '../src/modules/platform/platform.service.js';

function run(mw, req) {
  const next = vi.fn();
  const res = { set: vi.fn() };
  mw(req, res, next);
  return { next, res };
}

describe('rate limiter', () => {
  it('blocks after max hits in the window and recovers after it', () => {
    let t = 0;
    const mw = rateLimit({ windowMs: 1000, max: 2, keyFn: () => 'k', now: () => t });
    expect(run(mw, {}).next.mock.calls[0]).toEqual([]);
    expect(run(mw, {}).next.mock.calls[0]).toEqual([]);
    const blocked = run(mw, {});
    expect(blocked.next.mock.calls[0][0]).toMatchObject({ status: 429, code: 'RATE_LIMITED' });
    expect(blocked.res.set).toHaveBeenCalledWith('Retry-After', '1');
    t = 1001;
    expect(run(mw, {}).next.mock.calls[0]).toEqual([]);
  });

  it('keeps separate buckets per key', () => {
    const mw = rateLimit({ windowMs: 1000, max: 1, keyFn: (r) => r.k });
    run(mw, { k: 'a' });
    expect(run(mw, { k: 'b' }).next.mock.calls[0]).toEqual([]);
  });
});

describe('MFA bypass fix', () => {
  const svc = (verified) =>
    createAuthService({
      prisma: { mfaFactor: { count: vi.fn().mockResolvedValue(verified), create: vi.fn().mockResolvedValue({ id: 'f' }) } },
    });
  const actor = { id: 'u1', isOwner: false };

  it('pending-MFA session cannot enroll a new factor when one is already verified', async () => {
    await expect(svc(1).enrollTotp({ userId: 'u1', actor, mfaSatisfied: false })).rejects.toMatchObject({ code: 'MFA_REQUIRED' });
    await expect(svc(1).confirmTotpEnrollment({ userId: 'u1', factorId: 'f', code: '123456', actor, mfaSatisfied: false })).rejects.toMatchObject({ code: 'MFA_REQUIRED' });
  });

  it('allows first-time enrollment and enrollment from a fully verified session', async () => {
    await expect(svc(0).enrollTotp({ userId: 'u1', actor, mfaSatisfied: false })).resolves.toHaveProperty('factorId');
    await expect(svc(1).enrollTotp({ userId: 'u1', actor, mfaSatisfied: true })).resolves.toHaveProperty('factorId');
  });
});

describe('audit read permission', () => {
  it('denies non-owner without a grant, allows owner and granted users', async () => {
    const deny = createAuditService({ prisma: {}, rbac: { can: vi.fn().mockResolvedValue(false) } });
    await expect(deny.requirePermission({ id: 'u', isOwner: false }, 'audit.logs.read')).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(createAuditService({ prisma: {} }).requirePermission({ id: 'u', isOwner: false }, 'audit.logs.read')).rejects.toMatchObject({ code: 'FORBIDDEN' });
    const allow = createAuditService({ prisma: {}, rbac: { can: vi.fn().mockResolvedValue(true) } });
    await expect(allow.requirePermission({ id: 'u', isOwner: false }, 'audit.logs.read')).resolves.toBe(true);
    await expect(deny.requirePermission({ id: 'o', isOwner: true }, 'audit.logs.read')).resolves.toBe(true);
  });
});

describe('approval single use', () => {
  it('rejects a second consumer when the atomic claim fails', async () => {
    const row = {
      id: 'a1',
      resourceType: 'domain',
      resourceId: 'd1',
      status: 'approved',
      requesterId: 'u1',
      decidedAt: new Date(),
      createdAt: new Date(),
      impactJson: { action: 'dns.change', context: { binding: null } },
    };
    const prisma = {
      approvalRequest: {
        findUnique: vi.fn().mockResolvedValue(row),
        updateMany: vi.fn().mockResolvedValue({ count: 0 }),
      },
    };
    const platform = createPlatformService({ prisma });
    await expect(
      platform.gate({ action: 'dns.change', resourceType: 'domain', resourceId: 'd1', approvalId: 'a1', binding: null }, { id: 'u1' }),
    ).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });
});
