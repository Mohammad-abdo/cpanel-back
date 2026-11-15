import { describe, expect, it, vi } from 'vitest';
import { createAuthService } from '../src/modules/auth/auth.service.js';
import { changePasswordBodySchema, sessionIdParamsSchema } from '../src/modules/auth/auth.validator.js';
import { verifyPassword } from '../src/common/crypto/password.js';
import { createActivityService } from '../src/modules/activity/activity.service.js';
import { listAuditQuerySchema } from '../src/modules/audit/audit.validator.js';

const U1 = '11111111-1111-4111-8111-111111111111';
const S1 = '33333333-3333-4333-8333-333333333333';

function makePrisma(hash) {
  return {
    user: { findUnique: vi.fn().mockResolvedValue({ id: U1, passwordHash: hash }), update: vi.fn() },
    session: {
      updateMany: vi.fn().mockResolvedValue({ count: 2 }),
      findMany: vi.fn().mockResolvedValue([{ id: S1, createdAt: new Date(), expiresAt: new Date(), mfaSatisfied: true }]),
      findFirst: vi.fn(),
      update: vi.fn(),
    },
    mfaFactor: { count: vi.fn().mockResolvedValue(0) },
  };
}

describe('password change', () => {
  const OLD = 'correct horse battery';
  const hash = createAuthService({ prisma: makePrisma() }).hashPassword(OLD);

  it('validator enforces 12 character minimum and strictness', () => {
    expect(changePasswordBodySchema.safeParse({ currentPassword: 'a', newPassword: 'short-pass' }).success).toBe(false);
    expect(changePasswordBodySchema.safeParse({ currentPassword: 'a', newPassword: 'x'.repeat(12) }).success).toBe(true);
    expect(changePasswordBodySchema.safeParse({ currentPassword: 'a', newPassword: 'x'.repeat(12), id: 1 }).success).toBe(false);
  });

  it('rejects a wrong current password and audits the denial', async () => {
    const prisma = makePrisma(hash);
    const auditService = { record: vi.fn() };
    const auth = createAuthService({ prisma, auditService });
    await expect(
      auth.changePassword({ userId: U1, currentSessionId: S1, currentPassword: 'nope nope nope', newPassword: 'another long pass 1' }),
    ).rejects.toMatchObject({ status: 401 });
    expect(prisma.user.update).not.toHaveBeenCalled();
    expect(auditService.record.mock.calls[0][0]).toMatchObject({ action: 'auth.password.change', result: 'denied' });
  });

  it('enforces policy in the service even if the validator is bypassed', async () => {
    const auth = createAuthService({ prisma: makePrisma(hash) });
    await expect(
      auth.changePassword({ userId: U1, currentSessionId: S1, currentPassword: OLD, newPassword: 'short' }),
    ).rejects.toMatchObject({ code: 'PASSWORD_POLICY' });
    await expect(
      auth.changePassword({ userId: U1, currentSessionId: S1, currentPassword: OLD, newPassword: OLD }),
    ).rejects.toMatchObject({ code: 'PASSWORD_POLICY' });
  });

  it('stores a scrypt hash and revokes all other sessions', async () => {
    const prisma = makePrisma(hash);
    const auditService = { record: vi.fn() };
    const auth = createAuthService({ prisma, auditService });
    const res = await auth.changePassword({
      userId: U1, currentSessionId: S1, currentPassword: OLD, newPassword: 'a brand new passphrase',
    });
    expect(res.revokedSessions).toBe(2);
    const stored = prisma.user.update.mock.calls[0][0].data.passwordHash;
    expect(stored.startsWith('scrypt$')).toBe(true);
    expect(verifyPassword('a brand new passphrase', stored)).toBe(true);
    expect(prisma.session.updateMany.mock.calls[0][0].where).toMatchObject({ userId: U1, id: { not: S1 } });
    expect(JSON.stringify(auditService.record.mock.calls)).not.toContain('passphrase');
  });
});

describe('sessions', () => {
  it('lists own sessions without token hashes and flags the current one', async () => {
    const prisma = makePrisma('x');
    const auth = createAuthService({ prisma });
    const rows = await auth.listSessions({ userId: U1, currentSessionId: S1 });
    expect(prisma.session.findMany.mock.calls[0][0].where.userId).toBe(U1);
    expect(prisma.session.findMany.mock.calls[0][0].select.tokenHash).toBeUndefined();
    expect(rows[0].current).toBe(true);
    expect(rows[0]).not.toHaveProperty('tokenHash');
  });

  it('cannot revoke a session owned by someone else', async () => {
    const prisma = makePrisma('x');
    prisma.session.findFirst.mockResolvedValue(null);
    const auth = createAuthService({ prisma });
    await expect(auth.revokeSession({ userId: U1, sessionId: S1 })).rejects.toMatchObject({ status: 404 });
    expect(prisma.session.findFirst.mock.calls[0][0].where).toEqual({ id: S1, userId: U1 });
    expect(prisma.session.update).not.toHaveBeenCalled();
  });

  it('revokes an owned session and validates the id', async () => {
    const prisma = makePrisma('x');
    prisma.session.findFirst.mockResolvedValue({ id: S1, userId: U1, revokedAt: null });
    const auditService = { record: vi.fn() };
    const auth = createAuthService({ prisma, auditService });
    await auth.revokeSession({ userId: U1, sessionId: S1 });
    expect(prisma.session.update).toHaveBeenCalled();
    expect(auditService.record.mock.calls[0][0].action).toBe('auth.session.revoke');
    expect(sessionIdParamsSchema.safeParse({ id: 'not-a-uuid' }).success).toBe(false);
  });
});

describe('my activity and audit filters', () => {
  it('my timeline always scopes to the session user', async () => {
    const model = () => ({ findMany: vi.fn().mockResolvedValue([]), findUnique: vi.fn().mockResolvedValue(null) });
    const prisma = Object.fromEntries(
      ['operationJob', 'deployment', 'approvalRequest', 'auditEvent', 'activityEvent', 'resourceGrant', 'incidentAssignment', 'securityEvent', 'project'].map((m) => [m, model()]),
    );
    const svc = createActivityService({ prisma });
    await svc.myTimeline({ limit: 10 }, { id: U1 });
    expect(prisma.activityEvent.findMany.mock.calls[0][0].where.actorId).toBe(U1);
    expect(prisma.deployment.findMany.mock.calls[0][0].where.initiatedById).toBe(U1);
    await expect(svc.myTimeline({ limit: 10 }, null)).rejects.toMatchObject({ status: 401 });
  });

  it('audit query accepts result and date filters but stays strict', () => {
    expect(listAuditQuerySchema.safeParse({ result: 'denied', from: '2026-11-01T00:00:00.000Z' }).success).toBe(true);
    expect(listAuditQuerySchema.safeParse({ result: 'weird' }).success).toBe(false);
    expect(listAuditQuerySchema.safeParse({ foo: 1 }).success).toBe(false);
  });
});
