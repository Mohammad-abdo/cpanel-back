import { describe, expect, it, vi } from 'vitest';
import { createAuthService } from '../src/modules/auth/auth.service.js';
import { generateTotp } from '../src/common/crypto/totp.js';

function makePrisma() {
  return {
    user: { findUnique: vi.fn() },
    session: {
      create: vi.fn(),
      findUnique: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(),
    },
    mfaFactor: {
      count: vi.fn(),
      findMany: vi.fn(),
      create: vi.fn(),
      findFirst: vi.fn(),
      update: vi.fn(),
    },
  };
}

describe('auth.service', () => {
  const fixedNow = new Date('2026-11-15T12:00:00.000Z');

  it('rejects invalid credentials', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue(null);
    const auth = createAuthService({ prisma, now: () => fixedNow });
    await expect(auth.login({ email: 'a@b.com', password: 'password1' })).rejects.toMatchObject({
      code: 'AUTH_INVALID',
    });
  });

  it('creates pending MFA session when factors exist', async () => {
    const prisma = makePrisma();
    prisma.user.findUnique.mockResolvedValue({
      id: 'u1',
      email: 'owner@example.com',
      displayName: 'Owner',
      passwordHash: createAuthService({ prisma: makePrisma() }).hashPassword('password1'),
      status: 'active',
      disabledAt: null,
      ownerFlag: true,
    });
    prisma.mfaFactor.count.mockResolvedValue(1);
    prisma.session.create.mockResolvedValue({ id: 's1', mfaSatisfied: false });
    const auth = createAuthService({ prisma, now: () => fixedNow });
    const result = await auth.login({ email: 'owner@example.com', password: 'password1' });
    expect(result.mfaRequired).toBe(true);
    expect(result.authorized).toBe(false);
    expect(prisma.session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ mfaSatisfied: false }),
      }),
    );
  });

  it('verifies valid TOTP and authorizes session', async () => {
    const secret = 'JBSWY3DPEHPK3PXP';
    const prisma = makePrisma();
    prisma.session.findUnique.mockResolvedValue({
      id: 's1',
      userId: 'u1',
      revokedAt: null,
      expiresAt: new Date('2026-11-16T12:00:00.000Z'),
      user: { id: 'u1' },
    });
    prisma.mfaFactor.findMany.mockResolvedValue([{ id: 'f1', secretRef: secret }]);
    prisma.session.update.mockResolvedValue({ id: 's1', mfaSatisfied: true });
    const auth = createAuthService({ prisma, now: () => fixedNow });
    const code = generateTotp(secret, { now: fixedNow.getTime() });
    const result = await auth.verifyMfa({ sessionId: 's1', code });
    expect(result.authorized).toBe(true);
  });

  it('rejects invalid TOTP', async () => {
    const prisma = makePrisma();
    prisma.session.findUnique.mockResolvedValue({
      id: 's1',
      userId: 'u1',
      revokedAt: null,
      expiresAt: new Date('2026-11-16T12:00:00.000Z'),
      user: { id: 'u1' },
    });
    prisma.mfaFactor.findMany.mockResolvedValue([{ id: 'f1', secretRef: 'JBSWY3DPEHPK3PXP' }]);
    const auth = createAuthService({ prisma, now: () => fixedNow });
    await expect(auth.verifyMfa({ sessionId: 's1', code: '000000' })).rejects.toMatchObject({
      code: 'MFA_INVALID',
    });
  });
});
