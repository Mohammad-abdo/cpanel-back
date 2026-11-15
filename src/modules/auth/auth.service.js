import { createHash, randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { generateTotpSecret, verifyTotp } from '../../common/crypto/totp.js';
import { hashPassword, verifyPassword, isLegacyPasswordHash } from '../../common/crypto/password.js';

function hashToken(value) {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Auth service — sessions + TOTP MFA against Laragon/Prisma schema field names.
 */
export function createAuthService({ prisma, now = () => new Date(), auditService = null }) {
  if (!prisma) {
    throw new Error('auth.service requires prisma');
  }

  // A pending-MFA session must not add its own factor: that would defeat MFA with a stolen password.
  async function requireMfaIfEnrolled(userId, mfaSatisfied) {
    const verified = await prisma.mfaFactor.count({ where: { userId, verifiedAt: { not: null } } });
    if (verified > 0 && !mfaSatisfied) {
      throw new AppError(401, 'MFA_REQUIRED', 'MFA verification required');
    }
  }

  async function writeAudit(event) {
    if (!auditService?.record) return;
    await auditService.record(event);
  }

  return {
    hashPassword,

    async login({ email, password }) {
      const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
      if (!user || !user.passwordHash || user.status !== 'active' || user.disabledAt) {
        throw new AppError(401, 'AUTH_INVALID', 'Invalid credentials');
      }

      if (!verifyPassword(password, user.passwordHash)) {
        throw new AppError(401, 'AUTH_INVALID', 'Invalid credentials');
      }
      if (isLegacyPasswordHash(user.passwordHash)) {
        // Transparent upgrade from legacy SHA-256 to salted scrypt.
        await prisma.user.update({ where: { id: user.id }, data: { passwordHash: hashPassword(password) } });
      }

      const mfaCount = await prisma.mfaFactor.count({
        where: { userId: user.id, verifiedAt: { not: null } },
      });
      const mfaRequired = mfaCount > 0;

      const rawToken = randomBytes(32).toString('base64url');
      const expiresAt = new Date(now().getTime() + 12 * 60 * 60 * 1000);
      const session = await prisma.session.create({
        data: {
          userId: user.id,
          tokenHash: hashToken(rawToken),
          expiresAt,
          mfaSatisfied: !mfaRequired,
        },
      });

      await writeAudit({
        actorId: user.id,
        action: 'auth.login',
        resourceType: 'session',
        resourceId: session.id,
        result: 'success',
        occurredAt: now().toISOString(),
        metadata: { mfaRequired },
      });

      return {
        sessionId: session.id,
        token: rawToken,
        expiresAt: expiresAt.toISOString(),
        mfaRequired,
        authorized: !mfaRequired,
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          isOwner: user.ownerFlag,
        },
      };
    },

    async verifyMfa({ sessionId, code }) {
      const session = await prisma.session.findUnique({
        where: { id: sessionId },
        include: { user: true },
      });
      if (!session || session.revokedAt || session.expiresAt <= now()) {
        throw new AppError(401, 'SESSION_INVALID', 'Session invalid');
      }
      if (!code) {
        throw new AppError(400, 'MFA_CODE_REQUIRED', 'MFA code required');
      }

      const factors = await prisma.mfaFactor.findMany({
        where: {
          userId: session.userId,
          type: 'totp',
          verifiedAt: { not: null },
        },
      });
      if (factors.length === 0) {
        throw new AppError(400, 'MFA_NOT_ENROLLED', 'No MFA factors enrolled');
      }

      const matched = factors.some(
        (factor) => factor.secretRef && verifyTotp(factor.secretRef, code, { now: now().getTime() }),
      );
      if (!matched) {
        await writeAudit({
          actorId: session.userId,
          action: 'auth.mfa.verify',
          resourceType: 'session',
          resourceId: session.id,
          result: 'denied',
          occurredAt: now().toISOString(),
        });
        throw new AppError(401, 'MFA_INVALID', 'Invalid MFA code');
      }

      const updated = await prisma.session.update({
        where: { id: session.id },
        data: { mfaSatisfied: true },
      });

      await writeAudit({
        actorId: session.userId,
        action: 'auth.mfa.verify',
        resourceType: 'session',
        resourceId: session.id,
        result: 'success',
        occurredAt: now().toISOString(),
      });

      return {
        sessionId: updated.id,
        authorized: true,
        mfaVerifiedAt: now().toISOString(),
      };
    },

    async enrollTotp({ userId, actor, mfaSatisfied = false }) {
      if (!actor || (actor.id !== userId && !actor.isOwner)) {
        throw new AppError(403, 'FORBIDDEN', 'Cannot enroll MFA for another user');
      }
      await requireMfaIfEnrolled(userId, mfaSatisfied);
      const secret = generateTotpSecret();
      const factor = await prisma.mfaFactor.create({
        data: {
          userId,
          type: 'totp',
          secretRef: secret,
          verifiedAt: null,
        },
      });
      return {
        factorId: factor.id,
        secret,
        otpauthUrl: `otpauth://totp/NodeTeam:${encodeURIComponent(userId)}?secret=${secret}&issuer=NodeTeam`,
      };
    },

    async confirmTotpEnrollment({ userId, factorId, code, actor, mfaSatisfied = false }) {
      if (!actor || (actor.id !== userId && !actor.isOwner)) {
        throw new AppError(403, 'FORBIDDEN', 'Cannot confirm MFA for another user');
      }
      await requireMfaIfEnrolled(userId, mfaSatisfied);
      const factor = await prisma.mfaFactor.findFirst({
        where: { id: factorId, userId, type: 'totp' },
      });
      if (!factor?.secretRef) {
        throw new AppError(404, 'MFA_FACTOR_NOT_FOUND', 'MFA factor not found');
      }
      if (!verifyTotp(factor.secretRef, code, { now: now().getTime() })) {
        throw new AppError(401, 'MFA_INVALID', 'Invalid MFA code');
      }
      await prisma.mfaFactor.update({
        where: { id: factor.id },
        data: { verifiedAt: now() },
      });
      return { ok: true, factorId: factor.id };
    },

    /** Verifies the current password, stores a new scrypt hash and revokes every other session. */
    async changePassword({ userId, currentSessionId, currentPassword, newPassword }) {
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user?.passwordHash || !verifyPassword(currentPassword, user.passwordHash)) {
        await writeAudit({
          actorId: userId, action: 'auth.password.change', resourceType: 'user', resourceId: userId,
          result: 'denied', occurredAt: now().toISOString(),
        });
        throw new AppError(401, 'AUTH_INVALID', 'Current password is incorrect');
      }
      if (newPassword.length < 12) {
        throw new AppError(400, 'PASSWORD_POLICY', 'New password must be at least 12 characters');
      }
      if (newPassword === currentPassword) {
        throw new AppError(400, 'PASSWORD_POLICY', 'New password must differ from the current password');
      }
      await prisma.user.update({ where: { id: userId }, data: { passwordHash: hashPassword(newPassword) } });
      const revoked = await prisma.session.updateMany({
        where: { userId, revokedAt: null, id: { not: currentSessionId } },
        data: { revokedAt: now() },
      });
      await writeAudit({
        actorId: userId, action: 'auth.password.change', resourceType: 'user', resourceId: userId,
        result: 'success', occurredAt: now().toISOString(), metadata: { revokedSessions: revoked.count },
      });
      return { ok: true, revokedSessions: revoked.count };
    },

    async me({ user }) {
      const mfaFactors = await prisma.mfaFactor.count({ where: { userId: user.id, verifiedAt: { not: null } } });
      return { id: user.id, email: user.email, displayName: user.displayName, isOwner: user.isOwner, mfaEnabled: mfaFactors > 0 };
    },

    /** Own active sessions only. Token hashes and ip/user-agent hashes are never returned. */
    async listSessions({ userId, currentSessionId }) {
      const rows = await prisma.session.findMany({
        where: { userId, revokedAt: null, expiresAt: { gt: now() } },
        orderBy: { createdAt: 'desc' },
        select: { id: true, createdAt: true, expiresAt: true, mfaSatisfied: true },
      });
      return rows.map((s) => ({ ...s, current: s.id === currentSessionId }));
    },

    async revokeSession({ userId, sessionId }) {
      const session = await prisma.session.findFirst({ where: { id: sessionId, userId } });
      if (!session) throw new AppError(404, 'SESSION_NOT_FOUND', 'Session not found');
      if (!session.revokedAt) {
        await prisma.session.update({ where: { id: session.id }, data: { revokedAt: now() } });
        await writeAudit({
          actorId: userId, action: 'auth.session.revoke', resourceType: 'session', resourceId: session.id,
          result: 'success', occurredAt: now().toISOString(),
        });
      }
      return { ok: true };
    },

    async logout({ tokenHash, actorId = null }) {
      if (!tokenHash) return { ok: true };
      await prisma.session.updateMany({
        where: { tokenHash, revokedAt: null },
        data: { revokedAt: now() },
      });
      await writeAudit({
        actorId,
        action: 'auth.logout',
        resourceType: 'session',
        resourceId: null,
        result: 'success',
        occurredAt: now().toISOString(),
      });
      return { ok: true };
    },
  };
}
