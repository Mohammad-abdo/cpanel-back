import { createHash } from 'node:crypto';
import { AppError } from '../errors/app-error.js';
import { prisma } from '../../config/prisma.js';

function hashToken(value) {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Session gate. When the user has verified MFA factors, mfaSatisfied is required
 * unless allowPendingMfa is set.
 */
export function requireSession(options = {}) {
  const { requireMfa = 'auto', allowPendingMfa = false } = options;

  return async (req, _res, next) => {
    try {
      const header = req.get('authorization') || '';
      const raw = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
      if (!raw) {
        return next(new AppError(401, 'AUTH_REQUIRED', 'Authentication required'));
      }

      const session = await prisma.session.findUnique({
        where: { tokenHash: hashToken(raw) },
        include: {
          user: {
            include: {
              mfaFactors: {
                where: { verifiedAt: { not: null } },
                select: { id: true },
              },
            },
          },
        },
      });

      if (!session || session.revokedAt || session.expiresAt <= new Date()) {
        return next(new AppError(401, 'SESSION_INVALID', 'Session invalid'));
      }

      if (session.user.status !== 'active' || session.user.disabledAt) {
        return next(new AppError(403, 'USER_DISABLED', 'User disabled'));
      }

      const hasMfa = session.user.mfaFactors.length > 0;
      const mustVerify =
        requireMfa === true || (requireMfa === 'auto' && hasMfa && !allowPendingMfa);

      if (mustVerify && !session.mfaSatisfied) {
        return next(new AppError(401, 'MFA_REQUIRED', 'MFA verification required'));
      }

      req.session = session;
      req.user = {
        id: session.user.id,
        email: session.user.email,
        displayName: session.user.displayName,
        isOwner: session.user.ownerFlag,
      };
      return next();
    } catch (error) {
      return next(error);
    }
  };
}
