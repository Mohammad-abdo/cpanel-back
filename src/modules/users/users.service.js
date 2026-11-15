import { AppError } from '../../common/errors/app-error.js';
import { hashPassword } from '../../common/crypto/password.js';

/**
 * Owner protection: only an existing Owner may create/promote Owners.
 */
export function createUsersService({ prisma }) {
  return {
    async create(input, actor) {
      if (!actor) {
        throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      }
      if (input.isOwner && !actor.isOwner) {
        throw new AppError(403, 'OWNER_ESCALATION_DENIED', 'Only Owner can create Owner accounts');
      }
      if (!actor.isOwner) {
        throw new AppError(403, 'FORBIDDEN', 'Only Owner can create users in this slice');
      }

      const email = input.email.toLowerCase();
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing) {
        throw new AppError(409, 'USER_EXISTS', 'User already exists');
      }

      return prisma.user.create({
        data: {
          email,
          displayName: input.displayName,
          passwordHash: hashPassword(input.password),
          ownerFlag: Boolean(input.isOwner),
          status: 'active',
        },
        select: {
          id: true,
          email: true,
          displayName: true,
          ownerFlag: true,
          status: true,
          createdAt: true,
        },
      }).then((row) => ({
        ...row,
        isOwner: row.ownerFlag,
      }));
    },

    async list(actor, { limit = 100 } = {}) {
      if (!actor) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const select = {
        id: true,
        email: true,
        displayName: true,
        ownerFlag: true,
        status: true,
        createdAt: true,
        updatedAt: true,
      };
      // Non-owners only see themselves; directory visibility stays Owner-gated.
      const rows = actor.isOwner
        ? await prisma.user.findMany({ select, orderBy: { displayName: 'asc' }, take: limit })
        : await prisma.user.findMany({ where: { id: actor.id }, select, take: 1 });
      return rows.map((u) => ({ ...u, isOwner: u.ownerFlag }));
    },

    async getById(id, actor) {
      if (!actor) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      if (!actor.isOwner && actor.id !== id) {
        throw new AppError(403, 'FORBIDDEN', 'Cannot view other users');
      }
      const user = await prisma.user.findUnique({
        where: { id },
        select: {
          id: true,
          email: true,
          displayName: true,
          ownerFlag: true,
          status: true,
          createdAt: true,
          updatedAt: true,
        },
      });
      if (!user) throw new AppError(404, 'USER_NOT_FOUND', 'User not found');
      return { ...user, isOwner: user.ownerFlag };
    },

    async patch(id, input, actor) {
      if (!actor) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      if (!actor.isOwner) {
        throw new AppError(403, 'FORBIDDEN', 'Only Owner can patch users');
      }
      if (input.isOwner === false) {
        const target = await prisma.user.findUnique({ where: { id } });
        if (target?.ownerFlag && target.id === actor.id) {
          throw new AppError(403, 'OWNER_LOCK', 'Owner cannot demote self');
        }
      }

      const row = await prisma.user.update({
        where: { id },
        data: {
          ...(input.displayName !== undefined ? { displayName: input.displayName } : {}),
          ...(input.status !== undefined
            ? {
                status: input.status,
                disabledAt: input.status === 'disabled' ? new Date() : null,
              }
            : {}),
          ...(input.isOwner !== undefined ? { ownerFlag: input.isOwner } : {}),
        },
        select: {
          id: true,
          email: true,
          displayName: true,
          ownerFlag: true,
          status: true,
          updatedAt: true,
        },
      });
      return { ...row, isOwner: row.ownerFlag };
    },
  };
}
