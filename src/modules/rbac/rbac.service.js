import { permissionRequiresEnvironment } from '@nodeteam/permission-catalog';
import { TEAM_SCOPED_ONLY } from './rbac.roles.js';
import { AppError } from '../../common/errors/app-error.js';

const ASSIGN = 'team.permission.assign';

export function createRbacService({ prisma, now = () => new Date(), auditService = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  /**
   * Exact-scope check. Environment-scoped permissions never match without an environment,
   * and a grant for one environment never satisfies another (staging != production).
   */
  async function hasGrant({ userId, permissionKey, resourceType, resourceId, environmentId }) {
    if (permissionRequiresEnvironment(permissionKey) && !environmentId) return false;
    const grant = await prisma.resourceGrant.findFirst({
      where: {
        userId,
        permissionCode: permissionKey,
        resourceType,
        resourceId,
        revokedAt: null,
        AND: [
          { OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] },
          { OR: environmentId ? [{ environmentId }] : [{ environmentId: null }] },
        ],
      },
    });
    return Boolean(grant);
  }

  /**
   * Role-based match. Environment-requiring permissions need a role scoped to that exact
   * environment (so a staging role never implies production); team.permission.assign only
   * matches on a role scoped to the same team.
   */
  async function hasRole({ userId, permissionKey, resourceType, resourceId, environmentId }) {
    if (!prisma.userRole?.findMany) return false;
    const needsEnv = permissionRequiresEnvironment(permissionKey);
    if (needsEnv && !environmentId) return false;
    const rows = await prisma.userRole.findMany({
      where: { userId },
      include: { role: { include: { rolePermissions: { include: { permission: true } } } } },
    });
    return rows.some((ur) => {
      if (!ur.role || ur.role.code === 'owner') return false;
      if (!ur.role.rolePermissions?.some((rp) => rp.permission?.code === permissionKey)) return false;
      const { scopeType, scopeId } = ur;
      if (needsEnv) return scopeType === 'environment' && scopeId === environmentId;
      if (TEAM_SCOPED_ONLY.has(permissionKey)) return scopeType === 'team' && resourceType === 'team' && scopeId === resourceId;
      if (!scopeType) return !environmentId;
      if (scopeType === 'environment') return Boolean(environmentId) && scopeId === environmentId;
      return scopeType === resourceType && scopeId === resourceId && !environmentId;
    });
  }

  return {
    hasGrant,
    hasRole,

    /** Owner always passes; everyone else needs an exact-scope grant. */
    async can(actor, check) {
      if (actor?.isOwner) return true;
      if (!actor?.id) return false;
      if (await hasGrant({ userId: actor.id, ...check })) return true;
      return hasRole({ userId: actor.id, ...check });
    },

    async grant(input, actor) {
      if (!actor?.id) {
        throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      }
      if (permissionRequiresEnvironment(input.permissionKey) && !input.environmentId) {
        throw new AppError(400, 'ENVIRONMENT_REQUIRED', 'Environment scope required for this permission');
      }
      if (!actor.isOwner) {
        if (input.userId === actor.id) {
          throw new AppError(403, 'SELF_GRANT_DENIED', 'Cannot grant permissions to yourself');
        }
        const scope = {
          resourceType: input.resourceType,
          resourceId: input.resourceId,
          environmentId: input.environmentId ?? null,
        };
        // Delegation: the actor needs assign rights AND must already hold what they hand out.
        const mayAssign = await hasGrant({ userId: actor.id, permissionKey: ASSIGN, ...scope });
        const holdsPermission = await hasGrant({ userId: actor.id, permissionKey: input.permissionKey, ...scope });
        if (!mayAssign || !holdsPermission) {
          await audit({
            actorId: actor.id,
            action: 'rbac.grant',
            resourceType: input.resourceType,
            resourceId: input.resourceId,
            environmentId: input.environmentId ?? null,
            result: 'denied',
            after: { permissionKey: input.permissionKey, subject: input.userId },
          });
          throw new AppError(403, 'SCOPE_EXPANSION_DENIED', 'Grant exceeds your own scope');
        }
      }
      const created = await prisma.resourceGrant.create({
        data: {
          userId: input.userId,
          permissionCode: input.permissionKey,
          resourceType: input.resourceType,
          resourceId: input.resourceId,
          environmentId: input.environmentId ?? null,
          conditionsJson: input.conditionsJson ?? undefined,
          grantedById: actor.id,
        },
      });
      await audit({
        actorId: actor.id,
        action: 'rbac.grant',
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        environmentId: input.environmentId ?? null,
        result: 'success',
        after: { permissionKey: input.permissionKey, subject: input.userId, grantId: created.id },
      });
      return created;
    },

    async revoke(grantId, actor) {
      const grant = await prisma.resourceGrant.findUnique({ where: { id: grantId } });
      if (!grant || grant.revokedAt) {
        throw new AppError(404, 'GRANT_NOT_FOUND', 'Grant not found');
      }
      if (!actor?.isOwner && grant.grantedById !== actor?.id) {
        throw new AppError(403, 'FORBIDDEN', 'Only the Owner or the original grantor can revoke');
      }
      const updated = await prisma.resourceGrant.update({ where: { id: grantId }, data: { revokedAt: now() } });
      await audit({
        actorId: actor.id,
        action: 'rbac.revoke',
        resourceType: grant.resourceType,
        resourceId: grant.resourceId,
        environmentId: grant.environmentId,
        result: 'success',
        before: { permissionKey: grant.permissionCode, subject: grant.userId, grantId },
      });
      return updated;
    },

    async list(query, actor) {
      const where = {
        revokedAt: null,
        ...(query.resourceType ? { resourceType: query.resourceType } : {}),
        ...(query.resourceId ? { resourceId: query.resourceId } : {}),
        // Non-owners only see their own grants.
        ...(actor?.isOwner ? (query.userId ? { userId: query.userId } : {}) : { userId: actor?.id }),
      };
      return prisma.resourceGrant.findMany({ where, take: query.limit, orderBy: { createdAt: 'desc' } });
    },
  };
}
