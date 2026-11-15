import { AppError } from '../../common/errors/app-error.js';

/**
 * Team management. Owner manages everything; a team lead manages only their own team
 * and cannot create leads (no self-escalation or scope widening).
 */
export function createTeamsService({ prisma, auditService = null }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'team', result: 'success', ...event }) : null);

  async function requireManager(teamId, actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (actor.isOwner) return;
    const membership = await prisma.teamMember.findUnique({
      where: { teamId_userId: { teamId, userId: actor.id } },
    });
    if (membership?.teamRole !== 'lead') {
      throw new AppError(403, 'FORBIDDEN', 'Team lead or Owner required');
    }
  }

  return {
    async create(input, actor) {
      if (!actor?.isOwner) throw new AppError(403, 'FORBIDDEN', 'Only Owner can create teams');
      const existing = await prisma.team.findUnique({ where: { slug: input.slug } });
      if (existing) throw new AppError(409, 'TEAM_EXISTS', 'Team slug already exists');
      const team = await prisma.team.create({ data: { name: input.name, slug: input.slug } });
      await audit({ actorId: actor.id, action: 'team.create', resourceId: team.id, after: { slug: input.slug } });
      return team;
    },

    async list(actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const where = actor.isOwner
        ? { archivedAt: null }
        : { archivedAt: null, members: { some: { userId: actor.id } } };
      return prisma.team.findMany({ where, orderBy: { name: 'asc' }, take: 100 });
    },

    async addMember(teamId, input, actor) {
      await requireManager(teamId, actor);
      if (input.teamRole === 'lead' && !actor.isOwner) {
        throw new AppError(403, 'SCOPE_EXPANSION_DENIED', 'Only Owner can appoint team leads');
      }
      const team = await prisma.team.findUnique({ where: { id: teamId } });
      if (!team || team.archivedAt) throw new AppError(404, 'TEAM_NOT_FOUND', 'Team not found');
      const user = await prisma.user.findUnique({ where: { id: input.userId } });
      if (!user || user.status !== 'active' || user.disabledAt) {
        throw new AppError(404, 'USER_NOT_FOUND', 'User not found');
      }
      const member = await prisma.teamMember.upsert({
        where: { teamId_userId: { teamId, userId: input.userId } },
        update: {},
        create: { teamId, userId: input.userId, teamRole: input.teamRole },
      });
      await audit({
        actorId: actor.id,
        action: 'team.member.add',
        resourceId: teamId,
        after: { userId: input.userId, teamRole: input.teamRole },
      });
      return member;
    },

    async removeMember(teamId, userId, actor) {
      await requireManager(teamId, actor);
      const target = await prisma.teamMember.findUnique({
        where: { teamId_userId: { teamId, userId } },
      });
      if (!target) throw new AppError(404, 'MEMBER_NOT_FOUND', 'Member not found');
      if (target.teamRole === 'lead' && !actor.isOwner) {
        throw new AppError(403, 'SCOPE_EXPANSION_DENIED', 'Only Owner can remove team leads');
      }
      await prisma.teamMember.delete({ where: { teamId_userId: { teamId, userId } } });
      await audit({ actorId: actor.id, action: 'team.member.remove', resourceId: teamId, before: { userId } });
      return { removed: true };
    },
  };
}
