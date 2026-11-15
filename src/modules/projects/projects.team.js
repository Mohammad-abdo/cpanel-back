import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { notify } from '../notifications/notifications.service.js';

const schemaRequired = () => new AppError(501, 'SCHEMA_REQUIRED', 'ProjectTeam table is not available until the Prisma client is regenerated');

/** Project member and team-link management. Composed into the projects service. */
export function createProjectTeamOps({ prisma, now, auditService }) {
  const scope = createScope({ prisma, now });
  const rbac = createRbacService({ prisma, now });
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  /** Run a ProjectTeam operation; a stale client (missing delegate) degrades to 501. */
  async function links(fn) {
    if (!prisma.projectTeam) throw schemaRequired();
    try {
      return await fn(prisma.projectTeam);
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (/Unknown argument|projectTeam|ProjectTeam|doesn't exist|does not exist/i.test(String(e?.message))) throw schemaRequired();
      throw e;
    }
  }

  /** project.* permissions are environment-scoped: holding configure on any environment of the project counts. */
  async function holdsConfigure(actor, id) {
    const envs = (await prisma.projectEnvironment?.findMany?.({ where: { projectId: id } })) ?? [];
    for (const env of envs) {
      if (await rbac.can(actor, { permissionKey: 'project.configure', resourceType: 'project', resourceId: id, environmentId: env.id })) return true;
    }
    return false;
  }

  /** 404 for out-of-scope ids; returns { project, manager, lead }. */
  async function context(id, actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    await scope.requireProject(actor, id, 'PROJECT_NOT_FOUND', 'Project not found');
    const project = await prisma.project.findUnique({ where: { id } });
    if (!project) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
    const manager = Boolean(actor.isOwner) || (await holdsConfigure(actor, id));
    const mine = manager ? null : await prisma.projectMember.findFirst({ where: { projectId: id, userId: actor.id } });
    return { project, manager, lead: mine?.projectRole === 'lead' };
  }

  const deny = (msg) => new AppError(403, 'FORBIDDEN', msg);

  async function requireActiveUser(userId) {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new AppError(404, 'USER_NOT_FOUND', 'User not found');
    if (user.status !== 'active') throw new AppError(409, 'USER_NOT_ACTIVE', 'User is not active');
    return user;
  }

  async function record(actor, action, id, after) {
    await audit({ actorId: actor.id, action, resourceType: 'project', resourceId: id, result: 'success', after });
  }

  async function tell(userId, project, title, type = 'project.membership') {
    await notify({ userId, type, title, body: project.name, resourceType: 'project', resourceId: project.id }, { prisma });
  }

  /** Lead rules: developer/viewer only, never touching other leads. Managers may do anything. */
  function assertMayAssign(ctx, actor, role, target) {
    if (ctx.manager) return;
    if (!ctx.lead) throw deny('Only the Owner, a project manager or a project lead can manage members');
    if (target === actor.id) throw deny('You cannot change your own membership');
    if (role === 'lead') throw deny('Only the Owner or a project manager can assign the lead role');
  }

  return {
    /** Project teams with their members (role = team role). */
    async teams(id, actor) {
      const ctx = await context(id, actor);
      const rows = await links((m) => m.findMany({ where: { projectId: id } }));
      const out = [];
      for (const l of rows) {
        const team = await prisma.team.findUnique({ where: { id: l.teamId } });
        if (!team) continue;
        const tms = await prisma.teamMember.findMany({ where: { teamId: l.teamId } });
        const users = tms.length ? await prisma.user.findMany({ where: { id: { in: tms.map((m) => m.userId) } } }) : [];
        out.push({
          teamId: team.id,
          name: team.name,
          slug: team.slug,
          archived: Boolean(team.archivedAt),
          linkedAt: l.createdAt,
          members: tms.map((m) => {
            const u = users.find((x) => x.id === m.userId);
            return { userId: m.userId, teamRole: m.teamRole, displayName: u?.displayName ?? null, email: u?.email ?? null, status: u?.status ?? null };
          }),
        });
      }
      return { canManage: ctx.manager, canManageMembers: ctx.manager || ctx.lead, teams: out };
    },

    async linkTeam(id, { teamId }, actor) {
      const ctx = await context(id, actor);
      if (!ctx.manager) throw deny('Only the Owner or a project manager can link teams');
      const team = await prisma.team.findUnique({ where: { id: teamId } });
      if (!team || team.archivedAt) throw new AppError(404, 'TEAM_NOT_FOUND', 'Team not found');
      const row = await links(async (m) => {
        if (await m.findFirst({ where: { projectId: id, teamId } })) throw new AppError(409, 'ALREADY_LINKED', 'Team is already linked');
        return m.create({ data: { projectId: id, teamId, createdById: actor.id } });
      });
      await record(actor, 'project.team.link', id, { teamId });
      const tms = await prisma.teamMember.findMany({ where: { teamId } });
      for (const tm of tms) if (tm.userId !== actor.id) await tell(tm.userId, ctx.project, `Your team ${team.name} was linked to a project`);
      return { projectId: id, teamId, linkedAt: row.createdAt };
    },

    async unlinkTeam(id, teamId, actor) {
      const ctx = await context(id, actor);
      if (!ctx.manager) throw deny('Only the Owner or a project manager can unlink teams');
      const removed = await links((m) => m.deleteMany({ where: { projectId: id, teamId } }));
      if (!removed.count) throw new AppError(404, 'LINK_NOT_FOUND', 'Team is not linked');
      await record(actor, 'project.team.unlink', id, { teamId });
      return { projectId: id, teamId, removed: true };
    },

    async addMember(id, { userId, projectRole }, actor) {
      const ctx = await context(id, actor);
      assertMayAssign(ctx, actor, projectRole, userId);
      await requireActiveUser(userId);
      if (await prisma.projectMember.findFirst({ where: { projectId: id, userId } })) {
        throw new AppError(409, 'ALREADY_MEMBER', 'User is already a project member');
      }
      await prisma.projectMember.create({ data: { projectId: id, userId, projectRole } });
      await record(actor, 'project.member.add', id, { userId, projectRole });
      await tell(userId, ctx.project, `You were added to a project as ${projectRole}`);
      return { projectId: id, userId, projectRole };
    },

    async changeRole(id, userId, { projectRole }, actor) {
      const ctx = await context(id, actor);
      assertMayAssign(ctx, actor, projectRole, userId);
      const member = await prisma.projectMember.findFirst({ where: { projectId: id, userId } });
      if (!member) throw new AppError(404, 'MEMBER_NOT_FOUND', 'Not a project member');
      if (!ctx.manager && member.projectRole === 'lead') throw deny('Only the Owner or a project manager can change a lead');
      await prisma.projectMember.updateMany({ where: { projectId: id, userId }, data: { projectRole } });
      await record(actor, 'project.member.role', id, { userId, from: member.projectRole, to: projectRole });
      await tell(userId, ctx.project, `Your project role is now ${projectRole}`);
      return { projectId: id, userId, projectRole };
    },

    async removeMember(id, userId, actor) {
      const ctx = await context(id, actor);
      if (!ctx.manager && !ctx.lead) throw deny('Only the Owner, a project manager or a project lead can manage members');
      const member = await prisma.projectMember.findFirst({ where: { projectId: id, userId } });
      if (!member) throw new AppError(404, 'MEMBER_NOT_FOUND', 'Not a project member');
      if (!ctx.manager && member.projectRole === 'lead') throw deny('Only the Owner or a project manager can remove a lead');
      await prisma.projectMember.deleteMany({ where: { projectId: id, userId } });
      await record(actor, 'project.member.remove', id, { userId, projectRole: member.projectRole });
      await tell(userId, ctx.project, 'You were removed from a project');
      return { projectId: id, userId, removed: true };
    },
  };
}
