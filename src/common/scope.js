import { AppError } from './errors/app-error.js';

/**
 * Read-scope helper (project isolation). Owner sees everything (null = unrestricted).
 * Everyone else sees projects they are a ProjectMember of or hold an active project grant/role for,
 * the servers hosting those projects, and servers with an explicit server grant/role.
 * Fail-closed: a missing actor sees nothing. Callers answer 404 for out-of-scope ids.
 */
export function createScope({ prisma, now = () => new Date() }) {
  const live = () => [{ expiresAt: null }, { expiresAt: { gt: now() } }];

  async function grantIds(actor, resourceType) {
    const rows = (await prisma.resourceGrant?.findMany?.({ where: { userId: actor.id, resourceType, revokedAt: null, OR: live() } })) ?? [];
    return rows.map((g) => g.resourceId);
  }
  async function roleIds(actor, scopeType) {
    if (!prisma.userRole?.findMany) return [];
    const rows = await prisma.userRole.findMany({ where: { userId: actor.id, scopeType }, include: { role: true } });
    return rows.filter((r) => r.role?.code !== 'owner' && r.scopeId).map((r) => r.scopeId);
  }

  /** null = all (Owner); otherwise the visible project ids. */
  async function projectIds(actor) {
    if (actor?.isOwner) return null;
    if (!actor?.id) return [];
    const members = (await prisma.projectMember?.findMany?.({ where: { userId: actor.id } })) ?? [];
    return [
      ...new Set([
        ...members.map((m) => m.projectId),
        ...(await teamProjectIds(actor)),
        ...(await grantIds(actor, 'project')),
        ...(await roleIds(actor, 'project')),
      ]),
    ];
  }

  /** Projects linked to a team the actor belongs to. Fail-closed: a stale client or error adds nothing. */
  async function teamProjectIds(actor) {
    try {
      if (!prisma.teamMember?.findMany || !prisma.projectTeam?.findMany) return [];
      const memberships = await prisma.teamMember.findMany({ where: { userId: actor.id } });
      const teamIds = memberships.map((m) => m.teamId);
      if (!teamIds.length) return [];
      const links = await prisma.projectTeam.findMany({ where: { teamId: { in: teamIds } } });
      return links.map((l) => l.projectId);
    } catch {
      return [];
    }
  }

  /** Servers with an explicit server-scoped grant or role. */
  async function explicitServerIds(actor) {
    if (actor?.isOwner) return null;
    if (!actor?.id) return [];
    return [...new Set([...(await grantIds(actor, 'server')), ...(await roleIds(actor, 'server'))])];
  }

  /** null = all (Owner); otherwise servers hosting visible projects plus explicit server grants. */
  async function serverIds(actor) {
    if (actor?.isOwner) return null;
    const explicit = await explicitServerIds(actor);
    const pids = await projectIds(actor);
    const hosted = pids.length ? await prisma.project.findMany({ where: { id: { in: pids } }, select: { serverId: true } }) : [];
    return [...new Set([...explicit, ...hosted.map((p) => p.serverId)])];
  }

  /** Prisma clause for a project-id column, honouring an optional requested projectId. */
  async function projectClause(actor, requested) {
    const ids = await projectIds(actor);
    if (ids === null) return requested ? requested : undefined;
    if (requested) return ids.includes(requested) ? requested : { in: [] };
    return { in: ids };
  }

  async function serverClause(actor, requested) {
    const ids = await serverIds(actor);
    if (ids === null) return requested ? requested : undefined;
    if (requested) return ids.includes(requested) ? requested : { in: [] };
    return { in: ids };
  }

  /** Domain visibility: visible project, or project-less domain on an explicitly granted server. */
  async function domainWhere(actor) {
    const pids = await projectIds(actor);
    if (pids === null) return {};
    const sids = await explicitServerIds(actor);
    return { OR: [{ projectId: { in: pids } }, { projectId: null, serverId: { in: sids } }] };
  }

  const notFound = (code, message) => new AppError(404, code, message);

  return {
    projectIds,
    serverIds,
    explicitServerIds,
    projectClause,
    serverClause,
    domainWhere,
    async canSeeProject(actor, projectId) {
      const ids = await projectIds(actor);
      return ids === null || (Boolean(projectId) && ids.includes(projectId));
    },
    async canSeeServer(actor, serverId) {
      const ids = await serverIds(actor);
      return ids === null || (Boolean(serverId) && ids.includes(serverId));
    },
    async requireProject(actor, projectId, code = 'NOT_FOUND', message = 'Not found') {
      if (!(await this.canSeeProject(actor, projectId))) throw notFound(code, message);
    },
    async requireServer(actor, serverId, code = 'NOT_FOUND', message = 'Not found') {
      if (!(await this.canSeeServer(actor, serverId))) throw notFound(code, message);
    },
  };
}
