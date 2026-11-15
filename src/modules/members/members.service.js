import { AppError } from '../../common/errors/app-error.js';
import { collectFacts, toEvents } from '../activity/activity.service.js';

const PROVIDERS = ['ssh', 'github'];

/**
 * Identity mapping port. The ExternalIdentity table does not exist in the schema yet (proposed in the
 * TASK-014 self-review), so the default store reports SCHEMA_REQUIRED on writes and an empty mapping on
 * reads. Result: every external identity stays Unattributed until the Owner maps it.
 */
export function createPrismaIdentityStore(prisma) {
  const model = prisma.externalIdentity;
  const missing = () => new AppError(501, 'SCHEMA_REQUIRED', 'ExternalIdentity table is not migrated yet');
  return {
    available: Boolean(model),
    async list() {
      return model ? model.findMany({ where: {}, take: 1000 }) : [];
    },
    async upsert({ provider, externalId, userId }) {
      if (!model) throw missing();
      const existing = await model.findFirst({ where: { provider, externalId } });
      if (existing) return model.update({ where: { id: existing.id }, data: { userId, status: 'mapped' } });
      return model.create({ data: { provider, externalId, userId, status: 'mapped' } });
    },
    async remove(id) {
      if (!model) throw missing();
      return model.delete({ where: { id } });
    },
  };
}

export function createMembersService({ prisma, now = () => new Date(), auditService = null, identityStore = null }) {
  const identities = identityStore ?? createPrismaIdentityStore(prisma);
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  function requireSelfOrOwner(actor, userId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner && actor.id !== userId) {
      throw new AppError(403, 'FORBIDDEN', 'Only the Owner or the member can view this profile');
    }
  }
  function requireOwner(actor) {
    if (!actor?.isOwner) throw new AppError(403, 'FORBIDDEN', 'Only the Owner can manage identity mappings');
  }

  async function lookup() {
    const map = new Map();
    for (const row of await identities.list()) {
      if (row.userId && row.status !== 'revoked') map.set(`${row.provider}:${row.externalId}`, row.userId);
    }
    return (ext) => map.get(`${ext.provider}:${ext.id ?? ext.login ?? ext.externalId}`) ?? null;
  }

  /** Member events plus unattributed external events that the mapping resolves to this member. */
  async function memberEvents(userId, { from, to, limit }) {
    const identityLookup = await lookup();
    const facts = await collectFacts(prisma, { userId, from, to, limit });
    const orphans = await prisma.activityEvent.findMany({
      where: { actorId: null, ...(from || to ? { occurredAt: { ...(from ? { gte: from } : {}), ...(to ? { lt: to } : {}) } } : {}) },
      take: limit,
    });
    facts.activities = [...facts.activities, ...orphans.filter((a) => a.metadata?.externalIdentity)];
    return toEvents(facts, { userId, identityLookup });
  }

  return {
    /**
     * Per-member event counts for a period, from the same platform events as the timelines.
     * Owner only. Events without a mapped identity are counted as unattributed, never guessed.
     */
    async analytics({ from, to }, actor) {
      requireOwner(actor);
      const identityLookup = await lookup();
      const facts = await collectFacts(prisma, { from, to, limit: 5000 });
      const events = toEvents(facts, { identityLookup });
      const byUser = new Map();
      let unattributed = 0;
      for (const e of events) {
        if (!e.actorId) {
          unattributed += 1;
          continue;
        }
        const row = byUser.get(e.actorId) ?? { deployments: 0, approvals: 0, operations: 0, incidents: 0, total: 0 };
        if (e.category === 'deployment') row.deployments += 1;
        else if (e.category === 'approval' && e.role === 'approver') row.approvals += 1;
        else if (e.category === 'operation') row.operations += 1;
        else if (e.category === 'incident') row.incidents += 1;
        row.total += 1;
        byUser.set(e.actorId, row);
      }
      const users = byUser.size
        ? await prisma.user.findMany({ where: { id: { in: [...byUser.keys()] } }, select: { id: true, displayName: true, email: true } })
        : [];
      const members = users
        .map((u) => ({ userId: u.id, displayName: u.displayName, email: u.email, ...byUser.get(u.id) }))
        .sort((a, b) => b.total - a.total);
      return { from: from ?? null, to: to ?? null, members, unattributed, eventTotal: events.length };
    },

    async timeline(userId, { from, to, category, limit }, actor) {
      requireSelfOrOwner(actor, userId);
      const events = (await memberEvents(userId, { from, to, limit: 2000 })).filter(
        (e) => !category || e.category === category,
      );
      return events.slice(0, limit).map((e) => ({ ...e, link: { source: e.source, id: e.id } }));
    },

    async profile(userId, actor) {
      requireSelfOrOwner(actor, userId);
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) throw new AppError(404, 'USER_NOT_FOUND', 'Member not found');
      const teams = await prisma.teamMember.findMany({ where: { userId } });
      const projects = await prisma.projectMember.findMany({ where: { userId } });
      const roles = await prisma.userRole.findMany({ where: { userId } });
      const grants = await prisma.resourceGrant.findMany({
        where: { userId, revokedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] },
      });
      const events = await memberEvents(userId, { limit: 2000 });
      const counts = {};
      for (const e of events) counts[e.category] = (counts[e.category] ?? 0) + 1;
      return {
        user: {
          id: user.id,
          email: user.email,
          displayName: user.displayName,
          status: user.status,
          timezone: user.timezone,
          locale: user.locale,
          createdAt: user.createdAt,
        },
        teams: teams.map((t) => ({ teamId: t.teamId, teamRole: t.teamRole })),
        projects: projects.map((p) => ({ projectId: p.projectId, projectRole: p.projectRole })),
        roles: roles.map((r) => ({ roleId: r.roleId, scopeType: r.scopeType, scopeId: r.scopeId })),
        grants: grants.map((g) => ({
          id: g.id, permissionCode: g.permissionCode, resourceType: g.resourceType,
          resourceId: g.resourceId, environmentId: g.environmentId, expiresAt: g.expiresAt,
        })),
        lastActivityAt: events[0]?.at ?? null,
        eventCounts: counts,
        privacyNote: 'Only professional platform events are tracked. No personal device activity or keystrokes.',
      };
    },

    /** Unmapped SSH/GitHub events: always External/Unattributed, never guessed. */
    async listUnattributed({ from, to, limit }, actor) {
      requireOwner(actor);
      const map = await lookup();
      const rows = await prisma.activityEvent.findMany({
        where: { actorId: null, ...(from || to ? { occurredAt: { ...(from ? { gte: from } : {}), ...(to ? { lt: to } : {}) } } : {}) },
        take: limit,
        orderBy: { occurredAt: 'desc' },
      });
      return rows
        .filter((a) => a.metadata?.externalIdentity && !map(a.metadata.externalIdentity))
        .map((a) => ({
          id: a.id, at: a.occurredAt, action: a.action, source: a.source, projectId: a.projectId,
          externalIdentity: a.metadata.externalIdentity, attribution: 'unattributed',
        }));
    },

    async listMappings(actor) {
      requireOwner(actor);
      return identities.list();
    },

    async mapIdentity(input, actor) {
      requireOwner(actor);
      if (!PROVIDERS.includes(input.provider)) throw new AppError(400, 'PROVIDER_INVALID', 'Unknown provider');
      const user = await prisma.user.findUnique({ where: { id: input.userId } });
      if (!user) throw new AppError(404, 'USER_NOT_FOUND', 'Member not found');
      const row = await identities.upsert(input);
      await audit({
        actorId: actor.id,
        action: 'identity.map',
        resourceType: 'user',
        resourceId: input.userId,
        result: 'success',
        after: { provider: input.provider, externalId: input.externalId },
      });
      return row;
    },

    async unmapIdentity(id, actor) {
      requireOwner(actor);
      await identities.remove(id);
      await audit({ actorId: actor.id, action: 'identity.unmap', resourceType: 'external_identity', resourceId: id, result: 'success' });
      return { removed: true };
    },
  };
}
