import { createHash, randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { STALE_AFTER_MS } from '../agents/agents.service.js';

const sha = (v) => createHash('sha256').update(v).digest('hex');
const ENROLL_TTL_MS = 60 * 60 * 1000;

// Never expose agent credential material (certFingerprint) through the API.
const AGENT_PUBLIC = { select: { id: true, agentPublicId: true, lastSeenAt: true, revokedAt: true, createdAt: true } };

/** A silent agent means the data is stale: report offline instead of the last known status. */
function present(server, now) {
  const { agent, snapshots, ...rest } = server;
  let status = rest.status;
  if (!agent || agent.revokedAt) status = 'unknown';
  else if (!agent.lastSeenAt || now - new Date(agent.lastSeenAt).getTime() > STALE_AFTER_MS) status = 'offline';
  return { ...rest, status, agent: agent ?? null, latest: snapshots?.[0]?.summaryJson ?? null };
}

export function createServersService({ prisma, now = () => new Date(), auditService = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const scope = createScope({ prisma, now });
  const requireOwner = (actor) => {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'FORBIDDEN', 'Only Owner can manage servers');
  };

  return {
    async list({ limit, cursor }, actor) {
      const idClause = await scope.serverClause(actor);
      const rows = await prisma.server.findMany({
        where: { archivedAt: null, ...(idClause ? { id: idClause } : {}) },
        take: limit,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        orderBy: { alias: 'asc' },
        include: { agent: AGENT_PUBLIC, snapshots: { take: 1, orderBy: { capturedAt: 'desc' } } },
      });
      return rows.map((r) => present(r, now().getTime()));
    },

    async getById(id, actor) {
      await scope.requireServer(actor, id, 'SERVER_NOT_FOUND', 'Server not found');
      const server = await prisma.server.findUnique({
        where: { id },
        include: {
          agent: AGENT_PUBLIC,
          services: true,
          ports: true,
          snapshots: { take: 1, orderBy: { capturedAt: 'desc' } },
        },
      });
      if (!server) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
      return present(server, now().getTime());
    },

    async create(input, actor) {
      requireOwner(actor);
      const existing = await prisma.server.findUnique({ where: { alias: input.alias } });
      if (existing) throw new AppError(409, 'SERVER_EXISTS', 'Server alias already exists');
      const server = await prisma.server.create({ data: { alias: input.alias, hostname: input.hostname ?? null } });
      await audit({ actorId: actor.id, action: 'server.create', resourceType: 'server', resourceId: server.id, result: 'success' });
      return server;
    },

    /** One-time token, stored hashed, shown once, valid for one hour. */
    async issueEnrollment(serverId, actor) {
      requireOwner(actor);
      const server = await prisma.server.findUnique({ where: { id: serverId } });
      if (!server || server.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
      const token = randomBytes(32).toString('base64url');
      const expiresAt = new Date(now().getTime() + ENROLL_TTL_MS);
      await prisma.agentEnrollment.create({
        data: { serverId, tokenHash: sha(token), expiresAt, createdById: actor.id },
      });
      await audit({ actorId: actor.id, action: 'agent.enrollment.issue', resourceType: 'server', resourceId: serverId, result: 'success' });
      return { token, expiresAt: expiresAt.toISOString() };
    },

    /** Fleet-wide service rows reported by agents (read-only, scoped to visible servers). */
    async services({ serverId, limit }, actor) {
      const idClause = await scope.serverClause(actor, serverId);
      const rows = await prisma.serverService.findMany({
        where: { server: { archivedAt: null }, ...(idClause ? { serverId: idClause } : {}) },
        take: limit,
        orderBy: [{ serverId: 'asc' }, { name: 'asc' }],
        include: { server: { select: { id: true, alias: true } } },
      });
      return rows.map(({ metaJson, ...r }) => r);
    },

    /** Fleet-wide listening ports reported by agents. */
    async ports({ serverId, limit }, actor) {
      const idClause = await scope.serverClause(actor, serverId);
      return prisma.serverPort.findMany({
        where: { server: { archivedAt: null }, ...(idClause ? { serverId: idClause } : {}) },
        take: limit,
        orderBy: [{ serverId: 'asc' }, { port: 'asc' }],
        include: { server: { select: { id: true, alias: true } } },
      });
    },

    /** Project runtimes with environments and host server (read-only). */
    async runtimes(actor) {
      const projectClause = await scope.projectClause(actor);
      const rows = await prisma.project.findMany({
        where: { archivedAt: null, ...(projectClause ? { id: projectClause } : {}) },
        take: 200,
        orderBy: { name: 'asc' },
        include: {
          runtime: { select: { runtime: true, processManager: true, updatedAt: true } },
          environments: { select: { id: true, code: true, displayName: true } },
          server: { select: { id: true, alias: true } },
        },
      });
      return rows.map((p) => ({
        id: p.id, name: p.name, slug: p.slug, type: p.type, status: p.status,
        server: p.server, runtime: p.runtime, environments: p.environments,
      }));
    },

    async metrics(serverId, { hours }, actor) {
      await scope.requireServer(actor, serverId, 'SERVER_NOT_FOUND', 'Server not found');
      const since = new Date(now().getTime() - hours * 3600 * 1000);
      const rows = await prisma.serverSnapshot.findMany({
        where: { serverId, capturedAt: { gte: since } },
        orderBy: { capturedAt: 'asc' },
        take: 2000,
      });
      return rows.map((r) => ({ capturedAt: r.capturedAt, ...r.summaryJson }));
    },
  };
}
