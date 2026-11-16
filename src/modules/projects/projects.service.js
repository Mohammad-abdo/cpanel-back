import { createHash } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { redact } from '../audit/audit.service.js';
import { createProjectAccess } from './projects.access.js';
import { createProjectTeamOps } from './projects.team.js';

/** Deterministic UUID so a retried request maps to the same operation/correlation ids. */
export function deterministicUuid(seed, salt = '') {
  const h = createHash('sha256').update(`${salt}:${seed}`).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/** Drop credentials from a git remote URL before it is stored or shown. */
export function sanitizeRemoteUrl(value) {
  if (!value) return value;
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    return url.toString();
  } catch {
    // scp-style (git@host:org/repo.git) has no password component
    return value.replace(/\/\/[^/@]*@/, '//');
  }
}

/** Other projects on the same server sharing the process manager: restart blast radius. */
export async function computeSharedImpact(prisma, projectId) {
  const project = await prisma.project.findUnique({ where: { id: projectId } });
  if (!project) return { shared: false, projects: [] };
  const runtime = await prisma.projectRuntime.findFirst({ where: { projectId } });
  const siblings = await prisma.project.findMany({
    where: { serverId: project.serverId, id: { not: projectId }, archivedAt: null },
  });
  const impacted = [];
  for (const s of siblings) {
    const r = await prisma.projectRuntime.findFirst({ where: { projectId: s.id } });
    if (runtime?.processManager && r?.processManager === runtime.processManager) {
      impacted.push({ id: s.id, name: s.name, slug: s.slug });
    }
  }
  return {
    shared: impacted.length > 0,
    processManager: runtime?.processManager ?? null,
    serverId: project.serverId,
    projects: impacted,
  };
}

export function createProjectsService({ prisma, now = () => new Date(), auditService = null, operationsService = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const access = createProjectAccess({ prisma, now });
  const teamOps = createProjectTeamOps({ prisma, now, auditService });

  function requireOwner(actor, what) {
    if (!actor?.isOwner) throw new AppError(403, 'FORBIDDEN', `Only the Owner can ${what}`);
  }

  async function loadProject(id) {
    const project = await prisma.project.findUnique({ where: { id } });
    if (!project) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
    return project;
  }

  async function writeRuntime(projectId, runtime, extraMeta) {
    const existing = await prisma.projectRuntime.findFirst({ where: { projectId } });
    const metaJson = redact({ ...(existing?.metaJson ?? {}), ...extraMeta });
    const data = {
      ...(runtime?.runtime !== undefined ? { runtime: runtime.runtime } : {}),
      ...(runtime?.processManager !== undefined ? { processManager: runtime.processManager } : {}),
      metaJson,
    };
    if (existing) return prisma.projectRuntime.update({ where: { projectId }, data });
    return prisma.projectRuntime.create({ data: { projectId, ...data } });
  }

  async function writeRepository(projectId, repo) {
    if (!repo) return null;
    const data = {
      ...(repo.remoteUrl !== undefined ? { remoteUrl: sanitizeRemoteUrl(repo.remoteUrl) } : {}),
      ...(repo.defaultBranch !== undefined ? { defaultBranch: repo.defaultBranch } : {}),
      ...(repo.lastCommitSha !== undefined ? { lastCommitSha: repo.lastCommitSha } : {}),
    };
    const existing = await prisma.projectRepository.findFirst({ where: { projectId } });
    if (existing) return prisma.projectRepository.update({ where: { projectId }, data });
    return prisma.projectRepository.create({ data: { projectId, ...data } });
  }

  async function createEnvironments(projectId, envs) {
    const out = [];
    for (const e of envs) {
      const dup = await prisma.projectEnvironment.findFirst({ where: { projectId, code: e.code } });
      if (dup) continue;
      out.push(await prisma.projectEnvironment.create({ data: { projectId, code: e.code, displayName: e.displayName } }));
    }
    return out;
  }

  return {
    ...teamOps,
    async list({ limit, cursor, serverId }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const visible = await access.visibleProjectIds(actor);
      return prisma.project.findMany({
        where: {
          ...(serverId ? { serverId } : {}),
          ...(visible ? { id: { in: visible } } : {}),
        },
        take: limit,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        orderBy: { name: 'asc' },
        include: { environments: true, runtime: true },
      });
    },

    async getById(id, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const project = await prisma.project.findUnique({
        where: { id },
        include: { environments: true, runtime: true, repository: true, members: true },
      });
      if (!project || !(await access.canView(actor, id))) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      return project;
    },

    /** Read-only aggregate for the project detail page. Out-of-scope or unknown ids answer 404. */
    async overview(id, { environmentId } = {}, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const project = await prisma.project.findUnique({ where: { id } });
      if (!project || !(await access.canView(actor, id))) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      const env = environmentId ? { environmentId } : {};
      const OPEN_ALERTS = ['firing', 'acknowledged', 'escalated'];
      const [server, lastDeployment, lastSuccess, deployCount, openAlerts, errorGroups, policies, domains, databases, members, checks] =
        await Promise.all([
          prisma.server.findUnique({ where: { id: project.serverId } }),
          prisma.deployment.findFirst({ where: { projectId: id, ...env }, orderBy: { createdAt: 'desc' } }),
          prisma.deployment.findFirst({ where: { projectId: id, status: 'Success', ...env }, orderBy: { createdAt: 'desc' } }),
          prisma.deployment.count({ where: { projectId: id, ...env } }),
          prisma.alert.count({ where: { projectId: id, status: { in: OPEN_ALERTS } } }),
          prisma.errorGroup.findMany({ where: { projectId: id } }),
          prisma.backupPolicy.findMany({ where: { projectId: id, archivedAt: null, ...env } }),
          prisma.domain.findMany({ where: { projectId: id, archivedAt: null, ...env } }),
          prisma.managedDatabase.count({ where: { projectId: id, ...env } }),
          prisma.projectMember.count({ where: { projectId: id } }),
          prisma.healthCheck.findMany({ where: { projectId: id } }),
        ]);
      const policyIds = policies.map((p) => p.id);
      const lastBackup = policyIds.length
        ? await prisma.backupRun.findFirst({ where: { policyId: { in: policyIds } }, orderBy: { createdAt: 'desc' } })
        : null;
      const domainIds = domains.map((d) => d.id);
      const certs = domainIds.length ? await prisma.sslCertificate.findMany({ where: { domainId: { in: domainIds } } }) : [];
      const expiries = certs.filter((c) => c.expiresAt).map((c) => new Date(c.expiresAt).getTime());
      const nextExpiry = expiries.length ? new Date(Math.min(...expiries)) : null;
      const rank = { critical: 3, unhealthy: 3, failed: 3, warning: 2, degraded: 2, healthy: 1, ok: 1 };
      const worst = checks.reduce((acc, c) => ((rank[c.status] ?? 0) > (rank[acc] ?? 0) ? c.status : acc), null);
      return {
        projectId: id,
        environmentId: environmentId ?? null,
        server: server ? { id: server.id, alias: server.alias, hostname: server.hostname, status: server.status } : null,
        health: { status: worst ?? 'unknown', checks: checks.length },
        deployments: {
          total: deployCount,
          last: lastDeployment ? { id: lastDeployment.id, status: lastDeployment.status, createdAt: lastDeployment.createdAt, updatedAt: lastDeployment.updatedAt, environmentId: lastDeployment.environmentId, commitSha: lastDeployment.commitSha } : null,
          lastSuccessAt: lastSuccess?.updatedAt ?? null,
        },
        alerts: { open: openAlerts },
        errors: {
          groups: errorGroups.length,
          occurrences: errorGroups.reduce((n, g) => n + (g.count ?? 0), 0),
          lastSeenAt: errorGroups.length ? new Date(Math.max(...errorGroups.map((g) => new Date(g.lastSeenAt).getTime()))) : null,
        },
        backups: {
          policies: policies.length,
          last: lastBackup ? { id: lastBackup.id, status: lastBackup.status, finishedAt: lastBackup.finishedAt ?? lastBackup.createdAt, verificationStatus: lastBackup.verificationStatus } : null,
        },
        certificates: {
          total: certs.length,
          nextExpiryAt: nextExpiry,
          daysLeft: nextExpiry ? Math.floor((nextExpiry.getTime() - now().getTime()) / 86400000) : null,
        },
        counts: { domains: domains.length, databases, members },
      };
    },

    /** Project members with display details. Never exposes credentials or MFA state. */
    async members(id, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const project = await prisma.project.findUnique({ where: { id } });
      if (!project || !(await access.canView(actor, id))) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      const rows = await prisma.projectMember.findMany({ where: { projectId: id } });
      const users = rows.length ? await prisma.user.findMany({ where: { id: { in: rows.map((m) => m.userId) } } }) : [];
      return rows.map((m) => {
        const u = users.find((x) => x.id === m.userId);
        return { userId: m.userId, projectRole: m.projectRole, joinedAt: m.createdAt, displayName: u?.displayName ?? null, email: u?.email ?? null, status: u?.status ?? null };
      });
    },

    async create(input, actor) {
      requireOwner(actor, 'create or link projects');
      const server = await prisma.server.findUnique({ where: { id: input.serverId } });
      if (!server || server.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
      const dup = await prisma.project.findFirst({ where: { serverId: input.serverId, slug: input.slug } });
      if (dup) throw new AppError(409, 'PROJECT_EXISTS', 'Project slug already exists on this server');
      const project = await prisma.project.create({
        data: { serverId: input.serverId, name: input.name, slug: input.slug, type: input.type, status: 'active' },
      });
      const environments = await createEnvironments(project.id, input.environments);
      await writeRuntime(project.id, input.runtime, {});
      await writeRepository(project.id, input.repository);
      await audit({
        actorId: actor.id,
        action: 'project.create',
        resourceType: 'project',
        resourceId: project.id,
        result: 'success',
        after: { slug: project.slug, serverId: project.serverId, environments: environments.map((e) => e.code) },
      });
      return { ...project, environments };
    },

    /**
     * Read-only discovery: records agent-reported candidates as `discovered` projects.
     * It never modifies an existing project, deploys, or touches any server path.
     */
    async discover(input, actor) {
      requireOwner(actor, 'record discovered projects');
      const server = await prisma.server.findUnique({ where: { id: input.serverId } });
      if (!server || server.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
      const created = [];
      const skipped = [];
      for (const c of input.candidates) {
        const slug = c.slug ?? c.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
        if (!slug) {
          skipped.push({ name: c.name, reason: 'invalid-name' });
          continue;
        }
        const existing = await prisma.project.findFirst({ where: { serverId: input.serverId, slug } });
        if (existing) {
          skipped.push({ name: c.name, slug, reason: 'already-known' });
          continue;
        }
        const project = await prisma.project.create({
          data: { serverId: input.serverId, name: c.name, slug, type: c.type, status: 'discovered' },
        });
        await writeRuntime(project.id, { runtime: c.runtime, processManager: c.processManager }, {
          discoveredPath: c.path ?? null,
          discoveredAt: now().toISOString(),
          readOnlyDiscovery: true,
        });
        await writeRepository(project.id, {
          remoteUrl: c.remoteUrl,
          defaultBranch: c.branch,
          lastCommitSha: c.commitSha,
        });
        created.push(project);
      }
      await audit({
        actorId: actor.id,
        action: 'project.discover',
        resourceType: 'server',
        resourceId: input.serverId,
        result: 'success',
        after: { created: created.length, skipped: skipped.length },
      });
      return { created, skipped };
    },

    /** Confirms a discovered project by attaching environments; status becomes active. */
    async link(id, input, actor) {
      requireOwner(actor, 'link discovered projects');
      const project = await loadProject(id);
      if (project.status !== 'discovered') throw new AppError(409, 'NOT_DISCOVERED', 'Project is not in discovered state');
      const environments = await createEnvironments(id, input.environments);
      const updated = await prisma.project.update({ where: { id }, data: { status: 'active' } });
      await audit({
        actorId: actor.id,
        action: 'project.link',
        resourceType: 'project',
        resourceId: id,
        result: 'success',
        after: { environments: environments.map((e) => e.code) },
      });
      return { ...updated, environments };
    },

    /** Configuration stores metadata only. Secret values are rejected by the validator; only names are kept. */
    async configure(id, input, actor) {
      requireOwner(actor, 'configure projects');
      const project = await loadProject(id);
      if (project.archivedAt) throw new AppError(409, 'PROJECT_ARCHIVED', 'Project is archived');
      if (input.type) await prisma.project.update({ where: { id }, data: { type: input.type } });
      const meta = input.secretRefs ? { configuredEnvKeys: [...new Set(input.secretRefs)] } : {};
      if (input.runtime || input.secretRefs) await writeRuntime(id, input.runtime, meta);
      if (input.repository) await writeRepository(id, input.repository);
      await audit({
        actorId: actor.id,
        action: 'project.configure',
        resourceType: 'project',
        resourceId: id,
        result: 'success',
        after: { fields: Object.keys(input), secretRefCount: input.secretRefs?.length ?? undefined },
      });
      return this.getById(id, actor);
    },

    /** PM2 lifecycle goes through the approval-aware operation queue; nothing runs inline. */
    async lifecycle(id, action, input, actor) {
      if (!operationsService) throw new AppError(500, 'OPERATIONS_UNAVAILABLE', 'Operation queue unavailable');
      const project = await loadProject(id);
      if (project.archivedAt || project.status === 'archived') {
        throw new AppError(409, 'PROJECT_ARCHIVED', 'Project is archived');
      }
      if (project.status === 'discovered') {
        throw new AppError(409, 'PROJECT_NOT_LINKED', 'Link the discovered project before lifecycle actions');
      }
      const seed = `${actor.id}:${id}:${action}:${input.idempotencyKey}`;
      const { job, replayed } = await operationsService.enqueue(
        {
          operationId: deterministicUuid(seed, 'op'),
          correlationId: deterministicUuid(seed, 'corr'),
          idempotencyKey: `lifecycle:${deterministicUuid(seed, 'idem')}`,
          type: `project.${action}`,
          resourceType: 'project',
          resourceId: id,
          environmentId: input.environmentId,
          riskLevel: 'medium',
          expiresAt: new Date(now().getTime() + 60 * 60 * 1000).toISOString(),
          payload: { reason: input.reason ?? null, processManager: 'pm2' },
        },
        actor,
      );
      const impact = action === 'start' ? null : await computeSharedImpact(prisma, id);
      return { operation: job, replayed, sharedImpact: impact };
    },

    async restartImpact(id, actor) {
      await loadProject(id);
      await access.requireView(actor, id);
      return computeSharedImpact(prisma, id);
    },

    async archive(id, input, actor) {
      requireOwner(actor, 'archive projects');
      const project = await loadProject(id);
      if (project.archivedAt) throw new AppError(409, 'PROJECT_ARCHIVED', 'Project already archived');
      const active = await prisma.deployment.count({
        where: { projectId: id, status: { in: ['Queued', 'Preparing', 'Building', 'Deploying', 'Health Check'] } },
      });
      if (active > 0) throw new AppError(409, 'DEPLOYMENT_IN_PROGRESS', 'Finish active deployments before archiving');
      const updated = await prisma.project.update({ where: { id }, data: { status: 'archived', archivedAt: now() } });
      await audit({
        actorId: actor.id,
        action: 'project.archive',
        resourceType: 'project',
        resourceId: id,
        result: 'success',
        after: { reason: input.reason },
      });
      return updated;
    },
  };
}
