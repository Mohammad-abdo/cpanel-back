import { PERMISSIONS } from '../../common/permission-catalog.js';
import { AppError } from '../../common/errors/app-error.js';
import { createProjectAccess } from '../projects/projects.access.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { redactDeep, redactText } from './logs.redaction.js';
import { createInMemoryLogStore } from './logs.store.js';
import { createPrismaLogStore } from './logs.prisma-store.js';

const MAX_MESSAGE = 8000;
const MAX_STACK = 16000;
const FORMULA = /^[=+\-@\t\r]/;

function csvCell(value) {
  let s = value === null || value === undefined ? '' : String(value);
  if (FORMULA.test(s)) s = `'${s}`; // neutralize spreadsheet formula injection
  return `"${s.replace(/"/g, '""')}"`;
}

export function createLogsService({
  prisma,
  now = () => new Date(),
  auditService = null,
  // Durable by default when a real Prisma client is wired; mock clients (tests) get the in-memory store.
  store = typeof prisma?.$connect === 'function' ? createPrismaLogStore(prisma) : createInMemoryLogStore(),
  rbac = null,
  onError = null,
}) {
  const access = rbac ?? createRbacService({ prisma, now });
  const projects = createProjectAccess({ prisma, now });
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  /** Scope check for reading logs: Owner, or exact project+environment grant for project.logs.read. */
  async function authorizeRead(actor, { projectId, environmentId }) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (actor.isOwner) return;
    if (!environmentId) throw new AppError(400, 'ENVIRONMENT_REQUIRED', 'Environment scope required');
    const ok = await access.can(actor, {
      permissionKey: PERMISSIONS.PROJECT_LOGS_READ,
      resourceType: 'project',
      resourceId: projectId,
      environmentId,
    });
    if (!ok) {
      await audit({
        actorId: actor.id,
        action: 'logs.read',
        resourceType: 'project',
        resourceId: projectId,
        environmentId,
        result: 'denied',
      });
      throw new AppError(403, 'FORBIDDEN', 'No log access for this project and environment');
    }
  }

  /** Gateway-controlled tenancy: the project filter always comes from the authorized scope, never from raw labels. */
  const toFilter = (q) => ({
    projectId: q.projectId,
    environmentId: q.environmentId,
    kind: q.kind,
    level: q.level,
    minLevel: q.minLevel,
    requestId: q.requestId,
    traceId: q.traceId,
    deploymentId: q.deploymentId,
    from: q.from ? new Date(q.from) : undefined,
    to: q.to ? new Date(q.to) : undefined,
    q: q.q,
  });

  const display = (e) => ({
    ...e,
    message: redactText(e.message),
    stack: e.stack ? redactText(e.stack) : e.stack,
    fields: e.fields ? redactDeep(e.fields) : e.fields,
  });

  return {
    store,

    async listSources({ projectId, limit }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const visible = await projects.visibleProjectIds(actor);
      if (projectId && visible && !visible.includes(projectId)) {
        throw new AppError(404, 'NOT_FOUND', 'Not found');
      }
      return prisma.logSource.findMany({
        where: {
          ...(projectId ? { projectId } : {}),
          ...(visible && !projectId ? { projectId: { in: visible } } : {}),
        },
        take: limit,
        orderBy: { kind: 'asc' },
      });
    },

    async registerSource(input, actor) {
      if (!actor?.isOwner) throw new AppError(403, 'FORBIDDEN', 'Only the Owner can register log sources');
      if (input.projectId) {
        const project = await prisma.project.findUnique({ where: { id: input.projectId } });
        if (!project) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
        if (input.environmentId) {
          const env = await prisma.projectEnvironment.findUnique({ where: { id: input.environmentId } });
          if (!env || env.projectId !== project.id) {
            throw new AppError(400, 'ENVIRONMENT_MISMATCH', 'Environment does not belong to the project');
          }
        }
      }
      const source = await prisma.logSource.create({
        data: {
          projectId: input.projectId ?? null,
          serverId: input.serverId ?? null,
          kind: input.kind,
          labelJson: input.environmentId ? { environmentId: input.environmentId } : undefined,
        },
      });
      await audit({
        actorId: actor.id,
        action: 'logs.source.register',
        resourceType: 'log_source',
        resourceId: source.id,
        result: 'success',
        after: { kind: source.kind, projectId: source.projectId },
      });
      return source;
    },

    /**
     * Ingestion gateway. Labels (project/server/environment) are derived from the registered source,
     * never from the payload. Secrets are removed before anything is stored.
     * principal: { type: 'agent', serverId } or { type: 'user', actor } (Owner only).
     */
    async ingest({ sourceId, entries }, principal) {
      const source = await prisma.logSource.findUnique({ where: { id: sourceId } });
      if (!source) throw new AppError(404, 'LOG_SOURCE_NOT_FOUND', 'Log source not found');
      const project = source.projectId ? await prisma.project.findUnique({ where: { id: source.projectId } }) : null;
      const serverId = source.serverId ?? project?.serverId ?? null;

      if (principal?.type === 'agent') {
        if (!serverId || principal.serverId !== serverId) {
          await audit({
            action: 'logs.ingest',
            resourceType: 'log_source',
            resourceId: source.id,
            result: 'denied',
            metadata: { reason: 'agent not bound to source server' },
          });
          throw new AppError(403, 'SOURCE_FORBIDDEN', 'Agent is not bound to this log source');
        }
      } else if (!principal?.actor?.isOwner) {
        throw new AppError(403, 'FORBIDDEN', 'Only agents or the Owner can ingest logs');
      }

      const labels = {
        projectId: source.projectId ?? null,
        serverId,
        environmentId: source.labelJson?.environmentId ?? null,
        sourceId: source.id,
        kind: source.kind,
      };
      const accepted = [];
      const rejected = [];
      for (const [index, e] of entries.entries()) {
        if (e.deploymentId) {
          const dep = await prisma.deployment.findUnique({ where: { id: e.deploymentId } });
          if (!dep || dep.projectId !== source.projectId) {
            rejected.push({ index, reason: 'deployment-not-in-project' });
            continue;
          }
        }
        accepted.push({
          ts: e.timestamp ? new Date(e.timestamp) : now(),
          level: e.level,
          message: redactText(e.message).slice(0, MAX_MESSAGE),
          stack: e.stack ? redactText(e.stack).slice(0, MAX_STACK) : null,
          requestId: e.requestId ?? null,
          traceId: e.traceId ?? null,
          deploymentId: e.deploymentId ?? null,
          fields: e.fields ? redactDeep(e.fields) : null,
          labels,
        });
      }
      const stored = await store.append(accepted);
      if (onError && labels.projectId) {
        for (const entry of stored) {
          if (entry.level === 'error' || entry.level === 'fatal') await onError({ entry, labels });
        }
      }
      return { accepted: stored.length, rejected };
    },

    async search(query, actor) {
      await authorizeRead(actor, query);
      const items = await (store.queryDurable ?? store.query).call(store, toFilter(query), { limit: query.limit, beforeSeq: query.beforeSeq });
      return {
        items: items.map(display),
        nextBeforeSeq: items.length === query.limit ? items[items.length - 1].seq : null,
      };
    },

    async export(query, actor) {
      await authorizeRead(actor, query);
      const rows = (await (store.queryDurable ?? store.query).call(store, toFilter(query), { limit: query.limit })).map(display);
      await audit({
        actorId: actor.id,
        action: 'logs.export',
        resourceType: 'project',
        resourceId: query.projectId,
        environmentId: query.environmentId ?? null,
        result: 'success',
        after: { format: query.format, rows: rows.length },
      });
      if (query.format === 'json') {
        return { contentType: 'application/json', filename: 'logs.json', body: JSON.stringify(rows) };
      }
      const header = ['timestamp', 'level', 'kind', 'message', 'requestId', 'traceId', 'deploymentId'];
      const lines = rows.map((r) =>
        [new Date(r.ts).toISOString(), r.level, r.labels.kind, r.message, r.requestId, r.traceId, r.deploymentId]
          .map(csvCell)
          .join(','),
      );
      return { contentType: 'text/csv; charset=utf-8', filename: 'logs.csv', body: [header.join(','), ...lines].join('\n') };
    },

    /**
     * Opens a live subscription. Tenancy is enforced twice: at subscribe (authorizeRead) and per event
     * (filter pinned to the authorized project/environment). `session` is a createStreamSession().
     */
    async openStream(query, actor, session) {
      await authorizeRead(actor, query);
      const filter = toFilter(query);
      let last = query.lastEventId;
      // Subscribe first so nothing is lost between replay and live delivery; de-dupe by seq.
      const unsubscribe = store.subscribe((entry) => {
        if (entry.seq > (last ?? 0) && store.matches(entry, filter)) {
          last = entry.seq;
          session.push(display(entry));
        }
      });
      if (query.lastEventId !== undefined) {
        for (const e of await (store.queryDurable ?? store.query).call(store, filter, { afterSeq: query.lastEventId, limit: 500 })) {
          if (e.seq > (last ?? 0)) {
            last = e.seq;
            session.push(display(e));
          }
        }
      }
      await audit({
        actorId: actor.id,
        action: 'logs.stream.open',
        resourceType: 'project',
        resourceId: query.projectId,
        environmentId: query.environmentId ?? null,
        result: 'success',
      });
      return () => {
        unsubscribe();
        session.close();
      };
    },

    async createBookmark(input, actor) {
      await authorizeRead(actor, { projectId: input.projectId, environmentId: input.query?.environmentId });
      return prisma.logBookmark.create({
        data: { userId: actor.id, projectId: input.projectId, name: input.name, queryJson: input.query ?? undefined },
      });
    },

    async listBookmarks(actor) {
      return prisma.logBookmark.findMany({ where: { userId: actor.id }, orderBy: { createdAt: 'desc' } });
    },

    async deleteBookmark(id, actor) {
      const row = await prisma.logBookmark.findUnique({ where: { id } });
      if (!row || row.userId !== actor.id) throw new AppError(404, 'BOOKMARK_NOT_FOUND', 'Bookmark not found');
      await prisma.logBookmark.delete({ where: { id } });
      return { deleted: true };
    },
  };
}
