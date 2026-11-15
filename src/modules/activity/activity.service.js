import { AppError } from '../../common/errors/app-error.js';
import { redact } from '../audit/audit.service.js';
import { createProjectAccess } from '../projects/projects.access.js';

/** Half-open period [from, to): an event exactly at `to` belongs to the next period. */
const within = (from, to) => ({ ...(from ? { gte: from } : {}), ...(to ? { lt: to } : {}) });
const hasRange = (from, to) => Boolean(from || to);

/**
 * Collects the raw platform events behind every Team Intelligence number. Only professional platform
 * events are read (operations, deployments, approvals, audit, grants, incidents, security); no device
 * or keystroke data exists in this model. Each source row keeps its id so metrics can link back to it.
 */
export async function collectFacts(prisma, { projectId, userId, from, to, limit = 5000 }) {
  const t = (field) => (hasRange(from, to) ? { [field]: within(from, to) } : {});
  const project = projectId ? await prisma.project.findUnique({ where: { id: projectId } }) : null;
  const byUser = (...fields) => (userId ? { OR: fields.map((f) => ({ [f]: userId })) } : {});

  const operations = await prisma.operationJob.findMany({
    where: {
      ...(projectId ? { resourceType: 'project', resourceId: projectId } : {}),
      ...byUser('initiatorId', 'approverId'),
      ...t('createdAt'),
    },
    take: limit,
    orderBy: { createdAt: 'desc' },
  });
  const deployments = await prisma.deployment.findMany({
    where: { ...(projectId ? { projectId } : {}), ...(userId ? { initiatedById: userId } : {}), ...t('createdAt') },
    take: limit,
    orderBy: { createdAt: 'desc' },
  });
  const approvals = await prisma.approvalRequest.findMany({
    where: {
      ...(projectId ? { resourceType: 'project', resourceId: projectId } : {}),
      ...byUser('requesterId', 'approverId'),
      ...t('createdAt'),
    },
    take: limit,
    orderBy: { createdAt: 'desc' },
  });
  const audits = await prisma.auditEvent.findMany({
    where: {
      ...(projectId ? { resourceType: 'project', resourceId: projectId } : {}),
      ...byUser('actorId', 'initiatorId', 'approverId', 'executorId'),
      ...t('occurredAt'),
    },
    take: limit,
    orderBy: { occurredAt: 'desc' },
  });
  const activities = await prisma.activityEvent.findMany({
    where: { ...(projectId ? { projectId } : {}), ...(userId ? { actorId: userId } : {}), ...t('occurredAt') },
    take: limit,
    orderBy: { occurredAt: 'desc' },
  });
  const grants = projectId || userId
    ? await prisma.resourceGrant.findMany({
        where: {
          ...(projectId ? { resourceType: 'project', resourceId: projectId } : {}),
          ...byUser('userId', 'grantedById'),
        },
        take: limit,
      })
    : [];
  const incidents = await prisma.incidentAssignment.findMany({
    where: { ...(userId ? { userId } : {}), ...t('assignedAt') },
    take: limit,
  });
  const securityEvents = project?.serverId
    ? await prisma.securityEvent.findMany({ where: { serverId: project.serverId, ...t('occurredAt') }, take: limit })
    : [];
  return { operations, deployments, approvals, audits, activities, grants, incidents, securityEvents };
}

const CONFIG_ACTION = /^(project\.(configure|create|link|archive|discover)|domain\.|ssl\.)/;

function auditCategory(a) {
  if (a.result === 'denied') return 'denial';
  if (CONFIG_ACTION.test(a.action)) return 'config';
  if (a.action.startsWith('rbac.')) return 'access';
  if (a.action.startsWith('deployment.')) return 'deployment';
  if (a.action.startsWith('operation.')) return 'operation';
  return 'audit';
}

/**
 * Normalizes facts into a unified timeline. Roles stay separate: initiator, approver and executor are
 * never merged, and events with an unmapped external identity are Unattributed.
 */
export function toEvents(facts, { userId = null, identityLookup = () => null } = {}) {
  const ev = [];
  const push = (e) => ev.push({ projectId: null, environmentId: null, correlationId: null, result: null, ...e });
  for (const o of facts.operations) {
    const base = {
      source: 'operation', id: o.id, at: o.createdAt, category: 'operation', action: o.action,
      resourceType: o.resourceType, resourceId: o.resourceId, environmentId: o.environmentId ?? null,
      result: o.status, correlationId: o.correlationId, projectId: o.resourceType === 'project' ? o.resourceId : null,
    };
    if (o.initiatorId && (!userId || o.initiatorId === userId)) push({ ...base, role: 'initiator', actorId: o.initiatorId });
    if (o.approverId && (!userId || o.approverId === userId)) push({ ...base, role: 'approver', actorId: o.approverId });
  }
  for (const d of facts.deployments) {
    push({
      source: 'deployment', id: d.id, at: d.createdAt, category: 'deployment', action: 'deployment',
      resourceType: 'project', resourceId: d.projectId, projectId: d.projectId, environmentId: d.environmentId,
      result: d.status, correlationId: d.correlationId ?? null, role: 'initiator', actorId: d.initiatedById ?? null,
    });
  }
  for (const a of facts.approvals) {
    const base = {
      source: 'approval', id: a.id, category: 'approval', action: 'approval', resourceType: a.resourceType,
      resourceId: a.resourceId, projectId: a.resourceType === 'project' ? a.resourceId : null, result: a.status,
    };
    if (a.requesterId && (!userId || a.requesterId === userId)) push({ ...base, at: a.createdAt, role: 'requester', actorId: a.requesterId });
    if (a.approverId && (!userId || a.approverId === userId)) push({ ...base, at: a.decidedAt ?? a.createdAt, role: 'approver', actorId: a.approverId });
  }
  for (const a of facts.audits) {
    push({
      source: 'audit', id: a.id, at: a.occurredAt, category: auditCategory(a), action: a.action,
      resourceType: a.resourceType, resourceId: a.resourceId ?? null,
      projectId: a.resourceType === 'project' ? a.resourceId : null, environmentId: a.environmentId ?? null,
      result: a.result, correlationId: a.correlationId, role: a.executorId === userId && userId ? 'executor' : 'actor',
      actorId: a.actorId ?? a.initiatorId ?? null,
    });
  }
  for (const a of facts.activities) {
    const ext = a.metadata?.externalIdentity;
    const mappedTo = !a.actorId && ext ? identityLookup(ext) : null;
    const actorId = a.actorId ?? mappedTo;
    if (userId && actorId !== userId) continue;
    push({
      source: 'activity', id: a.id, at: a.occurredAt, category: a.category, action: a.action,
      resourceType: a.resourceType, resourceId: a.resourceId ?? null, projectId: a.projectId ?? null,
      environmentId: a.environmentId ?? null, result: a.result, correlationId: a.correlationId ?? null,
      role: 'actor', actorId,
      attribution: actorId ? (mappedTo ? 'mapped-external' : 'user') : 'unattributed',
      externalIdentity: ext ?? null,
    });
  }
  for (const i of facts.incidents) {
    push({
      source: 'incident', id: i.id, at: i.assignedAt, category: 'incident', action: 'incident.assigned',
      resourceType: 'incident', resourceId: i.incidentId, role: 'assignee', actorId: i.userId,
    });
  }
  return ev
    .map((e) => ({ attribution: e.actorId ? 'user' : 'unattributed', ...e }))
    .sort((a, b) => new Date(b.at) - new Date(a.at));
}

export function createActivityService({ prisma, now = () => new Date() }) {
  const access = createProjectAccess({ prisma, now });

  return {
    /** Writes an ActivityEvent. Metadata is redacted before storage. */
    async record(event) {
      return prisma.activityEvent.create({
        data: {
          actorId: event.actorId ?? null,
          serverId: event.serverId ?? null,
          projectId: event.projectId ?? null,
          environmentId: event.environmentId ?? null,
          operationJobId: event.operationJobId ?? null,
          category: event.category,
          action: event.action,
          resourceType: event.resourceType,
          resourceId: event.resourceId ?? null,
          result: event.result,
          source: event.source ?? 'platform',
          correlationId: event.correlationId ?? null,
          metadata: event.metadata ? redact(event.metadata) : undefined,
          occurredAt: event.occurredAt ?? now(),
        },
      });
    },

    /** The caller's own timeline only: the user id always comes from the session, never from input. */
    async myTimeline({ from, to, category, limit }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const facts = await collectFacts(prisma, { userId: actor.id, from, to, limit: Math.max(limit, 100) });
      const items = toEvents(facts, { userId: actor.id }).filter((e) => !category || e.category === category).slice(0, limit);
      return items.map((e) => ({ ...e, link: { source: e.source, id: e.id } }));
    },

    /** Project timeline for people who can view the project; each item links to its original event. */
    async projectTimeline({ projectId, from, to, category, limit }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      await access.requireView(actor, projectId);
      const facts = await collectFacts(prisma, { projectId, from, to, limit });
      const items = toEvents(facts).filter((e) => !category || e.category === category).slice(0, limit);
      return items.map((e) => ({ ...e, link: { source: e.source, id: e.id } }));
    },
  };
}
