import { AppError } from '../../common/errors/app-error.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { sha256 } from '../platform/platform.crypto.js';
import { createScope } from '../../common/scope.js';
import { notify } from '../notifications/notifications.service.js';

/** Detected -> Triaged -> Assigned -> Investigating -> Contained -> Resolved -> Closed. Closed reopens only via reopen(). */
export const INCIDENT_TRANSITIONS = Object.freeze({
  detected: ['triaged'],
  triaged: ['assigned'],
  assigned: ['investigating'],
  investigating: ['contained', 'resolved'],
  contained: ['investigating', 'resolved'],
  resolved: ['closed', 'investigating'],
  closed: [],
});
export const REOPEN_WINDOW_MS = 14 * 24 * 3600 * 1000;
const RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const SECRET_IN_TEXT = /\b(password|passwd|token|secret|api[-_]?key|authorization)\s*[=:]\s*\S+/gi;
const scrub = (text) => text.replace(SECRET_IN_TEXT, '$1=[REDACTED]');
const PLATFORM = { resourceType: 'platform', resourceId: 'platform', environmentId: null };

export function createIncidentsService({ prisma, now = () => new Date(), auditService = null, rbac = null }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'incident', ...event }) : null);

  const scope = createScope({ prisma, now });
  /** Read access: out-of-scope incidents answer 404 (no existence leak). Project-less incidents are Owner-only. */
  async function loadVisible(id, actor) {
    const row = await load(id);
    if (!(await scope.canSeeProject(actor, row.projectId))) throw new AppError(404, 'INCIDENT_NOT_FOUND', 'Incident not found');
    return row;
  }
  async function load(id) {
    const row = await prisma.securityIncident.findUnique({ where: { id }, include: { assignments: true } });
    if (!row) throw new AppError(404, 'INCIDENT_NOT_FOUND', 'Incident not found');
    return row;
  }
  const currentOwner = (inc) => [...(inc.assignments ?? [])].sort((a, b) => new Date(b.assignedAt) - new Date(a.assignedAt))[0]?.userId ?? null;

  async function requireManager(actor) {
    await assertCan(rbac, actor, { permissionKey: PERM.INCIDENT, ...PLATFORM });
  }
  /** Once an incident has an owner, only that owner or the Owner role may act on it. */
  function requireOwnership(inc, actor) {
    const owner = currentOwner(inc);
    if (owner && owner !== actor.id && !actor.isOwner) throw new AppError(403, 'NOT_INCIDENT_OWNER', 'Only the assigned owner can change this incident');
  }

  async function lastEvidence(id) {
    const rows = await prisma.auditEvent.findMany({ where: { resourceType: 'incident', resourceId: id, action: 'incident.evidence' }, orderBy: { occurredAt: 'desc' }, take: 1 });
    return rows[0]?.afterJson ?? null;
  }

  async function addEvidence(id, { type, summary }, actorId) {
    const prev = await lastEvidence(id);
    const clean = scrub(summary);
    const seq = (prev?.seq ?? 0) + 1;
    const contentHash = sha256(clean);
    const chainHash = sha256(`${prev?.chainHash ?? 'genesis'}|${seq}|${type}|${contentHash}`);
    await audit({ actorId, action: 'incident.evidence', resourceId: id, result: 'success', after: { seq, type, summary: clean, contentHash, prevHash: prev?.chainHash ?? null, chainHash } });
    return { seq, type, contentHash, chainHash };
  }

  return {
    async list({ status, limit }, actor) {
      const projectId = await scope.projectClause(actor);
      return prisma.securityIncident.findMany({ where: { ...(status ? { status } : {}), ...(projectId ? { projectId } : {}) }, take: limit, orderBy: { updatedAt: 'desc' }, include: { assignments: true } });
    },

    async get(id, actor) {
      const inc = await loadVisible(id, actor);
      return { ...inc, ownerId: currentOwner(inc) };
    },

    async create(input, actor) {
      await requireManager(actor);
      const inc = await prisma.securityIncident.create({ data: { status: 'detected', severity: input.severity, title: input.title, detectedAt: now() } });
      await audit({ actorId: actor.id, action: 'incident.create', resourceId: inc.id, result: 'success', after: { severity: input.severity, title: input.title } });
      return inc;
    },

    /** System entry point used by the Wazuh sync. Deduplicates against open incidents with the same title. */
    async openFromEvent({ event, title }) {
      const open = await prisma.securityIncident.findFirst({ where: { title, status: { not: 'closed' } } });
      const inc = open ?? (await prisma.securityIncident.create({ data: { status: 'detected', severity: event.severity, title, detectedAt: event.occurredAt ?? now() } }));
      if (!open) await audit({ action: 'incident.create', resourceId: inc.id, result: 'success', after: { severity: event.severity, title, source: 'wazuh' } });
      await addEvidence(inc.id, { type: 'event_ref', summary: `security_event ${event.id} (${event.category}, ${event.severity})` }, null);
      return inc;
    },

    async transition(id, { to, note }, actor) {
      await requireManager(actor);
      const inc = await load(id);
      requireOwnership(inc, actor);
      if (!INCIDENT_TRANSITIONS[inc.status]?.includes(to)) {
        throw new AppError(409, 'INVALID_INCIDENT_TRANSITION', `Cannot move incident from ${inc.status} to ${to}`);
      }
      if (to === 'assigned') throw new AppError(409, 'USE_ASSIGN', 'Use the assign action to set an owner');
      if (to === 'assigned' || to === 'investigating') {
        if (!currentOwner(inc)) throw new AppError(409, 'OWNER_REQUIRED', 'Incident needs an owner first');
      }
      if (to === 'closed') {
        if (!note) throw new AppError(422, 'RESOLUTION_NOTE_REQUIRED', 'A resolution note is required to close');
        if (inc.severity === 'critical' && !actor.isOwner) throw new AppError(403, 'OWNER_CLOSE_REQUIRED', 'Critical incidents are closed by the Owner');
      }
      const at = now();
      const updated = await prisma.securityIncident.update({ where: { id }, data: { status: to, ...(to === 'closed' ? { closedAt: at } : {}) } });
      await audit({ actorId: actor.id, action: 'incident.transition', resourceId: id, result: 'success', before: { status: inc.status }, after: { status: to, at: at.toISOString(), severity: inc.severity, ownerId: currentOwner(inc), note: note ? scrub(note) : null } });
      return updated;
    },

    async assign(id, { userId }, actor) {
      await requireManager(actor);
      const inc = await load(id);
      requireOwnership(inc, actor);
      if (inc.status === 'closed') throw new AppError(409, 'INCIDENT_CLOSED', 'Closed incidents cannot be assigned');
      if (!['triaged', 'assigned', 'investigating', 'contained'].includes(inc.status)) {
        throw new AppError(409, 'INVALID_INCIDENT_TRANSITION', `Cannot assign an incident in state ${inc.status}`);
      }
      const user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user || user.disabledAt || user.status !== 'active') throw new AppError(422, 'ASSIGNEE_INVALID', 'Assignee does not exist or is disabled');
      await prisma.incidentAssignment.create({ data: { incidentId: id, userId } });
      if (userId !== actor.id) {
        await notify(
          { userId, type: 'incident.assigned', title: `Incident assigned: ${inc.title ?? id}`, resourceType: 'incident', resourceId: id },
          { prisma },
        );
      }
      const updated = inc.status === 'triaged' ? await prisma.securityIncident.update({ where: { id }, data: { status: 'assigned' } }) : inc;
      await audit({ actorId: actor.id, action: 'incident.assign', resourceId: id, result: 'success', before: { ownerId: currentOwner(inc) }, after: { ownerId: userId, at: now().toISOString() } });
      return updated;
    },

    async addEvidence(id, input, actor) {
      await requireManager(actor);
      const inc = await load(id);
      if (inc.status === 'closed') throw new AppError(409, 'INCIDENT_CLOSED', 'Evidence cannot be added to a closed incident');
      requireOwnership(inc, actor);
      return addEvidence(id, input, actor.id);
    },

    /** Evidence is append-only; the hash chain makes removal or edits detectable. */
    async verifyEvidence(id, actor) {
      await loadVisible(id, actor);
      const rows = await prisma.auditEvent.findMany({ where: { resourceType: 'incident', resourceId: id, action: 'incident.evidence' }, orderBy: { occurredAt: 'asc' } });
      let prev = null;
      for (const r of rows) {
        const e = r.afterJson;
        const expect = sha256(`${prev ?? 'genesis'}|${e.seq}|${e.type}|${sha256(e.summary)}`);
        if (e.prevHash !== prev || e.chainHash !== expect || e.contentHash !== sha256(e.summary)) return { intact: false, brokenAt: e.seq, count: rows.length };
        prev = e.chainHash;
      }
      return { intact: true, count: rows.length };
    },

    async timeline(id, actor) {
      await loadVisible(id, actor);
      return prisma.auditEvent.findMany({ where: { resourceType: 'incident', resourceId: id }, orderBy: { occurredAt: 'asc' } });
    },

    /** Severity can only be raised, with a reason; it is never lowered silently. */
    async escalate(id, { severity, reason }, actor) {
      await requireManager(actor);
      const inc = await load(id);
      requireOwnership(inc, actor);
      if (RANK[severity] <= RANK[inc.severity]) throw new AppError(409, 'SEVERITY_NOT_HIGHER', 'Severity can only be raised');
      const updated = await prisma.securityIncident.update({ where: { id }, data: { severity } });
      await audit({ actorId: actor.id, action: 'incident.escalate', resourceId: id, result: 'success', before: { severity: inc.severity }, after: { severity, reason: scrub(reason), at: now().toISOString() } });
      return updated;
    },

    /** Reopen policy: closed incidents reopen within 14 days; later recurrence needs a new incident. */
    async reopen(id, { reason }, actor) {
      await requireManager(actor);
      const inc = await load(id);
      if (inc.status !== 'closed') throw new AppError(409, 'NOT_CLOSED', 'Only closed incidents can be reopened');
      if (now().getTime() - new Date(inc.closedAt).getTime() > REOPEN_WINDOW_MS) {
        throw new AppError(409, 'REOPEN_WINDOW_EXPIRED', 'Reopen window has passed; open a new incident');
      }
      if (!actor.isOwner && currentOwner(inc) !== actor.id) throw new AppError(403, 'NOT_INCIDENT_OWNER', 'Only the owner can reopen');
      const updated = await prisma.securityIncident.update({ where: { id }, data: { status: 'investigating', closedAt: null } });
      await audit({ actorId: actor.id, action: 'incident.reopen', resourceId: id, result: 'success', before: { status: 'closed', closedAt: inc.closedAt }, after: { status: 'investigating', reason: scrub(reason), at: now().toISOString() } });
      return updated;
    },
  };
}
