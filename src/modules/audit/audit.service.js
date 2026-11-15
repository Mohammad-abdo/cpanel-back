import { randomUUID } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';

const SECRET_KEY = /pass(word)?|secret|token|authorization|cookie|api[-_]?key/i;

/** Strip secret-looking values before anything is stored (required.md: redact before storage). */
export function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, SECRET_KEY.test(k) ? '[REDACTED]' : redact(v)]),
    );
  }
  return value;
}

export function createAuditService({ prisma, now = () => new Date(), rbac = null }) {
  return {
    async record(event) {
      return prisma.auditEvent.create({
        data: {
          actorId: event.actorId ?? null,
          actorType: event.actorId ? 'user' : 'system',
          action: event.action,
          resourceType: event.resourceType,
          resourceId: event.resourceId ?? null,
          environmentId: event.environmentId ?? null,
          result: event.result,
          correlationId: event.correlationId ?? randomUUID(),
          beforeJson: event.before ? redact(event.before) : event.metadata ? redact(event.metadata) : undefined,
          afterJson: event.after ? redact(event.after) : undefined,
          occurredAt: event.occurredAt ? new Date(event.occurredAt) : now(),
        },
      });
    },

    async list({ limit, cursor, resourceType, actorId, result, action, from, to }) {
      return prisma.auditEvent.findMany({
        where: {
          ...(resourceType ? { resourceType } : {}),
          ...(actorId ? { actorId } : {}),
          ...(result ? { result } : {}),
          ...(action ? { action: { startsWith: action } } : {}),
          ...(from || to
            ? { occurredAt: { ...(from ? { gte: new Date(from) } : {}), ...(to ? { lt: new Date(to) } : {}) } }
            : {}),
        },
        include: { actor: { select: { id: true, displayName: true, email: true } } },
        take: limit,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        orderBy: { occurredAt: 'desc' },
      });
    },

    async requirePermission(actor, permission) {
      if (!actor) {
        throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      }
      if (actor.isOwner) return true;
      const allowed = rbac
        ? await rbac.can(actor, { permissionKey: permission, resourceType: 'audit', resourceId: 'all' })
        : false;
      if (!allowed) throw new AppError(403, 'FORBIDDEN', 'Insufficient permission');
      return true;
    },
  };
}
