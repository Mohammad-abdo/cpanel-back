import { createHash } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { createProjectAccess } from '../projects/projects.access.js';
import { redactText } from '../logs/logs.redaction.js';

function fingerprintOf({ message, stack }) {
  const basis = `${redactText(message ?? '')}\n${redactText((stack ?? '').split('\n').slice(0, 8).join('\n'))}`;
  return createHash('sha256').update(basis).digest('hex').slice(0, 32);
}

/**
 * Error groups from ingested error/fatal log entries (TASK-013 slice).
 * Fingerprints are derived after redaction so secrets never enter the group key.
 */
export function createErrorsService({ prisma, now = () => new Date(), auditService = null }) {
  const projects = createProjectAccess({ prisma, now });
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  return {
    async observe({ entry, labels }) {
      if (!labels?.projectId) return null;
      if (entry.level !== 'error' && entry.level !== 'fatal') return null;
      const fingerprint = fingerprintOf(entry);
      const existing = await prisma.errorGroup.findUnique({
        where: { projectId_fingerprint: { projectId: labels.projectId, fingerprint } },
      });
      if (existing) {
        return prisma.errorGroup.update({
          where: { id: existing.id },
          data: { lastSeenAt: entry.ts ?? now(), count: { increment: 1 } },
        });
      }
      return prisma.errorGroup.create({
        data: {
          projectId: labels.projectId,
          fingerprint,
          firstSeenAt: entry.ts ?? now(),
          lastSeenAt: entry.ts ?? now(),
          count: 1,
        },
      });
    },

    async list({ projectId, limit = 50 }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const visible = await projects.visibleProjectIds(actor);
      if (projectId && visible && !visible.includes(projectId)) {
        throw new AppError(403, 'FORBIDDEN', 'No access to this project');
      }
      return prisma.errorGroup.findMany({
        where: {
          ...(projectId ? { projectId } : {}),
          ...(visible && !projectId ? { projectId: { in: visible } } : {}),
        },
        take: limit,
        orderBy: { lastSeenAt: 'desc' },
      });
    },

    async getById(id, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const row = await prisma.errorGroup.findUnique({ where: { id } });
      if (!row) throw new AppError(404, 'ERROR_GROUP_NOT_FOUND', 'Error group not found');
      const visible = await projects.visibleProjectIds(actor);
      if (visible && !visible.includes(row.projectId)) {
        await audit({
          actorId: actor.id,
          action: 'errors.read',
          resourceType: 'error_group',
          resourceId: id,
          result: 'denied',
        });
        throw new AppError(403, 'FORBIDDEN', 'No access to this error group');
      }
      return row;
    },
  };
}
