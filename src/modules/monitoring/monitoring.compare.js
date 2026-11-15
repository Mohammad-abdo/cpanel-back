import { PERMISSIONS } from '../../common/permission-catalog.js';
import { AppError } from '../../common/errors/app-error.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { redactText } from '../logs/logs.redaction.js';

/** Timing correlation is not proof of fault; responses never name a person as the cause. */
export const ATTRIBUTION_NOTE =
  'Error timing relative to a deployment is a correlation only. It does not identify who caused an error.';

/** Query-time grouping key: message with ids, hex and numbers collapsed (applied after redaction). */
export function normalizeMessage(message) {
  return redactText(String(message ?? ''))
    .split('\n')[0]
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '<id>')
    .replace(/\b0x[0-9a-f]+\b/gi, '<hex>')
    .replace(/\b[0-9a-f]{16,}\b/gi, '<hex>')
    .replace(/"[^"]{0,200}"|'[^']{0,200}'/g, '<str>')
    .replace(/\d+/g, '<n>')
    .trim()
    .slice(0, 100);
}

/**
 * Compares error groups in equal windows before and after a deployment finished.
 * Output is about error groups only; no actor or committer is attached (no developer blame).
 */
export function createComparisonService({ prisma, store, now = () => new Date(), rbac = null }) {
  const access = rbac ?? createRbacService({ prisma, now });

  async function authorize(actor, projectId, environmentId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (actor.isOwner) return;
    const ok = await access.can(actor, {
      permissionKey: PERMISSIONS.PROJECT_LOGS_READ,
      resourceType: 'project',
      resourceId: projectId,
      environmentId,
    });
    if (!ok) throw new AppError(403, 'FORBIDDEN', 'No access for this project and environment');
  }

  const tally = (rows) => {
    const m = new Map();
    for (const e of rows) {
      const key = normalizeMessage(e.message);
      m.set(key, (m.get(key) ?? 0) + 1);
    }
    return m;
  };

  return {
    async compareDeployment(deploymentId, { windowMinutes = 30 } = {}, actor) {
      const dep = await prisma.deployment.findUnique({ where: { id: deploymentId } });
      if (!dep) throw new AppError(404, 'DEPLOYMENT_NOT_FOUND', 'Deployment not found');
      await authorize(actor, dep.projectId, dep.environmentId);
      const pivot = new Date(dep.updatedAt ?? dep.createdAt);
      const win = windowMinutes * 60000;
      const base = { projectId: dep.projectId, environmentId: dep.environmentId, minLevel: 'error' };
      const before = store.query({ ...base, from: new Date(pivot.getTime() - win), to: pivot }, { limit: 5000 });
      const after = store.query({ ...base, from: pivot, to: new Date(pivot.getTime() + win) }, { limit: 5000 });
      const b = tally(before);
      const a = tally(after);
      const groups = [...new Set([...a.keys(), ...b.keys()])].map((title) => {
        const bc = b.get(title) ?? 0;
        const ac = a.get(title) ?? 0;
        const change = bc === 0 ? 'new' : ac === 0 ? 'gone' : ac > bc ? 'increased' : ac < bc ? 'decreased' : 'unchanged';
        return { title, before: bc, after: ac, change };
      });
      return {
        deploymentId,
        commitSha: dep.commitSha ?? null,
        pivotAt: pivot.toISOString(),
        windowMinutes,
        totals: { before: before.length, after: after.length },
        groups: groups.sort((x, y) => y.after - x.after),
        attributionNote: ATTRIBUTION_NOTE,
      };
    },
  };
}
