import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';

/**
 * Read visibility for projects: Owner, project member, or holder of any active grant on the project.
 * Mutations still require exact-scope permissions (rbac.can) or the Owner.
 */
export function createProjectAccess({ prisma, now = () => new Date() }) {
  const scope = createScope({ prisma, now });
  const canView = (actor, projectId) => scope.canSeeProject(actor, projectId);

  return {
    canView,
    async requireView(actor, projectId) {
      if (!(await canView(actor, projectId))) {
        throw new AppError(403, 'FORBIDDEN', 'No access to this project');
      }
    },
    /** Returns the ids a non-owner may see (members + grants). Owner gets null (= all). */
    async visibleProjectIds(actor) {
      return scope.projectIds(actor);
    },
  };
}
