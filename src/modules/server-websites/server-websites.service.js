import { AppError } from '../../common/errors/app-error.js';
import { parseWebsitesOutput, WEBSITES_SCRIPT } from './server-websites.scripts.js';

export function createServerWebsitesService({ prisma, serverAccessService = null, now = () => new Date() }) {
  function requireOwner(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can list live websites');
  }

  return {
    /** Live Apache/nginx vhost discovery over SSH (read-only). */
    async list(serverId, actor) {
      requireOwner(actor);
      const server = await prisma.server.findUnique({ where: { id: serverId } });
      if (!server || server.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
      if (!serverAccessService?.runRemote) throw new AppError(500, 'SSH_UNAVAILABLE', 'Server access is not wired');
      const res = await serverAccessService.runRemote(serverId, async ({ run }) =>
        run(WEBSITES_SCRIPT, { timeoutMs: 45_000, maxBytes: 512 * 1024 }),
      );
      if (res.timedOut) throw new AppError(504, 'WEBSITES_TIMEOUT', 'Website discovery over SSH timed out');
      const parsed = parseWebsitesOutput(res.stdout);
      return { ...parsed, collectedAt: now().toISOString() };
    },
  };
}
