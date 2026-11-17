import { respond } from '../platform/platform.http.js';

export function createServerCleanupController(svc) {
  return {
    async tasks(req, res) {
      res.status(200).json({ data: await svc.tasks(req.validated.params.serverId, req.user) });
    },
    async preview(req, res) {
      res.status(200).json({ data: await svc.preview(req.validated.params.serverId, req.validated.body, req.user) });
    },
    async apply(req, res) {
      respond(res, await svc.apply(req.validated.params.serverId, req.validated.body, req.user));
    },
  };
}
