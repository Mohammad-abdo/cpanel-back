import { respond } from '../platform/platform.http.js';

export function createFirewallController(svc) {
  return {
    async history(req, res) {
      res.status(200).json({ data: await svc.history(req.validated.query, req.user) });
    },
    async rules(req, res) {
      res.status(200).json({ data: await svc.rules(req.validated.params.serverId, req.user) });
    },
    async preview(req, res) {
      res.status(200).json({ data: await svc.preview(req.validated.params.serverId, req.validated.body, req.user) });
    },
    async apply(req, res) {
      respond(res, await svc.apply(req.validated.params.serverId, req.validated.body, req.user));
    },
  };
}
