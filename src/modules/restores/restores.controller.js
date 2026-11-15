import { respond } from '../platform/platform.http.js';

export function createRestoresController(svc) {
  return {
    async points(req, res) {
      res.status(200).json({ data: await svc.listRestorePoints(req.validated.query, req.user) });
    },
    async get(req, res) {
      res.status(200).json({ data: await svc.get(req.validated.params.id, req.user) });
    },
    async request(req, res) {
      respond(res, await svc.request(req.validated.body, req.user));
    },
    async execute(req, res) {
      res.status(200).json({ data: await svc.execute(req.validated.params.id, req.validated.body, req.user) });
    },
  };
}
