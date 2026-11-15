import { respond } from '../platform/platform.http.js';

export function createCertificatesController(svc) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.validated.query, req.user) });
    },
    async expiring(req, res) {
      res.status(200).json({ data: await svc.expiring(req.validated.query, req.user) });
    },
    async issue(req, res) {
      respond(res, await svc.issue(req.validated.params.domainId, req.validated.body, req.user), 201);
    },
    async renew(req, res) {
      res.status(200).json({ data: await svc.renew(req.validated.params.id, req.validated.body, req.user) });
    },
  };
}
