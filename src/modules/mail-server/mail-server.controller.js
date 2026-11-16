import { respond } from '../platform/platform.http.js';

export function createMailServerController(service) {
  return {
    async get(req, res) {
      res.status(200).json({ data: await service.get(req.validated.params.id, req.user) });
    },
    async enable(req, res) {
      res.status(200).json({ data: await service.enable(req.validated.params.id, req.validated.body, req.user) });
    },
    async disable(req, res) {
      res.status(200).json({ data: await service.disable(req.validated.params.id, req.validated.body, req.user) });
    },
    async health(req, res) {
      res.status(200).json({ data: await service.health(req.validated.params.id, req.user) });
    },
    async previewProvision(req, res) {
      res.status(200).json({ data: await service.previewProvision(req.validated.params.id, req.validated.body, req.user) });
    },
    async applyProvision(req, res) {
      respond(res, await service.applyProvision(req.validated.params.id, req.validated.body, req.user));
    },
  };
}
