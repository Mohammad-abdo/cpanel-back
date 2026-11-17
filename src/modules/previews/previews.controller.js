import { respond } from '../platform/platform.http.js';

export function createPreviewsController(svc) {
  return {
    async getSettings(req, res) {
      res.status(200).json({ data: await svc.getSettings(req.validated.params.id, req.user) });
    },
    async updateSettings(req, res) {
      res.status(200).json({ data: await svc.updateSettings(req.validated.params.id, req.validated.body, req.user) });
    },
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.validated.params.id, req.user) });
    },
    async create(req, res) {
      res.status(201).json({ data: await svc.create(req.validated.params.id, req.validated.body, req.user) });
    },
    async expose(req, res) {
      respond(res, await svc.expose(req.validated.params.id, req.validated.params.previewId, req.validated.body, req.user));
    },
    async destroy(req, res) {
      res.status(200).json({ data: await svc.destroy(req.validated.params.id, req.validated.params.previewId, req.user) });
    },
    async extend(req, res) {
      res.status(200).json({ data: await svc.extend(req.validated.params.id, req.validated.params.previewId, req.validated.body, req.user) });
    },
    async resetAuth(req, res) {
      res.status(200).json({ data: await svc.resetAuth(req.validated.params.id, req.validated.params.previewId, req.user) });
    },
  };
}
