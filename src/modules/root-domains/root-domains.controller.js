import { respond } from '../platform/platform.http.js';

export function createRootDomainsController(svc) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.user) });
    },
    async connect(req, res) {
      res.status(201).json({ data: await svc.connect(req.validated.body, req.user) });
    },
    async rotateToken(req, res) {
      res.status(200).json({ data: await svc.rotateToken(req.validated.params.id, req.validated.body, req.user) });
    },
    async remove(req, res) {
      res.status(200).json({ data: await svc.remove(req.validated.params.id, req.user) });
    },
    async listRecords(req, res) {
      res.status(200).json({ data: await svc.listRecords(req.validated.params.id, req.validated.query, req.user) });
    },
    async changeRecord(req, res) {
      respond(res, await svc.changeRecord(req.validated.params.id, req.validated.body, req.user));
    },
    async previewWildcard(req, res) {
      res.status(200).json({ data: await svc.previewWildcard(req.validated.params.id, req.validated.body, req.user) });
    },
    async issueWildcard(req, res) {
      respond(res, await svc.issueWildcard(req.validated.params.id, req.validated.body, req.user));
    },
  };
}
