import { respond } from '../platform/platform.http.js';

export function createDomainsController(domainsService) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await domainsService.list(req.validated.query, req.user) });
    },
    async get(req, res) {
      res.status(200).json({ data: await domainsService.getById(req.validated.params.id, req.user) });
    },
    async create(req, res) {
      res.status(201).json({ data: await domainsService.create(req.validated.body, req.user) });
    },
    async previewVhost(req, res) {
      res.status(200).json({ data: await domainsService.previewVhost(req.validated.params.id, req.validated.body, req.user) });
    },
    async applyVhost(req, res) {
      respond(res, await domainsService.applyVhost(req.validated.params.id, req.validated.body, req.user));
    },
    async changeDns(req, res) {
      respond(res, await domainsService.changeDns(req.validated.params.id, req.validated.body, req.user));
    },
  };
}
