import { respond } from '../platform/platform.http.js';

export function createDatabasesController(svc) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.validated.query, req.user) });
    },
    async instances(req, res) {
      res.status(200).json({ data: await svc.listInstances(req.user) });
    },
    async createInstance(req, res) {
      respond(res, await svc.createInstance(req.validated.body, req.user), 201);
    },
    async create(req, res) {
      respond(res, await svc.create(req.validated.body, req.user), 201);
    },
    async createUser(req, res) {
      respond(res, await svc.createUser(req.validated.params.id, req.validated.body, req.user), 201);
    },
    async drop(req, res) {
      respond(res, await svc.drop(req.validated.params.id, req.validated.body, req.user));
    },
  };
}
