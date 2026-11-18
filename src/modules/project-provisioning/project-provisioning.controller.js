import { respond } from '../platform/platform.http.js';

export function createProjectProvisioningController(svc) {
  return {
    async config(req, res) {
      res.status(200).json({ data: svc.config(req.user) });
    },
    async preview(req, res) {
      res.status(200).json({ data: await svc.preview(req.validated.body, req.user) });
    },
    async createRun(req, res) {
      respond(res, await svc.createRun(req.validated.body, req.user), 201);
    },
    async listRuns(req, res) {
      res.status(200).json({ data: await svc.listRuns(req.validated.query, req.user) });
    },
    async getRun(req, res) {
      res.status(200).json({ data: await svc.getRun(req.validated.params.id, req.user) });
    },
    async resume(req, res) {
      respond(res, await svc.resume(req.validated.params.id, req.validated.body, req.user));
    },
    async redeploy(req, res) {
      respond(res, await svc.redeploy(req.validated.params.projectId, req.validated.body, req.user), 201);
    },
    async updateVhost(req, res) {
      respond(res, await svc.updateVhost(req.validated.params.projectId, req.validated.body, req.user));
    },
    async decommission(req, res) {
      respond(res, await svc.decommission(req.validated.params.projectId, req.validated.body, req.user));
    },
    async serverState(req, res) {
      res.status(200).json({ data: await svc.serverState(req.validated.params.projectId, req.user) });
    },
  };
}
