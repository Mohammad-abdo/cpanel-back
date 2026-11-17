import { respond } from '../platform/platform.http.js';

export function createCronController(svc) {
  return {
    async commands(_req, res) {
      res.status(200).json({ data: svc.commands() });
    },
    async preview(req, res) {
      res.status(200).json({ data: svc.previewSchedule(req.validated.body) });
    },
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.validated.params.projectId, req.user) });
    },
    async create(req, res) {
      respond(res, await svc.create(req.validated.params.projectId, req.validated.body, req.user), 201);
    },
    async update(req, res) {
      const { projectId, jobId } = req.validated.params;
      respond(res, await svc.update(projectId, jobId, req.validated.body, req.user));
    },
    async remove(req, res) {
      const { projectId, jobId } = req.validated.params;
      res.status(200).json({ data: await svc.remove(projectId, jobId, req.user) });
    },
    async run(req, res) {
      const { projectId, jobId } = req.validated.params;
      respond(res, await svc.runNow(projectId, jobId, req.validated.body, req.user));
    },
    async runs(req, res) {
      const { projectId, jobId } = req.validated.params;
      res.status(200).json({ data: await svc.runs(projectId, jobId, req.validated.query, req.user) });
    },
  };
}
