import { respond } from '../platform/platform.http.js';

export function createBackupsController(svc) {
  return {
    async listPolicies(req, res) {
      res.status(200).json({ data: await svc.listPolicies(req.validated.query, req.user) });
    },
    async listRuns(req, res) {
      res.status(200).json({ data: await svc.listRuns(req.validated.query, req.user) });
    },
    async createPolicy(req, res) {
      res.status(201).json({ data: await svc.createPolicy(req.validated.body, req.user) });
    },
    async rpoStatus(req, res) {
      res.status(200).json({ data: await svc.rpoStatus(req.validated.params.id, req.user) });
    },
    async destinationStatus(req, res) {
      res.status(200).json({ data: await svc.destinationStatus(req.validated.params.id, req.user) });
    },
    async run(req, res) {
      res.status(201).json({ data: await svc.runBackup(req.validated.params.id, req.validated.body, req.user) });
    },
    async verifyArtifact(req, res) {
      res.status(200).json({ data: await svc.verifyArtifact(req.validated.params.id, req.user) });
    },
    async planRetention(req, res) {
      res.status(200).json({ data: await svc.planRetention(req.validated.params.id, req.user) });
    },
    async applyRetention(req, res) {
      respond(res, await svc.applyRetention(req.validated.params.id, req.validated.body, req.user));
    },
  };
}
