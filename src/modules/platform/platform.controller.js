import { AppError } from '../../common/errors/app-error.js';

const ownerOnly = (req) => {
  if (!req.user?.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can do this');
};

export function createPlatformController({ platformService, fleet, emergency }) {
  return {
    async listApprovals(req, res) {
      res.status(200).json({ data: await platformService.list(req.validated.query, req.user) });
    },
    async decide(req, res) {
      res.status(200).json({ data: await platformService.decide(req.validated.params.id, req.validated.body, req.user) });
    },
    async fleetOverview(req, res) {
      res.status(200).json({ data: await fleet.overview(req.validated.query) });
    },
    async fleetProbe(req, res) {
      ownerOnly(req);
      res.status(200).json({ data: await fleet.probe(req.validated.body) });
    },
    async breakGlassStatus(req, res) {
      res.status(200).json({ data: await emergency.status() });
    },
    async breakGlassActivate(req, res) {
      res.status(200).json({ data: await emergency.activate(req.validated.body, req.user) });
    },
    async breakGlassEnd(req, res) {
      res.status(200).json({ data: await emergency.deactivate(req.validated.body, req.user) });
    },
    async readiness(req, res) {
      ownerOnly(req);
      res.status(200).json({ data: await emergency.readiness() });
    },
  };
}
