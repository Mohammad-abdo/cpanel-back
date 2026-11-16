export function createMailOverviewController(service) {
  return {
    async overview(req, res) {
      res.status(200).json({ data: await service.overview(req.user) });
    },
    async audit(req, res) {
      res.status(200).json({ data: await service.audit(req.validated.query, req.user) });
    },
    async healthSummary(req, res) {
      res.status(200).json({ data: await service.healthSummary(req.user) });
    },
  };
}
