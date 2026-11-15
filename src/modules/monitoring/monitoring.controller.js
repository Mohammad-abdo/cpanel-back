export function createMonitoringController(monitoringService, errorsService = null) {
  return {
    async serverHealth(req, res) {
      const data = await monitoringService.getServerHealth(req.validated.params.id, req.user);
      res.status(200).json({ data });
    },

    async fleet(req, res) {
      const data = await monitoringService.fleet(req.validated.query, req.user);
      res.status(200).json({ data });
    },

    async listErrors(req, res) {
      if (!errorsService) {
        res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: 'Error groups unavailable' } });
        return;
      }
      res.status(200).json({ data: await errorsService.list(req.validated.query, req.user) });
    },

    async getError(req, res) {
      if (!errorsService) {
        res.status(501).json({ error: { code: 'NOT_IMPLEMENTED', message: 'Error groups unavailable' } });
        return;
      }
      res.status(200).json({ data: await errorsService.getById(req.validated.params.id, req.user) });
    },
  };
}
