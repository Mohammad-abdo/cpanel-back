export function createSecurityController(securityService) {
  return {
    async listIncidents(req, res) {
      res.status(200).json({ data: await securityService.listIncidents(req.validated.query, req.user) });
    },
    async listEvents(req, res) {
      res.status(200).json({ data: await securityService.listEvents(req.validated.query, req.user) });
    },
    async summary(req, res) {
      res.status(200).json({ data: await securityService.summary(req.user) });
    },
    async connection(req, res) {
      res.status(200).json({ data: await securityService.connection() });
    },
    async sync(req, res) {
      res.status(200).json({ data: await securityService.sync(req.validated.body, req.user) });
    },
  };
}
