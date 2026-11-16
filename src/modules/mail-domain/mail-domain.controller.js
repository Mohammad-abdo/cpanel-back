export function createMailDomainController(service) {
  return {
    async get(req, res) {
      res.status(200).json({ data: await service.get(req.validated.params.id, req.user) });
    },
    async enable(req, res) {
      res.status(200).json({ data: await service.enable(req.validated.params.id, req.validated.body, req.user) });
    },
    async disable(req, res) {
      res.status(200).json({ data: await service.disable(req.validated.params.id, req.validated.body, req.user) });
    },
    async update(req, res) {
      res.status(200).json({ data: await service.update(req.validated.params.id, req.validated.body, req.user) });
    },
    async dns(req, res) {
      res.status(200).json({ data: await service.dns(req.validated.params.id, req.user) });
    },
  };
}
