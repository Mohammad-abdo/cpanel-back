export function createMailboxesController(service) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await service.list(req.validated.query, req.user) });
    },
    async get(req, res) {
      res.status(200).json({ data: await service.get(req.validated.params.id, req.user) });
    },
    async create(req, res) {
      res.status(201).json({ data: await service.create(req.validated.body, req.user) });
    },
    async update(req, res) {
      res.status(200).json({ data: await service.update(req.validated.params.id, req.validated.body, req.user) });
    },
    async setPassword(req, res) {
      res.status(200).json({ data: await service.setPassword(req.validated.params.id, req.validated.body, req.user) });
    },
    async suspend(req, res) {
      res.status(200).json({ data: await service.suspend(req.validated.params.id, req.validated.body, req.user) });
    },
    async unsuspend(req, res) {
      res.status(200).json({ data: await service.unsuspend(req.validated.params.id, req.validated.body, req.user) });
    },
    async remove(req, res) {
      res.status(200).json({ data: await service.remove(req.validated.params.id, req.validated.query, req.user) });
    },
    async auditEvents(req, res) {
      res.status(200).json({ data: await service.auditEvents(req.validated.params.id, req.validated.query, req.user) });
    },
  };
}
