export function createAlertChannelsController(service) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await service.list(req.user) });
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
    async remove(req, res) {
      res.status(200).json({ data: await service.remove(req.validated.params.id, req.user) });
    },
    async test(req, res) {
      res.status(200).json({ data: await service.test(req.validated.params.id, req.user) });
    },
    async deliveries(req, res) {
      res.status(200).json({ data: await service.deliveries(req.validated.params.id, req.validated.query, req.user) });
    },
  };
}
