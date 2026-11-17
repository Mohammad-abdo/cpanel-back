export function createUptimeController(service) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await service.list(req.user, req.validated?.query ?? {}) });
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
    async checkNow(req, res) {
      res.status(200).json({ data: await service.checkNow(req.validated.params.id, req.user) });
    },
  };
}