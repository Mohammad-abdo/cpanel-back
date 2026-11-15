export function createDeploymentsController(deploymentsService) {
  return {
    async list(req, res) {
      const rows = await deploymentsService.list(req.validated.query, req.user);
      res.status(200).json({ data: rows });
    },

    async get(req, res) {
      const row = await deploymentsService.getById(req.validated.params.id, req.user);
      res.status(200).json({ data: row });
    },

    async create(req, res) {
      const result = await deploymentsService.create(req.validated.body, req.user);
      res.status(result.replayed ? 200 : 202).json({ data: result });
    },

    async run(req, res) {
      const result = await deploymentsService.run(req.validated.params.id, req.user);
      res.status(200).json({ data: result });
    },

    async rollback(req, res) {
      const result = await deploymentsService.rollback(req.validated.params.id, req.validated.body, req.user);
      res.status(result.replayed ? 200 : 202).json({ data: result });
    },
  };
}
