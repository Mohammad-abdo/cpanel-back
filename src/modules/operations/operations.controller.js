export function createOperationsController(operationsService) {
  return {
    async enqueue(req, res) {
      const { job, replayed } = await operationsService.enqueue(req.validated.body, req.user);
      res.status(replayed ? 200 : 202).json({ data: job, replayed });
    },

    async get(req, res) {
      const job = await operationsService.getById(req.validated.params.id, req.user);
      res.status(200).json({ data: job });
    },

    async cancel(req, res) {
      const job = await operationsService.cancel(req.validated.params.id, req.user);
      res.status(200).json({ data: job });
    },

    async approve(req, res) {
      const job = await operationsService.decide(req.validated.params.id, 'approve', req.validated.body, req.user);
      res.status(200).json({ data: job });
    },

    async deny(req, res) {
      const job = await operationsService.decide(req.validated.params.id, 'deny', req.validated.body, req.user);
      res.status(200).json({ data: job });
    },

    async execute(req, res) {
      const job = await operationsService.execute(req.validated.params.id, req.user);
      res.status(200).json({ data: job });
    },

    async impact(req, res) {
      const impact = await operationsService.impactPreview(req.validated.params.id, req.user);
      res.status(200).json({ data: impact });
    },

    async listApprovals(req, res) {
      const rows = await operationsService.listApprovals(req.validated.query, req.user);
      res.status(200).json({ data: rows });
    },
  };
}
