export function createAgentsController(agentsService) {
  return {
    async enroll(req, res) {
      const result = await agentsService.enroll(req.validated.body);
      res.status(201).json({ data: result });
    },

    async report(req, res) {
      const result = await agentsService.report(req.agent, req.validated.body);
      res.status(202).json({ data: result });
    },

    async revoke(req, res) {
      const result = await agentsService.revoke(req.validated.params.id, req.user);
      res.status(200).json({ data: result });
    },
  };
}
