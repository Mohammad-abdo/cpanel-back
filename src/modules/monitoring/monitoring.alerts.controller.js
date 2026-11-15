export function createAlertsController(alertsService, comparisonService) {
  return {
    async createRule(req, res) {
      res.status(201).json({ data: await alertsService.createRule(req.validated.body, req.user) });
    },
    async listRules(req, res) {
      res.status(200).json({ data: await alertsService.listRules(req.validated.query, req.user) });
    },
    async evaluateRule(req, res) {
      const rules = await alertsService.listRules({ projectId: req.validated.query.projectId }, req.user);
      const rule = rules.find((r) => r.id === req.validated.params.id);
      if (!rule) {
        res.status(404).json({ error: { code: 'RULE_NOT_FOUND', message: 'Rule not found' } });
        return;
      }
      res.status(200).json({ data: await alertsService.evaluateRule(rule) });
    },
    async listAlerts(req, res) {
      res.status(200).json({ data: await alertsService.list(req.validated.query, req.user) });
    },
    async acknowledge(req, res) {
      res.status(200).json({ data: await alertsService.acknowledge(req.validated.params.id, req.validated.body, req.user) });
    },
    async resolve(req, res) {
      res.status(200).json({ data: await alertsService.resolve(req.validated.params.id, req.validated.body, req.user) });
    },
    async compare(req, res) {
      const data = await comparisonService.compareDeployment(req.validated.params.id, req.validated.query, req.user);
      res.status(200).json({ data });
    },
  };
}
