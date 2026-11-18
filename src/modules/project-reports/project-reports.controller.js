export function createProjectReportsController(service) {
  return {
    async report(req, res) {
      const { id } = req.validated.params;
      res.status(200).json({ data: await service.getReport(id, req.validated.query, req.user) });
    },
    async export(req, res) {
      const { id } = req.validated.params;
      const file = await service.exportReport(id, req.validated.query, req.user);
      res.setHeader('Content-Type', file.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).send(file.body);
    },
    async overview(req, res) {
      res.status(200).json({ data: await service.projectsOverview(req.validated.query, req.user) });
    },
  };
}
