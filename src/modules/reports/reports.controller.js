export function createReportsController(service) {
  return {
    async listDefinitions(req, res) {
      res.status(200).json({ data: await service.listDefinitions(req.validated.query) });
    },
    async createDefinition(req, res) {
      res.status(201).json({ data: await service.createDefinition(req.validated.body, req.user) });
    },
    async preview(req, res) {
      res.status(200).json({ data: await service.preview(req.validated.query, req.user) });
    },
    async createRun(req, res) {
      const { run, artifacts, report } = await service.createRun(req.validated.body, req.user);
      res.status(201).json({ data: { run, artifacts, report } });
    },
    async getRun(req, res) {
      res.status(200).json({ data: await service.getRun(req.validated.params.id, req.user) });
    },
    async download(req, res) {
      const file = await service.downloadArtifact(req.validated.params.id, req.user);
      res.setHeader('Content-Type', file.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${file.filename}"`);
      res.status(200).send(file.body);
    },
    async createSchedule(req, res) {
      res.status(201).json({ data: await service.createSchedule(req.validated.body, req.user) });
    },
    async listSchedules(req, res) {
      res.status(200).json({ data: await service.listSchedules(req.user) });
    },
    async setScheduleEnabled(req, res) {
      const data = await service.setScheduleEnabled(req.validated.params.id, req.validated.body.enabled, req.user);
      res.status(200).json({ data });
    },
  };
}
