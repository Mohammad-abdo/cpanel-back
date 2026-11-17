export function createServerBackupsController(svc) {
  return {
    async getSettings(req, res) {
      res.status(200).json({ data: await svc.getSettings(req.validated.params.serverId, req.user) });
    },
    async putSettings(req, res) {
      res.status(200).json({ data: await svc.putSettings(req.validated.params.serverId, req.validated.body, req.user) });
    },
    async runNow(req, res) {
      res.status(202).json({ data: await svc.runNow(req.validated.params.serverId, req.user) });
    },
  };
}