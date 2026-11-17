export function createServerWebsitesController(svc) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.validated.params.serverId, req.user) });
    },
  };
}
