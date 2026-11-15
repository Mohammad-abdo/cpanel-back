export function createProjectEnvController(svc) {
  const p = (req) => req.validated.params;
  return {
    async list(req, res) {
      res.status(200).json({ data: await svc.list(p(req).id, p(req).envId, req.user) });
    },
    async set(req, res) {
      res.status(200).json({ data: await svc.set(p(req).id, p(req).envId, req.validated.body, req.user) });
    },
    async importText(req, res) {
      res.status(200).json({ data: await svc.importText(p(req).id, p(req).envId, req.validated.body, req.user) });
    },
    async reveal(req, res) {
      res.set('Cache-Control', 'no-store');
      res.status(200).json({ data: await svc.reveal(p(req).id, p(req).envId, p(req).key, req.user) });
    },
    async remove(req, res) {
      res.status(200).json({ data: await svc.remove(p(req).id, p(req).envId, p(req).key, req.user) });
    },
    async exportText(req, res) {
      res.set('Cache-Control', 'no-store');
      res.status(200).json({ data: await svc.exportText(p(req).id, p(req).envId, req.user) });
    },
    async writeToServer(req, res) {
      res.status(200).json({ data: await svc.writeToServer(p(req).id, p(req).envId, req.validated.body, req.user) });
    },
    async addEnvironment(req, res) {
      res.status(201).json({ data: await svc.addEnvironment(p(req).id, req.validated.body, req.user) });
    },
  };
}
