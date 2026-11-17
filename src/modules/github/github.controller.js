export function createGitHubController(svc) {
  return {
    async getApp(req, res) {
      res.status(200).json({ data: await svc.getApp(req.user) });
    },
    async putApp(req, res) {
      res.status(200).json({ data: await svc.upsertApp(req.validated.body, req.user) });
    },
    async deleteApp(req, res) {
      res.status(200).json({ data: await svc.deleteApp(req.user) });
    },
    async manifest(req, res) {
      res.status(200).json({ data: await svc.manifest(req.user) });
    },
    async listInstallationRepos(req, res) {
      res.status(200).json({ data: await svc.listInstallationRepos(req.user) });
    },
  };
}