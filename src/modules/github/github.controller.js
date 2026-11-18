export function createGitHubController(svc) {
  return {
    async getApp(req, res) {
      res.status(200).json({ data: await svc.getApp(req.user) });
    },
    async putApp(req, res) {
      res.status(200).json({ data: await svc.upsertApp(req.validated.body, req.user) });
    },
    async deleteApp(req, res) {
      res.status(200).json({ data: await svc.deleteApp(req.user, req.validated?.body?.approval ?? {}) });
    },
    async rotateSecret(req, res) {
      res.status(200).json({ data: await svc.rotateWebhookSecret(req.user, req.validated.body.approval ?? {}) });
    },
    async manifest(req, res) {
      res.status(200).json({ data: await svc.manifest(req.user) });
    },
    /** GitHub redirects the browser here; on success the browser continues to the dashboard. */
    async callback(req, res) {
      const { code, state } = req.validated.query;
      const out = await svc.completeManifest({ code, state });
      res.redirect(302, out.redirectTo);
    },
    async listInstallations(req, res) {
      res.status(200).json({ data: await svc.listInstallations(req.user, req.validated.query) });
    },
    async listInstallationRepos(req, res) {
      res.status(200).json({ data: await svc.listInstallationRepos(req.user, req.validated?.query ?? {}) });
    },
    async listBranches(req, res) {
      res.status(200).json({ data: await svc.listBranches(req.user, { ...req.validated.params, ...req.validated.query }) });
    },
    async linkProject(req, res) {
      res.status(200).json({ data: await svc.linkProjectRepo(req.validated.params.projectId, req.validated.body, req.user) });
    },
  };
}
