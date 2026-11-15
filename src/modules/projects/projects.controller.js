export function createProjectsController(projectsService) {
  return {
    async list(req, res) {
      const rows = await projectsService.list(req.validated.query, req.user);
      res.status(200).json({ data: rows });
    },

    async get(req, res) {
      const row = await projectsService.getById(req.validated.params.id, req.user);
      res.status(200).json({ data: row });
    },

    async overview(req, res) {
      const result = await projectsService.overview(req.validated.params.id, req.validated.query, req.user);
      res.status(200).json({ data: result });
    },

    async members(req, res) {
      const rows = await projectsService.members(req.validated.params.id, req.user);
      res.status(200).json({ data: rows });
    },

    async teams(req, res) {
      res.status(200).json({ data: await projectsService.teams(req.validated.params.id, req.user) });
    },

    async linkTeam(req, res) {
      res.status(201).json({ data: await projectsService.linkTeam(req.validated.params.id, req.validated.body, req.user) });
    },

    async unlinkTeam(req, res) {
      const { id, teamId } = req.validated.params;
      res.status(200).json({ data: await projectsService.unlinkTeam(id, teamId, req.user) });
    },

    async addMember(req, res) {
      res.status(201).json({ data: await projectsService.addMember(req.validated.params.id, req.validated.body, req.user) });
    },

    async changeRole(req, res) {
      const { id, userId } = req.validated.params;
      res.status(200).json({ data: await projectsService.changeRole(id, userId, req.validated.body, req.user) });
    },

    async removeMember(req, res) {
      const { id, userId } = req.validated.params;
      res.status(200).json({ data: await projectsService.removeMember(id, userId, req.user) });
    },

    async create(req, res) {
      const row = await projectsService.create(req.validated.body, req.user);
      res.status(201).json({ data: row });
    },

    async discover(req, res) {
      const result = await projectsService.discover(req.validated.body, req.user);
      res.status(200).json({ data: result });
    },

    async link(req, res) {
      const row = await projectsService.link(req.validated.params.id, req.validated.body, req.user);
      res.status(200).json({ data: row });
    },

    async configure(req, res) {
      const row = await projectsService.configure(req.validated.params.id, req.validated.body, req.user);
      res.status(200).json({ data: row });
    },

    async lifecycle(req, res) {
      const { id, action } = req.validated.params;
      const result = await projectsService.lifecycle(id, action, req.validated.body, req.user);
      res.status(result.replayed ? 200 : 202).json({ data: result });
    },

    async restartImpact(req, res) {
      const result = await projectsService.restartImpact(req.validated.params.id, req.user);
      res.status(200).json({ data: result });
    },

    async archive(req, res) {
      const row = await projectsService.archive(req.validated.params.id, req.validated.body, req.user);
      res.status(200).json({ data: row });
    },
  };
}
