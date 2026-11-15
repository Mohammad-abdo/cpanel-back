export function createTeamsController(teamsService) {
  return {
    async create(req, res) {
      const row = await teamsService.create(req.validated.body, req.user);
      res.status(201).json({ data: row });
    },

    async list(req, res) {
      const rows = await teamsService.list(req.user);
      res.status(200).json({ data: rows });
    },

    async addMember(req, res) {
      const row = await teamsService.addMember(req.validated.params.id, req.validated.body, req.user);
      res.status(201).json({ data: row });
    },

    async removeMember(req, res) {
      const { id, userId } = req.validated.params;
      const result = await teamsService.removeMember(id, userId, req.user);
      res.status(200).json({ data: result });
    },
  };
}
