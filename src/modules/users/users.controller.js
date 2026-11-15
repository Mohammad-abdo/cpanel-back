export function createUsersController(usersService) {
  return {
    async create(req, res) {
      const row = await usersService.create(req.validated.body, req.user);
      res.status(201).json({ data: row });
    },
    async list(req, res) {
      const rows = await usersService.list(req.user, req.validated?.query ?? {});
      res.status(200).json({ data: rows });
    },
    async get(req, res) {
      const row = await usersService.getById(req.validated.params.id, req.user);
      res.status(200).json({ data: row });
    },
    async patch(req, res) {
      const row = await usersService.patch(req.validated.params.id, req.validated.body, req.user);
      res.status(200).json({ data: row });
    },
  };
}
