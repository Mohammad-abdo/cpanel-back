export function createRbacController(rbacService) {
  return {
    async grant(req, res) {
      const row = await rbacService.grant(req.validated.body, req.user);
      res.status(201).json({ data: row });
    },

    async revoke(req, res) {
      const row = await rbacService.revoke(req.validated.params.id, req.user);
      res.status(200).json({ data: row });
    },

    async list(req, res) {
      const rows = await rbacService.list(req.validated.query, req.user);
      res.status(200).json({ data: rows });
    },
  };
}
