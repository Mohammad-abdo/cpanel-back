export function createServersController(serversService) {
  return {
    async list(req, res) {
      const rows = await serversService.list(req.validated.query, req.user);
      res.status(200).json({ data: rows });
    },

    async services(req, res) {
      res.status(200).json({ data: await serversService.services(req.validated.query, req.user) });
    },

    async ports(req, res) {
      res.status(200).json({ data: await serversService.ports(req.validated.query, req.user) });
    },

    async runtimes(req, res) {
      res.status(200).json({ data: await serversService.runtimes(req.user) });
    },

    async get(req, res) {
      const row = await serversService.getById(req.validated.params.id, req.user);
      res.status(200).json({ data: row });
    },

    async create(req, res) {
      const row = await serversService.create(req.validated.body, req.user);
      res.status(201).json({ data: row });
    },

    async update(req, res) {
      const row = await serversService.update(req.validated.params.id, req.validated.body, req.user);
      res.status(200).json({ data: row });
    },

    async archive(req, res) {
      const row = await serversService.archive(req.validated.params.id, req.validated.body, req.user);
      res.status(200).json({ data: row });
    },

    async issueEnrollment(req, res) {
      const result = await serversService.issueEnrollment(req.validated.params.id, req.user);
      res.status(201).json({ data: result });
    },

    async metrics(req, res) {
      const rows = await serversService.metrics(req.validated.params.id, req.validated.query, req.user);
      res.status(200).json({ data: rows });
    },
  };
}
