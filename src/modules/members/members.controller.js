const date = (v) => (v ? new Date(v) : undefined);

export function createMembersController(service) {
  return {
    async profile(req, res) {
      res.status(200).json({ data: await service.profile(req.validated.params.userId, req.user) });
    },
    async analytics(req, res) {
      const q = req.validated.query;
      res.status(200).json({ data: await service.analytics({ from: date(q.from), to: date(q.to) }, req.user) });
    },
    async timeline(req, res) {
      const q = req.validated.query;
      const data = await service.timeline(req.validated.params.userId, { ...q, from: date(q.from), to: date(q.to) }, req.user);
      res.status(200).json({ data });
    },
    async listUnattributed(req, res) {
      const q = req.validated.query;
      res.status(200).json({ data: await service.listUnattributed({ ...q, from: date(q.from), to: date(q.to) }, req.user) });
    },
    async listMappings(req, res) {
      res.status(200).json({ data: await service.listMappings(req.user) });
    },
    async mapIdentity(req, res) {
      res.status(201).json({ data: await service.mapIdentity(req.validated.body, req.user) });
    },
    async unmapIdentity(req, res) {
      res.status(200).json({ data: await service.unmapIdentity(req.validated.params.id, req.user) });
    },
  };
}
