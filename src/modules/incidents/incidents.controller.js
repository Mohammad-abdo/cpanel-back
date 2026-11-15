export function createIncidentsController(svc) {
  const id = (req) => req.validated.params.id;
  return {
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.validated.query, req.user) });
    },
    async get(req, res) {
      res.status(200).json({ data: await svc.get(id(req), req.user) });
    },
    async create(req, res) {
      res.status(201).json({ data: await svc.create(req.validated.body, req.user) });
    },
    async transition(req, res) {
      res.status(200).json({ data: await svc.transition(id(req), req.validated.body, req.user) });
    },
    async assign(req, res) {
      res.status(200).json({ data: await svc.assign(id(req), req.validated.body, req.user) });
    },
    async addEvidence(req, res) {
      res.status(201).json({ data: await svc.addEvidence(id(req), req.validated.body, req.user) });
    },
    async verifyEvidence(req, res) {
      res.status(200).json({ data: await svc.verifyEvidence(id(req), req.user) });
    },
    async timeline(req, res) {
      res.status(200).json({ data: await svc.timeline(id(req), req.user) });
    },
    async escalate(req, res) {
      res.status(200).json({ data: await svc.escalate(id(req), req.validated.body, req.user) });
    },
    async reopen(req, res) {
      res.status(200).json({ data: await svc.reopen(id(req), req.validated.body, req.user) });
    },
  };
}
