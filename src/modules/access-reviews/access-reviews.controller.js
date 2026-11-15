export function createAccessReviewsController(svc) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await svc.list(req.validated.query, req.user) });
    },
    async get(req, res) {
      res.status(200).json({ data: await svc.get(req.validated.params.id, req.user) });
    },
    async start(req, res) {
      res.status(201).json({ data: await svc.start(req.validated.body, req.user) });
    },
    async decide(req, res) {
      res.status(200).json({ data: await svc.decide(req.validated.params.id, req.validated.body, req.user) });
    },
    async complete(req, res) {
      res.status(200).json({ data: await svc.complete(req.validated.params.id, req.user) });
    },
  };
}
