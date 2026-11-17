export function createPortsController(svc) {
  return {
    async overview(req, res) {
      res.status(200).json({ data: await svc.overview(req.validated.params.serverId, req.user) });
    },
    async check(req, res) {
      res.status(200).json({ data: await svc.check(req.validated.params.serverId, req.validated.query.port, req.user) });
    },
    async listReservations(req, res) {
      res.status(200).json({ data: await svc.listReservations(req.validated.params.serverId, req.user) });
    },
    async reserve(req, res) {
      res.status(201).json({ data: await svc.reserve(req.validated.params.serverId, req.validated.body, req.user) });
    },
    async unreserve(req, res) {
      res.status(200).json({ data: await svc.unreserve(req.validated.params.serverId, req.validated.params.reservationId, req.user) });
    },
  };
}
