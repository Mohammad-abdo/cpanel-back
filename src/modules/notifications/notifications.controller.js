export function createNotificationsController(service) {
  return {
    async list(req, res) {
      res.status(200).json({ data: await service.list(req.user, req.validated.query) });
    },
    async markRead(req, res) {
      res.status(200).json({ data: await service.markRead(req.user, req.validated.params.id) });
    },
    async markAllRead(req, res) {
      res.status(200).json({ data: await service.markAllRead(req.user) });
    },
    async getPreferences(req, res) {
      res.status(200).json({ data: await service.getPreferences(req.user) });
    },
    async updatePreferences(req, res) {
      res.status(200).json({ data: await service.updatePreferences(req.user, req.validated.body) });
    },
  };
}
