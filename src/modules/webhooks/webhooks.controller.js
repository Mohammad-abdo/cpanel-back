import { respond } from '../platform/platform.http.js';

export function createWebhooksController(svc) {
  return {
    /** req.body is the raw Buffer (express.raw on this route only) so the signature covers the exact bytes. */
    async github(req, res) {
      const data = await svc.handleGithub({
        rawBody: req.body,
        signature: req.get('x-hub-signature-256'),
        event: req.get('x-github-event'),
        deliveryId: req.get('x-github-delivery'),
      });
      res.status(data.replayed ? 200 : 202).json({ data });
    },

    async trigger(req, res) {
      const data = await svc.triggerHook({ token: req.validated.params.token, body: req.validated.body ?? {} });
      res.status(202).json({ data });
    },

    async listHooks(req, res) {
      res.status(200).json({ data: await svc.listHooks(req.validated.params.id, req.user) });
    },
    async createHook(req, res) {
      res.status(201).json({ data: await svc.createHook(req.validated.params.id, req.validated.body, req.user) });
    },
    async rotateHook(req, res) {
      res.status(200).json({ data: await svc.rotateHook(req.validated.params.id, req.validated.params.hookId, req.user) });
    },
    async revokeHook(req, res) {
      res.status(200).json({ data: await svc.revokeHook(req.validated.params.id, req.validated.params.hookId, req.user) });
    },
    async getSettings(req, res) {
      res.status(200).json({ data: await svc.getSettings(req.validated.params.id, req.user) });
    },
    async updateSettings(req, res) {
      const data = await svc.updateSettings(req.validated.params.id, req.validated.body, req.user);
      res.status(data.approvalRequired ? 202 : 200).json({ data });
    },
  };
}
