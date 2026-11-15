import { createHash } from 'node:crypto';

export function createAuthController(authService) {
  return {
    async login(req, res) {
      const result = await authService.login(req.validated.body);
      res.status(200).json({ data: result });
    },

    async verifyMfa(req, res) {
      const result = await authService.verifyMfa(req.validated.body);
      res.status(200).json({ data: result });
    },

    async enrollTotp(req, res) {
      const result = await authService.enrollTotp({
        userId: req.user.id,
        actor: req.user,
        mfaSatisfied: req.session.mfaSatisfied,
      });
      res.status(201).json({ data: result });
    },

    async confirmTotp(req, res) {
      const result = await authService.confirmTotpEnrollment({
        userId: req.user.id,
        factorId: req.validated.body.factorId,
        code: req.validated.body.code,
        actor: req.user,
        mfaSatisfied: req.session.mfaSatisfied,
      });
      res.status(200).json({ data: result });
    },

    async changePassword(req, res) {
      const result = await authService.changePassword({
        userId: req.user.id,
        currentSessionId: req.session.id,
        ...req.validated.body,
      });
      res.status(200).json({ data: result });
    },

    async me(req, res) {
      res.status(200).json({ data: await authService.me({ user: req.user }) });
    },

    async listSessions(req, res) {
      const data = await authService.listSessions({ userId: req.user.id, currentSessionId: req.session.id });
      res.status(200).json({ data });
    },

    async revokeSession(req, res) {
      const data = await authService.revokeSession({ userId: req.user.id, sessionId: req.validated.params.id });
      res.status(200).json({ data });
    },

    async logout(req, res) {
      const header = req.get('authorization') || '';
      const raw = header.startsWith('Bearer ') ? header.slice(7) : '';
      const tokenHash = raw ? createHash('sha256').update(raw).digest('hex') : null;
      const result = await authService.logout({
        tokenHash,
        actorId: req.user?.id ?? null,
      });
      res.status(200).json({ data: result });
    },
  };
}
