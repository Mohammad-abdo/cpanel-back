export function createWebmailAuthController(authService) {
  return {
    async login(req, res) {
      const data = await authService.login(req.validated.body, {
        ip: req.ip || req.socket?.remoteAddress,
        userAgent: req.get('user-agent'),
      });
      const secure = process.env.NODE_ENV === 'production';
      res.cookie(authService.cookieName, data.token, {
        httpOnly: true,
        sameSite: 'strict',
        secure,
        path: '/',
        expires: new Date(data.expiresAt),
      });
      res.status(200).json({ data: { mailbox: data.mailbox, expiresAt: data.expiresAt } });
    },

    async logout(req, res) {
      await authService.logout(req.webmailToken);
      res.clearCookie(authService.cookieName, { path: '/' });
      res.status(200).json({ data: { ok: true } });
    },

    async me(req, res) {
      res.status(200).json({ data: authService.me(req.webmail) });
    },
  };
}
