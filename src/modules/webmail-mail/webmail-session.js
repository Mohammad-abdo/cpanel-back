import { AppError } from '../../common/errors/app-error.js';

/** Read Cookie header without cookie-parser. */
export function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    if (k !== name) continue;
    try {
      return decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      return part.slice(idx + 1).trim();
    }
  }
  return null;
}

export function wrap(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

/**
 * Mailbox session only. Owner /api/v1 tokens are never accepted here.
 * Token from nt_wm cookie or Authorization: Bearer (webmail SPA only).
 */
export function requireWebmailSession(authService, { optional = false } = {}) {
  return wrap(async (req, res, next) => {
    const header = req.get('authorization') || '';
    const bearer = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
    const token = bearer || readCookie(req, authService.cookieName);
    req.webmailToken = token || null;
    if (!token) {
      if (optional) return next();
      throw new AppError(401, 'WEBMAIL_SESSION_REQUIRED', 'Webmail login required');
    }
    req.webmail = await authService.resolveSession(token);
    return next();
  });
}
