import { AppError } from '../errors/app-error.js';

/**
 * Small fixed-window limiter (no dependency). In-memory, so it is per API process:
 * behind several instances or a proxy, replace with a shared store (REQUIRES DECISION).
 * keyFn returns the bucket key; return null to skip limiting.
 */
export function rateLimit({ windowMs, max, keyFn, code = 'RATE_LIMITED', now = () => Date.now() }) {
  const hits = new Map();

  return (req, res, next) => {
    const key = keyFn(req);
    if (key == null) return next();
    const t = now();
    const entry = hits.get(key);
    if (!entry || entry.resetAt <= t) {
      hits.set(key, { count: 1, resetAt: t + windowMs });
    } else {
      entry.count += 1;
      if (entry.count > max) {
        res.set('Retry-After', String(Math.ceil((entry.resetAt - t) / 1000)));
        return next(new AppError(429, code, 'Too many attempts. Try again later.'));
      }
    }
    // Opportunistic cleanup keeps memory bounded.
    if (hits.size > 10000) {
      for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
    }
    return next();
  };
}

const ip = (req) => req.ip || req.socket?.remoteAddress || 'unknown';

// 10 logins / 15 min per IP + email, and 50 / 15 min per IP.
export const loginLimiters = [
  rateLimit({ windowMs: 15 * 60_000, max: 50, keyFn: (req) => `login:ip:${ip(req)}` }),
  rateLimit({
    windowMs: 15 * 60_000,
    max: 10,
    keyFn: (req) => `login:${ip(req)}:${String(req.body?.email ?? '').toLowerCase()}`,
  }),
];

// 5 codes / 10 min per pending session (stops 6-digit TOTP brute force), 30 / 10 min per IP.
export const mfaVerifyLimiters = [
  rateLimit({ windowMs: 10 * 60_000, max: 30, keyFn: (req) => `mfa:ip:${ip(req)}` }),
  rateLimit({ windowMs: 10 * 60_000, max: 5, keyFn: (req) => `mfa:session:${req.body?.sessionId ?? ''}` }),
];

// 20 enrollments / hour per IP.
export const enrollLimiters = [rateLimit({ windowMs: 60 * 60_000, max: 20, keyFn: (req) => `enroll:ip:${ip(req)}` })];
