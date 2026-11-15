import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  changePasswordBodySchema,
  sessionIdParamsSchema,
  loginBodySchema,
  logoutBodySchema,
  mfaConfirmBodySchema,
  mfaEnrollBodySchema,
  mfaVerifyBodySchema,
} from './auth.validator.js';
import { createAuthController } from './auth.controller.js';
import { createAuthService } from './auth.service.js';
import { createAuditService } from '../audit/audit.service.js';
import { loginLimiters, mfaVerifyLimiters, rateLimit } from '../../common/middleware/rate-limit.js';
import { prisma } from '../../config/prisma.js';

const auditService = createAuditService({ prisma });
const authService = createAuthService({ prisma, auditService });
const authController = createAuthController(authService);

export const authRouter = Router();

authRouter.post('/login', ...loginLimiters, validate(loginBodySchema, 'body'), (req, res, next) => {
  authController.login(req, res).catch(next);
});

authRouter.post('/mfa/verify', ...mfaVerifyLimiters, validate(mfaVerifyBodySchema, 'body'), (req, res, next) => {
  authController.verifyMfa(req, res).catch(next);
});

authRouter.post(
  '/mfa/totp/enroll',
  requireSession({ allowPendingMfa: true }),
  validate(mfaEnrollBodySchema, 'body'),
  (req, res, next) => {
    authController.enrollTotp(req, res).catch(next);
  },
);

authRouter.post(
  '/mfa/totp/confirm',
  requireSession({ allowPendingMfa: true }),
  validate(mfaConfirmBodySchema, 'body'),
  (req, res, next) => {
    authController.confirmTotp(req, res).catch(next);
  },
);

const passwordChangeLimiter = rateLimit({
  windowMs: 15 * 60_000,
  max: 5,
  keyFn: (req) => `pwchange:${req.user?.id ?? req.ip}`,
});

authRouter.post(
  '/password/change',
  requireSession(),
  passwordChangeLimiter,
  validate(changePasswordBodySchema, 'body'),
  (req, res, next) => {
    authController.changePassword(req, res).catch(next);
  },
);

authRouter.get('/me', requireSession({ allowPendingMfa: true }), (req, res, next) => {
  authController.me(req, res).catch(next);
});

authRouter.get('/sessions',requireSession(), (req, res, next) => {
  authController.listSessions(req, res).catch(next);
});

authRouter.delete('/sessions/:id', requireSession(), validate(sessionIdParamsSchema, 'params'), (req, res, next) => {
  authController.revokeSession(req, res).catch(next);
});

authRouter.post('/logout', validate(logoutBodySchema, 'body'), (req, res, next) => {
  authController.logout(req, res).catch(next);
});
