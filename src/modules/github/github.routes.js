import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { rateLimit } from '../../common/middleware/rate-limit.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { createGitHubController } from './github.controller.js';
import { createGitHubService } from './github.service.js';
import {
  approvalBodySchema,
  branchesParamsSchema,
  callbackQuerySchema,
  installationQuerySchema,
  linkRepoBodySchema,
  pageQuerySchema,
  projectParamsSchema,
  upsertGitHubAppBodySchema,
} from './github.validator.js';

const deps = getDeps();
export const githubService = createGitHubService({ ...deps, prisma });
const c = createGitHubController(githubService);
const ownerMfa = requireSession({ requireMfa: true });
const ip = (req) => req.ip || req.socket?.remoteAddress || 'unknown';
/** The callback is public (the signed single-use state authenticates it), so it is rate limited per IP. */
export const callbackLimiter = rateLimit({ windowMs: 60_000, max: 10, keyFn: (req) => `ghcb:${ip(req)}` });

/** Mount at /github. Owner + MFA; credentials are accepted in bodies and never returned. */
export const githubRouter = Router();
githubRouter.get('/app/callback', callbackLimiter, validate(callbackQuerySchema, 'query'), wrap(c.callback));
githubRouter.get('/app', ownerMfa, wrap(c.getApp));
githubRouter.put('/app', ownerMfa, validate(upsertGitHubAppBodySchema, 'body'), wrap(c.putApp));
githubRouter.delete('/app', ownerMfa, wrap(c.deleteApp));
githubRouter.post('/app/disconnect', ownerMfa, validate(approvalBodySchema, 'body'), wrap(c.deleteApp));
githubRouter.post('/app/rotate-webhook-secret', ownerMfa, validate(approvalBodySchema, 'body'), wrap(c.rotateSecret));
githubRouter.post('/app/manifest', ownerMfa, wrap(c.manifest));
githubRouter.get('/installations', ownerMfa, validate(pageQuerySchema, 'query'), wrap(c.listInstallations));
githubRouter.get('/installations/repos', ownerMfa, validate(installationQuerySchema, 'query'), wrap(c.listInstallationRepos));
githubRouter.get('/repos/:owner/:repo/branches', ownerMfa, validate(branchesParamsSchema, 'params'), validate(installationQuerySchema, 'query'), wrap(c.listBranches));
githubRouter.put('/projects/:projectId/repository', ownerMfa, validate(projectParamsSchema, 'params'), validate(linkRepoBodySchema, 'body'), wrap(c.linkProject));
