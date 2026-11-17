import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { createGitHubController } from './github.controller.js';
import { createGitHubService } from './github.service.js';
import { upsertGitHubAppBodySchema } from './github.validator.js';

const deps = getDeps();
export const githubService = createGitHubService({ ...deps, prisma });
const c = createGitHubController(githubService);
const ownerMfa = requireSession({ requireMfa: true });

/** Mount at /github. Owner + MFA; credentials are accepted in bodies and never returned. */
export const githubRouter = Router();
githubRouter.get('/app', ownerMfa, wrap(c.getApp));
githubRouter.put('/app', ownerMfa, validate(upsertGitHubAppBodySchema, 'body'), wrap(c.putApp));
githubRouter.delete('/app', ownerMfa, wrap(c.deleteApp));
githubRouter.post('/app/manifest', ownerMfa, wrap(c.manifest));
githubRouter.get('/installations/repos', ownerMfa, wrap(c.listInstallationRepos));