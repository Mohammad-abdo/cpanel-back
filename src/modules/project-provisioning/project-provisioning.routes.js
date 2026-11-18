import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { rootDomainsService } from '../root-domains/root-domains.routes.js';
import { githubService } from '../github/github.routes.js';
import { createProjectProvisioningController } from './project-provisioning.controller.js';
import { createProjectProvisioningService } from './project-provisioning.service.js';
import {
  createRunBodySchema, decommissionBodySchema, listQuerySchema, previewBodySchema, projectParamsSchema, redeployBodySchema, resumeBodySchema, runParamsSchema, vhostBodySchema,
} from './project-provisioning.validator.js';

const deps = getDeps();
export const projectProvisioningService = createProjectProvisioningService({ ...deps, prisma, serverAccessService, rootDomains: rootDomainsService, githubApp: githubService });
const c = createProjectProvisioningController(projectProvisioningService);
const write = requireSession({ requireMfa: true });

/** Mount at /project-provisioning. Owner (new projects) or project.configure (existing projects); MFA required. */
export const projectProvisioningRouter = Router();
projectProvisioningRouter.get('/config', write, wrap(c.config));
projectProvisioningRouter.post('/preview', write, validate(previewBodySchema, 'body'), wrap(c.preview));
projectProvisioningRouter.get('/runs', write, validate(listQuerySchema, 'query'), wrap(c.listRuns));
projectProvisioningRouter.post('/runs', write, validate(createRunBodySchema, 'body'), wrap(c.createRun));
projectProvisioningRouter.get('/runs/:id', write, validate(runParamsSchema, 'params'), wrap(c.getRun));
projectProvisioningRouter.post('/runs/:id/resume', write, validate(runParamsSchema, 'params'), validate(resumeBodySchema, 'body'), wrap(c.resume));
projectProvisioningRouter.get('/projects/:projectId/server-state', write, validate(projectParamsSchema, 'params'), wrap(c.serverState));
projectProvisioningRouter.post('/projects/:projectId/redeploy', write, validate(projectParamsSchema, 'params'), validate(redeployBodySchema, 'body'), wrap(c.redeploy));
projectProvisioningRouter.post('/projects/:projectId/vhost', write, validate(projectParamsSchema, 'params'), validate(vhostBodySchema, 'body'), wrap(c.updateVhost));
projectProvisioningRouter.post('/projects/:projectId/decommission', write, validate(projectParamsSchema, 'params'), validate(decommissionBodySchema, 'body'), wrap(c.decommission));
