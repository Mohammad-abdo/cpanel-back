import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { createDeploymentsService } from '../deployments/deployments.service.js';
import { resolveDeploymentAdapters } from '../deployments/deployments.ssh-runner.js';
import { operationsService } from '../operations/operations.routes.js';
import { rootDomainsService } from '../root-domains/root-domains.routes.js';
import { createPreviewsController } from './previews.controller.js';
import { createPreviewsService } from './previews.service.js';
import { createBodySchema, exposeBodySchema, extendBodySchema, previewParamsSchema, projectParamsSchema, updateSettingsBodySchema } from './previews.validator.js';

const deps = getDeps();
const auditService = createAuditService({ prisma });
const deploymentsService = createDeploymentsService({ prisma, auditService, operationsService });
const runner = resolveDeploymentAdapters({ prisma }).runner;

/** Shared with the GitHub webhook (TASK-044) so pull_request deliveries drive the same lifecycle. */
export const previewsService = createPreviewsService({ ...deps, prisma, auditService, deploymentsService, rootDomains: rootDomainsService, teardown: (args) => runner.teardown(args) });
const c = createPreviewsController(previewsService);
const write = requireSession({ requireMfa: true });
const project = validate(projectParamsSchema, 'params');
const preview = validate(previewParamsSchema, 'params');

/** Mount at /projects (paths are /:id/previews...). Mutations are Owner only, MFA required. */
export const previewsRouter = Router();
previewsRouter.get('/:id/preview-settings', requireSession(), project, wrap(c.getSettings));
previewsRouter.put('/:id/preview-settings', write, project, validate(updateSettingsBodySchema, 'body'), wrap(c.updateSettings));
previewsRouter.get('/:id/previews', requireSession(), project, wrap(c.list));
previewsRouter.post('/:id/previews', write, project, validate(createBodySchema, 'body'), wrap(c.create));
previewsRouter.post('/:id/previews/:previewId/expose', write, preview, validate(exposeBodySchema, 'body'), wrap(c.expose));
previewsRouter.post('/:id/previews/:previewId/extend', write, preview, validate(extendBodySchema, 'body'), wrap(c.extend));
previewsRouter.post('/:id/previews/:previewId/auth-reset', write, preview, wrap(c.resetAuth));
previewsRouter.delete('/:id/previews/:previewId', write, preview, wrap(c.destroy));
