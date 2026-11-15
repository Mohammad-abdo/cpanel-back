import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  archiveBodySchema,
  configureBodySchema,
  createProjectBodySchema,
  discoverBodySchema,
  lifecycleBodySchema,
  lifecycleParamsSchema,
  linkBodySchema,
  listProjectsQuerySchema,
  projectIdParamsSchema,
  projectOverviewQuerySchema,
  projectTeamBodySchema,
  projectMemberBodySchema,
  projectMemberRoleBodySchema,
  projectTeamParamsSchema,
  projectMemberParamsSchema,
} from './projects.validator.js';
import { createProjectsController } from './projects.controller.js';
import { createProjectsService } from './projects.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { operationsService } from '../operations/operations.routes.js';

const projectsService = createProjectsService({
  prisma,
  auditService: createAuditService({ prisma }),
  operationsService,
});
const c = createProjectsController(projectsService);
const mfa = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const params = validate(projectIdParamsSchema, 'params');

export const projectsRouter = Router();

projectsRouter.get('/', requireSession(), validate(listProjectsQuerySchema, 'query'), wrap(c.list));
projectsRouter.post('/', mfa, validate(createProjectBodySchema, 'body'), wrap(c.create));
projectsRouter.post('/discover', mfa, validate(discoverBodySchema, 'body'), wrap(c.discover));
projectsRouter.get('/:id', requireSession(), params, wrap(c.get));
projectsRouter.get('/:id/overview', requireSession(), params, validate(projectOverviewQuerySchema, 'query'), wrap(c.overview));
projectsRouter.get('/:id/members', requireSession(), params, wrap(c.members));
projectsRouter.get('/:id/teams', requireSession(), params, wrap(c.teams));
projectsRouter.post('/:id/teams', mfa, params, validate(projectTeamBodySchema, 'body'), wrap(c.linkTeam));
projectsRouter.delete('/:id/teams/:teamId', mfa, validate(projectTeamParamsSchema, 'params'), wrap(c.unlinkTeam));
projectsRouter.post('/:id/members', mfa, params, validate(projectMemberBodySchema, 'body'), wrap(c.addMember));
projectsRouter.patch('/:id/members/:userId', mfa, validate(projectMemberParamsSchema, 'params'), validate(projectMemberRoleBodySchema, 'body'), wrap(c.changeRole));
projectsRouter.delete('/:id/members/:userId', mfa, validate(projectMemberParamsSchema, 'params'), wrap(c.removeMember));
projectsRouter.get('/:id/restart-impact', requireSession(), params, wrap(c.restartImpact));
projectsRouter.post('/:id/link', mfa, params, validate(linkBodySchema, 'body'), wrap(c.link));
projectsRouter.patch('/:id', mfa, params, validate(configureBodySchema, 'body'), wrap(c.configure));
projectsRouter.post('/:id/archive', mfa, params, validate(archiveBodySchema, 'body'), wrap(c.archive));
projectsRouter.post(
  '/:id/lifecycle/:action',
  mfa,
  validate(lifecycleParamsSchema, 'params'),
  validate(lifecycleBodySchema, 'body'),
  wrap(c.lifecycle),
);
