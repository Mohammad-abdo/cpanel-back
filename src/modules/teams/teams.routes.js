import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  addMemberBodySchema,
  createTeamBodySchema,
  teamIdParamsSchema,
  teamMemberParamsSchema,
} from './teams.validator.js';
import { createTeamsController } from './teams.controller.js';
import { createTeamsService } from './teams.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';

const teamsController = createTeamsController(
  createTeamsService({ prisma, auditService: createAuditService({ prisma }) }),
);

export const teamsRouter = Router();

teamsRouter.get('/', requireSession(), (req, res, next) => {
  teamsController.list(req, res).catch(next);
});

teamsRouter.post('/', requireSession({ requireMfa: true }), validate(createTeamBodySchema, 'body'), (req, res, next) => {
  teamsController.create(req, res).catch(next);
});

teamsRouter.post(
  '/:id/members',
  requireSession({ requireMfa: true }),
  validate(teamIdParamsSchema, 'params'),
  validate(addMemberBodySchema, 'body'),
  (req, res, next) => {
    teamsController.addMember(req, res).catch(next);
  },
);

teamsRouter.delete(
  '/:id/members/:userId',
  requireSession({ requireMfa: true }),
  validate(teamMemberParamsSchema, 'params'),
  (req, res, next) => {
    teamsController.removeMember(req, res).catch(next);
  },
);
