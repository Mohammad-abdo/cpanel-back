import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  analyticsQuerySchema,
  identityIdParamsSchema,
  mapIdentityBodySchema,
  memberIdParamsSchema,
  timelineQuerySchema,
  unattributedQuerySchema,
} from './members.validator.js';
import { createMembersController } from './members.controller.js';
import { createMembersService } from './members.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';

const c = createMembersController(createMembersService({ prisma, auditService: createAuditService({ prisma }) }));
const mfa = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);

/** Mount at /members. */
export const membersRouter = Router();

membersRouter.get('/identities', mfa, wrap(c.listMappings));
membersRouter.post('/identities', mfa, validate(mapIdentityBodySchema, 'body'), wrap(c.mapIdentity));
membersRouter.delete('/identities/:id', mfa, validate(identityIdParamsSchema, 'params'), wrap(c.unmapIdentity));
membersRouter.get('/analytics', mfa, validate(analyticsQuerySchema, 'query'), wrap(c.analytics));
membersRouter.get('/unattributed', mfa, validate(unattributedQuerySchema, 'query'), wrap(c.listUnattributed));
membersRouter.get('/:userId', requireSession(), validate(memberIdParamsSchema, 'params'), wrap(c.profile));
membersRouter.get(
  '/:userId/timeline',
  requireSession(),
  validate(memberIdParamsSchema, 'params'),
  validate(timelineQuerySchema, 'query'),
  wrap(c.timeline),
);
