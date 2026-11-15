import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  createUserBodySchema,
  listUsersQuerySchema,
  patchUserBodySchema,
  userIdParamsSchema,
} from './users.validator.js';
import { createUsersController } from './users.controller.js';
import { createUsersService } from './users.service.js';
import { prisma } from '../../config/prisma.js';

const usersService = createUsersService({ prisma });
const usersController = createUsersController(usersService);

export const usersRouter = Router();

usersRouter.post(
  '/',
  requireSession({ requireMfa: true }),
  validate(createUserBodySchema, 'body'),
  (req, res, next) => {
    usersController.create(req, res).catch(next);
  },
);

usersRouter.get('/', requireSession(), validate(listUsersQuerySchema, 'query'), (req, res, next) => {
  usersController.list(req, res).catch(next);
});

usersRouter.get('/:id', requireSession(), validate(userIdParamsSchema, 'params'), (req, res, next) => {
  usersController.get(req, res).catch(next);
});

usersRouter.patch(
  '/:id',
  requireSession({ requireMfa: true }),
  validate(userIdParamsSchema, 'params'),
  validate(patchUserBodySchema, 'body'),
  (req, res, next) => {
    usersController.patch(req, res).catch(next);
  },
);
