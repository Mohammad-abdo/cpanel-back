import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { createDatabaseBodySchema, createInstanceBodySchema, createUserBodySchema, databaseIdParamsSchema, dropDatabaseBodySchema, listDatabasesQuerySchema } from './databases.validator.js';
import { createDatabasesController } from './databases.controller.js';
import { createDatabasesService } from './databases.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const c = createDatabasesController(createDatabasesService(getDeps()));
const write = requireSession({ requireMfa: true });

/** Mount at /databases */
export const databasesRouter = Router();

databasesRouter.get('/', requireSession(), validate(listDatabasesQuerySchema, 'query'), wrap(c.list));
databasesRouter.get('/instances', requireSession(), wrap(c.instances));
databasesRouter.post('/instances', write, validate(createInstanceBodySchema, 'body'), wrap(c.createInstance));
databasesRouter.post('/', write, validate(createDatabaseBodySchema, 'body'), wrap(c.create));
databasesRouter.post('/:id/users', write, validate(databaseIdParamsSchema, 'params'), validate(createUserBodySchema, 'body'), wrap(c.createUser));
databasesRouter.post('/:id/drop', write, validate(databaseIdParamsSchema, 'params'), validate(dropDatabaseBodySchema, 'body'), wrap(c.drop));
