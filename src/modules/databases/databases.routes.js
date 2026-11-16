import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  createDatabaseBodySchema,
  createInstanceBodySchema,
  createUserBodySchema,
  databaseIdParamsSchema,
  dropDatabaseBodySchema,
  instanceIdParamsSchema,
  instanceLiveQueryBodySchema,
  instanceLiveTableQuerySchema,
  instanceLiveTablesQuerySchema,
  instanceLoginBodySchema,
  listDatabasesQuerySchema,
} from './databases.validator.js';
import { createDatabasesController } from './databases.controller.js';
import { createDatabasesService } from './databases.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';
import { serverAccessService } from '../server-access/server-access.routes.js';

const c = createDatabasesController(createDatabasesService({ ...getDeps(), serverAccessService }));
const write = requireSession({ requireMfa: true });
const owner = requireSession({ requireMfa: true });
const instanceParams = validate(instanceIdParamsSchema, 'params');

/** Mount at /databases */
export const databasesRouter = Router();

databasesRouter.get('/', requireSession(), validate(listDatabasesQuerySchema, 'query'), wrap(c.list));
databasesRouter.get('/instances', requireSession(), wrap(c.instances));
databasesRouter.post('/instances', write, validate(createInstanceBodySchema, 'body'), wrap(c.createInstance));
databasesRouter.get('/instances/:id', requireSession(), instanceParams, wrap(c.getInstance));
databasesRouter.put('/instances/:id/login', owner, instanceParams, validate(instanceLoginBodySchema, 'body'), wrap(c.setInstanceLogin));
databasesRouter.delete('/instances/:id/login', owner, instanceParams, wrap(c.clearInstanceLogin));
databasesRouter.get('/instances/:id/live/schemas', owner, instanceParams, wrap(c.liveSchemas));
databasesRouter.get(
  '/instances/:id/live/tables',
  owner,
  instanceParams,
  validate(instanceLiveTablesQuerySchema, 'query'),
  wrap(c.liveTables),
);
databasesRouter.get(
  '/instances/:id/live/columns',
  owner,
  instanceParams,
  validate(instanceLiveTableQuerySchema, 'query'),
  wrap(c.liveColumns),
);
databasesRouter.get(
  '/instances/:id/live/rows',
  owner,
  instanceParams,
  validate(instanceLiveTableQuerySchema, 'query'),
  wrap(c.liveRows),
);
databasesRouter.post(
  '/instances/:id/live/query',
  owner,
  instanceParams,
  validate(instanceLiveQueryBodySchema, 'body'),
  wrap(c.liveQuery),
);
databasesRouter.post('/', write, validate(createDatabaseBodySchema, 'body'), wrap(c.create));
databasesRouter.post('/:id/users', write, validate(databaseIdParamsSchema, 'params'), validate(createUserBodySchema, 'body'), wrap(c.createUser));
databasesRouter.post('/:id/drop', write, validate(databaseIdParamsSchema, 'params'), validate(dropDatabaseBodySchema, 'body'), wrap(c.drop));
