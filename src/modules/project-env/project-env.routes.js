import express, { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { getDeps } from '../platform/platform.wiring.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { createProjectEnvController } from './project-env.controller.js';
import { createProjectEnvService } from './project-env.service.js';
import {
  addEnvironmentBodySchema,
  envKeyParamsSchema,
  envParamsSchema,
  importBodySchema,
  projectParamsSchema,
  setVarsBodySchema,
  pullServerBodySchema,
  writeServerBodySchema,
} from './project-env.validator.js';

const deps = getDeps();
const c = createProjectEnvController(createProjectEnvService({ prisma: deps.prisma, rbac: deps.rbac, auditService: deps.auditService, serverAccess: serverAccessService }));
const read = requireSession();
const write = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const env = validate(envParamsSchema, 'params');
const envKey = validate(envKeyParamsSchema, 'params');
/** Bulk set and .env import may exceed the app-wide 64 KB JSON limit. */
const bigJson = express.json({ limit: '600kb' });

export const projectEnvRouter = Router();
projectEnvRouter.post('/:id/environments', write, validate(projectParamsSchema, 'params'), validate(addEnvironmentBodySchema, 'body'), wrap(c.addEnvironment));
projectEnvRouter.get('/:id/environments/:envId/vars', read, env, wrap(c.list));
projectEnvRouter.put('/:id/environments/:envId/vars', bigJson, write, env, validate(setVarsBodySchema, 'body'), wrap(c.set));
projectEnvRouter.post('/:id/environments/:envId/vars/import', bigJson, write, env, validate(importBodySchema, 'body'), wrap(c.importText));
projectEnvRouter.get('/:id/environments/:envId/vars/export', write, env, wrap(c.exportText));
projectEnvRouter.post('/:id/environments/:envId/vars/write-server', write, env, validate(writeServerBodySchema, 'body'), wrap(c.writeToServer));
projectEnvRouter.post('/:id/environments/:envId/vars/pull-server', write, env, validate(pullServerBodySchema, 'body'), wrap(c.pullFromServer));
projectEnvRouter.get('/:id/environments/:envId/vars/:key/reveal', write, envKey, wrap(c.reveal));
projectEnvRouter.delete('/:id/environments/:envId/vars/:key', write, envKey, wrap(c.remove));
