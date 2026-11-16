import express, { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { createServerAccessController } from './server-access.controller.js';
import { MAX_EDIT_BYTES, MAX_UPLOAD_BYTES, createServerAccessService } from './server-access.service.js';
import { createSshConnector } from './ssh.connector.js';
import {
  addServerBodySchema,
  credentialBodySchema,
  deleteQuerySchema,
  listQuerySchema,
  mkdirBodySchema,
  pathQuerySchema,
  renameBodySchema,
  serverIdParamsSchema,
  serviceBodySchema,
  writeBodySchema,
  inventoryImportBodySchema,
} from './server-access.validator.js';

/** Shared instance: the terminal WebSocket (server.js) consumes tickets issued by these routes. */
export const serverAccessService = createServerAccessService({
  prisma,
  connector: createSshConnector(),
  auditService: createAuditService({ prisma }),
});
const c = createServerAccessController(serverAccessService);
const owner = requireSession({ requireMfa: true });
const params = validate(serverIdParamsSchema, 'params');
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);

/** Large bodies only on the two file routes (the app-wide JSON limit is 64 KB). */
const editJson = express.json({ limit: MAX_EDIT_BYTES + 64 * 1024 });
const rawUpload = express.raw({ type: () => true, limit: MAX_UPLOAD_BYTES });

export const serverAccessRouter = Router();
serverAccessRouter.post('/ssh', owner, validate(addServerBodySchema, 'body'), wrap(c.addServer));
serverAccessRouter.get('/:id/ssh', owner, params, wrap(c.getCredential));
serverAccessRouter.put('/:id/ssh', owner, params, validate(credentialBodySchema, 'body'), wrap(c.setCredential));
serverAccessRouter.delete('/:id/ssh', owner, params, wrap(c.removeCredential));
serverAccessRouter.post('/:id/ssh/test', owner, params, wrap(c.test));
serverAccessRouter.get('/:id/ssh/info', owner, params, wrap(c.info));
serverAccessRouter.post('/:id/ssh/service', owner, params, validate(serviceBodySchema, 'body'), wrap(c.service));

serverAccessRouter.get('/:id/files', owner, params, validate(listQuerySchema, 'query'), wrap(c.list));
serverAccessRouter.get('/:id/files/content', owner, params, validate(pathQuerySchema, 'query'), wrap(c.read));
serverAccessRouter.put('/:id/files/content', editJson, owner, params, validate(writeBodySchema, 'body'), wrap(c.write));
serverAccessRouter.post('/:id/files/upload', rawUpload, owner, params, validate(pathQuerySchema, 'query'), wrap(c.upload));
serverAccessRouter.get('/:id/files/download', owner, params, validate(pathQuerySchema, 'query'), wrap(c.download));
serverAccessRouter.post('/:id/files/mkdir', owner, params, validate(mkdirBodySchema, 'body'), wrap(c.mkdir));
serverAccessRouter.post('/:id/files/rename', owner, params, validate(renameBodySchema, 'body'), wrap(c.rename));
serverAccessRouter.delete('/:id/files', owner, params, validate(deleteQuerySchema, 'query'), wrap(c.remove));

serverAccessRouter.post('/:id/terminal/ticket', owner, params, wrap(c.ticket));
serverAccessRouter.post('/:id/inventory/scan', owner, params, wrap(c.scanInventory));
serverAccessRouter.post('/:id/inventory/import', owner, params, validate(inventoryImportBodySchema, 'body'), wrap(c.importInventory));
