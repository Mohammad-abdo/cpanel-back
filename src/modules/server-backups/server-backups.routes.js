import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { wrap } from '../platform/platform.http.js';
import { createServerBackupsController } from './server-backups.controller.js';
import { createServerBackupsService } from './server-backups.service.js';
import { putSettingsBodySchema, serverIdParamsSchema } from './server-backups.validator.js';

const svc = createServerBackupsService({ prisma, auditService: createAuditService({ prisma }) });
const c = createServerBackupsController(svc);
const ownerWrite = requireSession({ requireMfa: true });
const read = requireSession();

/** Mount under /servers: GET/PUT/POST …/backup-settings */
export const serverBackupsRouter = Router();

serverBackupsRouter.get('/:serverId/backup-settings', read, validate(serverIdParamsSchema, 'params'), wrap(c.getSettings));
serverBackupsRouter.put('/:serverId/backup-settings', ownerWrite, validate(serverIdParamsSchema, 'params'), validate(putSettingsBodySchema, 'body'), wrap(c.putSettings));
serverBackupsRouter.post('/:serverId/backup-settings/run', ownerWrite, validate(serverIdParamsSchema, 'params'), wrap(c.runNow));