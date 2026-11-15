import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  bookmarkIdParamsSchema,
  createBookmarkBodySchema,
  exportLogsQuerySchema,
  ingestBodySchema,
  listLogSourcesQuerySchema,
  registerSourceBodySchema,
  searchLogsQuerySchema,
  streamLogsQuerySchema,
} from './logs.validator.js';
import { createLogsController } from './logs.controller.js';
import { createLogsService } from './logs.service.js';
import { prisma } from '../../config/prisma.js';
import { createAuditService } from '../audit/audit.service.js';
import { createAgentsService } from '../agents/agents.service.js';
import { createErrorsService } from '../monitoring/monitoring.errors.js';

const auditService = createAuditService({ prisma });
const errorsService = createErrorsService({ prisma, auditService });
const logsService = createLogsService({
  prisma,
  auditService,
  onError: ({ entry, labels }) => errorsService.observe({ entry, labels }),
});
const c = createLogsController(logsService);
const agents = createAgentsService({ prisma });
const mfa = requireSession({ requireMfa: true });
const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);

const requireAgent = (req, _res, next) => {
  agents
    .authenticate(req.get('authorization'))
    .then((agent) => {
      req.agent = agent;
      next();
    })
    .catch(next);
};

export { logsService };
export const logsRouter = Router();

logsRouter.get('/sources', requireSession(), validate(listLogSourcesQuerySchema, 'query'), wrap(c.listSources));
logsRouter.post('/sources', mfa, validate(registerSourceBodySchema, 'body'), wrap(c.registerSource));
logsRouter.post('/ingest', requireAgent, validate(ingestBodySchema, 'body'), wrap(c.ingestAgent));
logsRouter.post('/ingest/manual', mfa, validate(ingestBodySchema, 'body'), wrap(c.ingestManual));
logsRouter.get('/search', requireSession(), validate(searchLogsQuerySchema, 'query'), wrap(c.search));
logsRouter.get('/export', mfa, validate(exportLogsQuerySchema, 'query'), wrap(c.export));
logsRouter.get('/stream', requireSession(), validate(streamLogsQuerySchema, 'query'), wrap(c.stream));
logsRouter.get('/bookmarks', requireSession(), wrap(c.listBookmarks));
logsRouter.post('/bookmarks', requireSession(), validate(createBookmarkBodySchema, 'body'), wrap(c.createBookmark));
logsRouter.delete('/bookmarks/:id', requireSession(), validate(bookmarkIdParamsSchema, 'params'), wrap(c.deleteBookmark));
