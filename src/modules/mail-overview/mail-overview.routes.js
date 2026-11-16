import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { mailAuditQuerySchema, mailHealthSummaryQuerySchema, mailOverviewQuerySchema } from './mail-overview.validator.js';
import { createMailOverviewController } from './mail-overview.controller.js';
import { createMailOverviewService } from './mail-overview.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const config = { provisioningDisabled: process.env.MAIL_PROVISIONING_DISABLED === 'true' };
const controller = createMailOverviewController(createMailOverviewService({ ...getDeps(), config }));

/** Mount at /mail. Read-only, stored data only (no SSH). Scope-aware: non-owners see only visible servers and domains. */
export const mailOverviewRouter = Router();

mailOverviewRouter.get('/overview', requireSession(), validate(mailOverviewQuerySchema, 'query'), wrap(controller.overview));
mailOverviewRouter.get('/audit', requireSession(), validate(mailAuditQuerySchema, 'query'), wrap(controller.audit));
mailOverviewRouter.get('/health-summary', requireSession(), validate(mailHealthSummaryQuerySchema, 'query'), wrap(controller.healthSummary));
