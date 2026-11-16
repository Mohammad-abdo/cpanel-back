import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { rateLimit } from '../../common/middleware/rate-limit.js';
import { webmailAuthService } from '../webmail-auth/webmail-auth.wiring.js';
import { requireWebmailSession, wrap } from './webmail-session.js';
import { createWebmailMailService } from './webmail-mail.service.js';
import { createWebmailMailController } from './webmail-mail.controller.js';
import {
  listMessagesQuerySchema,
  messageParamsSchema,
  messageQuerySchema,
  sendMessageBodySchema,
} from './webmail-mail.validator.js';

const controller = createWebmailMailController(createWebmailMailService());
const auth = requireWebmailSession(webmailAuthService);
const sendLimiter = rateLimit({
  windowMs: 15 * 60_000,
  max: 60,
  keyFn: (req) => `wm:send:${req.webmail?.mailboxId ?? req.ip}`,
  code: 'WEBMAIL_SEND_RATE',
});

export const webmailMailRouter = Router();

webmailMailRouter.get('/folders', auth, wrap(controller.folders));
webmailMailRouter.get('/messages', auth, validate(listMessagesQuerySchema, 'query'), wrap(controller.messages));
webmailMailRouter.get('/messages/:uid', auth, validate(messageParamsSchema, 'params'), validate(messageQuerySchema, 'query'), wrap(controller.message));
webmailMailRouter.post('/send', auth, sendLimiter, validate(sendMessageBodySchema), wrap(controller.send));
