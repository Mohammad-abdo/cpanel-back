import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { rateLimit } from '../../common/middleware/rate-limit.js';
import { webmailAuthService } from '../webmail-auth/webmail-auth.wiring.js';
import { requireWebmailSession, wrap } from './webmail-session.js';
import { createWebmailMailService } from './webmail-mail.service.js';
import { createWebmailMailController } from './webmail-mail.controller.js';
import express from 'express';
import {
  actionMessagesBodySchema,
  attachmentParamsSchema,
  flagsBodySchema,
  saveDraftBodySchema,
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
const actionLimiter = rateLimit({
  windowMs: 15 * 60_000,
  max: 120,
  keyFn: (req) => `wm:action:${req.webmail?.mailboxId ?? req.ip}`,
  code: 'WEBMAIL_ACTION_RATE',
});

// Send/draft carry base64 attachments (20 MB raw ~ 27 MB encoded); the app-level parser skips these paths.
export const WEBMAIL_LARGE_BODY_PATHS = ['/wm/v1/mail/send', '/wm/v1/mail/drafts'];
const largeJson = express.json({ limit: '28mb' });
const draftLimiter = rateLimit({
  windowMs: 15 * 60_000,
  max: 200,
  keyFn: (req) => `wm:draft:${req.webmail?.mailboxId ?? req.ip}`,
  code: 'WEBMAIL_DRAFT_RATE',
});

export const webmailMailRouter = Router();

webmailMailRouter.get('/folders', auth, wrap(controller.folders));
webmailMailRouter.get('/messages', auth, validate(listMessagesQuerySchema, 'query'), wrap(controller.messages));
webmailMailRouter.get('/messages/:uid', auth, validate(messageParamsSchema, 'params'), validate(messageQuerySchema, 'query'), wrap(controller.message));
webmailMailRouter.get('/messages/:uid/attachments/:index', auth, validate(attachmentParamsSchema, 'params'), validate(messageQuerySchema, 'query'), wrap(controller.attachment));
webmailMailRouter.post('/send', auth, sendLimiter, largeJson, validate(sendMessageBodySchema), wrap(controller.send));
webmailMailRouter.post('/messages/action', auth, actionLimiter, validate(actionMessagesBodySchema), wrap(controller.action));
webmailMailRouter.post('/drafts', auth, draftLimiter, largeJson, validate(saveDraftBodySchema), wrap(controller.saveDraft));
webmailMailRouter.post('/messages/flags', auth, actionLimiter, validate(flagsBodySchema), wrap(controller.flags));
