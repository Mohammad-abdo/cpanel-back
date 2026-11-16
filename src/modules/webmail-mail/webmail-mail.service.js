import { actionMessages, getAttachment, getMessage, listFolders, listMessages, saveDraft, sendMessage, setFlags } from '../../common/webmail-imap.js';
import { webmailAuthService } from '../webmail-auth/webmail-auth.wiring.js';

/** Every call is scoped to the caller's own mailbox session (credentials come from the session, never from input). */
export function createWebmailMailService() {
  return {
    folders: (session) => webmailAuthService.withMail(session, (ctx) => listFolders(ctx)),
    messages: (session, query) => webmailAuthService.withMail(session, (ctx) => listMessages(ctx, query)),
    message: (session, { uid, folder }) => webmailAuthService.withMail(session, (ctx) => getMessage(ctx, { uid, folder })),
    attachment: (session, args) => webmailAuthService.withMail(session, (ctx) => getAttachment(ctx, args)),
    send: (session, body) => webmailAuthService.withMail(session, (ctx) => sendMessage(ctx, body)),
    saveDraft: (session, body) => webmailAuthService.withMail(session, (ctx) => saveDraft(ctx, body)),
    action: (session, body) => webmailAuthService.withMail(session, (ctx) => actionMessages(ctx, body)),
    flags: (session, body) => webmailAuthService.withMail(session, (ctx) => setFlags(ctx, body)),
  };
}
