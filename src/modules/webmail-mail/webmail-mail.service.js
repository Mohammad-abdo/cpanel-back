import { actionMessages, getMessage, listFolders, listMessages, sendMessage } from '../../common/webmail-imap.js';
import { webmailAuthService } from '../webmail-auth/webmail-auth.wiring.js';

export function createWebmailMailService() {
  return {
    folders(session) {
      return webmailAuthService.withMail(session, (ctx) => listFolders(ctx));
    },
    messages(session, query) {
      return webmailAuthService.withMail(session, (ctx) => listMessages(ctx, query));
    },
    message(session, { uid, folder }) {
      return webmailAuthService.withMail(session, (ctx) => getMessage(ctx, { uid, folder }));
    },
    send(session, body) {
      return webmailAuthService.withMail(session, (ctx) => sendMessage(ctx, body));
    },
    action(session, body) {
      return webmailAuthService.withMail(session, (ctx) => actionMessages(ctx, body));
    },
  };
}
