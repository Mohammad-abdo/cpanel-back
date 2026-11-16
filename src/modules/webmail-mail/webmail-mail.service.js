import { getMessage, listFolders, listMessages, sendMessage } from '../../common/webmail-imap.js';

export function createWebmailMailService() {
  function ctx(session) {
    return {
      host: session.host,
      address: session.address,
      password: session.password,
      tlsInsecure: session.tlsInsecure,
    };
  }

  return {
    folders(session) {
      return listFolders(ctx(session));
    },
    messages(session, query) {
      return listMessages(ctx(session), query);
    },
    message(session, { uid, folder }) {
      return getMessage(ctx(session), { uid, folder });
    },
    send(session, body) {
      return sendMessage(ctx(session), body);
    },
  };
}
