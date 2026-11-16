import net from 'node:net';
import { AppError } from './errors/app-error.js';

/**
 * Local TCP listener that forwards each connection through an open ssh2 client
 * to remoteHost:remotePort (typically 127.0.0.1:993 on the mail VPS).
 */
export function createLocalForward(sshClient, remoteHost, remotePort) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((sock) => {
      sshClient.forwardOut('127.0.0.1', 0, remoteHost, remotePort, (err, stream) => {
        if (err) {
          sock.destroy();
          return;
        }
        sock.pipe(stream);
        stream.pipe(sock);
        const kill = () => {
          try {
            sock.destroy();
          } catch {
            /* ignore */
          }
          try {
            stream.close?.();
            stream.destroy?.();
          } catch {
            /* ignore */
          }
        };
        stream.on('error', kill);
        sock.on('error', kill);
        stream.on('close', () => sock.destroy());
        sock.on('close', () => {
          try {
            stream.close?.();
          } catch {
            /* ignore */
          }
        });
      });
    });
    server.once('error', (err) => reject(new AppError(502, 'WEBMAIL_TUNNEL_FAILED', `SSH tunnel listen failed: ${err.message}`)));
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        port: addr.port,
        close: () =>
          new Promise((r) => {
            server.close(() => r());
            // Force-close lingering sockets so the SSH session can end.
            server.closeAllConnections?.();
          }),
      });
    });
  });
}

/** Open IMAP (993) + SMTP (465) local forwards over one SSH client. */
export async function openMailForwards(sshClient) {
  const imap = await createLocalForward(sshClient, '127.0.0.1', 993);
  let smtp;
  try {
    smtp = await createLocalForward(sshClient, '127.0.0.1', 465);
  } catch (e) {
    await imap.close();
    throw e;
  }
  return {
    imapPort: imap.port,
    smtpPort: smtp.port,
    close: async () => {
      await Promise.allSettled([imap.close(), smtp.close()]);
    },
  };
}
