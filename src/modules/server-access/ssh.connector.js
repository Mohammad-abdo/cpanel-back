import { createHash } from 'node:crypto';
import ssh2 from 'ssh2';
import { AppError } from '../../common/errors/app-error.js';

const { Client } = ssh2;

/** SHA256 host key fingerprint in OpenSSH style (base64, no padding). */
export const fingerprint = (key) => `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;

/**
 * Real SSH connector (ssh2). `expectedHostKey` pins the server's host key: a different key is refused
 * (possible man-in-the-middle). Errors are mapped to stable codes; the password never appears in them.
 */
export function createSshConnector({ timeoutMs = 10_000 } = {}) {
  return {
    connect({ host, port = 22, username, password, expectedHostKey = null }) {
      return new Promise((resolve, reject) => {
        const client = new Client();
        let seenKey = null;
        let mismatch = false;
        let settled = false;
        const done = (fn, v) => {
          if (settled) return;
          settled = true;
          fn(v);
        };
        client.on('ready', () => done(resolve, { client, hostKeySha256: seenKey }));
        client.on('error', (err) => {
          client.end();
          if (mismatch) return done(reject, new AppError(409, 'SSH_HOST_KEY_MISMATCH', 'The server host key changed since it was added. Refusing to connect (possible man-in-the-middle).'));
          if (err.level === 'client-authentication') return done(reject, new AppError(422, 'SSH_AUTH_FAILED', 'SSH login failed: wrong username or password'));
          if (err.level === 'client-timeout' || /timed out/i.test(err.message)) return done(reject, new AppError(504, 'SSH_TIMEOUT', `SSH connection to ${host}:${port} timed out`));
          return done(reject, new AppError(502, 'SSH_UNREACHABLE', `Cannot reach SSH on ${host}:${port}: ${err.code ?? 'connection failed'}`));
        });
        client.connect({
          host,
          port,
          username,
          password,
          readyTimeout: timeoutMs,
          tryKeyboard: false,
          hostVerifier: (key) => {
            seenKey = fingerprint(key);
            if (expectedHostKey && seenKey !== expectedHostKey) {
              mismatch = true;
              return false;
            }
            return true;
          },
        });
      });
    },
  };
}

/** Runs one command and collects output (bounded). */
export function execCommand(client, command, { maxBytes = 64 * 1024, timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    client.exec(command, (err, stream) => {
      if (err) return reject(new AppError(502, 'SSH_EXEC_FAILED', 'Could not run the command over SSH'));
      let out = '';
      const timer = setTimeout(() => {
        stream.close();
        resolve({ code: null, stdout: out, timedOut: true });
      }, timeoutMs);
      stream.on('data', (d) => {
        if (out.length < maxBytes) out += d.toString('utf8');
      });
      stream.stderr.on('data', () => {});
      stream.on('close', (code) => {
        clearTimeout(timer);
        resolve({ code, stdout: out.slice(0, maxBytes) });
      });
    });
  });
}

/**
 * Runs a multi-line script on stdin via `bash -s` (avoids bash -c newline/quoting breakage).
 * Script must be fixed/trusted — never interpolate user input into it.
 */
export function execScript(client, script, { maxBytes = 64 * 1024, timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    client.exec('bash -s', (err, stream) => {
      if (err) return reject(new AppError(502, 'SSH_EXEC_FAILED', 'Could not run the script over SSH'));
      let out = '';
      const timer = setTimeout(() => {
        stream.close();
        resolve({ code: null, stdout: out, timedOut: true });
      }, timeoutMs);
      stream.on('data', (d) => {
        if (out.length < maxBytes) out += d.toString('utf8');
      });
      stream.stderr.on('data', () => {});
      stream.on('close', (code) => {
        clearTimeout(timer);
        resolve({ code, stdout: out.slice(0, maxBytes) });
      });
      stream.end(String(script).replace(/\r\n/g, '\n'));
    });
  });
}

export function openSftp(client) {
  return new Promise((resolve, reject) => {
    client.sftp((err, sftp) => (err ? reject(new AppError(502, 'SFTP_UNAVAILABLE', 'SFTP is not available on this server')) : resolve(sftp)));
  });
}
