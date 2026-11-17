/**
 * Shared helper (TASK-045/047): run one FIXED script on a server over SSH with positional args and an optional stdin payload.
 * Uses the stored encrypted server login, the same way the deploy runner does. Tests inject the fake SSH connector.
 */
import { AppError } from '../../common/errors/app-error.js';
import { decrypt } from '../platform/platform.crypto.js';
import { execScriptStdin } from './ssh.connector.js';

export function createScriptRunner({ prisma, connector, credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY }) {
  return {
    async run(serverId, script, { args = [], stdin = '', timeoutMs = 60_000 } = {}) {
      if (!connector) throw new AppError(500, 'SSH_UNAVAILABLE', 'SSH connector is not wired');
      const cred = await prisma.serverCredential.findUnique({ where: { serverId } });
      if (!cred) throw new AppError(409, 'SSH_CREDENTIAL_NOT_FOUND', 'This server has no SSH login saved');
      const password = decrypt(Buffer.from(cred.secretEnc), credentialKey()).toString('utf8');
      const conn = await connector.connect({ host: cred.host, port: cred.port, username: cred.username, password, expectedHostKey: cred.hostKeySha256 ?? null });
      try {
        return await execScriptStdin(conn.client, script, { args, stdin, timeoutMs });
      } finally {
        conn.client.end();
      }
    },
  };
}
