import { createHash, randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { verifyMailboxLogin } from '../../common/webmail-imap.js';
import { decrypt, encrypt, sha256 } from '../platform/platform.crypto.js';

const COOKIE = 'nt_wm';
const SESSION_HOURS = 12;

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function credentialKey() {
  return process.env.CREDENTIAL_ENCRYPTION_KEY;
}

function tlsInsecure() {
  return process.env.WEBMAIL_TLS_INSECURE === '1' || process.env.WEBMAIL_TLS_INSECURE === 'true' || process.env.NODE_ENV !== 'production';
}

/** Resolve IMAP host for a mailbox's server. Prefer mailHostname, else SSH credential host. */
async function resolveMailHost(prisma, domain) {
  if (!domain?.serverId) throw new AppError(409, 'DOMAIN_NO_SERVER', 'Domain is not linked to a mail server');
  const mail = await prisma.serverMailService.findUnique({ where: { serverId: domain.serverId } });
  if (!mail?.provisioned) throw new AppError(409, 'MAIL_NOT_PROVISIONED', 'Mail stack is not provisioned on this server');
  if (mail.mailHostname) return { host: mail.mailHostname, serverId: domain.serverId, mail };
  const cred = await prisma.serverCredential.findUnique({ where: { serverId: domain.serverId } });
  if (cred?.host) return { host: cred.host, serverId: domain.serverId, mail };
  throw new AppError(409, 'MAIL_HOST_UNKNOWN', 'No mail hostname is configured');
}

export function createWebmailAuthService({ prisma, now = () => new Date() }) {
  return {
    cookieName: COOKIE,

    async login({ address, password }, meta = {}) {
      const at = address.lastIndexOf('@');
      const localPart = address.slice(0, at);
      const domainName = address.slice(at + 1);
      const domain = await prisma.domain.findFirst({
        where: { name: domainName, archivedAt: null },
        include: { mailConfig: true },
      });
      // Uniform failure — do not reveal whether the domain or mailbox exists.
      const deny = () => {
        throw new AppError(401, 'WEBMAIL_AUTH_FAILED', 'Invalid email or password');
      };
      if (!domain?.mailConfig?.enabled) deny();
      const mailbox = await prisma.mailboxAccount.findFirst({
        where: { domainId: domain.id, localPart, status: 'active', deletedAt: null },
      });
      if (!mailbox?.provisioned) deny();

      let hostInfo;
      try {
        hostInfo = await resolveMailHost(prisma, domain);
      } catch (e) {
        if (e instanceof AppError && e.status === 409) deny();
        throw e;
      }

      await verifyMailboxLogin({ host: hostInfo.host, address, password, tlsInsecure: tlsInsecure() });

      const token = randomBytes(32).toString('base64url');
      const expiresAt = new Date(now().getTime() + SESSION_HOURS * 3600_000);
      await prisma.mailboxSession.create({
        data: {
          mailboxId: mailbox.id,
          tokenHash: hashToken(token),
          secretEnc: encrypt(Buffer.from(password, 'utf8'), credentialKey()),
          expiresAt,
          lastSeenAt: now(),
          ipHash: meta.ip ? sha256(meta.ip) : null,
          userAgentHash: meta.userAgent ? sha256(meta.userAgent) : null,
        },
      });

      return {
        token,
        cookieName: COOKIE,
        expiresAt: expiresAt.toISOString(),
        mailbox: {
          id: mailbox.id,
          address,
          displayName: mailbox.displayName,
          domain: domain.name,
        },
      };
    },

    async logout(token) {
      if (!token) return { ok: true };
      await prisma.mailboxSession.updateMany({
        where: { tokenHash: hashToken(token), revokedAt: null },
        data: { revokedAt: now() },
      });
      return { ok: true };
    },

    async resolveSession(token) {
      if (!token) throw new AppError(401, 'WEBMAIL_SESSION_REQUIRED', 'Webmail login required');
      const row = await prisma.mailboxSession.findUnique({
        where: { tokenHash: hashToken(token) },
        include: {
          mailbox: {
            include: {
              domain: { include: { mailConfig: true, server: { include: { mailService: true, credential: true } } } },
            },
          },
        },
      });
      if (!row || row.revokedAt || row.expiresAt <= now()) {
        throw new AppError(401, 'WEBMAIL_SESSION_EXPIRED', 'Webmail session expired');
      }
      const mb = row.mailbox;
      if (!mb || mb.status !== 'active' || mb.deletedAt) throw new AppError(401, 'WEBMAIL_SESSION_EXPIRED', 'Webmail session expired');
      const domain = mb.domain;
      const address = `${mb.localPart}@${domain.name}`;
      const host = domain.server?.mailService?.mailHostname || domain.server?.credential?.host;
      if (!host) throw new AppError(409, 'MAIL_HOST_UNKNOWN', 'Mail hostname is not configured');
      let password;
      try {
        password = decrypt(Buffer.from(row.secretEnc), credentialKey()).toString('utf8');
      } catch {
        throw new AppError(401, 'WEBMAIL_SESSION_EXPIRED', 'Webmail session expired');
      }
      await prisma.mailboxSession.update({ where: { id: row.id }, data: { lastSeenAt: now() } });
      return {
        sessionId: row.id,
        mailboxId: mb.id,
        address,
        displayName: mb.displayName,
        domain: domain.name,
        host,
        password,
        tlsInsecure: tlsInsecure(),
      };
    },

    me(session) {
      return {
        address: session.address,
        displayName: session.displayName,
        domain: session.domain,
      };
    },
  };
}
