import { createHash, randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { verifyMailboxLogin, withSshMailTunnel } from '../../common/webmail-imap.js';
import { decrypt, encrypt, sha256 } from '../platform/platform.crypto.js';

const COOKIE = 'nt_wm';
const SESSION_HOURS = 12;

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function credentialKey() {
  return process.env.CREDENTIAL_ENCRYPTION_KEY;
}

/**
 * Webmail auth. IMAP is reached through an SSH tunnel to 127.0.0.1:993 on the
 * mailbox's server so public DNS mistakes / closed 993 do not break panel webmail.
 */
export function createWebmailAuthService({ prisma, ssh = null, now = () => new Date() }) {
  async function resolveServerId(domain) {
    if (!domain?.serverId) throw new AppError(409, 'DOMAIN_NO_SERVER', 'Domain is not linked to a mail server');
    const mail = await prisma.serverMailService.findUnique({ where: { serverId: domain.serverId } });
    if (!mail?.provisioned) throw new AppError(409, 'MAIL_NOT_PROVISIONED', 'Mail stack is not provisioned on this server');
    return domain.serverId;
  }

  async function sleep(ms) {
    await new Promise((r) => setTimeout(r, ms));
  }

  /** SSH to this VPS is occasionally flaky (ETIMEDOUT). Retry transient tunnel failures only. */
  async function viaTunnel(serverId, address, password, fn) {
    if (!ssh?.runRemote) throw new AppError(500, 'SSH_UNAVAILABLE', 'SSH access is not wired for webmail');
    const attempts = 3;
    let last;
    for (let i = 0; i < attempts; i++) {
      try {
        return await ssh.runRemote(serverId, async ({ client }) => {
          if (!client) throw new AppError(500, 'SSH_UNAVAILABLE', 'SSH client missing');
          return withSshMailTunnel(client, { address, password }, fn);
        });
      } catch (e) {
        last = e;
        const code = e?.code;
        const retryable =
          code === 'SSH_UNREACHABLE' ||
          code === 'SSH_TIMEOUT' ||
          code === 'WEBMAIL_TUNNEL_FAILED' ||
          code === 'WEBMAIL_IMAP_UNREACHABLE';
        if (!retryable || i === attempts - 1) throw e;
        await sleep(1200 * (i + 1));
      }
    }
    throw last;
  }

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

      let serverId;
      try {
        serverId = await resolveServerId(domain);
      } catch (e) {
        if (e instanceof AppError && e.status === 409) deny();
        throw e;
      }

      try {
        await viaTunnel(serverId, address, password, (ctx) => verifyMailboxLogin(ctx));
      } catch (e) {
        // Wrong password stays 401; SSH/tunnel problems become clear 502s (not "invalid password").
        if (e instanceof AppError && e.status === 401) deny();
        throw e;
      }

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
      const expired = () => {
        throw new AppError(401, 'WEBMAIL_SESSION_EXPIRED', 'Webmail session expired');
      };
      let row;
      try {
        row = await prisma.mailboxSession.findUnique({
          where: { tokenHash: hashToken(token) },
          include: {
            mailbox: {
              include: {
                domain: { include: { mailConfig: true, server: { select: { id: true } } } },
              },
            },
          },
        });
      } catch {
        expired();
      }
      if (!row || row.revokedAt || row.expiresAt <= now()) expired();
      const mb = row.mailbox;
      if (!mb || mb.status !== 'active' || mb.deletedAt) expired();
      const domain = mb.domain;
      if (!domain?.name) expired();
      const address = `${mb.localPart}@${domain.name}`;
      const serverId = domain.serverId || domain.server?.id;
      if (!serverId) throw new AppError(409, 'MAIL_HOST_UNKNOWN', 'Mail server is not linked');
      let password;
      try {
        const blob = Buffer.isBuffer(row.secretEnc) ? row.secretEnc : Buffer.from(row.secretEnc);
        password = decrypt(blob, credentialKey()).toString('utf8');
      } catch {
        expired();
      }
      try {
        await prisma.mailboxSession.update({ where: { id: row.id }, data: { lastSeenAt: now() } });
      } catch {
        /* non-fatal */
      }
      return {
        sessionId: row.id,
        mailboxId: mb.id,
        serverId,
        address,
        displayName: mb.displayName,
        domain: domain.name,
        password,
      };
    },

    /** Execute IMAP/SMTP work inside an SSH tunnel for this session. */
    async withMail(session, fn) {
      return viaTunnel(session.serverId, session.address, session.password, fn);
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
