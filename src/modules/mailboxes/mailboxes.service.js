import { AppError } from '../../common/errors/app-error.js';
import { hashPassword } from '../../common/crypto/password.js';
import { checkMailboxPassword } from './mailboxes.validator.js';
import { createMailAccess, guardSchema, mailDelegate } from '../../common/mail-support.js';

/**
 * Public mailbox shape. Built field by field so passwordHash (or any new column) can never leak.
 * The panel keeps a scrypt hash only; the Dovecot-format hash is produced on the server at provisioning (TASK-035).
 */
export function toMailboxDto(row, domainName) {
  return {
    id: row.id,
    domainId: row.domainId,
    address: `${row.localPart}@${domainName}`,
    localPart: row.localPart,
    displayName: row.displayName ?? null,
    quotaMb: row.quotaMb,
    status: row.status,
    provisioned: Boolean(row.provisioned),
    passwordSet: Boolean(row.passwordHash || row.passwordSetAt),
    passwordSetAt: row.passwordSetAt ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

const EVENT_FIELDS = ['id', 'mailboxId', 'actorId', 'action', 'metadataJson', 'createdAt'];
const toEventDto = (e) => Object.fromEntries(EVENT_FIELDS.map((k) => [k, e[k] ?? null]));

export function createMailboxesService({ prisma, now = () => new Date(), auditService = null, rbac = null, remote = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const access = createMailAccess({ prisma, rbac, now });

  /** Push to a provisioned server. The password goes over the SSH session (stdin) only; never logged, audited or returned. */
  async function pushMailbox(mb, domain, password, actor) {
    if (!remote) return { pushed: false, reason: 'no_executor' };
    const address = `${mb.localPart}@${domain.name}`;
    try {
      const res = await remote.setMailbox(domain.serverId, { address, quotaMb: mb.quotaMb, password });
      if (res.pushed) await guardSchema(() => mailDelegate(prisma, 'mailboxAccount').update({ where: { id: mb.id }, data: { provisioned: true } }));
      await event(mb.id, actor, 'push', { pushed: res.pushed, reason: res.reason ?? null });
      await audit({ actorId: actor.id, action: 'mailbox.push', resourceType: 'mailbox', resourceId: mb.id, result: res.pushed ? 'success' : 'skipped', metadata: { address, reason: res.reason ?? null } });
      return { pushed: res.pushed, reason: res.reason ?? null };
    } catch (e) {
      await audit({ actorId: actor.id, action: 'mailbox.push', resourceType: 'mailbox', resourceId: mb.id, result: 'failure', metadata: { address, code: e?.code ?? 'ERROR' } });
      return { pushed: false, reason: e?.code ?? 'push_failed' };
    }
  }

  async function event(mailboxId, actor, action, metadataJson = null) {
    await guardSchema(() => mailDelegate(prisma, 'mailboxAuditEvent').create({ data: { mailboxId, actorId: actor.id, action, metadataJson } }));
  }

  async function loadMailbox(id, actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const mb = await guardSchema(() => mailDelegate(prisma, 'mailboxAccount').findUnique({ where: { id } }));
    if (!mb) throw new AppError(404, 'MAILBOX_NOT_FOUND', 'Mailbox not found');
    // Visibility is the domain's: out-of-scope domains answer 404 for the mailbox too.
    let domain;
    try {
      domain = await access.loadDomain(mb.domainId, actor);
    } catch (e) {
      if (e?.status === 404) throw new AppError(404, 'MAILBOX_NOT_FOUND', 'Mailbox not found');
      throw e;
    }
    return { mb, domain };
  }

  async function mutableMailbox(id, actor) {
    const ctx = await loadMailbox(id, actor);
    await access.requireWrite(actor, ctx.domain);
    if (ctx.mb.status === 'deleted') throw new AppError(409, 'MAILBOX_DELETED', 'Mailbox is deleted');
    return ctx;
  }

  /** Cross-domain list (scope-aware): filters by server/domain/status/search, paginated. Metadata only, never hashes. */
  async function listAcross({ domainId, serverId, q, status, limit, offset }, actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const domainWhere = await access.scope.domainWhere(actor);
    let domains = await prisma.domain.findMany({ where: { archivedAt: null, ...domainWhere } });
    if (domainId) domains = domains.filter((d) => d.id === domainId);
    if (serverId) domains = domains.filter((d) => d.serverId === serverId);
    const byId = new Map(domains.map((d) => [d.id, d]));
    let servers = [];
    try {
      servers = (await prisma.server?.findMany?.({ where: {} })) ?? [];
    } catch {
      /* alias is cosmetic */
    }
    const needle = q ? q.toLowerCase() : null;
    let all;
    try {
      all = await mailDelegate(prisma, 'mailboxAccount').findMany({
        where: { domainId: { in: [...byId.keys()] }, ...(status ? { status } : { status: { not: 'deleted' } }) },
        orderBy: { localPart: 'asc' },
      });
    } catch (e) {
      if (e?.code === 'SCHEMA_REQUIRED') return { items: [], total: 0, limit, offset, schemaPending: true };
      return guardSchema(() => Promise.reject(e));
    }
    const dtos = all
      .map((r) => {
        const d = byId.get(r.domainId);
        return { ...toMailboxDto(r, d.name), domainName: d.name, serverId: d.serverId ?? null, serverAlias: servers.find((s) => s.id === d.serverId)?.alias ?? null };
      })
      .filter((m) => !needle || m.address.toLowerCase().includes(needle) || (m.displayName ?? '').toLowerCase().includes(needle));
    return { items: dtos.slice(offset, offset + limit), total: dtos.length, limit, offset };
  }

  return {
    async list({ domainId, serverId, q, status, limit, offset = 0 }, actor) {
      if (domainId && !serverId && !q && !offset) {
        const domain = await access.loadDomain(domainId, actor);
        let rows;
        try {
          rows = await mailDelegate(prisma, 'mailboxAccount').findMany({
            where: { domainId, ...(status ? { status } : { status: { not: 'deleted' } }) },
            orderBy: { localPart: 'asc' },
            take: limit,
          });
        } catch (e) {
          if (e?.code === 'SCHEMA_REQUIRED') return { items: [], schemaPending: true };
          return guardSchema(() => Promise.reject(e));
        }
        return { items: rows.map((r) => toMailboxDto(r, domain.name)) };
      }
      return listAcross({ domainId, serverId, q, status, limit, offset }, actor);
    },

    async get(id, actor) {
      const { mb, domain } = await loadMailbox(id, actor);
      return toMailboxDto(mb, domain.name);
    },

    async create(input, actor) {
      const domain = await access.loadDomain(input.domainId, actor);
      await access.requireWrite(actor, domain);
      const weak = checkMailboxPassword(input.password, input.localPart);
      if (weak) throw new AppError(400, 'WEAK_PASSWORD', weak);
      const cfgD = mailDelegate(prisma, 'domainMailConfig');
      const cfg = await guardSchema(() => cfgD.findUnique({ where: { domainId: domain.id } }));
      if (!cfg?.enabled) throw new AppError(409, 'MAIL_DOMAIN_NOT_ENABLED', 'Enable mail for this domain first');
      const d = mailDelegate(prisma, 'mailboxAccount');
      const dup = await guardSchema(() => d.findUnique({ where: { domainId_localPart: { domainId: domain.id, localPart: input.localPart } } }));
      if (dup) throw new AppError(409, 'MAILBOX_EXISTS', 'A mailbox with this name already exists');
      const row = await guardSchema(() =>
        d.create({
          data: {
            domainId: domain.id,
            localPart: input.localPart,
            displayName: input.displayName ?? null,
            quotaMb: input.quotaMb ?? cfg.quotaDefaultMb ?? 1024,
            status: 'active',
            passwordHash: hashPassword(input.password),
            passwordSetAt: now(),
            provisioned: false,
            createdById: actor.id,
          },
        }),
      );
      await event(row.id, actor, 'create', { address: `${row.localPart}@${domain.name}`, quotaMb: row.quotaMb });
      await audit({ actorId: actor.id, action: 'mailbox.create', resourceType: 'mailbox', resourceId: row.id, result: 'success', after: { address: `${row.localPart}@${domain.name}`, quotaMb: row.quotaMb } });
      const remoteResult = await pushMailbox(row, domain, input.password, actor);
      return { ...toMailboxDto({ ...row, provisioned: remoteResult.pushed || row.provisioned }, domain.name), remote: remoteResult };
    },

    async update(id, input, actor) {
      const { mb, domain } = await mutableMailbox(id, actor);
      const data = {};
      for (const k of ['displayName', 'quotaMb']) if (input[k] !== undefined) data[k] = input[k];
      const row = await guardSchema(() => mailDelegate(prisma, 'mailboxAccount').update({ where: { id }, data }));
      await event(id, actor, 'update', data);
      await audit({ actorId: actor.id, action: 'mailbox.update', resourceType: 'mailbox', resourceId: id, result: 'success', after: data });
      return toMailboxDto(row ?? { ...mb, ...data }, domain.name);
    },

    /** Never echoes the password or any hash; the audit/event records only that it changed. */
    async setPassword(id, { password }, actor) {
      const { mb, domain } = await mutableMailbox(id, actor);
      const weak = checkMailboxPassword(password, mb.localPart);
      if (weak) throw new AppError(400, 'WEAK_PASSWORD', weak);
      const row = await guardSchema(() =>
        mailDelegate(prisma, 'mailboxAccount').update({ where: { id }, data: { passwordHash: hashPassword(password), passwordSetAt: now(), provisioned: false } }),
      );
      await event(id, actor, 'password.set', { provisioned: false });
      await audit({ actorId: actor.id, action: 'mailbox.password.set', resourceType: 'mailbox', resourceId: id, result: 'success', metadata: { address: `${mb.localPart}@${domain.name}` } });
      const remoteResult = await pushMailbox({ ...mb, ...(row ?? {}) }, domain, password, actor);
      return { ...toMailboxDto({ ...(row ?? mb), provisioned: remoteResult.pushed }, domain.name), remote: remoteResult };
    },

    async suspend(id, { reason }, actor) {
      const { mb, domain } = await mutableMailbox(id, actor);
      if (mb.status === 'suspended') return toMailboxDto(mb, domain.name);
      const row = await guardSchema(() => mailDelegate(prisma, 'mailboxAccount').update({ where: { id }, data: { status: 'suspended' } }));
      await event(id, actor, 'suspend', { reason: reason ?? null });
      await audit({ actorId: actor.id, action: 'mailbox.suspend', resourceType: 'mailbox', resourceId: id, result: 'success', metadata: { reason: reason ?? null } });
      return toMailboxDto(row ?? { ...mb, status: 'suspended' }, domain.name);
    },

    async unsuspend(id, { reason }, actor) {
      const { mb, domain } = await mutableMailbox(id, actor);
      if (mb.status === 'active') return toMailboxDto(mb, domain.name);
      const row = await guardSchema(() => mailDelegate(prisma, 'mailboxAccount').update({ where: { id }, data: { status: 'active' } }));
      await event(id, actor, 'unsuspend', { reason: reason ?? null });
      await audit({ actorId: actor.id, action: 'mailbox.unsuspend', resourceType: 'mailbox', resourceId: id, result: 'success', metadata: { reason: reason ?? null } });
      return toMailboxDto(row ?? { ...mb, status: 'active' }, domain.name);
    },

    /** Soft delete: status=deleted, credentials wiped. The row and its audit trail are kept. */
    async remove(id, { reason }, actor) {
      const { mb, domain } = await mutableMailbox(id, actor);
      const cfg = await guardSchema(() => mailDelegate(prisma, 'domainMailConfig').findUnique({ where: { domainId: domain.id } }));
      if (cfg?.catchAllMailboxId === id) throw new AppError(409, 'MAILBOX_IS_CATCHALL', 'Unset the catch-all before deleting this mailbox');
      const row = await guardSchema(() =>
        mailDelegate(prisma, 'mailboxAccount').update({ where: { id }, data: { status: 'deleted', deletedAt: now(), passwordHash: null } }),
      );
      if (remote && mb.provisioned) {
        try {
          await remote.removeMailbox(domain.serverId, { address: `${mb.localPart}@${domain.name}` });
        } catch {
          /* best effort: login is already disabled panel-side; the audit row below records the delete */
        }
      }
      await event(id, actor, 'delete', { reason: reason ?? null });
      await audit({ actorId: actor.id, action: 'mailbox.delete', resourceType: 'mailbox', resourceId: id, result: 'success', before: { address: `${mb.localPart}@${domain.name}` }, metadata: { reason: reason ?? null } });
      return toMailboxDto(row ?? { ...mb, status: 'deleted' }, domain.name);
    },

    async auditEvents(id, { limit }, actor) {
      await loadMailbox(id, actor);
      const rows = await guardSchema(() => mailDelegate(prisma, 'mailboxAuditEvent').findMany({ where: { mailboxId: id }, orderBy: { createdAt: 'desc' }, take: limit }));
      return { items: rows.map(toEventDto) };
    },
  };
}
