import { AppError } from '../../common/errors/app-error.js';
import { createMailAccess, provisioningState } from '../../common/mail-support.js';
import { normalizeStoredHealth } from '../../common/mail-provision.scripts.js';

const webmailUrl = () => process.env.WEBMAIL_PUBLIC_URL || 'http://127.0.0.1:5196';

/** Safe read of a table that may be missing on a stale client: returns [] instead of throwing. */
async function rows(prisma, model, args) {
  try {
    if (!prisma[model]?.findMany) return [];
    return await prisma[model].findMany(args);
  } catch {
    return [];
  }
}

const AUDIT_FIELDS = ['id', 'actorId', 'action', 'resourceType', 'resourceId', 'result', 'occurredAt'];
const toAuditDto = (e) => ({
  ...Object.fromEntries(AUDIT_FIELDS.map((k) => [k, e[k] ?? null])),
  actor: e.actor ? { id: e.actor.id, displayName: e.actor.displayName ?? null } : null,
});

const dnsRank = { verified: 3, published: 2, pending: 1, error: 0 };

/** Aggregate, read-only mail dashboard data. Never touches SSH, never returns hashes or key material. */
export function createMailOverviewService({ prisma, now = () => new Date(), config = {} }) {
  const access = createMailAccess({ prisma, now });

  async function visible(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const sids = await access.scope.serverIds(actor);
    const explicit = await access.scope.explicitServerIds(actor);
    const domainWhere = await access.scope.domainWhere(actor);
    const domains = await rows(prisma, 'domain', { where: { archivedAt: null, ...domainWhere } });
    const serverIdSet = sids === null ? null : new Set([...sids, ...(explicit ?? []), ...domains.map((d) => d.serverId).filter(Boolean)]);
    const servers = (await rows(prisma, 'server', { where: { archivedAt: null } })).filter((s) => serverIdSet === null || serverIdSet.has(s.id));
    return { servers, domains };
  }

  return {
    async overview(actor) {
      const { servers, domains } = await visible(actor);
      const serverIds = servers.map((s) => s.id);
      const domainIds = domains.map((d) => d.id);
      const svc = await rows(prisma, 'serverMailService', { where: { serverId: { in: serverIds } } });
      const cfgs = await rows(prisma, 'domainMailConfig', { where: { domainId: { in: domainIds } } });
      const boxes = await rows(prisma, 'mailboxAccount', { where: { domainId: { in: domainIds }, status: { not: 'deleted' } } });
      const fw = await rows(prisma, 'auditEvent', { where: { action: 'mail.firewall.open', result: 'success', resourceId: { in: serverIds } } });
      const approvals = await rows(prisma, 'approvalRequest', { where: { status: 'pending', action: { startsWith: 'mail.' } } });
      const pendingApprovals = actor.isOwner ? approvals.length : approvals.filter((a) => a.requesterId === actor.id).length;

      const cfgByDomain = new Map(cfgs.map((c) => [c.domainId, c]));
      const boxCount = new Map();
      for (const b of boxes) boxCount.set(b.domainId, (boxCount.get(b.domainId) ?? 0) + 1);

      const domainView = domains
        .filter((d) => cfgByDomain.get(d.id)?.enabled)
        .map((d) => {
          const c = cfgByDomain.get(d.id);
          return {
            domainId: d.id,
            domain: d.name,
            serverId: d.serverId ?? null,
            enabled: true,
            catchAllMailboxId: c.catchAllMailboxId ?? null,
            quotaDefaultMb: c.quotaDefaultMb ?? 1024,
            dkimSelector: c.dkimSelector ?? 'nt1',
            dkimPublicKeyPresent: Boolean(c.dkimPublicKey),
            dnsState: c.dnsState ?? 'pending',
            mailboxCount: boxCount.get(d.id) ?? 0,
          };
        });

      const serverView = servers.map((s) => {
        const row = svc.find((r) => r.serverId === s.id) ?? null;
        const stored = normalizeStoredHealth(row?.lastHealthJson?.health ?? null);
        const sd = domainView.filter((d) => d.serverId === s.id);
        const hasHealth = Boolean(row?.lastHealthAt);
        const portsOpened = fw.some((e) => e.resourceId === s.id);
        const readiness = [
          { id: 'preflight', state: row?.lastHealthJson?.provision || row?.provisioned ? 'done' : row ? 'todo' : 'blocked' },
          { id: 'provision', state: row?.provisioned ? 'done' : row?.status === 'error' ? 'failed' : row ? 'todo' : 'blocked' },
          { id: 'firewall', state: portsOpened ? 'done' : row?.provisioned ? 'todo' : 'blocked' },
          { id: 'health', state: hasHealth ? (stored?.ok === false ? 'failed' : 'done') : row?.provisioned ? 'todo' : 'blocked' },
          { id: 'dns', state: sd.length && sd.every((d) => dnsRank[d.dnsState] >= 2) ? 'done' : sd.length ? 'todo' : 'blocked' },
          { id: 'mailbox', state: sd.some((d) => d.mailboxCount > 0) ? 'done' : sd.length ? 'todo' : 'blocked' },
        ];
        return {
          serverId: s.id,
          serverAlias: s.alias,
          status: row?.status ?? 'disabled',
          provisioned: row?.provisioned ?? false,
          mailHostname: row?.mailHostname ?? null,
          stackVersion: row?.stackVersion ?? null,
          lastHealthAt: row?.lastHealthAt ?? null,
          healthOk: stored?.ok ?? null,
          openRelay: stored?.openRelay ?? 'unknown',
          tls: stored?.tls ?? 'unknown',
          portsOpened,
          domainsEnabled: sd.length,
          mailboxes: sd.reduce((n, d) => n + d.mailboxCount, 0),
          readiness,
        };
      });

      return {
        kpis: {
          serversWithMail: serverView.filter((s) => s.status !== 'disabled').length,
          provisionedStacks: serverView.filter((s) => s.provisioned).length,
          domainsEnabled: domainView.length,
          mailboxes: boxes.length,
          suspended: boxes.filter((b) => b.status === 'suspended').length,
          dnsPending: domainView.filter((d) => dnsRank[d.dnsState] < 2).length,
          pendingApprovals,
        },
        servers: serverView,
        domains: domainView,
        provisioning: provisioningState(config),
        webmailUrl: webmailUrl(),
        generatedAt: now(),
      };
    },

    /** Recent mail-related audit events, limited to resources the actor can see. */
    async audit({ limit, serverId, domainId }, actor) {
      const { servers, domains } = await visible(actor);
      const where = { OR: [{ action: { startsWith: 'mail.' } }, { action: { startsWith: 'mailbox.' } }] };
      let list = await rows(prisma, 'auditEvent', {
        where,
        orderBy: { occurredAt: 'desc' },
        take: 400,
        include: { actor: { select: { id: true, displayName: true } } },
      });
      if (!actor.isOwner) {
        const boxes = await rows(prisma, 'mailboxAccount', { where: { domainId: { in: domains.map((d) => d.id) } } });
        const allowed = new Set([...servers.map((s) => s.id), ...domains.map((d) => d.id), ...boxes.map((b) => b.id)]);
        list = list.filter((e) => e.resourceId && allowed.has(e.resourceId));
      }
      if (serverId) list = list.filter((e) => e.resourceId === serverId);
      if (domainId) list = list.filter((e) => e.resourceId === domainId);
      return { items: list.slice(0, limit).map(toAuditDto) };
    },

    /** Stored health data only (from the last probe). A live queue read needs SSH and is not done here. */
    async healthSummary(actor) {
      const { servers } = await visible(actor);
      const svc = await rows(prisma, 'serverMailService', { where: { serverId: { in: servers.map((s) => s.id) } } });
      const items = svc.map((row) => {
        const stored = normalizeStoredHealth(row.lastHealthJson?.health ?? null);
        return {
          serverId: row.serverId,
          serverAlias: servers.find((s) => s.id === row.serverId)?.alias ?? null,
          lastHealthAt: row.lastHealthAt ?? null,
          probe: stored ? 'STORED' : 'NOT_RUN',
          ok: stored?.ok ?? null,
          openRelay: stored?.openRelay ?? 'unknown',
          tls: stored?.tls ?? 'unknown',
          failing: (stored?.checks ?? []).filter((c) => !c.pass).map((c) => ({ id: c.id, detail: String(c.detail ?? '').slice(0, 200) })),
          queue: { source: 'NOT_COLLECTED', note: 'Queue depth needs a live SSH probe; it is not read from stored data.' },
        };
      });
      return { items };
    },
  };
}
