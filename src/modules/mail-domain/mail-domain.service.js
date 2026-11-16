import { createHash } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { createMailAccess, guardSchema, mailDelegate } from '../../common/mail-support.js';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
export const DKIM_PLACEHOLDER = 'PENDING_SERVER_KEY_GENERATION';

/**
 * Pure DNS recipe for a mail-enabled domain. Names are relative to the zone ("@" = apex).
 * DKIM carries a placeholder until the server generates a key (TASK-035); the private key never enters the panel.
 */
export function renderMailDnsRecipe({ domain, mailHostname = null, serverIp = null, selector = 'nt1', dkimPublicKey = null }) {
  const host = mailHostname ?? `mail.${domain}`;
  const inZoneHost = host === `mail.${domain}` ? 'mail' : null;
  const ip = serverIp && IPV4.test(serverIp) ? serverIp : null;
  const records = [
    { id: 'mx', type: 'MX', name: '@', value: `10 ${host}.`, ttl: 3600, purpose: 'Route inbound mail to this server', status: 'ready' },
  ];
  if (inZoneHost) {
    records.push({ id: 'mail-a', type: 'A', name: inZoneHost, value: ip ?? '<SERVER_PUBLIC_IP>', ttl: 3600, purpose: 'Mail host address', status: ip ? 'ready' : 'placeholder' });
  }
  records.push(
    { id: 'spf', type: 'TXT', name: '@', value: 'v=spf1 mx ~all', ttl: 3600, purpose: 'Authorize this MX to send (soft-fail while warming up)', status: 'ready' },
    {
      id: 'dkim',
      type: 'TXT',
      name: `${selector}._domainkey`,
      value: dkimPublicKey ? `v=DKIM1; k=rsa; p=${dkimPublicKey}` : `v=DKIM1; k=rsa; p=${DKIM_PLACEHOLDER}`,
      ttl: 3600,
      purpose: 'DKIM public key (private key stays on the mail server)',
      status: dkimPublicKey ? 'ready' : 'placeholder',
    },
    { id: 'dmarc', type: 'TXT', name: '_dmarc', value: `v=DMARC1; p=none; rua=mailto:postmaster@${domain}`, ttl: 3600, purpose: 'Start in monitor mode, tighten after reports', status: 'ready' },
  );
  return {
    domain,
    mailHostname: host,
    records,
    notes: [
      'Reverse DNS (PTR) for the server IP must be set at the hosting provider and match the mail hostname.',
      'Deliverability is not guaranteed: IP reputation and warm-up are outside the panel.',
      'This is a recipe only. Publishing records is a separate approval-gated DNS change.',
    ],
  };
}

export function createMailDomainService({ prisma, now = () => new Date(), auditService = null, rbac = null, remote = null, platform = null, adapters = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const access = createMailAccess({ prisma, rbac, now });

  async function resolveServerIp(domain) {
    if (!domain.serverId || !prisma.serverCredential?.findUnique) return null;
    try {
      const cred = await prisma.serverCredential.findUnique({ where: { serverId: domain.serverId } });
      if (cred?.host && IPV4.test(cred.host)) return cred.host;
    } catch {
      /* ignore */
    }
    return null;
  }

  async function buildDnsChecklist(domain, cfg) {
    let mailHostname = null;
    if (domain.serverId && prisma.serverMailService?.findUnique) {
      try {
        mailHostname = (await prisma.serverMailService.findUnique({ where: { serverId: domain.serverId } }))?.mailHostname ?? null;
      } catch {
        /* degrade */
      }
    }
    const serverIp = await resolveServerIp(domain);
    const recipe = renderMailDnsRecipe({
      domain: domain.name,
      mailHostname,
      serverIp,
      selector: cfg?.dkimSelector ?? 'nt1',
      dkimPublicKey: cfg?.dkimPublicKey ?? null,
    });
    const existing = domain.dnsRecords ?? [];
    const records = recipe.records.map((r) => {
      const hit = existing.find((e) => e.type === r.type && (e.name === r.name || (r.name === '@' && e.name === domain.name)));
      return { ...r, present: Boolean(hit), matches: hit ? hit.valueSummary === r.value : false };
    });
    return { ...recipe, enabled: cfg?.enabled ?? false, dnsState: cfg?.dnsState ?? 'pending', records, webmailUrl: process.env.WEBMAIL_PUBLIC_URL || 'http://127.0.0.1:5196' };
  }

  /** Push virtual domain + DKIM generation to a provisioned server. Never throws: panel state stays authoritative (metadata-only fallback). */
  async function pushDomain(domain, cfg, actor) {
    if (!remote) return { pushed: false, reason: 'no_executor' };
    try {
      const res = await remote.addDomain(domain.serverId, { domain: domain.name, selector: cfg.dkimSelector ?? 'nt1' });
      if (res.pushed && res.dkimPublicKey) {
        await guardSchema(() => mailDelegate(prisma, 'domainMailConfig').update({ where: { domainId: domain.id }, data: { dkimPublicKey: res.dkimPublicKey } }));
        cfg.dkimPublicKey = res.dkimPublicKey;
      }
      await audit({ actorId: actor.id, action: 'mail.domain.push', resourceType: 'domain', resourceId: domain.id, result: res.pushed ? 'success' : 'skipped', metadata: { reason: res.reason ?? null, dkimPublished: Boolean(res.dkimPublicKey) } });
      return { pushed: res.pushed, reason: res.reason ?? null };
    } catch (e) {
      await audit({ actorId: actor.id, action: 'mail.domain.push', resourceType: 'domain', resourceId: domain.id, result: 'failure', metadata: { code: e?.code ?? 'ERROR' } });
      return { pushed: false, reason: e?.code ?? 'push_failed' };
    }
  }

  const view = (domain, cfg, mailboxCount, serverMail) => ({
    domainId: domain.id,
    domain: domain.name,
    serverId: domain.serverId ?? null,
    serverAlias: domain.server?.alias ?? null,
    enabled: cfg?.enabled ?? false,
    catchAllMailboxId: cfg?.catchAllMailboxId ?? null,
    quotaDefaultMb: cfg?.quotaDefaultMb ?? 1024,
    dkimSelector: cfg?.dkimSelector ?? 'nt1',
    dkimPublicKeyPresent: Boolean(cfg?.dkimPublicKey),
    dnsState: cfg?.dnsState ?? 'pending',
    mailboxCount,
    serverMail: { status: serverMail?.status ?? 'disabled', provisioned: serverMail?.provisioned ?? false },
  });

  async function readConfig(domainId) {
    if (!prisma.domainMailConfig?.findUnique) return { cfg: null, pending: true };
    try {
      return { cfg: await prisma.domainMailConfig.findUnique({ where: { domainId } }) };
    } catch (e) {
      if (/doesn't exist|does not exist|Unknown/i.test(String(e?.message))) return { cfg: null, pending: true };
      throw e;
    }
  }

  async function aux(domain) {
    let mailboxCount = 0;
    let serverMail = null;
    try {
      if (prisma.mailboxAccount?.count) mailboxCount = await prisma.mailboxAccount.count({ where: { domainId: domain.id, status: { not: 'deleted' } } });
      if (domain.serverId && prisma.serverMailService?.findUnique) serverMail = await prisma.serverMailService.findUnique({ where: { serverId: domain.serverId } });
    } catch {
      /* stale client or table missing: degrade */
    }
    return { mailboxCount, serverMail };
  }

  return {
    async get(domainId, actor) {
      const domain = await access.loadDomain(domainId, actor);
      const { cfg, pending } = await readConfig(domainId);
      const { mailboxCount, serverMail } = await aux(domain);
      const out = view(domain, cfg, mailboxCount, serverMail);
      return pending ? { ...out, schemaPending: true } : out;
    },

    async enable(domainId, input, actor) {
      const domain = await access.loadDomain(domainId, actor);
      await access.requireWrite(actor, domain);
      if (!domain.serverId) throw new AppError(409, 'DOMAIN_NO_SERVER', 'Domain is not linked to a server');
      const d = mailDelegate(prisma, 'domainMailConfig');
      const row = await guardSchema(() =>
        d.upsert({
          where: { domainId },
          create: { domainId, enabled: true, ...(input.quotaDefaultMb ? { quotaDefaultMb: input.quotaDefaultMb } : {}), ...(input.dkimSelector ? { dkimSelector: input.dkimSelector } : {}) },
          update: { enabled: true, ...(input.quotaDefaultMb ? { quotaDefaultMb: input.quotaDefaultMb } : {}), ...(input.dkimSelector ? { dkimSelector: input.dkimSelector } : {}) },
        }),
      );
      await audit({ actorId: actor.id, action: 'mail.domain.enable', resourceType: 'domain', resourceId: domainId, result: 'success', after: { enabled: true, quotaDefaultMb: row.quotaDefaultMb } });
      const remoteResult = await pushDomain(domain, row, actor);
      const { mailboxCount, serverMail } = await aux(domain);
      return { ...view(domain, row, mailboxCount, serverMail), remote: remoteResult };
    },

    /** Re-push the virtual domain and DKIM key (e.g. enabled before the stack was provisioned). */
    async sync(domainId, actor) {
      const domain = await access.loadDomain(domainId, actor);
      await access.requireWrite(actor, domain);
      const cfg = await guardSchema(() => mailDelegate(prisma, 'domainMailConfig').findUnique({ where: { domainId } }));
      if (!cfg?.enabled) throw new AppError(409, 'MAIL_DOMAIN_NOT_ENABLED', 'Enable mail for this domain first');
      const remoteResult = await pushDomain(domain, { ...cfg }, actor);
      const { cfg: fresh } = await readConfig(domainId);
      const { mailboxCount, serverMail } = await aux(domain);
      return { ...view(domain, fresh ?? cfg, mailboxCount, serverMail), remote: remoteResult };
    },

    async disable(domainId, { reason }, actor) {
      const domain = await access.loadDomain(domainId, actor);
      await access.requireWrite(actor, domain);
      const d = mailDelegate(prisma, 'domainMailConfig');
      const existing = await guardSchema(() => d.findUnique({ where: { domainId } }));
      if (!existing) throw new AppError(404, 'MAIL_DOMAIN_NOT_FOUND', 'Mail is not enabled for this domain');
      const row = await guardSchema(() => d.update({ where: { domainId }, data: { enabled: false, catchAllMailboxId: null } }));
      await audit({ actorId: actor.id, action: 'mail.domain.disable', resourceType: 'domain', resourceId: domainId, result: 'success', metadata: { reason: reason ?? null } });
      const { mailboxCount, serverMail } = await aux(domain);
      return view(domain, row, mailboxCount, serverMail);
    },

    async update(domainId, input, actor) {
      const domain = await access.loadDomain(domainId, actor);
      await access.requireWrite(actor, domain);
      const d = mailDelegate(prisma, 'domainMailConfig');
      const existing = await guardSchema(() => d.findUnique({ where: { domainId } }));
      if (!existing?.enabled) throw new AppError(409, 'MAIL_DOMAIN_NOT_ENABLED', 'Enable mail for this domain first');
      if (input.catchAllMailboxId) {
        const mb = await guardSchema(() => mailDelegate(prisma, 'mailboxAccount').findUnique({ where: { id: input.catchAllMailboxId } }));
        if (!mb || mb.domainId !== domainId || mb.status !== 'active') {
          throw new AppError(422, 'CATCHALL_MAILBOX_INVALID', 'Catch-all must be an active mailbox of this domain');
        }
      }
      const data = {};
      for (const k of ['quotaDefaultMb', 'dkimSelector', 'catchAllMailboxId']) if (input[k] !== undefined) data[k] = input[k];
      const row = await guardSchema(() => d.update({ where: { domainId }, data }));
      await audit({ actorId: actor.id, action: 'mail.domain.update', resourceType: 'domain', resourceId: domainId, result: 'success', after: data });
      const { mailboxCount, serverMail } = await aux(domain);
      return view(domain, row, mailboxCount, serverMail);
    },

    /** DNS checklist: the recipe plus which records already exist in the panel DNS metadata. */
    async dns(domainId, actor) {
      const domain = await access.loadDomain(domainId, actor);
      const { cfg } = await readConfig(domainId);
      return buildDnsChecklist(domain, cfg);
    },

    /**
     * Publish ready mail DNS records (skip placeholders) through platform.gate + DNS adapter.
     * Stores panel DnsRecord rows on success and sets dnsState=published.
     */
    async publishDns(domainId, input, actor) {
      if (!platform?.gate) throw new AppError(500, 'PLATFORM_UNAVAILABLE', 'Approval gate is not wired');
      if (!adapters?.dns) throw new AppError(500, 'DNS_ADAPTER_UNAVAILABLE', 'DNS adapter is not wired');
      const domain = await access.loadDomain(domainId, actor);
      await access.requireWrite(actor, domain);
      const { cfg } = await readConfig(domainId);
      if (!cfg?.enabled) throw new AppError(409, 'MAIL_DOMAIN_NOT_ENABLED', 'Enable mail for this domain first');
      const checklist = await buildDnsChecklist(domain, cfg);
      const toPublish = checklist.records.filter((r) => r.status === 'ready' && (!r.present || !r.matches));
      if (!toPublish.length) {
        return { published: 0, skipped: checklist.records.length, alreadyOk: true, dnsState: cfg.dnsState, webmailUrl: checklist.webmailUrl };
      }
      const impact = toPublish.map((r) => `Upsert ${r.type} ${r.name} → ${String(r.value).slice(0, 96)}`);
      const binding = sha256(JSON.stringify(toPublish.map((r) => [r.type, r.name, r.value, r.ttl])));
      const gate = await platform.gate(
        {
          action: 'mail.dns.publish',
          binding,
          resourceType: 'domain',
          resourceId: domainId,
          approvalId: input.approvalId,
          reason: input.reason,
          impact,
          rollbackPlan: input.rollbackNote,
          context: { environmentId: domain.environmentId ?? null },
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval, impact, count: toPublish.length };

      const saved = [];
      try {
        for (const r of toPublish) {
          const record = { type: r.type, name: r.name, value: r.value, ttl: r.ttl };
          await adapters.dns.upsert(record);
          const existing = (domain.dnsRecords ?? []).find((e) => e.type === r.type && e.name === r.name);
          let row;
          if (existing) {
            row = await prisma.dnsRecord.update({
              where: { id: existing.id },
              data: { valueSummary: r.value.slice(0, 255), ttl: r.ttl },
            });
          } else {
            row = await prisma.dnsRecord.create({
              data: { domainId, type: r.type, name: r.name, valueSummary: r.value.slice(0, 255), ttl: r.ttl },
            });
          }
          saved.push(row);
        }
        await guardSchema(() =>
          mailDelegate(prisma, 'domainMailConfig').update({ where: { domainId }, data: { dnsState: 'published' } }),
        );
      } catch (e) {
        if (input.approvalId && platform.releaseFailedExecution) await platform.releaseFailedExecution(input.approvalId, actor);
        await audit({
          actorId: actor.id,
          action: 'mail.dns.publish',
          resourceType: 'domain',
          resourceId: domainId,
          result: 'failure',
          metadata: { code: e?.code ?? 'ERROR' },
        });
        if (e instanceof AppError) throw e;
        throw new AppError(502, 'DNS_PROVIDER_FAILED', 'DNS provider rejected a mail record; remaining records were not applied');
      }

      await audit({
        actorId: actor.id,
        action: 'mail.dns.publish',
        resourceType: 'domain',
        resourceId: domainId,
        result: 'success',
        after: { count: saved.length, types: toPublish.map((r) => r.type) },
      });
      return {
        published: saved.length,
        simulated: Boolean(adapters.simulated),
        dnsState: 'published',
        webmailUrl: checklist.webmailUrl,
      };
    },
  };
}
