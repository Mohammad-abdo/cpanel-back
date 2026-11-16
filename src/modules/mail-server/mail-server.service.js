import { AppError } from '../../common/errors/app-error.js';
import { createMailAccess, guardSchema, mailDelegate, provisioningState } from '../../common/mail-support.js';
import { sha256 } from '../platform/platform.crypto.js';

/** Planned listening ports. Nothing is opened in slice 1; opening is a separate approval (mail.firewall.open). */
export const MAIL_PORTS = Object.freeze([
  { port: 25, protocol: 'smtp', role: 'Inbound SMTP (receive)' },
  { port: 465, protocol: 'smtps', role: 'Submission (implicit TLS)' },
  { port: 587, protocol: 'submission', role: 'Submission (STARTTLS)' },
  { port: 993, protocol: 'imaps', role: 'IMAPS' },
  { port: 2096, protocol: 'https', role: 'Webmail (TASK-037)' },
]);

/** Pure planner: ordered steps a future authorized apply would run. Executes nothing. */
export function planProvisioning({ serverAlias, mailHostname }) {
  const host = mailHostname ?? '<mail hostname>';
  return [
    { id: 'preflight', title: 'Preflight checks', detail: 'OS version, free disk, existing MTA, ports 25/465/587/993 not in use', risk: 'low', requiresApproval: false },
    { id: 'packages', title: 'Install packages', detail: 'postfix, dovecot-imapd, dovecot-lmtpd, opendkim, opendkim-tools via apt (argv, no shell interpolation)', risk: 'high', requiresApproval: true },
    { id: 'postfix', title: 'Render Postfix virtual config', detail: `myhostname=${host}; virtual domains/mailboxes maps; smtpd_relay_restrictions=permit_sasl_authenticated,reject_unauth_destination`, risk: 'high', requiresApproval: true },
    { id: 'dovecot', title: 'Render Dovecot auth and mail location', detail: 'passwd-file users with ARGON2ID (fallback SHA512-CRYPT) hashes made by doveadm on the server; maildir under /var/vmail', risk: 'high', requiresApproval: true },
    { id: 'opendkim', title: 'Generate DKIM keys on the server', detail: 'Private keys stay on the server (0600); only public TXT values are returned to the panel', risk: 'high', requiresApproval: true },
    { id: 'tls', title: 'TLS certificate for mail host', detail: `Certificate for ${host} via the certificates module; TLS 1.2+ only`, risk: 'high', requiresApproval: true },
    { id: 'firewall', title: 'Open mail ports', detail: 'ufw allow 25,465,587,993 (and 2096 for webmail later)', risk: 'critical', requiresApproval: true, action: 'mail.firewall.open' },
    { id: 'relaytest', title: 'Open-relay probe', detail: 'Unauthenticated relay to a foreign recipient must be rejected before any MX is published', risk: 'low', requiresApproval: false },
    { id: 'health', title: 'Health probe', detail: 'Services active, ports listening, relay closed, drift against panel metadata', risk: 'low', requiresApproval: false },
  ].map((s) => ({ ...s, server: serverAlias }));
}

export function createMailServerService({ prisma, now = () => new Date(), auditService = null, rbac = null, platform = null, config = {} }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const access = createMailAccess({ prisma, rbac, now });

  const ownerOnly = (actor) => {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage the server mail service');
  };

  const view = (server, row, domainsEnabled) => ({
    serverId: server.id,
    serverAlias: server.alias,
    status: row?.status ?? 'disabled',
    provisioned: row?.provisioned ?? false,
    mailHostname: row?.mailHostname ?? null,
    stackVersion: row?.stackVersion ?? null,
    lastHealthAt: row?.lastHealthAt ?? null,
    plannedPorts: MAIL_PORTS,
    domainsEnabled,
    provisioning: provisioningState(config, server.id),
  });

  async function countEnabled(serverId) {
    try {
      if (!prisma.domainMailConfig?.count) return { count: 0, pending: true };
      return { count: await prisma.domainMailConfig.count({ where: { enabled: true, domain: { serverId } } }) };
    } catch {
      return { count: 0, pending: true };
    }
  }

  async function current(serverId) {
    if (!prisma.serverMailService?.findUnique) return { row: null, pending: true };
    try {
      return { row: await prisma.serverMailService.findUnique({ where: { serverId } }) };
    } catch (e) {
      if (/doesn't exist|does not exist|Unknown/i.test(String(e?.message))) return { row: null, pending: true };
      throw e;
    }
  }

  return {
    async get(serverId, actor) {
      const server = await access.requireServerVisible(actor, serverId);
      const { row, pending } = await current(serverId);
      const enabled = await countEnabled(serverId);
      const out = view(server, row, enabled.count);
      return pending || enabled.pending ? { ...out, schemaPending: true } : out;
    },

    /** Records intent only. Never installs or configures anything. */
    async enable(serverId, { mailHostname }, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      const d = mailDelegate(prisma, 'serverMailService');
      const row = await guardSchema(() =>
        d.upsert({
          where: { serverId },
          create: { serverId, status: 'enabled', mailHostname: mailHostname ?? null, portsJson: MAIL_PORTS.map((p) => p.port) },
          update: { status: 'enabled', ...(mailHostname ? { mailHostname } : {}) },
        }),
      );
      await audit({ actorId: actor.id, action: 'mail.server.enable', resourceType: 'server', resourceId: serverId, result: 'success', after: { status: 'enabled', mailHostname: mailHostname ?? null, provisioned: false } });
      return view(server, row, (await countEnabled(serverId)).count);
    },

    async disable(serverId, { reason }, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      const d = mailDelegate(prisma, 'serverMailService');
      const existing = await guardSchema(() => d.findUnique({ where: { serverId } }));
      if (!existing) throw new AppError(404, 'MAIL_SERVICE_NOT_FOUND', 'Mail service is not enabled for this server');
      const row = await guardSchema(() => d.update({ where: { serverId }, data: { status: 'disabled' } }));
      await audit({ actorId: actor.id, action: 'mail.server.disable', resourceType: 'server', resourceId: serverId, result: 'success', metadata: { reason: reason ?? null } });
      return view(server, row, (await countEnabled(serverId)).count);
    },

    /** Stored health only. No remote probe runs until TASK-035 is authorized. */
    async health(serverId, actor) {
      const server = await access.requireServerVisible(actor, serverId);
      const { row } = await current(serverId);
      return {
        serverId: server.id,
        checked: Boolean(row?.lastHealthAt),
        lastHealthAt: row?.lastHealthAt ?? null,
        probe: 'NOT_AUTHORIZED',
        services: { postfix: 'unknown', dovecot: 'unknown', opendkim: 'unknown' },
        ports: MAIL_PORTS.map((p) => ({ port: p.port, state: 'unknown' })),
        openRelay: 'unknown',
        detail: row?.lastHealthJson ?? null,
      };
    },

    /** Read-only plan of what an authorized provisioning would do. Nothing is executed. */
    async previewProvision(serverId, { mailHostname }, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      const { row } = await current(serverId);
      const host = mailHostname ?? row?.mailHostname ?? null;
      const steps = planProvisioning({ serverAlias: server.alias, mailHostname: host });
      return {
        serverId,
        mailHostname: host,
        steps,
        impact: ['Installs Postfix, Dovecot and OpenDKIM', 'Opens mail ports on the firewall (separate critical approval)', 'Adds an internet-facing MTA (attack surface)'],
        executes: false,
        simulated: true,
        provisioning: provisioningState(config, serverId),
      };
    },

    /** Closed by default. Even when the flag and lab allowlist open it, the executor is not built yet (501). */
    async applyProvision(serverId, input, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      const state = provisioningState(config, serverId);
      if (!state.authorized) {
        await audit({ actorId: actor.id, action: 'mail.provision.apply', resourceType: 'server', resourceId: serverId, result: 'denied', metadata: { reason: 'not_authorized', ...state } });
        throw new AppError(403, 'MAIL_PROVISIONING_NOT_AUTHORIZED', 'Mail provisioning is not authorized. The Owner must name a lab server and enable provisioning first.');
      }
      const { row } = await current(serverId);
      const host = input.mailHostname ?? row?.mailHostname ?? null;
      const steps = planProvisioning({ serverAlias: server.alias, mailHostname: host });
      const gate = await platform.gate(
        {
          action: 'mail.provision.apply',
          binding: sha256(JSON.stringify(steps.map((s) => s.id).concat([serverId, host]))),
          resourceType: 'server',
          resourceId: serverId,
          approvalId: input.approvalId,
          reason: input.reason,
          impact: steps.filter((s) => s.requiresApproval).map((s) => s.title),
          rollbackPlan: input.rollbackNote,
          context: {},
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      throw new AppError(501, 'MAIL_EXECUTOR_NOT_IMPLEMENTED', 'The provisioning executor is not implemented (TASK-035 is gated)');
    },
  };
}
