import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { sha256 } from '../platform/platform.crypto.js';

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const HOST = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}\.?$/;

/** Pure renderer: deterministic vhost text so previews and diffs are reproducible. */
export function renderVhost({ name, upstreamPort, webserver = 'nginx' }) {
  if (webserver === 'apache') {
    return [
      '<VirtualHost *:80>',
      `  ServerName ${name}`,
      `  ProxyPass / http://127.0.0.1:${upstreamPort}/`,
      `  ProxyPassReverse / http://127.0.0.1:${upstreamPort}/`,
      '</VirtualHost>',
    ].join('\n');
  }
  return ['server {', '  listen 80;', `  server_name ${name};`, `  location / { proxy_pass http://127.0.0.1:${upstreamPort}; }`, '}'].join('\n');
}

export function validateDnsRecord(domainName, { type, name, value }) {
  const inZone = name === '@' || name === domainName || name.endsWith(`.${domainName}`) || !name.includes('.');
  if (!inZone) throw new AppError(422, 'DNS_OUT_OF_ZONE', 'Record name is outside the domain zone');
  if (type === 'A' && !IPV4.test(value)) throw new AppError(422, 'DNS_VALUE_INVALID', 'A record needs an IPv4 address');
  if (type === 'CNAME') {
    if (!HOST.test(value)) throw new AppError(422, 'DNS_VALUE_INVALID', 'CNAME needs a hostname target');
    if (name === '@' || name === domainName) throw new AppError(422, 'DNS_CNAME_APEX', 'CNAME is not allowed at the zone apex');
  }
  if (type === 'TXT' && value.length > 512) throw new AppError(422, 'DNS_VALUE_INVALID', 'TXT value too long');
}

export function createDomainsService({ prisma, now = () => new Date(), auditService = null, rbac = null, platform = null, adapters = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const scope = createScope({ prisma, now });

  /** Environment must belong to the project, then the exact-scope permission is checked (staging != production). */
  async function authorize(actor, projectId, environmentId, permissionKey = PERM.DOMAIN) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const env = await prisma.projectEnvironment.findUnique({ where: { id: environmentId } });
    if (!env || env.projectId !== projectId) {
      throw new AppError(409, 'ENVIRONMENT_PROJECT_MISMATCH', 'Environment does not belong to this project');
    }
    await assertCan(rbac, actor, { permissionKey, resourceType: 'project', resourceId: projectId, environmentId });
    return env;
  }

  async function load(id) {
    const row = await prisma.domain.findUnique({ where: { id }, include: { dnsRecords: true, certificates: true } });
    if (!row) throw new AppError(404, 'DOMAIN_NOT_FOUND', 'Domain not found');
    return row;
  }

  return {
    async list({ projectId, serverId, limit }, actor) {
      const visible = await scope.domainWhere(actor);
      return prisma.domain.findMany({
        where: {
          archivedAt: null,
          ...(projectId ? { projectId } : {}),
          ...(serverId ? { serverId } : {}),
          ...visible,
        },
        take: limit,
        orderBy: { name: 'asc' },
        include: { certificates: true, server: { select: { id: true, alias: true } } },
      });
    },

    async getById(id, actor) {
      const row = await load(id);
      if (actor?.isOwner) return row;
      const visible = (await scope.canSeeProject(actor, row.projectId)) || (!row.projectId && (await scope.explicitServerIds(actor))?.includes(row.serverId));
      if (!visible) throw new AppError(404, 'DOMAIN_NOT_FOUND', 'Domain not found');
      return row;
    },

    async create(input, actor) {
      await authorize(actor, input.projectId, input.environmentId);
      if (await prisma.domain.findUnique({ where: { name: input.name } })) {
        throw new AppError(409, 'DOMAIN_EXISTS', 'Domain already registered');
      }
      const row = await prisma.domain.create({ data: { name: input.name, projectId: input.projectId, serverId: input.serverId ?? null } });
      await audit({ actorId: actor.id, action: 'domain.create', resourceType: 'domain', resourceId: row.id, environmentId: input.environmentId, result: 'success', after: { name: row.name, projectId: row.projectId } });
      return row;
    },

    /**
     * Load the live virtual-host file for a discovered/managed domain (Owner, via SFTP).
     * `serverAccess.read` must be injected; without it this stays unavailable.
     */
    async readConf(id, actor, serverAccess = null) {
      if (!actor?.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can read domain conf files');
      const domain = await load(id);
      const confPath = domain.metaJson?.confPath;
      if (!confPath) throw new AppError(409, 'DOMAIN_CONF_UNKNOWN', 'No conf path is known for this domain. Run server inventory first.');
      if (!domain.serverId) throw new AppError(409, 'DOMAIN_NO_SERVER', 'Domain is not linked to a server');
      if (!serverAccess?.read) throw new AppError(500, 'SFTP_UNAVAILABLE', 'File access is not wired');
      const file = await serverAccess.read(domain.serverId, confPath, actor);
      return { domain: domain.name, confPath, webserver: domain.metaJson?.webserver ?? null, ...file };
    },

    /** Save a conf file over SFTP and keep metaJson in sync. Owner only. */
    async writeConf(id, { content }, actor, serverAccess = null) {
      if (!actor?.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can edit domain conf files');
      const domain = await load(id);
      const confPath = domain.metaJson?.confPath;
      if (!confPath) throw new AppError(409, 'DOMAIN_CONF_UNKNOWN', 'No conf path is known for this domain. Run server inventory first.');
      if (!domain.serverId) throw new AppError(409, 'DOMAIN_NO_SERVER', 'Domain is not linked to a server');
      if (!serverAccess?.write) throw new AppError(500, 'SFTP_UNAVAILABLE', 'File access is not wired');
      const saved = await serverAccess.write(domain.serverId, { path: confPath, content }, actor);
      await audit({
        actorId: actor.id,
        action: 'domain.conf.write',
        resourceType: 'domain',
        resourceId: id,
        result: 'success',
        after: { confPath, bytes: content?.length ?? 0 },
      });
      return { domain: domain.name, confPath, ...saved };
    },

    /** Read-only preview: rendered config, validation result and impact. Nothing is applied. */
    async previewVhost(id, input, actor) {
      const domain = await load(id);
      await authorize(actor, domain.projectId, input.environmentId);
      const config = renderVhost({ name: domain.name, upstreamPort: input.upstreamPort, webserver: input.webserver });
      const check = await adapters.webserver.validate(config);
      return {
        domain: domain.name,
        config,
        diff: config.split('\n').map((l) => `+ ${l}`),
        valid: check.ok,
        errors: check.errors ?? [],
        impact: [`Adds ${input.webserver} virtual host for ${domain.name}`, 'Reloads the web server'],
        simulated: Boolean(adapters.simulated),
      };
    },

    async applyVhost(id, input, actor) {
      const domain = await load(id);
      await authorize(actor, domain.projectId, input.environmentId);
      const preview = await this.previewVhost(id, input, actor);
      if (!preview.valid) {
        await audit({ actorId: actor.id, action: 'vhost.apply', resourceType: 'domain', resourceId: id, environmentId: input.environmentId, result: 'denied', metadata: { reason: 'config_invalid' } });
        throw new AppError(422, 'VHOST_INVALID', 'Virtual host configuration failed validation');
      }
      const gate = await platform.gate(
        { action: 'vhost.apply', binding: sha256(preview.config), resourceType: 'domain', resourceId: id, approvalId: input.approvalId, reason: input.reason, impact: preview.impact, rollbackPlan: input.rollbackNote, context: { environmentId: input.environmentId } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      try {
        await adapters.webserver.apply({ domain: domain.name, config: preview.config });
      } catch {
        await adapters.webserver.rollback({ domain: domain.name });
        await audit({ actorId: actor.id, action: 'vhost.apply', resourceType: 'domain', resourceId: id, environmentId: input.environmentId, result: 'failure', metadata: { rolledBack: true } });
        throw new AppError(502, 'VHOST_APPLY_FAILED', 'Apply failed and was rolled back');
      }
      await audit({ actorId: actor.id, action: 'vhost.apply', resourceType: 'domain', resourceId: id, environmentId: input.environmentId, result: 'success', after: { config: preview.config } });
      return { applied: true, simulated: Boolean(adapters.simulated), diff: preview.diff };
    },

    async changeDns(id, input, actor) {
      const domain = await load(id);
      await authorize(actor, domain.projectId, input.environmentId);
      validateDnsRecord(domain.name, input);
      const impact = [`${input.op} ${input.type} ${input.name} -> ${input.value} (ttl ${input.ttl})`, 'Traffic for this name may shift after TTL expires'];
      const gate = await platform.gate(
        { action: 'dns.change', binding: sha256(JSON.stringify([input.op, input.type, input.name, input.value, input.ttl])), resourceType: 'domain', resourceId: id, approvalId: input.approvalId, reason: input.reason, impact, rollbackPlan: input.rollbackNote, context: { environmentId: input.environmentId } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      const record = { type: input.type, name: input.name, value: input.value, ttl: input.ttl };
      try {
        await (input.op === 'upsert' ? adapters.dns.upsert(record) : adapters.dns.remove(record));
      } catch {
        await audit({ actorId: actor.id, action: 'dns.change', resourceType: 'domain', resourceId: id, environmentId: input.environmentId, result: 'failure', metadata: { type: input.type, name: input.name } });
        throw new AppError(502, 'DNS_PROVIDER_FAILED', 'DNS provider rejected the change; nothing was stored');
      }
      const existing = domain.dnsRecords.find((r) => r.type === input.type && r.name === input.name);
      let saved = null;
      if (input.op === 'remove') {
        if (existing) await prisma.dnsRecord.delete({ where: { id: existing.id } });
      } else if (existing) {
        saved = await prisma.dnsRecord.update({ where: { id: existing.id }, data: { valueSummary: input.value.slice(0, 255), ttl: input.ttl } });
      } else {
        saved = await prisma.dnsRecord.create({ data: { domainId: id, type: input.type, name: input.name, valueSummary: input.value.slice(0, 255), ttl: input.ttl } });
      }
      await audit({ actorId: actor.id, action: 'dns.change', resourceType: 'domain', resourceId: id, environmentId: input.environmentId, result: 'success', before: existing ? { value: existing.valueSummary } : undefined, after: { op: input.op, type: input.type, name: input.name } });
      return { record: saved, op: input.op, simulated: Boolean(adapters.simulated) };
    },
  };
}
