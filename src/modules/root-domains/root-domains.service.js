/**
 * TASK-047: root domains and the DNS provider adapter.
 * - Provider tokens are AES-256-GCM encrypted (CREDENTIAL_ENCRYPTION_KEY) and never returned, logged or audited.
 * - Record changes use the existing `dns.change` platform gate (High: separate approver, impact, rollback note).
 * - `system` methods are for in-process callers that already passed their own gate (preview environments).
 * - A wildcard certificate is issued through the ACME adapter (ACME_EXECUTOR) behind the `ssl.wildcard.issue` gate.
 */
import { AppError } from '../../common/errors/app-error.js';
import { encrypt, sha256 } from '../platform/platform.crypto.js';
import { validateDnsRecord } from '../domains/domains.service.js';
import { planWildcardCertificate } from '../certificates/certbot.script.js';
import { clientForRoot, toFqdn } from './root-domains.adapters.js';
import { createCloudflareClient } from './cloudflare.client.js';

const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|RootDomain/i;
const schemaRequired = () => new AppError(501, 'SCHEMA_REQUIRED', 'Root domain tables are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');

/** In-memory provider used when provider = simulated. Never touches a network. */
function createSimulatedProvider() {
  const records = new Map();
  let n = 0;
  const key = (r) => `${r.type}|${r.name}`;
  return {
    async upsertRecord(_zone, r) {
      const k = r.type === 'TXT' ? `${key(r)}|${r.content}` : key(r);
      const had = records.get(k);
      records.set(k, { id: had?.id ?? `sim${String(++n).padStart(29, '0')}`, type: r.type, name: r.name, content: r.content, ttl: r.ttl, proxied: Boolean(r.proxied) });
      return { action: had ? 'updated' : 'created', record: records.get(k) };
    },
    async deleteRecord(_zone, r) {
      let removed = 0;
      for (const [k, v] of records) if (v.type === r.type && v.name === r.name && (r.content == null || v.content === r.content)) (records.delete(k), (removed += 1));
      return { removed };
    },
    async listRecords(_zone, { type, name } = {}) {
      return { records: [...records.values()].filter((v) => (!type || v.type === type) && (!name || v.name === name)), totalPages: 1 };
    },
  };
}

export function createRootDomainsService({
  prisma,
  auditService = null,
  platform = null,
  adapters = null,
  env = process.env,
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
  fetchImpl,
  clientFactory = createCloudflareClient,
  now = () => new Date(),
}) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'root_domain', ...event }) : null);
  const sim = createSimulatedProvider();

  const table = () => {
    if (!prisma?.rootDomain) throw schemaRequired();
    return prisma.rootDomain;
  };
  async function guard(fn) {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (STALE.test(String(e?.message))) throw schemaRequired();
      throw e;
    }
  }
  function requireOwner(actor) {
    if (!actor?.id && !actor?.system) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage root domains');
  }
  /** Never exposes tokenEnc. */
  const view = (r) => ({ id: r.id, name: r.name, provider: r.provider, zoneId: r.zoneId, status: r.status, hasToken: Boolean(r.tokenEnc), meta: r.metaJson ?? null, createdAt: r.createdAt, updatedAt: r.updatedAt });

  async function load(id) {
    const row = await table().findUnique({ where: { id } });
    if (!row || row.archivedAt) throw new AppError(404, 'ROOT_DOMAIN_NOT_FOUND', 'Root domain not found');
    return row;
  }
  const providerFor = (root) => (root.provider === 'cloudflare' ? clientForRoot(root, { credentialKey, fetchImpl, clientFactory }) : sim);

  async function verifyAccess(client, name) {
    const ok = await client.verifyToken();
    if (!ok.active) throw new AppError(422, 'DNS_TOKEN_REJECTED', 'The token is not active');
    const zone = await client.findZone(name);
    if (!zone) throw new AppError(422, 'DNS_ZONE_NOT_FOUND', 'The token cannot see a zone with this name');
    return zone;
  }

  const normalizeRecord = (root, input) => {
    validateDnsRecord(root.name, { type: input.type, name: input.name, value: input.value });
    return { type: input.type, name: toFqdn(input.name, root.name), content: input.value, ttl: input.ttl, proxied: Boolean(input.proxied) };
  };

  const svc = {
    async list(actor) {
      requireOwner(actor);
      return guard(async () => (await table().findMany({ where: { archivedAt: null }, orderBy: { name: 'asc' }, take: 200 })).map(view));
    },

    async connect(input, actor) {
      requireOwner(actor);
      return guard(async () => {
        if (await table().findUnique({ where: { name: input.name } })) throw new AppError(409, 'ROOT_DOMAIN_EXISTS', 'Root domain is already connected');
        let zoneId = 'simulated';
        let tokenEnc = null;
        let meta = { simulated: true };
        if (input.provider === 'cloudflare') {
          const client = clientFactory({ token: input.apiToken, ...(fetchImpl ? { fetchImpl } : {}) });
          const zone = await verifyAccess(client, input.name);
          zoneId = zone.id;
          tokenEnc = encrypt(input.apiToken, credentialKey());
          meta = { zoneStatus: zone.status, verifiedAt: now().toISOString() };
        }
        const row = await table().create({ data: { name: input.name, provider: input.provider, zoneId, tokenEnc, metaJson: meta, createdById: actor.id ?? null } });
        await audit({ actorId: actor.id, action: 'root_domain.connect', resourceId: row.id, result: 'success', after: { name: row.name, provider: row.provider } });
        return view(row);
      });
    },

    async rotateToken(id, input, actor) {
      requireOwner(actor);
      return guard(async () => {
        const root = await load(id);
        if (root.provider !== 'cloudflare') throw new AppError(409, 'ROOT_DOMAIN_NO_TOKEN', 'This root domain does not use a provider token');
        const client = clientFactory({ token: input.apiToken, ...(fetchImpl ? { fetchImpl } : {}) });
        const zone = await verifyAccess(client, root.name);
        if (zone.id !== root.zoneId) throw new AppError(422, 'DNS_ZONE_MISMATCH', 'The token sees a different zone for this name');
        const row = await table().update({ where: { id }, data: { tokenEnc: encrypt(input.apiToken, credentialKey()), metaJson: { ...(root.metaJson ?? {}), verifiedAt: now().toISOString() } } });
        await audit({ actorId: actor.id, action: 'root_domain.token.rotate', resourceId: id, result: 'success' });
        return view(row);
      });
    },

    async remove(id, actor) {
      requireOwner(actor);
      return guard(async () => {
        await load(id);
        const row = await table().update({ where: { id }, data: { archivedAt: now(), tokenEnc: null, status: 'archived' } });
        await audit({ actorId: actor.id, action: 'root_domain.remove', resourceId: id, result: 'success' });
        return view(row);
      });
    },

    async listRecords(id, query, actor) {
      requireOwner(actor);
      return guard(async () => {
        const root = await load(id);
        const name = query.name ? toFqdn(query.name, root.name) : undefined;
        return providerFor(root).listRecords(root.zoneId, { type: query.type, name, page: query.page });
      });
    },

    /** Owner-facing change: gated by `dns.change`. */
    async changeRecord(id, input, actor) {
      requireOwner(actor);
      return guard(async () => {
        const root = await load(id);
        const rec = normalizeRecord(root, input);
        const impact = [`${input.op} ${rec.type} ${rec.name} -> ${rec.content} (ttl ${rec.ttl}${rec.proxied ? ', proxied' : ''})`, `Zone ${root.name} via ${root.provider}`];
        const gate = await platform.gate(
          { action: 'dns.change', binding: sha256(JSON.stringify([input.op, rec.type, rec.name, rec.content, rec.ttl, rec.proxied])), resourceType: 'root_domain', resourceId: id, approvalId: input.approvalId, reason: input.reason, impact, rollbackPlan: input.rollbackNote, context: {} },
          actor,
        );
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
        const result = await svc.system.apply(root, input.op, rec);
        await audit({ actorId: actor.id, action: 'dns.change', resourceId: id, result: 'success', after: { op: input.op, type: rec.type, name: rec.name, provider: root.provider } });
        return { op: input.op, ...result, simulated: root.provider !== 'cloudflare' };
      });
    },

    /** In-process helpers: callers must already have passed their own approval gate. */
    system: {
      async apply(root, op, rec) {
        const provider = providerFor(root);
        try {
          if (op === 'remove') return { removed: (await provider.deleteRecord(root.zoneId, rec)).removed };
          const res = await provider.upsertRecord(root.zoneId, rec);
          return { action: res.action, record: res.record };
        } catch (error) {
          if (error instanceof AppError) throw error;
          throw new AppError(502, 'DNS_PROVIDER_FAILED', 'DNS provider rejected the change');
        }
      },
      async findFor(hostname) {
        const host = String(hostname).toLowerCase();
        const roots = await table().findMany({ where: { archivedAt: null } });
        return roots.filter((r) => host === r.name || host.endsWith(`.${r.name}`)).sort((a, b) => b.name.length - a.name.length)[0] ?? null;
      },
      async byId(id) {
        return table().findUnique({ where: { id } });
      },
    },

    /** Read-only: the exact certbot script and argv a wildcard issue would run. No credential is included. */
    async previewWildcard(id, input, actor) {
      requireOwner(actor);
      return guard(async () => {
        const root = await load(id);
        if (root.provider !== 'cloudflare') throw new AppError(409, 'WILDCARD_NEEDS_PROVIDER', 'Wildcard DNS-01 needs a Cloudflare root domain');
        const plan = planWildcardCertificate({ domain: root.name, email: input.email ?? env.ACME_EMAIL, staging: input.staging, propagationSeconds: input.propagationSeconds });
        return { domain: root.name, ...plan, executor: String(env.ACME_EXECUTOR ?? 'simulated').toLowerCase() === 'certbot' ? 'certbot' : 'simulated' };
      });
    },

    async issueWildcard(id, input, actor) {
      requireOwner(actor);
      return guard(async () => {
        const root = await load(id);
        const plan = await svc.previewWildcard(id, input, actor);
        const gate = await platform.gate(
          { action: 'ssl.wildcard.issue', binding: sha256(JSON.stringify([root.name, input.serverId, input.staging])), resourceType: 'root_domain', resourceId: id, approvalId: input.approvalId, reason: input.reason, impact: [`Issue wildcard certificate for ${plan.names.join(', ')} on server ${input.serverId} via DNS-01 (${plan.executor})`, 'Creates and removes _acme-challenge TXT records in the zone'], rollbackPlan: input.rollbackNote, context: {} },
          actor,
        );
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
        let domain = await prisma.domain.findUnique({ where: { name: root.name } });
        if (!domain) domain = await prisma.domain.create({ data: { name: root.name, serverId: input.serverId } });
        const cert = await prisma.sslCertificate.create({ data: { domainId: domain.id, status: 'pending', provider: null, challenge: 'dns-01' } });
        try {
          const res = await adapters.acme.issue({ domain: root.name, challenge: 'dns-01', wildcard: true, serverId: input.serverId, email: input.email ?? env.ACME_EMAIL, staging: input.staging });
          const saved = await prisma.sslCertificate.update({ where: { id: cert.id }, data: { status: 'active', provider: res.provider, expiresAt: res.expiresAt } });
          await audit({ actorId: actor.id, action: 'ssl.wildcard.issue', resourceId: id, result: 'success', after: { certificateId: cert.id, expiresAt: res.expiresAt } });
          return { certificate: { id: saved.id, status: saved.status, expiresAt: saved.expiresAt, provider: saved.provider }, simulated: adapters.acme.simulated ?? Boolean(adapters.simulated) };
        } catch (error) {
          await prisma.sslCertificate.update({ where: { id: cert.id }, data: { status: 'failed', lastError: String(error?.code ?? 'ACME_ISSUE_FAILED').slice(0, 100) } });
          await audit({ actorId: actor.id, action: 'ssl.wildcard.issue', resourceId: id, result: 'failure' });
          throw new AppError(502, 'ACME_ISSUE_FAILED', 'Certificate issue failed; nothing was installed');
        }
      });
    },
  };
  return svc;
}

