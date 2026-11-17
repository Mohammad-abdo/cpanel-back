/**
 * TASK-047: provider adapters behind the existing adapter ports (adapters.dns, adapters.acme).
 *   DNS_PROVIDER=simulated|cloudflare   (default simulated)
 *   ACME_EXECUTOR=simulated|certbot     (default simulated; certbot needs a server login and ACME_EMAIL)
 * Anything else falls back to simulated. Real calls are NOT_RUN without Owner authorization and credentials.
 */
import dns from 'node:dns/promises';
import { AppError } from '../../common/errors/app-error.js';
import { decrypt } from '../platform/platform.crypto.js';
import { buildCloudflareCredentials, parseOpensslDate, planWildcardCertificate } from '../certificates/certbot.script.js';
import { createScriptRunner } from '../server-access/ssh-script.runner.js';
import { createCloudflareClient } from './cloudflare.client.js';

const defaultKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY;

/** Longest-suffix match of a hostname against the connected (non archived) root domains. */
export async function findRootFor(prisma, fqdn, { provider = 'cloudflare' } = {}) {
  const host = String(fqdn).toLowerCase().replace(/\.$/, '');
  const roots = await prisma.rootDomain.findMany({ where: { archivedAt: null, provider } });
  return roots.filter((r) => host === r.name || host.endsWith(`.${r.name}`)).sort((a, b) => b.name.length - a.name.length)[0] ?? null;
}

export function clientForRoot(root, { credentialKey = defaultKey, fetchImpl, clientFactory = createCloudflareClient } = {}) {
  if (!root?.tokenEnc || !root.zoneId) throw new AppError(409, 'DNS_NOT_CONNECTED', 'This root domain has no provider token');
  const token = decrypt(Buffer.from(root.tokenEnc), credentialKey()).toString('utf8');
  return clientFactory({ token, ...(fetchImpl ? { fetchImpl } : {}) });
}

/** Names in the DNS-change form are relative to the domain: "@" is the domain, a bare label is a subdomain of it. */
export function toFqdn(name, domain) {
  const n = String(name).toLowerCase();
  const d = String(domain).toLowerCase();
  if (n === '@' || n === d) return d;
  if (n.endsWith(`.${d}`)) return n;
  return `${n}.${d}`;
}

export function createCloudflareDnsAdapter({ prisma, credentialKey = defaultKey, fetchImpl, clientFactory } = {}) {
  async function context(record) {
    const fqdn = toFqdn(record.name, record.domain ?? '');
    const root = await findRootFor(prisma, fqdn);
    if (!root) throw new AppError(422, 'DNS_ZONE_NOT_FOUND', 'No connected Cloudflare zone covers this name');
    return { fqdn, root, client: clientForRoot(root, { credentialKey, fetchImpl, clientFactory }) };
  }
  return {
    simulated: false,
    provider: 'cloudflare',
    async upsert(record) {
      const { fqdn, root, client } = await context(record);
      const res = await client.upsertRecord(root.zoneId, { type: record.type, name: fqdn, content: record.value, ttl: record.ttl, proxied: record.proxied });
      return { providerRef: res.record.id, action: res.action };
    },
    async remove(record) {
      const { fqdn, root, client } = await context(record);
      const res = await client.deleteRecord(root.zoneId, { type: record.type, name: fqdn, content: record.type === 'TXT' ? record.value : undefined });
      return { removed: res.removed > 0 };
    },
    async resolve(name) {
      for (const fn of [dns.resolve4, dns.resolve6, dns.resolveCname]) {
        try {
          if ((await fn(name)).length) return { name, resolves: true };
        } catch {
          /* try the next record family */
        }
      }
      return { name, resolves: false };
    },
  };
}

/** certbot over SSH. Wildcards use DNS-01 through the Cloudflare plugin; the token travels over stdin only. */
export function createCertbotAcmeAdapter({ prisma, connector, credentialKey = defaultKey, env = process.env, now = () => new Date(), runner = null } = {}) {
  const scripts = runner ?? createScriptRunner({ prisma, connector, credentialKey });
  return {
    simulated: false,
    provider: 'certbot-dns-cloudflare',
    async issue({ domain, challenge, wildcard, serverId, email = env.ACME_EMAIL, staging = false, renewal = false }) {
      if (!serverId) throw new AppError(409, 'DOMAIN_NO_SERVER', 'The certificate needs a server to run certbot on');
      if (challenge !== 'dns-01' || !wildcard) throw new AppError(422, 'ACME_CHALLENGE_UNSUPPORTED', 'The certbot executor currently issues wildcard DNS-01 certificates only');
      void renewal;
      const root = await findRootFor(prisma, domain);
      if (!root || root.name !== domain) throw new AppError(422, 'DNS_ZONE_NOT_FOUND', 'Wildcard certificates need a connected root domain with this exact name');
      const plan = planWildcardCertificate({ domain, email, staging });
      const token = decrypt(Buffer.from(root.tokenEnc), credentialKey()).toString('utf8');
      const res = await scripts.run(serverId, plan.script, { args: plan.args, stdin: buildCloudflareCredentials(token), timeoutMs: 15 * 60_000 });
      if (res.code !== 0) throw new AppError(502, 'ACME_ISSUE_FAILED', 'certbot did not complete');
      const expiresAt = parseOpensslDate(res.stdout) ?? new Date(now().getTime() + 80 * 86400000);
      return { provider: 'certbot-dns-cloudflare', expiresAt };
    },
  };
}

/** Partial adapter set to merge over the simulated one. */
export function resolveProviderAdapters({ prisma, env = process.env, connector = null, fetchImpl, createConnector = null } = {}) {
  const out = {};
  if (String(env.DNS_PROVIDER ?? 'simulated').toLowerCase() === 'cloudflare') out.dns = createCloudflareDnsAdapter({ prisma, fetchImpl });
  if (String(env.ACME_EXECUTOR ?? 'simulated').toLowerCase() === 'certbot') {
    out.acme = createCertbotAcmeAdapter({ prisma, env, connector: connector ?? createConnector?.() ?? null });
  }
  return out;
}
