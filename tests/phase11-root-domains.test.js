import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import { CLOUDFLARE_BASE_URL, createCloudflareClient, isValidCloudflareToken, maskToken } from '../src/modules/root-domains/cloudflare.client.js';
import { createRootDomainsService } from '../src/modules/root-domains/root-domains.service.js';
import { createCertbotAcmeAdapter, createCloudflareDnsAdapter, findRootFor, resolveProviderAdapters, toFqdn } from '../src/modules/root-domains/root-domains.adapters.js';
import { connectBodySchema, recordBodySchema } from '../src/modules/root-domains/root-domains.validator.js';
import { CERTBOT_DNS_CLOUDFLARE_SCRIPT, buildCloudflareCredentials, parseOpensslDate, planWildcardCertificate } from '../src/modules/certificates/certbot.script.js';
import { isPrivateAddress, probeTls } from '../src/modules/certificates/certificates.probe.js';
import { createCertificatesService } from '../src/modules/certificates/certificates.service.js';
import { createDomainsService } from '../src/modules/domains/domains.service.js';
import { CADDY_APPLY_SCRIPT, DETECT_WEBSERVER_SCRIPT, lintCaddySite, parseWebserverProbe, renderCaddySite } from '../src/modules/domains/domains.proxy.js';
import { createScriptRunner } from '../src/modules/server-access/ssh-script.runner.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';
import { fakePrisma } from './phase3-helpers.js';
import { APPROVER, ENV_PROD, OWNER, PROJECT, U, approve, makeCtx } from './phase6-helpers.js';
import { createFakeSsh } from './server-access-fake-ssh.js';

const KEY = randomBytes(32).toString('hex');
const TOKEN = 'cfTOKEN_abcdefghijklmnopqrstuvwxyz0123456789';
const ZONE = 'a'.repeat(32);
beforeEach(() => vi.stubEnv('CREDENTIAL_ENCRYPTION_KEY', KEY));
afterEach(() => vi.unstubAllEnvs());

const res = (status, json, headers = {}) => ({ status, ok: status >= 200 && status < 300, headers: { get: (k) => headers[k.toLowerCase()] ?? null }, json: async () => json });
const ok = (result, info) => res(200, { success: true, result, ...(info ? { result_info: info } : {}) });

/** Router-style Cloudflare mock; `calls` records every request. */
function cfMock(handlers) {
  const calls = [];
  const fetchImpl = vi.fn(async (url, init) => {
    const u = new URL(url);
    const call = { method: init.method, path: u.pathname.replace('/client/v4', ''), query: Object.fromEntries(u.searchParams), body: init.body ? JSON.parse(init.body) : undefined, headers: init.headers, init, origin: u.origin };
    calls.push(call);
    return handlers(call, calls.length);
  });
  return { fetchImpl, calls };
}
const noWait = { sleep: vi.fn(async () => {}), minIntervalMs: 0 };

describe('Cloudflare client', () => {
  it('validates the token format and never reveals the token', async () => {
    expect(isValidCloudflareToken(TOKEN)).toBe(true);
    expect(isValidCloudflareToken('short')).toBe(false);
    expect(isValidCloudflareToken('has space has space has space')).toBe(false);
    expect(() => createCloudflareClient({ token: 'bad token', fetchImpl: vi.fn() })).toThrow(/invalid format/);
    const c = createCloudflareClient({ token: TOKEN, fetchImpl: vi.fn() });
    expect(JSON.stringify(c)).not.toContain(TOKEN);
    expect(String(c)).not.toContain(TOKEN);
    expect(maskToken(TOKEN)).not.toContain(TOKEN.slice(5));
  });

  it('uses the fixed api.cloudflare.com base, Bearer auth, refuses redirects, and exact request shapes', async () => {
    const { fetchImpl, calls } = cfMock((c) => {
      if (c.path === '/user/tokens/verify') return ok({ status: 'active' });
      if (c.path === '/zones') return ok([{ id: ZONE, name: 'example.com', status: 'active' }]);
      return ok([]);
    });
    const client = createCloudflareClient({ token: TOKEN, fetchImpl, ...noWait });
    expect(await client.verifyToken()).toEqual({ active: true });
    expect(await client.findZone('example.com')).toEqual({ id: ZONE, name: 'example.com', status: 'active' });
    expect(await client.findZone('other.com')).toBeNull();
    expect(CLOUDFLARE_BASE_URL).toBe('https://api.cloudflare.com/client/v4');
    for (const c of calls) {
      expect(c.origin).toBe('https://api.cloudflare.com');
      expect(c.headers.Authorization).toBe(`Bearer ${TOKEN}`);
      expect(c.init.redirect).toBe('error');
    }
    expect(calls[1].query).toEqual({ name: 'example.com', per_page: '1' });
  });

  it('upsert: creates, updates in place, and is a no-op when unchanged (idempotent)', async () => {
    const existing = { id: 'b'.repeat(32), type: 'A', name: 'app.example.com', content: '1.2.3.4', ttl: 300, proxied: false };
    let stored = [];
    const { fetchImpl, calls } = cfMock((c) => {
      if (c.method === 'GET') return ok(stored, { total_pages: 1 });
      if (c.method === 'POST') return ok({ ...c.body, id: existing.id });
      if (c.method === 'PUT') return ok({ ...c.body, id: existing.id });
      return ok({});
    });
    const client = createCloudflareClient({ token: TOKEN, fetchImpl, ...noWait });
    const rec = { type: 'A', name: 'app.example.com', content: '1.2.3.4', ttl: 300, proxied: false };
    expect((await client.upsertRecord(ZONE, rec)).action).toBe('created');
    expect(calls.at(-1).method).toBe('POST');
    expect(calls.at(-1).body).toEqual({ type: 'A', name: 'app.example.com', content: '1.2.3.4', ttl: 300, proxied: false });
    stored = [existing];
    const before = calls.length;
    expect((await client.upsertRecord(ZONE, rec)).action).toBe('unchanged');
    expect(calls.length).toBe(before + 1); // only the lookup, no write
    expect((await client.upsertRecord(ZONE, { ...rec, content: '5.6.7.8' })).action).toBe('updated');
    expect(calls.at(-1).method).toBe('PUT');
    expect(calls.at(-1).path).toBe(`/zones/${ZONE}/dns_records/${existing.id}`);
  });

  it('proxied records use ttl 1; TXT is matched by content and never proxied', async () => {
    const { fetchImpl, calls } = cfMock((c) => (c.method === 'GET' ? ok([{ id: 'c'.repeat(32), type: 'TXT', name: '_acme-challenge.example.com', content: 'other', ttl: 120, proxied: false }]) : ok({ id: 'd'.repeat(32), ...c.body })));
    const client = createCloudflareClient({ token: TOKEN, fetchImpl, ...noWait });
    await client.upsertRecord(ZONE, { type: 'CNAME', name: 'www.example.com', content: 'app.example.com', ttl: 600, proxied: true });
    expect(calls.at(-1).body).toMatchObject({ proxied: true, ttl: 1 });
    const out = await client.upsertRecord(ZONE, { type: 'TXT', name: '_acme-challenge.example.com', content: 'token-123', ttl: 120, proxied: true });
    expect(out.action).toBe('created'); // different content = a second TXT value
    expect(calls.at(-1).body).not.toHaveProperty('proxied');
  });

  it('delete removes matches and succeeds when nothing matches', async () => {
    const id = 'e'.repeat(32);
    const { fetchImpl, calls } = cfMock((c) => (c.method === 'GET' ? ok([{ id, type: 'A', name: 'x.example.com', content: '1.1.1.1', ttl: 300 }]) : ok({ id })));
    const client = createCloudflareClient({ token: TOKEN, fetchImpl, ...noWait });
    expect(await client.deleteRecord(ZONE, { type: 'A', name: 'x.example.com' })).toEqual({ removed: 1 });
    expect(calls.at(-1)).toMatchObject({ method: 'DELETE', path: `/zones/${ZONE}/dns_records/${id}` });
    const empty = createCloudflareClient({ token: TOKEN, fetchImpl: cfMock(() => ok([])).fetchImpl, ...noWait });
    expect(await empty.deleteRecord(ZONE, { type: 'A', name: 'none.example.com' })).toEqual({ removed: 0 });
  });

  it('backs off on 429 (Retry-After) and 5xx GETs, but never retries a POST on 5xx', async () => {
    const sleep = vi.fn(async () => {});
    let n = 0;
    const { fetchImpl } = cfMock((c) => {
      n += 1;
      if (c.method === 'GET' && n === 1) return res(429, { success: false, errors: [{ code: 971 }] }, { 'retry-after': '2' });
      if (c.method === 'GET' && n === 2) return res(503, { success: false });
      return ok([]);
    });
    const client = createCloudflareClient({ token: TOKEN, fetchImpl, sleep, minIntervalMs: 0, baseDelayMs: 100 });
    await client.listRecords(ZONE, {});
    expect(sleep).toHaveBeenCalledWith(2000);
    expect(sleep).toHaveBeenCalledWith(200);
    const post = cfMock((c) => (c.method === 'GET' ? ok([]) : res(502, { success: false })));
    const c2 = createCloudflareClient({ token: TOKEN, fetchImpl: post.fetchImpl, ...noWait });
    await expect(c2.upsertRecord(ZONE, { type: 'A', name: 'a.example.com', content: '1.1.1.1', ttl: 300 })).rejects.toMatchObject({ code: 'DNS_PROVIDER_FAILED' });
    expect(post.calls.filter((c) => c.method === 'POST')).toHaveLength(1);
  });

  it('gives up with DNS_RATE_LIMITED and keeps the token out of errors', async () => {
    const { fetchImpl } = cfMock(() => res(429, { success: false }));
    const client = createCloudflareClient({ token: TOKEN, fetchImpl, sleep: vi.fn(async () => {}), minIntervalMs: 0, maxRetries: 2 });
    const err = await client.listRecords(ZONE, {}).catch((e) => e);
    expect(err.code).toBe('DNS_RATE_LIMITED');
    expect(String(err.message)).not.toContain(TOKEN);
    const boom = createCloudflareClient({ token: TOKEN, fetchImpl: vi.fn(async () => { throw Object.assign(new Error(`socket ${TOKEN}`), { name: 'FetchError' }); }), ...noWait, maxRetries: 0 });
    const e2 = await boom.verifyToken().catch((e) => e);
    expect(e2.code).toBe('DNS_PROVIDER_UNREACHABLE');
    expect(JSON.stringify(e2)).not.toContain(TOKEN);
  });

  it('maps 401/403 to DNS_TOKEN_REJECTED and rejects malformed zone ids', async () => {
    const { fetchImpl } = cfMock(() => res(403, { success: false, errors: [{ code: 9109 }] }));
    const client = createCloudflareClient({ token: TOKEN, fetchImpl, ...noWait });
    await expect(client.verifyToken()).rejects.toMatchObject({ code: 'DNS_TOKEN_REJECTED' });
    await expect(client.listRecords('../../evil', {})).rejects.toMatchObject({ code: 'DNS_ZONE_INVALID' });
  });
});

function rootSetup({ provider = 'cloudflare' } = {}) {
  const prisma = fakePrisma({ projectEnvironment: [{ id: ENV_PROD, projectId: PROJECT }] });
  const ctx = makeCtx();
  const cf = cfMock((c) => {
    if (c.path === '/user/tokens/verify') return ok({ status: 'active' });
    if (c.path === '/zones') return ok([{ id: ZONE, name: 'example.com', status: 'active' }]);
    if (c.method === 'GET') return ok([]);
    return ok({ id: 'f'.repeat(32), ...c.body });
  });
  const svc = createRootDomainsService({ prisma, auditService: ctx.auditService, platform: ctx.platform, adapters: ctx.adapters, credentialKey: () => KEY, fetchImpl: cf.fetchImpl, clientFactory: (o) => createCloudflareClient({ ...o, ...noWait }) });
  return { prisma, ctx, cf, svc, provider };
}

describe('root domains service', () => {
  it('connects a zone: token verified, stored encrypted, never returned or audited', async () => {
    const t = rootSetup();
    const out = await t.svc.connect({ name: 'example.com', provider: 'cloudflare', apiToken: TOKEN }, OWNER);
    expect(out).toMatchObject({ name: 'example.com', provider: 'cloudflare', zoneId: ZONE, hasToken: true });
    expect(JSON.stringify(out)).not.toContain(TOKEN);
    const row = t.prisma.rootDomain.rows[0];
    expect(Buffer.from(row.tokenEnc).includes(Buffer.from(TOKEN))).toBe(false);
    expect(JSON.stringify(t.ctx.auditService.record.mock.calls)).not.toContain(TOKEN);
    expect(JSON.stringify(await t.svc.list(OWNER))).not.toContain('tokenEnc');
    await expect(t.svc.connect({ name: 'example.com', provider: 'cloudflare', apiToken: TOKEN }, OWNER)).rejects.toMatchObject({ code: 'ROOT_DOMAIN_EXISTS' });
  });

  it('is Owner only and rejects a token that cannot see the zone', async () => {
    const t = rootSetup();
    await expect(t.svc.connect({ name: 'example.com', provider: 'cloudflare', apiToken: TOKEN }, { id: U(2), isOwner: false })).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.list(null)).rejects.toMatchObject({ status: 401 });
    const none = rootSetup();
    none.cf.fetchImpl.mockImplementation(async (url) => (String(url).includes('/zones') ? ok([]) : ok({ status: 'active' })));
    await expect(none.svc.connect({ name: 'example.com', provider: 'cloudflare', apiToken: TOKEN }, OWNER)).rejects.toMatchObject({ code: 'DNS_ZONE_NOT_FOUND' });
  });

  it('DNS change goes through the dns.change gate: pending, approve, execute once, idempotent upsert', async () => {
    const t = rootSetup();
    const root = await t.svc.connect({ name: 'example.com', provider: 'cloudflare', apiToken: TOKEN }, OWNER);
    const body = { op: 'upsert', type: 'A', name: 'app', value: '203.0.113.10', ttl: 300, proxied: true, reason: 'launch app', rollbackNote: 'remove record' };
    const first = await t.svc.changeRecord(root.id, body, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.cf.calls.some((c) => c.method === 'POST')).toBe(false);
    await approve(t.ctx, first.approval.id);
    const done = await t.svc.changeRecord(root.id, { ...body, approvalId: first.approval.id }, OWNER);
    expect(done).toMatchObject({ op: 'upsert', action: 'created', simulated: false });
    const post = t.cf.calls.find((c) => c.method === 'POST');
    expect(post.body).toEqual({ type: 'A', name: 'app.example.com', content: '203.0.113.10', ttl: 1, proxied: true });
    await expect(t.svc.changeRecord(root.id, { ...body, approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });

  it('a changed record cannot reuse an approval, and out-of-zone or invalid records are rejected', async () => {
    const t = rootSetup();
    const root = await t.svc.connect({ name: 'example.com', provider: 'cloudflare', apiToken: TOKEN }, OWNER);
    const base = { op: 'upsert', type: 'A', name: 'app', value: '203.0.113.10', ttl: 300, proxied: false, reason: 'launch app', rollbackNote: 'remove record' };
    const g = await t.svc.changeRecord(root.id, base, OWNER);
    await approve(t.ctx, g.approval.id);
    await expect(t.svc.changeRecord(root.id, { ...base, value: '203.0.113.99', approvalId: g.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    await expect(t.svc.changeRecord(root.id, { ...base, name: 'a.b.other.org' }, OWNER)).rejects.toMatchObject({ code: 'DNS_OUT_OF_ZONE' });
    await expect(t.svc.changeRecord(root.id, { ...base, value: 'not-an-ip' }, OWNER)).rejects.toMatchObject({ code: 'DNS_VALUE_INVALID' });
    expect(t.cf.calls.some((c) => c.method === 'POST' || c.method === 'PUT')).toBe(false);
  });

  it('rotating the token re-verifies the same zone and re-encrypts; remove clears the token', async () => {
    const t = rootSetup();
    const root = await t.svc.connect({ name: 'example.com', provider: 'cloudflare', apiToken: TOKEN }, OWNER);
    const before = Buffer.from(t.prisma.rootDomain.rows[0].tokenEnc).toString('hex');
    await t.svc.rotateToken(root.id, { apiToken: `${TOKEN}_new` }, OWNER);
    expect(Buffer.from(t.prisma.rootDomain.rows[0].tokenEnc).toString('hex')).not.toBe(before);
    await t.svc.remove(root.id, OWNER);
    expect(t.prisma.rootDomain.rows[0].tokenEnc).toBeNull();
    await expect(t.svc.listRecords(root.id, {}, OWNER)).rejects.toMatchObject({ code: 'ROOT_DOMAIN_NOT_FOUND' });
  });

  it('simulated provider works without a token or any fetch', async () => {
    const t = rootSetup();
    const root = await t.svc.connect({ name: 'lab.example.com', provider: 'simulated' }, OWNER);
    expect(root).toMatchObject({ provider: 'simulated', hasToken: false });
    const b = { op: 'upsert', type: 'TXT', name: '@', value: 'hello', ttl: 300, proxied: false, reason: 'verify domain', rollbackNote: 'remove txt' };
    const g = await t.svc.changeRecord(root.id, b, OWNER);
    await approve(t.ctx, g.approval.id);
    const r = await t.svc.changeRecord(root.id, { ...b, approvalId: g.approval.id }, OWNER);
    expect(r.simulated).toBe(true);
    expect((await t.svc.listRecords(root.id, {}, OWNER)).records).toHaveLength(1);
    expect(t.cf.fetchImpl).not.toHaveBeenCalled();
  });

  it('validators: token only in the body, strict, provider rules', () => {
    expect(connectBodySchema.safeParse({ name: 'example.com', provider: 'cloudflare' }).success).toBe(false);
    expect(connectBodySchema.safeParse({ name: 'example.com', provider: 'cloudflare', apiToken: TOKEN }).success).toBe(true);
    expect(connectBodySchema.safeParse({ name: 'example.com', provider: 'simulated' }).success).toBe(true);
    expect(connectBodySchema.safeParse({ name: 'example.com', apiToken: 'bad token with spaces!!' }).success).toBe(false);
    expect(recordBodySchema.safeParse({ op: 'upsert', type: 'MX', name: 'a', value: 'x' }).success).toBe(false);
  });
});

describe('DNS adapter behind the domains DNS-change gate (DNS_PROVIDER=cloudflare)', () => {
  it('domains.changeDns drives the Cloudflare adapter only after approval', async () => {
    const DOMAIN_ID = U(20);
    const prisma = fakePrisma({
      rootDomain: [{ id: 'r1', name: 'example.com', provider: 'cloudflare', zoneId: ZONE, tokenEnc: encrypt(TOKEN, KEY), archivedAt: null }],
      projectEnvironment: [{ id: ENV_PROD, projectId: PROJECT }],
      domain: [{ id: DOMAIN_ID, name: 'app.example.com', projectId: PROJECT, archivedAt: null }],
    });
    const cf = cfMock((c) => (c.method === 'GET' ? ok([]) : ok({ id: 'f'.repeat(32), ...c.body })));
    const ctx = makeCtx();
    const dnsAdapter = createCloudflareDnsAdapter({ prisma, credentialKey: () => KEY, fetchImpl: cf.fetchImpl, clientFactory: (o) => createCloudflareClient({ ...o, ...noWait }) });
    const svc = createDomainsService({ ...ctx, prisma: Object.assign(Object.create(prisma), { dnsRecord: { create: vi.fn(async ({ data }) => ({ id: U(30), ...data })), update: vi.fn(), delete: vi.fn() } }), adapters: { ...ctx.adapters, dns: dnsAdapter } });
    // domain.load uses include; supply a prisma with the include-shaped row
    svc.__prisma = null;
    const body = { op: 'upsert', type: 'A', name: '@', value: '198.51.100.7', ttl: 300, proxied: true, environmentId: ENV_PROD, reason: 'point apex', rollbackNote: 'remove record' };
    const loader = prisma.domain;
    loader.findUnique = async ({ where }) => ({ id: where.id ?? DOMAIN_ID, name: 'app.example.com', projectId: PROJECT, dnsRecords: [], certificates: [] });
    const pending = await svc.changeDns(DOMAIN_ID, body, OWNER);
    expect(pending.approvalRequired).toBe(true);
    expect(cf.fetchImpl).not.toHaveBeenCalled();
    await approve(ctx, pending.approval.id);
    const out = await svc.changeDns(DOMAIN_ID, { ...body, approvalId: pending.approval.id }, OWNER);
    expect(out.simulated).toBe(false);
    expect(cf.calls.find((c) => c.method === 'POST').body).toMatchObject({ type: 'A', name: 'app.example.com', content: '198.51.100.7', proxied: true });
  });

  it('toFqdn, zone matching (longest suffix) and fail-closed without a zone', async () => {
    expect(toFqdn('@', 'app.example.com')).toBe('app.example.com');
    expect(toFqdn('www', 'example.com')).toBe('www.example.com');
    expect(toFqdn('a.example.com', 'example.com')).toBe('a.example.com');
    const prisma = fakePrisma({ rootDomain: [{ id: '1', name: 'example.com', provider: 'cloudflare', archivedAt: null }, { id: '2', name: 'dev.example.com', provider: 'cloudflare', archivedAt: null }] });
    expect((await findRootFor(prisma, 'x.dev.example.com')).id).toBe('2');
    expect(await findRootFor(prisma, 'evilexample.com')).toBeNull();
    const adapter = createCloudflareDnsAdapter({ prisma: fakePrisma({ rootDomain: [] }), credentialKey: () => KEY });
    await expect(adapter.upsert({ type: 'A', name: 'x', value: '1.1.1.1', ttl: 300, domain: 'nowhere.org' })).rejects.toMatchObject({ code: 'DNS_ZONE_NOT_FOUND' });
  });

  it('provider selection: simulated by default, cloudflare / certbot only when asked', () => {
    expect(resolveProviderAdapters({ prisma: {}, env: {} })).toEqual({});
    const r = resolveProviderAdapters({ prisma: {}, env: { DNS_PROVIDER: 'cloudflare', ACME_EXECUTOR: 'certbot' }, connector: {} });
    expect(r.dns.provider).toBe('cloudflare');
    expect(r.acme.provider).toBe('certbot-dns-cloudflare');
    expect(resolveProviderAdapters({ prisma: {}, env: { DNS_PROVIDER: 'bogus' } })).toEqual({});
  });
});

describe('wildcard certificate over DNS-01 (certbot dns-cloudflare)', () => {
  const root = () => ({ id: 'r1', name: 'example.com', provider: 'cloudflare', zoneId: ZONE, tokenEnc: encrypt(TOKEN, KEY), archivedAt: null });

  it('script never contains the token; credentials come only over stdin as a 0600 file', () => {
    const plan = planWildcardCertificate({ domain: 'example.com', email: 'ops@example.com' });
    expect(plan.names).toEqual(['example.com', '*.example.com']);
    expect(plan.script).not.toContain(TOKEN);
    expect(plan.args.join(' ')).not.toContain(TOKEN);
    expect(plan.stdinPreview).not.toContain(TOKEN);
    expect(CERTBOT_DNS_CLOUDFLARE_SCRIPT).toContain('umask 077');
    expect(CERTBOT_DNS_CLOUDFLARE_SCRIPT).toContain('chmod 600 "$DIR/cloudflare.ini"');
    expect(CERTBOT_DNS_CLOUDFLARE_SCRIPT).toContain("trap 'rm -rf \"$DIR\"' EXIT");
    expect(CERTBOT_DNS_CLOUDFLARE_SCRIPT).toContain('cat > "$DIR/cloudflare.ini"');
    expect(buildCloudflareCredentials(TOKEN)).toBe(`dns_cloudflare_api_token = ${TOKEN}\n`);
    expect(() => buildCloudflareCredentials('x\nevil = 1')).toThrow();
    expect(() => planWildcardCertificate({ domain: 'bad domain', email: 'ops@example.com' })).toThrow();
    expect(() => planWildcardCertificate({ domain: 'example.com', email: 'nope' })).toThrow();
    expect(parseOpensslDate('NT_EXPIRES=Jan  5 10:00:00 2027 GMT\n')?.toISOString()).toBe('2027-01-05T10:00:00.000Z');
    expect(parseOpensslDate('garbage')).toBeNull();
  });

  it('adapter runs the script over the fake SSH connector with the token only on stdin', async () => {
    const prisma = fakePrisma({
      rootDomain: [root()],
      serverCredential: [{ serverId: U(5), host: '203.0.113.9', port: 22, username: 'deploy', secretEnc: encrypt('pw', KEY), hostKeySha256: null }],
    });
    const ssh = createFakeSsh({ respond: () => ({ stdout: 'NT_EXPIRES=Mar 10 12:00:00 2027 GMT\n', code: 0 }) });
    const adapter = createCertbotAcmeAdapter({ prisma, connector: ssh.connector, credentialKey: () => KEY, env: { ACME_EMAIL: 'ops@example.com' } });
    const out = await adapter.issue({ domain: 'example.com', challenge: 'dns-01', wildcard: true, serverId: U(5) });
    expect(out.expiresAt.toISOString()).toBe('2027-03-10T12:00:00.000Z');
    const call = ssh.calls.at(-1);
    expect(call.command).not.toContain(TOKEN);
    expect(call.args.join(' ')).not.toContain(TOKEN);
    expect(Buffer.from(call.command.match(/printf %s '([^']+)'/)[1], 'base64').toString()).not.toContain(TOKEN);
    expect(call.script).toBe(`dns_cloudflare_api_token = ${TOKEN}\n`);
  });

  it('refuses non-wildcard http-01, missing server, unknown zone; failure hides certbot output', async () => {
    const prisma = fakePrisma({ rootDomain: [root()], serverCredential: [{ serverId: U(5), host: 'h', port: 22, username: 'u', secretEnc: encrypt('pw', KEY) }] });
    const ssh = createFakeSsh({ respond: () => ({ code: 70, stderr: 'boom' }) });
    const adapter = createCertbotAcmeAdapter({ prisma, connector: ssh.connector, credentialKey: () => KEY, env: { ACME_EMAIL: 'ops@example.com' } });
    await expect(adapter.issue({ domain: 'example.com', challenge: 'http-01', wildcard: false, serverId: U(5) })).rejects.toMatchObject({ code: 'ACME_CHALLENGE_UNSUPPORTED' });
    await expect(adapter.issue({ domain: 'example.com', challenge: 'dns-01', wildcard: true })).rejects.toMatchObject({ code: 'DOMAIN_NO_SERVER' });
    await expect(adapter.issue({ domain: 'sub.example.com', challenge: 'dns-01', wildcard: true, serverId: U(5) })).rejects.toMatchObject({ code: 'DNS_ZONE_NOT_FOUND' });
    await expect(adapter.issue({ domain: 'example.com', challenge: 'dns-01', wildcard: true, serverId: U(5) })).rejects.toMatchObject({ code: 'ACME_ISSUE_FAILED' });
  });

  it('issueWildcard is gated (ssl.wildcard.issue), preview shows no secret, certificate row is recorded', async () => {
    const prisma = fakePrisma({ rootDomain: [root()] });
    const ctx = makeCtx();
    const svc = createRootDomainsService({ prisma, auditService: ctx.auditService, platform: ctx.platform, adapters: ctx.adapters, env: { ACME_EMAIL: 'ops@example.com' }, credentialKey: () => KEY });
    const preview = await svc.previewWildcard('r1', { staging: true, propagationSeconds: 30 }, OWNER);
    expect(JSON.stringify(preview)).not.toContain(TOKEN);
    expect(preview.executor).toBe('simulated');
    const input = { serverId: U(5), staging: true, propagationSeconds: 30, reason: 'wildcard for previews', rollbackNote: 'remove cert' };
    const pending = await svc.issueWildcard('r1', input, OWNER);
    expect(pending.approvalRequired).toBe(true);
    expect(prisma.sslCertificate.rows).toHaveLength(0);
    await approve(ctx, pending.approval.id);
    const done = await svc.issueWildcard('r1', { ...input, approvalId: pending.approval.id }, OWNER);
    expect(done.certificate.status).toBe('active');
    expect(done.simulated).toBe(true);
    expect(prisma.sslCertificate.rows[0]).toMatchObject({ challenge: 'dns-01', provider: 'simulated-acme' });
    expect(ctx.adapters.calls.find((c) => c.name === 'acme.issue').arg).toMatchObject({ domain: 'example.com', wildcard: true, challenge: 'dns-01' });
  });
});

describe('real certificate expiry scan', () => {
  const NOW = new Date('2026-12-01T00:00:00Z');
  function fakeTls({ cert, authorized = true, authorizationError = null, fail = null, onOpts }) {
    return (opts, cb) => {
      onOpts?.(opts);
      const s = new EventEmitter();
      s.destroy = vi.fn();
      s.authorized = authorized;
      s.authorizationError = authorizationError;
      s.getPeerCertificate = () => cert;
      s.getProtocol = () => 'TLSv1.3';
      setImmediate(() => (fail ? s.emit('error', Object.assign(new Error('x'), { code: fail })) : cb()));
      return s;
    };
  }
  const goodCert = { valid_from: 'Nov  1 00:00:00 2026 GMT', valid_to: 'Jan 15 00:00:00 2027 GMT', issuer: { O: "Let's Encrypt" }, subject: { CN: 'app.example.com' }, subjectaltname: 'DNS:app.example.com' };
  const pub = async () => [{ address: '93.184.216.34', family: 4 }];

  it('reads expiry with SNI = hostname and reports trust from the verification result', async () => {
    let seen;
    const r = await probeTls('app.example.com', { connect: fakeTls({ cert: goodCert, onOpts: (o) => { seen = o; } }), lookup: pub, now: () => NOW });
    expect(r).toMatchObject({ ok: true, trusted: true, daysLeft: 45, issuer: "Let's Encrypt", protocol: 'TLSv1.3' });
    expect(seen.servername).toBe('app.example.com');
    expect(seen.host).toBe('93.184.216.34'); // pinned to the address that passed the SSRF check
    expect(seen.port).toBe(443);
  });

  it('an untrusted chain or hostname mismatch is reported as NOT trusted, never as valid', async () => {
    const r = await probeTls('app.example.com', { connect: fakeTls({ cert: goodCert, authorized: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }), lookup: pub, now: () => NOW });
    expect(r).toMatchObject({ ok: true, trusted: false, authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT' });
  });

  it('refuses IP literals, bad names, private/loopback resolution, and reports errors without throwing', async () => {
    expect(await probeTls('10.0.0.1', {})).toMatchObject({ ok: false, error: 'HOSTNAME_INVALID' });
    expect(await probeTls('localhost', {})).toMatchObject({ ok: false, error: 'HOSTNAME_INVALID' });
    expect(await probeTls('internal.example.com', { lookup: async () => [{ address: '127.0.0.1' }] })).toMatchObject({ error: 'ADDRESS_REFUSED' });
    expect(await probeTls('internal.example.com', { lookup: async () => [{ address: '93.184.216.34' }, { address: '169.254.169.254' }] })).toMatchObject({ error: 'ADDRESS_REFUSED' });
    expect(await probeTls('x.example.com', { lookup: async () => { throw new Error('nx'); } })).toMatchObject({ error: 'DNS_FAILED' });
    expect(await probeTls('x.example.com', { lookup: pub, connect: fakeTls({ cert: goodCert, fail: 'ECONNREFUSED' }) })).toMatchObject({ ok: false, error: 'ECONNREFUSED' });
    expect(['10.1.2.3', '172.16.0.1', '192.168.1.1', '127.0.0.1', '::1', 'fe80::1', 'fd00::1', '100.64.0.1'].every(isPrivateAddress)).toBe(true);
    expect(isPrivateAddress('93.184.216.34')).toBe(false);
  });

  it('scanLive stores observed expiry, flags invalid chains, then feeds the existing expiry alerts', async () => {
    const prisma = fakePrisma({
      domain: [
        { id: 'd1', name: 'ok.example.com', status: 'active', archivedAt: null },
        { id: 'd2', name: 'bad.example.com', status: 'active', archivedAt: null },
        { id: 'd3', name: 'down.example.com', status: 'active', archivedAt: null },
        { id: 'd4', name: 'nocert.example.com', status: 'active', archivedAt: null },
      ],
      sslCertificate: [
        { id: 'c1', domainId: 'd1', status: 'active', expiresAt: null, createdAt: NOW },
        { id: 'c2', domainId: 'd2', status: 'active', expiresAt: new Date('2027-06-01T00:00:00Z'), createdAt: NOW },
        { id: 'c3', domainId: 'd3', status: 'active', expiresAt: new Date('2027-06-01T00:00:00Z'), createdAt: NOW },
      ],
    });
    const probe = vi.fn(async (host) => {
      if (host === 'ok.example.com') return { ok: true, trusted: true, validTo: new Date('2026-12-10T00:00:00Z') };
      if (host === 'bad.example.com') return { ok: true, trusted: false, authorizationError: 'CERT_HAS_EXPIRED', validTo: new Date('2027-06-01T00:00:00Z') };
      return { ok: false, error: 'TIMEOUT' };
    });
    const svc = createCertificatesService({ prisma, now: () => NOW, probe });
    const out = await svc.scanLive();
    expect(probe).toHaveBeenCalledTimes(3); // domain without a certificate record is skipped
    expect(out).toMatchObject({ probed: 3, updated: 2, unreachable: 1 });
    expect(out.invalid).toEqual([{ certificateId: 'c2', reason: 'CERT_HAS_EXPIRED' }]);
    expect(prisma.sslCertificate.rows.find((c) => c.id === 'c1')).toMatchObject({ status: 'active', expiresAt: new Date('2026-12-10T00:00:00Z') });
    expect(prisma.sslCertificate.rows.find((c) => c.id === 'c2')).toMatchObject({ status: 'invalid', lastError: 'CERT_HAS_EXPIRED' });
    expect(out.expiry.expiring).toEqual(['c1']); // 9 days left: existing alert path
  });
});

describe('Caddy mode generators', () => {
  it('renders a plain reverse proxy site', () => {
    expect(renderCaddySite({ hostname: 'app.example.com', upstreamPort: 3000 })).toBe('app.example.com {\n\tencode gzip\n\treverse_proxy 127.0.0.1:3000\n}\n');
    const www = renderCaddySite({ hostname: 'app.example.com', upstreamPort: 3000, wwwRedirect: true });
    expect(www).toContain('www.app.example.com {');
    expect(lintCaddySite(www).ok).toBe(true);
  });

  it('rejects injection through every value', () => {
    const bad = ['a.com {\n\texec rm -rf /\n}\nb.com', 'a.com\nimport /etc/passwd', 'a.com { }', 'a.com;evil', '{env.SECRET}.com', 'a b.com', 'a.com\r\nrespond "x"'];
    for (const hostname of bad) expect(() => renderCaddySite({ hostname, upstreamPort: 3000 }), hostname).toThrow(/Hostname/);
    for (const upstreamPort of [0, 70000, 3000.5, '3000', '3000\nrespond', NaN]) expect(() => renderCaddySite({ hostname: 'a.example.com', upstreamPort })).toThrow(/port/);
    const hash = `$2y$10$${'a'.repeat(53)}`;
    expect(renderCaddySite({ hostname: 'a.example.com', upstreamPort: 1, basicAuth: { user: 'preview', hash } })).toContain(`preview ${hash}`);
    expect(() => renderCaddySite({ hostname: 'a.example.com', upstreamPort: 1, basicAuth: { user: 'x\n}', hash } })).toThrow();
    expect(() => renderCaddySite({ hostname: 'a.example.com', upstreamPort: 1, basicAuth: { user: 'preview', hash: 'plain\n}\nrespond' } })).toThrow();
    expect(lintCaddySite('a.com {\n import x\n}').ok).toBe(false);
    expect(lintCaddySite('a.com {').ok).toBe(false);
  });

  it('apply script validates, reloads, rolls back, and takes the site only from stdin', () => {
    expect(CADDY_APPLY_SCRIPT).toContain('caddy validate');
    expect(CADDY_APPLY_SCRIPT).toContain('systemctl reload caddy');
    expect(CADDY_APPLY_SCRIPT).toContain('restore');
    expect(CADDY_APPLY_SCRIPT).toContain('cat > "$TMP"');
    expect(CADDY_APPLY_SCRIPT).not.toMatch(/\brm -rf\b/);
  });

  it('Caddy preview is read-only; apply is closed by default, gated, and rolled back on failure', async () => {
    const dom = { id: U(20), name: 'app.example.com', projectId: PROJECT, serverId: U(5), dnsRecords: [], certificates: [] };
    const run = vi.fn(async () => ({ code: 0, stdout: 'NT_CADDY=applied\n' }));
    const mk = (env) => {
      const ctx = makeCtx({ prismaExtra: { projectEnvironment: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: PROJECT })) }, domain: { findUnique: vi.fn(async () => dom) } } });
      return { ctx, svc: createDomainsService({ ...ctx, scriptRunner: { run }, env }) };
    };
    const input = { upstreamPort: 3000, wwwRedirect: false, environmentId: ENV_PROD, reason: 'switch to caddy', rollbackNote: 'delete site file' };
    const off = mk({});
    const p = await off.svc.previewCaddy(dom.id, input, OWNER);
    expect(p).toMatchObject({ valid: true, caddyMode: 'off' });
    expect(p.config).toContain('reverse_proxy 127.0.0.1:3000');
    await expect(off.svc.applyCaddy(dom.id, input, OWNER)).rejects.toMatchObject({ code: 'CADDY_DISABLED' });
    expect(run).not.toHaveBeenCalled();
    const on = mk({ CADDY_MODE: 'on' });
    const g = await on.svc.applyCaddy(dom.id, input, OWNER);
    expect(g.approvalRequired).toBe(true);
    expect(run).not.toHaveBeenCalled();
    await approve(on.ctx, g.approval.id);
    expect((await on.svc.applyCaddy(dom.id, { ...input, approvalId: g.approval.id }, OWNER)).applied).toBe(true);
    expect(run).toHaveBeenCalledWith(U(5), CADDY_APPLY_SCRIPT, expect.objectContaining({ args: ['app.example.com'], stdin: p.config }));
    run.mockResolvedValueOnce({ code: 71, stdout: '' });
    const g2 = await on.svc.applyCaddy(dom.id, { ...input, upstreamPort: 3001 }, OWNER);
    await approve(on.ctx, g2.approval.id);
    await expect(on.svc.applyCaddy(dom.id, { ...input, upstreamPort: 3001, approvalId: g2.approval.id }, OWNER)).rejects.toMatchObject({ code: 'CADDY_APPLY_FAILED' });
  });
});

describe('Apache / nginx detection (read-only probe)', () => {
  it('script is read-only and the parser classifies the listener', () => {
    expect(DETECT_WEBSERVER_SCRIPT).not.toMatch(/\b(rm|systemctl|install|mv|cp|sed -i|tee|>>|apt|reload|restart)\b/);
    expect(parseWebserverProbe('nginx=nginx version: nginx/1.24.0\napache=none\ncaddy=none\nport80=nginx\nport443=nginx\n')).toEqual({ nginx: 'nginx version: nginx/1.24.0', apache: null, caddy: null, port80: 'nginx', port443: 'nginx', recommended: 'nginx' });
    expect(parseWebserverProbe('nginx=none\napache=Server version: Apache/2.4.58\ncaddy=none\nport80=apache2\nport443=none\n').recommended).toBe('apache');
    expect(parseWebserverProbe('nginx=none\napache=none\ncaddy=v2.8\nport80=caddy\nport443=caddy\n').recommended).toBe('caddy');
    expect(parseWebserverProbe('rubbish; rm -rf /').recommended).toBeNull();
  });

  it('runs through the fake SSH runner and the domains service', async () => {
    const prisma = fakePrisma({ serverCredential: [{ serverId: U(5), host: 'h', port: 22, username: 'u', secretEnc: encrypt('pw', KEY) }] });
    const ssh = createFakeSsh({ respond: () => ({ stdout: 'nginx=nginx/1.24\napache=none\ncaddy=none\nport80=nginx\nport443=nginx\n' }) });
    const dom = { id: U(20), name: 'app.example.com', projectId: PROJECT, serverId: U(5) };
    const ctx = makeCtx({ prismaExtra: { projectEnvironment: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: PROJECT })) }, domain: { findUnique: vi.fn(async () => dom) } } });
    const svc = createDomainsService({ ...ctx, scriptRunner: createScriptRunner({ prisma, connector: ssh.connector, credentialKey: () => KEY }) });
    const out = await svc.detectWebserver(dom.id, { environmentId: ENV_PROD }, OWNER);
    expect(out).toMatchObject({ recommended: 'nginx', port80: 'nginx' });
    expect(APPROVER).toBeTruthy();
  });
});
