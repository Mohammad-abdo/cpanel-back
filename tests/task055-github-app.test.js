import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createVerify, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createGitHubClient, signAppJwt } from '../src/modules/github/github.client.js';
import { createGitHubService, GITHUB_APP_CONFIG_ID, STATE_TTL_MS } from '../src/modules/github/github.service.js';
import { createWebhooksService } from '../src/modules/webhooks/webhooks.service.js';
import { githubSignature } from '../src/modules/webhooks/webhooks.crypto.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';
import { FETCH_SCRIPT } from '../src/modules/deployments/deployments.commands.js';
import { linkRepoBodySchema, upsertGitHubAppBodySchema } from '../src/modules/github/github.validator.js';
import { fakePrisma, U } from './phase3-helpers.js';

const KEY = randomBytes(32).toString('hex');
const OWNER = { id: U(1), isOwner: true };
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const APP_SECRET = 'app-level-webhook-secret-value';
const PROJECT_SECRET = 'project-level-webhook-secret';
const TOKEN = 'ghs_installation_token_value_123';

const res = (status, body, headers = {}) => ({ ok: status < 300, status, headers: { get: (k) => headers[k.toLowerCase()] ?? null }, json: async () => body });
const inOneHour = () => new Date(Date.now() + 3600_000).toISOString();

beforeEach(() => vi.stubEnv('CREDENTIAL_ENCRYPTION_KEY', KEY));
afterEach(() => vi.unstubAllEnvs());

function setup({ fetchImpl, configured = true, clock = { t: Date.now() }, platform = null } = {}) {
  const rows = configured ? [{ id: GITHUB_APP_CONFIG_ID, appId: 777, privateKeyEnc: encrypt(privateKey, KEY), webhookSecretEnc: encrypt(APP_SECRET, KEY), status: 'active', metaJson: {} }] : [];
  const prisma = fakePrisma({
    gitHubAppConfig: rows,
    project: [{ id: U(10), name: 'Api', archivedAt: null }],
    projectEnvironment: [{ id: U(20), projectId: U(10), code: 'production' }],
  });
  const auditService = { record: vi.fn() };
  const client = createGitHubClient({ fetchImpl, now: () => clock.t, sleep: async () => {} });
  const svc = createGitHubService({ prisma, auditService, client, now: () => new Date(clock.t), platform });
  return { prisma, svc, auditService, client, clock };
}

describe('App JWT', () => {
  it('signs RS256 with iss and a lifetime under 10 minutes; signature verifies', () => {
    const nowMs = Date.parse('2026-11-18T10:00:00Z');
    const jwt = signAppJwt({ appId: 777, privateKeyPem: privateKey, nowMs });
    const [h, p, s] = jwt.split('.');
    expect(JSON.parse(Buffer.from(h, 'base64url'))).toEqual({ alg: 'RS256', typ: 'JWT' });
    const claims = JSON.parse(Buffer.from(p, 'base64url'));
    expect(claims.iss).toBe('777');
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
    expect(claims.exp).toBeGreaterThan(Math.floor(nowMs / 1000));
    expect(createVerify('RSA-SHA256').update(`${h}.${p}`).verify(publicKey, Buffer.from(s, 'base64url'))).toBe(true);
  });
  it('rejects a garbage key without echoing it', () => {
    try {
      signAppJwt({ appId: 1, privateKeyPem: 'not a key SECRETVALUE' });
      throw new Error('should fail');
    } catch (e) {
      expect(e.code).toBe('GITHUB_PRIVATE_KEY_INVALID');
      expect(e.message).not.toContain('SECRETVALUE');
    }
  });
});

describe('client: host pinning, tokens, pagination, rate limits', () => {
  it('only calls api.github.com, refuses redirects, rejects hostile paths', async () => {
    const calls = [];
    const fetchImpl = vi.fn(async (url, init) => {
      calls.push({ url, init });
      return res(200, { ok: 1 });
    });
    const client = createGitHubClient({ fetchImpl });
    await client.request('GET', '/rate_limit', { token: 'x' });
    expect(calls[0].url.startsWith('https://api.github.com/')).toBe(true);
    expect(calls[0].init.redirect).toBe('error');
    expect(calls[0].init.signal).toBeTruthy();
    await expect(client.request('GET', '//evil.example/x')).rejects.toMatchObject({ code: 'GITHUB_PATH_INVALID' });
    await expect(client.request('GET', 'https://evil.example/x')).rejects.toMatchObject({ code: 'GITHUB_PATH_INVALID' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('caches installation tokens until 60 s before expiry, then refreshes', async () => {
    const clock = { t: Date.parse('2026-11-18T10:00:00Z') };
    const fetchImpl = vi.fn(async () => res(201, { token: TOKEN, expires_at: new Date(clock.t + 3600_000).toISOString() }));
    const client = createGitHubClient({ fetchImpl, now: () => clock.t });
    const creds = { appId: 1, privateKeyPem: privateKey };
    await client.installationToken(creds, '55');
    await client.installationToken(creds, '55');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    clock.t += 3600_000 - 30_000;
    await client.installationToken(creds, '55');
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    const call = fetchImpl.mock.calls[0];
    expect(call[0]).toBe('https://api.github.com/app/installations/55/access_tokens');
    expect(call[1].headers.Authorization).toMatch(/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/);
  });

  it('paginates repositories by page number and reports hasMore', async () => {
    const urls = [];
    const fetchImpl = vi.fn(async (url) => {
      urls.push(url);
      if (url.includes('access_tokens')) return res(201, { token: TOKEN, expires_at: inOneHour() });
      return res(200, { total_count: 3, repositories: [{ id: 1, full_name: 'a/b', private: true, default_branch: 'main' }, { id: 2, full_name: 'a/c' }] });
    });
    const { svc } = setup({ fetchImpl });
    const out = await svc.listInstallationRepos(OWNER, { installationId: '9', page: 2 });
    expect(urls.some((u) => u.includes('/installation/repositories') && u.includes('page=2'))).toBe(true);
    expect(out.items[0]).toEqual({ id: 1, fullName: 'a/b', private: true, defaultBranch: 'main' });
    expect(JSON.stringify(out)).not.toContain(TOKEN);
  });

  it('maps rate limiting to 429, retries 5xx, and keeps bodies out of errors', async () => {
    const limited = createGitHubClient({ fetchImpl: async () => res(403, { message: 'secret detail' }, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 30) }) });
    await expect(limited.request('GET', '/x', { token: 't' })).rejects.toMatchObject({ status: 429, code: 'GITHUB_RATE_LIMITED' });
    let n = 0;
    const flaky = createGitHubClient({ fetchImpl: async () => (++n < 3 ? res(502, { message: 'bad' }) : res(200, { ok: true })), sleep: async () => {} });
    expect(await flaky.request('GET', '/x', { token: 't' })).toEqual({ ok: true });
    const down = createGitHubClient({ fetchImpl: async () => res(500, { message: 'body leak tokenvalue' }), sleep: async () => {} });
    await expect(down.request('GET', '/x', { token: 'tokenvalue' })).rejects.toThrow(/HTTP 500$/);
  });
});

describe('manifest flow', () => {
  const conversion = { id: 4242, slug: 'nodeteam-x', client_id: 'Iv1.abc', client_secret: 'CLIENT_SECRET_NEVER_STORED', webhook_secret: 'whsec-from-github-123456', pem: privateKey };

  it('builds the manifest with our webhook URL and the required permissions', async () => {
    const { svc } = setup({ fetchImpl: vi.fn(), configured: false });
    const out = await svc.manifest(OWNER);
    expect(out.manifest.hook_attributes.url).toBe('https://cpanel-review.nodeteam.site/api/v1/webhooks/github');
    expect(out.manifest.default_permissions).toMatchObject({ contents: 'read', metadata: 'read', pull_requests: 'write' });
    expect(out.manifest.default_events).toEqual(['push', 'pull_request']);
    expect(out.postUrl.startsWith('https://github.com/settings/apps/new?state=')).toBe(true);
  });

  it('exchanges the code once, stores credentials encrypted, never returns or audits them', async () => {
    const fetchImpl = vi.fn(async () => res(201, conversion));
    const { svc, prisma, auditService } = setup({ fetchImpl, configured: false });
    const { state } = await svc.manifest(OWNER);
    const done = await svc.completeManifest({ code: 'tempcode12345', state });
    expect(fetchImpl.mock.calls[0][0]).toBe('https://api.github.com/app-manifests/tempcode12345/conversions');
    expect(fetchImpl.mock.calls[0][1].method).toBe('POST');
    const row = prisma.gitHubAppConfig.rows[0];
    expect(Buffer.from(row.privateKeyEnc).includes(Buffer.from('BEGIN PRIVATE KEY'))).toBe(false);
    expect(row.appId).toBe(4242);
    const everything = JSON.stringify([done, await svc.getApp(OWNER), auditService.record.mock.calls]);
    for (const secret of ['CLIENT_SECRET_NEVER_STORED', 'whsec-from-github-123456', 'BEGIN PRIVATE KEY', TOKEN]) expect(everything).not.toContain(secret);
    expect((await svc.getApp(OWNER)).hasPrivateKey).toBe(true);
    await expect(svc.completeManifest({ code: 'tempcode12345', state })).rejects.toMatchObject({ code: 'GITHUB_STATE_INVALID' });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('rejects tampered, expired and malformed state before any network call', async () => {
    const fetchImpl = vi.fn(async () => res(201, conversion));
    const { svc, clock } = setup({ fetchImpl, configured: false });
    const { state } = await svc.manifest(OWNER);
    const [nonce, exp, sig] = state.split('.');
    await expect(svc.completeManifest({ code: 'tempcode12345', state: `${nonce}.${Number(exp) + 1}.${sig}` })).rejects.toMatchObject({ code: 'GITHUB_STATE_INVALID' });
    await expect(svc.completeManifest({ code: 'tempcode12345', state: `${nonce}.${exp}.${sig.slice(1)}x` })).rejects.toMatchObject({ code: 'GITHUB_STATE_INVALID' });
    await expect(svc.completeManifest({ code: 'tempcode12345', state: 'a.b.c' })).rejects.toMatchObject({ code: 'GITHUB_STATE_INVALID' });
    clock.t += STATE_TTL_MS + 1000;
    await expect(svc.completeManifest({ code: 'tempcode12345', state })).rejects.toMatchObject({ code: 'GITHUB_STATE_INVALID' });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('manual entry is write-only and masked; non-owners refused; base URL must be https', async () => {
    const { svc, prisma } = setup({ fetchImpl: vi.fn(), configured: false });
    const out = await svc.upsertApp({ appId: 5, privateKey, webhookSecret: PROJECT_SECRET, installationId: '123', publicBaseUrl: 'https://cp.example.com/' }, OWNER);
    expect(out).toMatchObject({ hasPrivateKey: true, hasWebhookSecret: true, installationCount: 1, webhookUrl: 'https://cp.example.com/api/v1/webhooks/github' });
    expect(JSON.stringify(out)).not.toContain('PRIVATE KEY');
    expect(JSON.stringify(prisma.gitHubAppConfig.rows[0].metaJson)).not.toContain('"id":"123"');
    await expect(svc.upsertApp({ publicBaseUrl: 'http://x.test' }, OWNER)).rejects.toMatchObject({ code: 'PUBLIC_BASE_URL_INVALID' });
    await expect(svc.getApp({ id: U(2), isOwner: false })).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    expect(upsertGitHubAppBodySchema.safeParse({ appId: 1, extra: 1 }).success).toBe(false);
  });

  it('disconnect and secret rotation go through the approval gate when wired', async () => {
    const gate = vi.fn(async () => ({ proceed: false, approval: { id: 'ap1' } }));
    const { svc, prisma } = setup({ fetchImpl: vi.fn(), platform: { gate } });
    expect(await svc.deleteApp(OWNER)).toEqual({ approvalRequired: true, approval: { id: 'ap1' } });
    expect(await svc.rotateWebhookSecret(OWNER)).toMatchObject({ approvalRequired: true });
    expect(gate.mock.calls.map((c) => c[0].action)).toEqual(['github.app.disconnect', 'github.app.rotate_secret']);
    expect(prisma.gitHubAppConfig.rows[0].privateKeyEnc).toBeTruthy();
  });
});

describe('project link and clone credential', () => {
  it('links a repo, writes repository + webhook rows, validates env codes', async () => {
    const fetchImpl = vi.fn(async (url) => {
      if (url.endsWith('/installation')) return res(200, { id: 99 });
      if (url.includes('access_tokens')) return res(201, { token: TOKEN, expires_at: inOneHour() });
      return res(200, { default_branch: 'trunk' });
    });
    const { svc, prisma } = setup({ fetchImpl });
    const out = await svc.linkProjectRepo(U(10), { repo: 'Acme/Api', branchMap: { trunk: 'production' }, autoDeploy: true }, OWNER);
    expect(out).toMatchObject({ remoteUrl: 'https://github.com/Acme/Api.git', defaultBranch: 'trunk' });
    expect(prisma.projectRepository.rows[0].remoteUrl).toBe('https://github.com/Acme/Api.git');
    expect(prisma.projectWebhook.rows[0]).toMatchObject({ enabled: true, branchMapJson: { trunk: 'production' } });
    await expect(svc.linkProjectRepo(U(10), { repo: 'Acme/Api', branchMap: { x: 'nope' } }, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_CODE_UNKNOWN' });
    expect(linkRepoBodySchema.safeParse({ repo: 'not a repo' }).success).toBe(false);
  });

  it('issues a down-scoped clone token only for the repository the Owner linked to that project', async () => {
    const bodies = [];
    const fetchImpl = vi.fn(async (url, init) => {
      if (url.endsWith('/installation')) return res(200, { id: 99 });
      if (url.includes('access_tokens')) {
        bodies.push(init.body ? JSON.parse(init.body) : null);
        return res(201, { token: TOKEN, expires_at: inOneHour() });
      }
      return res(200, { default_branch: 'main' });
    });
    const { svc, prisma, auditService } = setup({ fetchImpl });
    prisma.project.create({ data: { id: U(11), name: 'Other', archivedAt: null } });
    await svc.linkProjectRepo(U(10), { repo: 'Acme/Api' }, OWNER);
    // case and .git normalization
    const cred = await svc.cloneCredential('https://github.com/acme/API', { projectId: U(10) });
    expect(cred.token).toBe(TOKEN);
    const scoped = bodies.filter(Boolean).at(-1);
    expect(scoped).toEqual({ repositories: ['API'], permissions: { contents: 'read' } });
    // not cached: a second call mints again
    await svc.cloneCredential('https://github.com/Acme/Api.git', { projectId: U(10) });
    expect(bodies.filter(Boolean).length).toBe(2);
    // unlinked repo, other project, no project: refused, never an installation-wide fallback
    const before = fetchImpl.mock.calls.length;
    await expect(svc.cloneCredential('https://github.com/Acme/Secret.git', { projectId: U(10) })).rejects.toMatchObject({ code: 'GITHUB_REPO_NOT_LINKED' });
    await expect(svc.cloneCredential('https://github.com/Acme/Api.git', { projectId: U(11) })).rejects.toMatchObject({ code: 'GITHUB_REPO_NOT_LINKED' });
    await expect(svc.cloneCredential('https://github.com/Acme/Api.git')).rejects.toMatchObject({ code: 'GITHUB_REPO_NOT_LINKED' });
    expect(fetchImpl.mock.calls.length).toBe(before);
    expect(await svc.cloneCredential('https://gitlab.com/a/b.git', { projectId: U(10) })).toBeNull();
    // manual edit of the stored remote breaks the link
    prisma.projectRepository.rows[0].remoteUrl = 'https://github.com/Acme/Secret.git';
    await expect(svc.cloneCredential('https://github.com/Acme/Secret.git', { projectId: U(10) })).rejects.toMatchObject({ code: 'GITHUB_REPO_NOT_LINKED' });
    expect(JSON.stringify(auditService.record.mock.calls)).not.toContain(TOKEN);
    expect(FETCH_SCRIPT).not.toContain(TOKEN);
    expect(FETCH_SCRIPT).toContain('head -c 4096 > "$NT_TMP/secret"');
    expect(FETCH_SCRIPT).toContain('umask 077');
    expect(FETCH_SCRIPT).toContain('GIT_ASKPASS');
    const { svc: none } = setup({ fetchImpl, configured: false });
    expect(await none.cloneCredential('https://github.com/Acme/Api.git', { projectId: U(10) })).toBeNull();
  });
});

describe('webhook endpoint: app-level and project-level secrets, installation events', () => {
  function hooks() {
    const { svc: github, prisma } = setup({ fetchImpl: vi.fn() });
    prisma.user.create({ data: { id: U(1), email: 'o@x.test', displayName: 'O', status: 'active', disabledAt: null, ownerFlag: true } });
    prisma.projectRepository.create({ data: { projectId: U(10), remoteUrl: 'https://github.com/Acme/Api.git', defaultBranch: 'main' } });
    prisma.projectWebhook.create({ data: { projectId: U(10), enabled: true, secretEnc: encrypt(PROJECT_SECRET, KEY), branchMapJson: { main: 'production' }, prMapJson: {}, actorUserId: U(1) } });
    const deploymentsService = { create: vi.fn(async () => ({ deployment: { id: 'd1' }, operation: { status: 'PENDING_APPROVAL' } })) };
    const svc = createWebhooksService({ prisma, deploymentsService, githubApp: github });
    return { svc, prisma, github, deploymentsService };
  }
  const push = { ref: 'refs/heads/main', after: 'c'.repeat(40), deleted: false, repository: { clone_url: 'https://github.com/acme/api.git', html_url: 'https://github.com/acme/api' } };
  const send = (payload, secret, id, event = 'push') => {
    const rawBody = Buffer.from(JSON.stringify(payload));
    return { rawBody, event, deliveryId: id, signature: githubSignature(rawBody, secret) };
  };

  it('accepts push signed with the App secret or the project secret, rejects others; deployments still go through deployments.create', async () => {
    const { svc, deploymentsService } = hooks();
    expect((await svc.handleGithub(send(push, APP_SECRET, 'deliv-app-01'))).approvalRequired).toBe(true);
    expect((await svc.handleGithub(send(push, PROJECT_SECRET, 'deliv-prj-01'))).accepted).toBe(true);
    await expect(svc.handleGithub(send(push, 'wrong-secret', 'deliv-bad-01'))).rejects.toMatchObject({ status: 401 });
    expect(deploymentsService.create).toHaveBeenCalledTimes(2);
  });

  it('handles installation events only with the App secret, de-duplicates, and refreshes the list', async () => {
    const { svc, github } = hooks();
    const evt = { action: 'created', installation: { id: 31, account: { login: 'acme' } } };
    await expect(svc.handleGithub(send(evt, PROJECT_SECRET, 'deliv-inst-00', 'installation'))).rejects.toMatchObject({ status: 401 });
    expect(await svc.handleGithub(send(evt, APP_SECRET, 'deliv-inst-01', 'installation'))).toMatchObject({ accepted: true, installations: 1 });
    expect(await svc.handleGithub(send(evt, APP_SECRET, 'deliv-inst-01', 'installation'))).toMatchObject({ replayed: true });
    const app = await github.getApp(OWNER);
    expect(app.installations).toEqual([{ id: '31', account: 'acme' }]);
    expect(app.lastEvents[0]).toMatchObject({ event: 'installation', outcome: 'accepted' });
    await svc.handleGithub(send({ action: 'deleted', installation: { id: 31 } }, APP_SECRET, 'deliv-inst-02', 'installation'));
    expect((await github.getApp(OWNER)).installations).toEqual([]);
  });
});
