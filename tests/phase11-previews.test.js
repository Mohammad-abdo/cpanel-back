import { describe, expect, it, vi } from 'vitest';
import { allocatePort, previewHostname, validatePortRange } from '../src/modules/previews/previews.ports.js';
import { createPreviewCredentials, hashPassword, htpasswdLine, verifyPassword } from '../src/modules/previews/previews.auth.js';
import { createPreviewsService, renderPreviewVhost } from '../src/modules/previews/previews.service.js';
import { APPROVER, KEY, OWNER, PROJECT, U, approve, makeCtx } from './phase6-helpers.js';

const SERVER = U(5);
const ROOT = U(70);
const DEPLOY_ID = U(90);
const NOW = new Date('2026-06-01T12:00:00Z');

function matchWhere(row, where = {}) {
  for (const [key, cond] of Object.entries(where)) {
    if (key === 'OR') {
      if (!cond.some((clause) => matchWhere(row, clause))) return false;
      continue;
    }
    const val = row[key];
    if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
      if ('in' in cond && !cond.in.includes(val)) return false;
      if ('notIn' in cond && cond.notIn.includes(val)) return false;
      if ('not' in cond && (cond.not === null ? val == null : val === cond.not)) return false;
      if ('lte' in cond && !(new Date(val).getTime() <= new Date(cond.lte).getTime())) return false;
      if ('not' in cond === false && 'in' in cond === false && 'notIn' in cond === false && 'lte' in cond === false) {
        /* plain object ignored */
      }
    } else if (val !== cond) return false;
  }
  return true;
}

describe('preview ports and hostnames', () => {
  it('allocates a free port from the range without collisions', () => {
    validatePortRange(20000, 20005);
    const port = allocatePort({ start: 20000, end: 20005, taken: [20000, 20001], seed: 0 });
    expect(port).toBeGreaterThanOrEqual(20000);
    expect(port).toBeLessThanOrEqual(20005);
    expect([20000, 20001]).not.toContain(port);
    expect(() => allocatePort({ start: 20000, end: 20001, taken: [20000, 20001], seed: 1 })).toThrow(/No free port/);
    expect(() => validatePortRange(80, 90)).toThrow(/Port range/);
  });

  it('builds a bounded pr-<n>.slug.root hostname', () => {
    expect(previewHostname({ prNumber: 12, slug: 'api', rootName: 'example.com' })).toBe('pr-12.api.example.com');
    expect(() => previewHostname({ prNumber: 0, slug: 'api', rootName: 'example.com' })).toThrow(/hostname/i);
    expect(() => previewHostname({ prNumber: 1, slug: 'BAD_SLUG', rootName: 'example.com' })).toThrow(/hostname/i);
  });
});

describe('preview basic auth (apr1)', () => {
  it('hashes, verifies, and formats an htpasswd line without storing the password', () => {
    const creds = createPreviewCredentials();
    expect(creds.user).toBe('preview');
    expect(creds.password.length).toBeGreaterThan(10);
    expect(verifyPassword(creds.password, creds.hash)).toBe(true);
    expect(verifyPassword('wrong', creds.hash)).toBe(false);
    expect(htpasswdLine(creds.user, creds.hash)).toBe(`preview:${creds.hash}\n`);
    expect(hashPassword('same', 'saltsalt')).toBe(hashPassword('same', 'saltsalt'));
  });
});

describe('preview vhost renderer', () => {
  it('emits a safe nginx block and rejects bad input', () => {
    const conf = renderPreviewVhost({ hostname: 'pr-1.api.example.com', port: 20001, basicAuth: true });
    expect(conf).toContain('server_name pr-1.api.example.com');
    expect(conf).toContain('proxy_pass http://127.0.0.1:20001');
    expect(conf).toContain('auth_basic');
    expect(() => renderPreviewVhost({ hostname: 'evil;rm', port: 1 })).toThrow();
  });
});

describe('previews service (mocked)', () => {
  function setup() {
    const settingsStore = new Map();
    const previewStore = new Map();
    const envStore = new Map();
    const varStore = new Map();
    const domainStore = new Map();
    let n = 800;
    const ctx = makeCtx({ now: () => NOW });
    const project = { id: PROJECT, serverId: SERVER, slug: 'api', status: 'active', archivedAt: null };

    const filterPreviews = (where) => [...previewStore.values()].filter((r) => matchWhere(r, where));

    Object.assign(ctx.prisma, {
      project: {
        findUnique: vi.fn(async ({ where }) => (where.id === PROJECT ? project : null)),
      },
      projectRepository: { findUnique: vi.fn(async () => ({ remoteUrl: 'https://github.com/acme/api.git' })) },
      projectEnvironment: {
        findFirst: vi.fn(async ({ where }) => [...envStore.values()].find((e) => e.projectId === where.projectId && e.code === where.code) ?? null),
        findUnique: vi.fn(async ({ where }) => envStore.get(where.id) ?? null),
        create: vi.fn(async ({ data }) => {
          const row = { id: U(++n), ...data };
          envStore.set(row.id, row);
          return row;
        }),
      },
      projectEnvVar: {
        findMany: vi.fn(async () => []),
        findFirst: vi.fn(async ({ where }) => [...varStore.values()].find((v) => v.environmentId === where.environmentId && v.key === where.key) ?? null),
        create: vi.fn(async ({ data }) => {
          const row = { id: U(++n), ...data };
          varStore.set(row.id, row);
          return row;
        }),
        update: vi.fn(async ({ where, data }) => Object.assign(varStore.get(where.id), data)),
        deleteMany: vi.fn(async ({ where }) => {
          for (const [k, v] of varStore) if (v.environmentId === where.environmentId) varStore.delete(k);
        }),
      },
      serverCredential: { findUnique: vi.fn(async () => ({ host: '203.0.113.10' })) },
      domain: {
        findUnique: vi.fn(async ({ where }) => domainStore.get(where.name) ?? null),
        create: vi.fn(async ({ data }) => {
          domainStore.set(data.name, { id: U(++n), ...data });
          return domainStore.get(data.name);
        }),
        update: vi.fn(async () => ({})),
        updateMany: vi.fn(async () => ({ count: 1 })),
      },
      deployment: {
        findUnique: vi.fn(async ({ where }) => (where.id === DEPLOY_ID ? { id: DEPLOY_ID, status: 'Success' } : null)),
      },
      projectPreviewSettings: {
        findUnique: vi.fn(async ({ where }) => settingsStore.get(where.projectId) ?? null),
        create: vi.fn(async ({ data }) => {
          const row = { id: U(++n), ...data };
          settingsStore.set(data.projectId, row);
          return row;
        }),
        update: vi.fn(async ({ where, data }) => {
          const cur = settingsStore.get(where.projectId) ?? [...settingsStore.values()][0];
          Object.assign(cur, data);
          return cur;
        }),
      },
      previewEnvironment: {
        findUnique: vi.fn(async ({ where }) => previewStore.get(where.id) ?? null),
        findFirst: vi.fn(async ({ where }) => filterPreviews(where)[0] ?? null),
        findMany: vi.fn(async ({ where } = {}) => filterPreviews(where)),
        count: vi.fn(async ({ where } = {}) => filterPreviews(where).length),
        create: vi.fn(async ({ data }) => {
          const row = { id: U(++n), createdAt: NOW, updatedAt: NOW, closedAt: null, destroyedAt: null, ...data };
          previewStore.set(row.id, row);
          return row;
        }),
        update: vi.fn(async ({ where, data }) => {
          Object.assign(previewStore.get(where.id), data, { updatedAt: NOW });
          return previewStore.get(where.id);
        }),
      },
    });

    settingsStore.set(PROJECT, {
      id: U(71),
      projectId: PROJECT,
      enabled: true,
      rootDomainId: ROOT,
      sourceEnvCode: null,
      envKeysJson: [],
      portStart: 20000,
      portEnd: 20010,
      ttlDays: 7,
      maxActive: 5,
      basicAuth: false,
      dnsMode: 'per-pr',
      commentEnabled: false,
      githubTokenEnc: null,
    });

    const rootDomains = {
      system: {
        byId: vi.fn(async (id) => (id === ROOT ? { id: ROOT, name: 'example.com', archivedAt: null, provider: 'simulated' } : null)),
        apply: vi.fn(async () => ({ ok: true })),
      },
    };
    const deploymentsService = {
      create: vi.fn(async () => ({
        deployment: { id: DEPLOY_ID, status: 'Queued' },
        operation: { status: 'QUEUED' },
      })),
      run: vi.fn(async () => ({ deployment: { status: 'Success' } })),
    };
    const webserver = {
      validate: vi.fn(async () => ({ ok: true })),
      apply: vi.fn(async () => ({ ok: true })),
      rollback: vi.fn(async () => ({ ok: true })),
    };

    const svc = createPreviewsService({
      ...ctx,
      credentialKey: () => KEY,
      rootDomains,
      deploymentsService,
      background: false,
      adapters: { webserver },
      teardown: vi.fn(async () => ({ ok: true })),
      commenter: { upsert: vi.fn(async () => '1') },
    });
    return { ctx, svc, previewStore, rootDomains, deploymentsService, webserver };
  }

  it('Owner reads settings and lists empty previews', async () => {
    const t = setup();
    const s = await t.svc.getSettings(PROJECT, OWNER);
    expect(s.enabled).toBe(true);
    expect(s.portStart).toBe(20000);
    expect(await t.svc.list(PROJECT, OWNER)).toEqual([]);
  });

  it('creates a preview, allocates a port and hostname, then kicks a deployment', async () => {
    const t = setup();
    const out = await t.svc.create(PROJECT, { prNumber: 7, branch: 'feature/x', commitSha: 'abcdef1234567' }, OWNER);
    expect(out.preview).toMatchObject({
      prNumber: 7,
      hostname: 'pr-7.api.example.com',
    });
    expect(out.preview.port).toBeGreaterThanOrEqual(20000);
    expect(out.expose?.approvalRequired || out.expose?.exposed).toBeTruthy();
    expect(t.deploymentsService.create).toHaveBeenCalled();
    expect(t.deploymentsService.run).toHaveBeenCalled();
  });

  it('expose is approval-gated then applies DNS + vhost', async () => {
    const t = setup();
    // Seed a row without going through create (create already requests exposure approval).
    const id = U(55);
    t.previewStore.set(id, {
      id,
      projectId: PROJECT,
      serverId: SERVER,
      environmentId: U(56),
      prNumber: 3,
      branch: 'main',
      commitSha: 'aaaaaaaaaaaa',
      status: 'awaiting_exposure',
      port: 20003,
      hostname: 'pr-3.api.example.com',
      url: 'https://pr-3.api.example.com',
      rootDomainId: ROOT,
      deploymentId: null,
      basicAuthUser: null,
      basicAuthHash: null,
      dnsStatus: null,
      exposeApprovalId: null,
      lastError: null,
      expiresAt: new Date(NOW.getTime() + 7 * 86400000),
      closedAt: null,
      destroyedAt: null,
      createdAt: NOW,
      updatedAt: NOW,
    });

    const gate = await t.svc.expose(PROJECT, id, { reason: 'publish preview host', rollbackNote: 'destroy preview' }, OWNER);
    expect(gate.approvalRequired).toBe(true);
    await approve(t.ctx, gate.approval.id, APPROVER);
    const done = await t.svc.expose(
      PROJECT,
      id,
      { approvalId: gate.approval.id, reason: 'publish preview host', rollbackNote: 'destroy preview' },
      OWNER,
    );
    expect(done.exposed).toBe(true);
    expect(t.rootDomains.system.apply).toHaveBeenCalled();
    expect(t.webserver.apply).toHaveBeenCalled();
  });

  it('destroy tears down and frees the port', async () => {
    const t = setup();
    const id = U(57);
    t.previewStore.set(id, {
      id,
      projectId: PROJECT,
      serverId: SERVER,
      environmentId: U(58),
      prNumber: 9,
      branch: 'main',
      commitSha: 'bbbbbbbbbbbb',
      status: 'active',
      port: 20009,
      hostname: 'pr-9.api.example.com',
      url: 'https://pr-9.api.example.com',
      rootDomainId: ROOT,
      deploymentId: null,
      basicAuthUser: null,
      basicAuthHash: null,
      dnsStatus: 'applied',
      exposeApprovalId: null,
      lastError: null,
      expiresAt: new Date(NOW.getTime() + 7 * 86400000),
      closedAt: null,
      destroyedAt: null,
      createdAt: NOW,
      updatedAt: NOW,
    });
    const gone = await t.svc.destroy(PROJECT, id, OWNER);
    expect(gone.status).toBe('destroyed');
    expect(gone.port).toBeNull();
  });

  it('cleanupExpired destroys past-TTL previews as SYSTEM', async () => {
    const t = setup();
    const id = U(59);
    t.previewStore.set(id, {
      id,
      projectId: PROJECT,
      serverId: SERVER,
      environmentId: U(60),
      prNumber: 11,
      branch: 'old',
      commitSha: 'cccccccccccc',
      status: 'active',
      port: 20011,
      hostname: 'pr-11.api.example.com',
      url: 'https://pr-11.api.example.com',
      rootDomainId: ROOT,
      deploymentId: null,
      basicAuthUser: null,
      basicAuthHash: null,
      dnsStatus: 'applied',
      exposeApprovalId: null,
      lastError: null,
      expiresAt: new Date(NOW.getTime() - 1000),
      closedAt: null,
      destroyedAt: null,
      createdAt: NOW,
      updatedAt: NOW,
    });
    const out = await t.svc.cleanupExpired(NOW);
    expect(out.destroyed.length).toBeGreaterThanOrEqual(1);
    expect(out.destroyed).toContain(id);
  });

  it('rejects basic auth when Caddy mode is on', async () => {
    const t = setup();
    const svcOn = createPreviewsService({
      prisma: t.ctx.prisma,
      platform: t.ctx.platform,
      auditService: t.ctx.auditService,
      now: () => NOW,
      credentialKey: () => KEY,
      rootDomains: t.rootDomains,
      deploymentsService: t.deploymentsService,
      background: false,
      env: { CADDY_MODE: 'on' },
      adapters: { webserver: t.webserver },
    });
    await expect(svcOn.updateSettings(PROJECT, { basicAuth: true }, OWNER)).rejects.toMatchObject({
      code: 'PREVIEW_AUTH_NEEDS_BCRYPT',
    });
    const svcOff = createPreviewsService({
      prisma: t.ctx.prisma,
      platform: t.ctx.platform,
      auditService: t.ctx.auditService,
      now: () => NOW,
      credentialKey: () => KEY,
      rootDomains: t.rootDomains,
      deploymentsService: t.deploymentsService,
      background: false,
      env: { CADDY_MODE: 'off' },
      adapters: { webserver: t.webserver },
    });
    const s = await svcOff.updateSettings(PROJECT, { basicAuth: true }, OWNER);
    expect(s.basicAuth).toBe(true);
  });
});
