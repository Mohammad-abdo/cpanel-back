/**
 * Demo data seed (development only). Fills the local database through the real API.
 *
 *   npm run seed:demo            (API must be running: npm run dev)
 *
 * - Refuses to run unless NT_API points at localhost/127.0.0.1 and NODE_ENV is not production.
 * - Every created name/slug/alias is prefixed `demo-`. Idempotent: existing records are skipped.
 * - High-risk actions go through the real approval flow with a second user (demo-approver).
 * - There is no delete path: remove demo rows directly in the database.
 */
const API = process.env.NT_API || 'http://127.0.0.1:4000/api/v1';
const OWNER_EMAIL = process.env.NT_OWNER_EMAIL || process.env.SEED_OWNER_EMAIL || 'owner@localhost.local';
const OWNER_PASSWORD = process.env.NT_OWNER_PASSWORD || process.env.SEED_OWNER_PASSWORD || 'change-me-now-please';
const APPROVER_EMAIL = 'demo-approver@localhost.local';
const APPROVER_PASSWORD = process.env.NT_DEMO_APPROVER_PASSWORD || 'demo-approver-pass-123';

if (process.env.NODE_ENV === 'production') fail('Refusing to run with NODE_ENV=production');
if (!/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(API)) fail(`Refusing to run against non-local API: ${API}`);

const results = [];
const record = (step, status, detail = '') => {
  results.push({ step, status, detail: String(detail).slice(0, 90) });
  console.log(`${status.padEnd(8)} ${step}${detail ? `  (${String(detail).slice(0, 90)})` : ''}`);
};

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

const uuid = () => crypto.randomUUID();
const iso = (msAgo = 0) => new Date(Date.now() - msAgo).toISOString();
const HOUR = 3600_000;

async function call(token, method, path, body, extraHeaders = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: token.startsWith('Agent ') ? token : `Bearer ${token}` } : {}),
      ...extraHeaders,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* empty body */
  }
  return { status: res.status, ok: res.ok, data: json?.data ?? json, error: json?.error };
}

const errText = (r) => `${r.status} ${r.error?.code ?? ''} ${r.error?.message ?? ''}`.trim();
const listOf = (r) => (Array.isArray(r.data) ? r.data : r.data?.items ?? r.data?.rows ?? []);

/** Run a step; never throws, records result. */
async function step(name, fn) {
  try {
    const out = await fn();
    if (out?.skipped) record(name, 'skipped', out.detail);
    else record(name, 'created', out?.detail ?? '');
    return out?.value ?? out;
  } catch (e) {
    record(name, 'failed', e.message);
    return null;
  }
}

async function must(r, what) {
  if (!r.ok) throw new Error(`${what}: ${errText(r)}`);
  return r.data;
}

async function login(email, password) {
  const r = await call(null, 'POST', '/auth/login', { email, password });
  if (!r.ok) throw new Error(`login ${email}: ${errText(r)}`);
  if (r.data?.mfaRequired) throw new Error(`login ${email}: MFA is enrolled; disable it or log in manually`);
  return r.data.token;
}

let owner;
let approver;

/** Perform a privileged call; if it returns approvalRequired, approve with demo-approver and retry. */
async function withApproval(method, path, body, what) {
  const first = await call(owner, method, path, body);
  if (!first.ok) throw new Error(`${what}: ${errText(first)}`);
  if (!first.data?.approvalRequired) return first.data;
  if (!approver) throw new Error(`${what}: approval required but no approver available`);
  const approvalId = first.data.approvalId ?? first.data.approval?.id;
  const d = await call(approver, 'POST', `/platform/approvals/${approvalId}/decision`, { decision: 'approve', note: 'demo seed approval' });
  if (!d.ok) throw new Error(`${what} approve: ${errText(d)}`);
  const second = await call(owner, method, path, { ...body, approvalId });
  if (!second.ok) throw new Error(`${what} (approved): ${errText(second)}`);
  return second.data;
}

const reason = { reason: 'Demo seed data for local development', rollbackNote: 'Delete demo- rows from the local database' };

async function main() {
  console.log(`Seeding demo data via ${API}\n`);
  owner = await login(OWNER_EMAIL, OWNER_PASSWORD);

  // ---- approver user --------------------------------------------------------------------------
  const users = listOf(await call(owner, 'GET', '/users?limit=200'));
  let approverUser = users.find((u) => u.email === APPROVER_EMAIL);
  await step('user demo-approver', async () => {
    if (approverUser) return { skipped: true };
    approverUser = await must(
      await call(owner, 'POST', '/users', { email: APPROVER_EMAIL, displayName: 'demo-approver', password: APPROVER_PASSWORD }),
      'create user',
    );
  });
  await step('grant demo-approver platform.approval.decide', async () => {
    const grants = listOf(await call(owner, 'GET', `/rbac/grants?userId=${approverUser.id}`));
    if (grants.some((g) => (g.permissionCode ?? g.permissionKey) === 'platform.approval.decide' && !g.revokedAt)) return { skipped: true };
    const r = await call(owner, 'POST', '/rbac/grants', {
      userId: approverUser.id,
      permissionKey: 'platform.approval.decide',
      resourceType: 'platform',
      resourceId: 'platform',
      environmentId: null,
    });
    if (r.status === 409) return { skipped: true };
    await must(r, 'grant');
  });
  try {
    approver = await login(APPROVER_EMAIL, APPROVER_PASSWORD);
  } catch (e) {
    record('login demo-approver', 'failed', e.message);
  }

  // ---- teams ----------------------------------------------------------------------------------
  const teams = listOf(await call(owner, 'GET', '/teams'));
  let team = teams.find((t) => t.slug === 'demo-platform');
  await step('team demo-platform', async () => {
    if (team) return { skipped: true };
    team = await must(await call(owner, 'POST', '/teams', { name: 'demo-platform', slug: 'demo-platform' }), 'team');
  });

  // ---- servers + agents + metrics -------------------------------------------------------------
  const existingServers = listOf(await call(owner, 'GET', '/servers'));
  const servers = {};
  for (const [alias, hostname, base] of [
    ['demo-web-01', 'web-01.demo.local', 35],
    ['demo-db-01', 'db-01.demo.local', 55],
  ]) {
    let srv = existingServers.find((s) => s.alias === alias);
    await step(`server ${alias}`, async () => {
      if (srv) return { skipped: true };
      srv = await must(await call(owner, 'POST', '/servers', { alias, hostname }), 'server');
    });
    servers[alias] = srv;
    if (!srv) continue;
    const activeAgent = srv.agent && !srv.agent.revokedAt ? srv.agent : null;
    if (activeAgent && srv.latest) {
      record(`agent ${alias}`, 'skipped', 'enrolled and reporting');
      continue;
    }
    await step(`agent ${alias} + 12 metric reports`, async () => {
      // An agent left without metrics by an interrupted run: revoke it so the server can re-enroll.
      if (activeAgent) await must(await call(owner, 'DELETE', `/agents/${activeAgent.id}`), 'revoke stale agent');
      const en = await must(await call(owner, 'POST', `/servers/${srv.id}/enrollment`, {}), 'enrollment');
      const token = en.token ?? en.enrollmentToken;
      const ag = await must(await call(null, 'POST', '/agents/enroll', { token, hostname, capabilities: { demo: true } }), 'agent enroll');
      const key = `Agent ${ag.agentId}.${ag.agentKey}`;
      for (let i = 11; i >= 0; i--) {
        const wave = Math.sin(i / 2) * 12;
        await must(
          await call(key, 'POST', '/agents/report', {
            capturedAt: iso(i * HOUR),
            cpuPercent: Math.max(2, Math.min(98, base + wave)),
            memPercent: Math.max(5, Math.min(95, base + 10 - wave / 2)),
            swapPercent: 3,
            diskPercent: base + 8,
            load1: Number((base / 40).toFixed(2)),
            uptimeSec: 864000 + i,
            services: [
              { name: 'nginx', manager: 'systemd', state: 'running' },
              { name: alias.includes('db') ? 'mysql' : 'pm2-demo', manager: 'systemd', state: 'running' },
            ],
            ports: [
              { port: 22, proto: 'tcp', processHint: 'sshd' },
              { port: 443, proto: 'tcp', processHint: 'nginx' },
            ],
          }),
          'report',
        );
      }
    });
  }
  const web = servers['demo-web-01'];
  const dbSrv = servers['demo-db-01'];
  if (!web) return;

  // ---- projects -------------------------------------------------------------------------------
  const existingProjects = listOf(await call(owner, 'GET', '/projects'));
  const projects = {};
  for (const p of [
    { slug: 'demo-shop', name: 'demo-shop', type: 'node', runtime: { runtime: 'node20', processManager: 'pm2' }, repo: 'git@github.com:demo/shop.git' },
    { slug: 'demo-blog', name: 'demo-blog', type: 'laravel', runtime: { runtime: 'php8.3', processManager: 'php-fpm' }, repo: 'git@github.com:demo/blog.git' },
  ]) {
    let proj = existingProjects.find((x) => x.slug === p.slug);
    await step(`project ${p.slug}`, async () => {
      if (proj) return { skipped: true };
      proj = await must(
        await call(owner, 'POST', '/projects', {
          serverId: web.id,
          name: p.name,
          slug: p.slug,
          type: p.type,
          environments: [
            { code: 'staging', displayName: 'Staging' },
            { code: 'production', displayName: 'Production' },
          ],
          repository: { remoteUrl: p.repo, defaultBranch: 'main' },
          runtime: p.runtime,
        }),
        'project',
      );
    });
    if (proj && !proj.environments) {
      const full = await call(owner, 'GET', `/projects/${proj.id}`);
      if (full.ok) proj = full.data;
    }
    projects[p.slug] = proj;
  }
  const shop = projects['demo-shop'];
  if (!shop) return;
  const envOf = (proj, code) => (proj?.environments ?? []).find((e) => e.code === code);
  const stg = envOf(shop, 'staging');
  const prod = envOf(shop, 'production');
  if (!stg || !prod) {
    record('project environments', 'failed', 'demo-shop has no staging/production environments in the response');
    return;
  }

  // ---- deployments ----------------------------------------------------------------------------
  const deps = listOf(await call(owner, 'GET', `/deployments?projectId=${shop.id}`));
  await step('deployments demo-shop staging x3', async () => {
    if (deps.length >= 3) return { skipped: true, detail: `${deps.length} present` };
    for (const sha of ['a1b2c3d', 'b2c3d4e', 'c3d4e5f']) {
      const d = await must(
        await call(owner, 'POST', '/deployments', {
          projectId: shop.id,
          environmentId: stg.id,
          idempotencyKey: `demo-deploy-${sha}`,
          commitSha: sha.padEnd(40, '0'),
          branch: 'main',
          rollbackPlan: 'Roll back to previous release',
        }),
        'deployment',
      );
      const id = d.deployment?.id ?? d.id;
      if (id) await call(owner, 'POST', `/deployments/${id}/run`, {});
    }
  });

  // ---- domains, vhost, DNS, SSL ---------------------------------------------------------------
  const domains = listOf(await call(owner, 'GET', '/domains'));
  let domain = domains.find((d) => d.name === 'demo-shop.example.test');
  const domainExisted = Boolean(domain);
  await step('domain demo-shop.example.test', async () => {
    if (domain) return { skipped: true };
    const out = await withApproval('POST', '/domains', { name: 'demo-shop.example.test', projectId: shop.id, environmentId: prod.id, serverId: web.id }, 'domain');
    domain = out.domain ?? out;
  });
  if (domain?.id) {
    await step('vhost apply (nginx -> :3000)', async () => {
      if (domainExisted) return { skipped: true };
      const preview = await must(await call(owner, 'POST', `/domains/${domain.id}/vhost/preview`, { upstreamPort: 3000, webserver: 'nginx', environmentId: prod.id }), 'preview');
      if (preview?.unchanged) return { skipped: true, detail: 'unchanged' };
      await withApproval('POST', `/domains/${domain.id}/vhost/apply`, { upstreamPort: 3000, webserver: 'nginx', environmentId: prod.id, ...reason }, 'vhost apply');
    });
    await step('DNS A record', async () => {
      if (domainExisted) return { skipped: true };
      await withApproval('POST', `/domains/${domain.id}/dns`, { op: 'upsert', type: 'A', name: '@', value: '203.0.113.10', ttl: 300, environmentId: prod.id, ...reason }, 'dns');
    });
    const certs = listOf(await call(owner, 'GET', '/certificates'));
    await step('SSL certificate demo-shop.example.test', async () => {
      if (certs.some((c) => c.domainId === domain.id || c.domain?.id === domain.id)) return { skipped: true };
      await withApproval('POST', `/certificates/domains/${domain.id}/issue`, { environmentId: prod.id, challenge: 'http-01', ...reason }, 'ssl issue');
    });
  }

  // ---- databases ------------------------------------------------------------------------------
  const instances = listOf(await call(owner, 'GET', '/databases/instances'));
  let inst = instances.find((i) => i.name === 'demo-mysql-01');
  await step('database instance demo-mysql-01', async () => {
    if (inst) return { skipped: true };
    const out = await withApproval(
      'POST',
      '/databases/instances',
      { engine: 'mysql', name: 'demo-mysql-01', serverId: dbSrv?.id, host: '10.0.0.12', port: 3306, adminSecretRef: 'DEMO_MYSQL_ADMIN', ...reason },
      'instance',
    );
    inst = out.instance ?? out;
  });
  if (inst?.id) {
    const dbs = listOf(await call(owner, 'GET', `/databases?projectId=${shop.id}`));
    let db = dbs.find((d) => d.dbName === 'demo_shop' || d.name === 'demo_shop');
    await step('database demo_shop', async () => {
      if (db) return { skipped: true };
      const out = await withApproval('POST', '/databases', { projectId: shop.id, environmentId: prod.id, instanceId: inst.id, dbName: 'demo_shop', ...reason }, 'database');
      db = out.database ?? out;
    });
    if (db?.id) {
      await step('database user demo_shop_ro (read)', async () => {
        const r = await call(owner, 'POST', `/databases/${db.id}/users`, { environmentId: prod.id, username: 'demo_shop_ro', level: 'read', ...reason });
        if (r.status === 409) return { skipped: true };
        if (r.ok && r.data?.approvalRequired) {
          await withApproval('POST', `/databases/${db.id}/users`, { environmentId: prod.id, username: 'demo_shop_ro', level: 'read', ...reason }, 'db user');
          return;
        }
        await must(r, 'db user');
      });
    }
  }

  // ---- backups --------------------------------------------------------------------------------
  const policies = listOf(await call(owner, 'GET', `/backups/policies?projectId=${shop.id}`));
  let policy = policies[0];
  const policyExisted = Boolean(policy);
  await step('backup policy demo-shop production (daily)', async () => {
    if (policy) return { skipped: true };
    policy = await must(
      await call(owner, 'POST', '/backups/policies', {
        projectId: shop.id,
        environmentId: prod.id,
        frequency: 'daily',
        retentionDays: 14,
        encryption: 'aes-256-gcm',
        destinationCategory: 'offsite',
        rpoMinutes: 1440,
        rtoMinutes: 120,
      }),
      'policy',
    );
    policy = policy.policy ?? policy;
  });
  if (policy?.id) {
    await step('backup run + verify', async () => {
      if (policyExisted) return { skipped: true };
      const run = await must(await call(owner, 'POST', `/backups/policies/${policy.id}/run`, { environmentId: prod.id, kinds: ['db', 'config'], trigger: 'manual' }), 'run');
      const artifacts = run.artifacts ?? run.run?.artifacts ?? [];
      for (const a of artifacts) await call(owner, 'POST', `/backups/artifacts/${a.id}/verify`, {});
      return { detail: `${artifacts.length} artifacts`, value: artifacts };
    });
    await step('isolated restore drill (approved by demo-approver)', async () => {
      if (policyExisted) return { skipped: true };
      const points = listOf(await call(owner, 'GET', `/restores/points?projectId=${shop.id}`));
      const art = points[0]?.artifacts?.find((a) => a.kind === 'db');
      if (!art) throw new Error('no restore point');
      const req = await must(
        await call(owner, 'POST', '/restores', { artifactId: art.id, mode: 'isolated', targetEnvironmentId: prod.id, reason: 'Demo isolated restore drill', rollbackNote: 'Discard the trial area' }),
        'restore request',
      );
      await must(await call(approver, 'POST', `/platform/approvals/${req.approvalId}/decision`, { decision: 'approve', note: 'demo drill' }), 'restore approve');
      const done = await must(await call(owner, 'POST', `/restores/${req.restoreId}/execute`, { environmentId: prod.id }), 'restore execute');
      return { detail: done.restore?.status };
    });
  }

  // ---- logs + errors + alerts -----------------------------------------------------------------
  await step('log source + 8 entries (2 errors)', async () => {
    const sources = listOf(await call(owner, 'GET', `/logs/sources?projectId=${shop.id}`));
    if (sources.some((s) => s.kind === 'application')) return { skipped: true };
    const src = await must(await call(owner, 'POST', '/logs/sources', { projectId: shop.id, serverId: web.id, environmentId: prod.id, kind: 'application' }), 'source');
    const sourceId = src.id ?? src.source?.id;
    const entries = [
      ['info', 'Server started on port 3000'],
      ['info', 'GET /api/products 200 34ms'],
      ['warn', 'Slow query: SELECT * FROM orders took 1200ms'],
      ['error', 'TypeError: Cannot read properties of undefined (reading "price")'],
      ['info', 'POST /api/cart 201 18ms'],
      ['error', 'TypeError: Cannot read properties of undefined (reading "price")'],
      ['info', 'GET /health 200 2ms'],
      ['info', 'Cache warmed: 120 keys'],
    ].map(([level, message], i) => ({
      timestamp: iso((8 - i) * 5 * 60_000),
      level,
      message,
      ...(level === 'error' ? { stack: 'TypeError: ...\n    at cartTotal (src/cart.js:42:17)' } : {}),
      requestId: `demo-req-${i}`,
    }));
    await must(await call(owner, 'POST', '/logs/ingest/manual', { sourceId, entries }), 'ingest');
  });
  const rules = listOf(await call(owner, 'GET', `/monitoring/rules?projectId=${shop.id}`));
  await step('alert rule (error_count >= 1)', async () => {
    if (rules.length) return { skipped: true };
    const rule = await must(
      await call(owner, 'POST', '/monitoring/rules', { projectId: shop.id, severity: 'warning', threshold: { kind: 'error_count', threshold: 1, windowMinutes: 60 } }),
      'rule',
    );
    await call(owner, 'POST', `/monitoring/rules/${rule.id ?? rule.rule?.id}/evaluate`, {});
  });

  // ---- incidents ------------------------------------------------------------------------------
  const incidents = listOf(await call(owner, 'GET', '/incidents'));
  await step('incident demo-checkout-errors', async () => {
    if (incidents.some((i) => i.title === 'demo-checkout-errors')) return { skipped: true };
    const inc = await must(await call(owner, 'POST', '/incidents', { title: 'demo-checkout-errors', severity: 'high' }), 'incident');
    const id = inc.id ?? inc.incident?.id;
    await call(owner, 'POST', `/incidents/${id}/evidence`, { type: 'log', summary: 'Repeated TypeError in cart total' });
    await call(owner, 'POST', `/incidents/${id}/transition`, { to: 'triaged', note: 'Confirmed in production logs' });
  });

  // ---- reports + access review ----------------------------------------------------------------
  await step('report run project-summary (7 days)', async () => {
    if (domainExisted) return { skipped: true };
    await must(await call(owner, 'POST', '/reports/runs', { type: 'project-summary', projectId: shop.id, from: iso(7 * 24 * HOUR), to: iso(), formats: ['csv'] }), 'report');
  });
  const reviews = listOf(await call(owner, 'GET', '/access-reviews'));
  await step('access review (last 30 days)', async () => {
    if (reviews.length) return { skipped: true };
    await must(await call(owner, 'POST', '/access-reviews', { periodStart: iso(30 * 24 * HOUR), periodEnd: iso() }), 'review');
  });
}

main()
  .catch((e) => record('seed', 'failed', e.message))
  .finally(() => {
    const count = (s) => results.filter((r) => r.status === s).length;
    console.log(`\ncreated ${count('created')}, skipped ${count('skipped')}, failed ${count('failed')}`);
    process.exitCode = count('failed') ? 1 : 0;
  });
