/**
 * Live API smoke test (local only). Run with the API up and demo data seeded:
 *   npm run smoke
 * Calls every GET route in docs/openapi.json (path ids filled from seeded data) as the Owner and
 * fails on any 5xx. Also checks that protected routes reject anonymous and non-owner callers.
 */
import { readFileSync, existsSync } from 'node:fs';

const API = process.env.NT_API || 'http://127.0.0.1:4000/api/v1';
if (!/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(API)) {
  console.error(`Refusing to run against non-local API: ${API}`);
  process.exit(1);
}
const specPath = ['../docs/openapi.json', 'docs/openapi.json'].find((p) => existsSync(new URL(`../${p}`, import.meta.url)));
const spec = JSON.parse(readFileSync(new URL(`../${specPath}`, import.meta.url), 'utf8'));

async function call(token, method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* SSE or CSV */
  }
  return { status: res.status, data: json?.data ?? json, error: json?.error, ctype: res.headers.get('content-type') ?? '' };
}
const list = (r) => (Array.isArray(r.data) ? r.data : r.data?.items ?? []);
async function login(email, password) {
  const r = await call(null, 'POST', '/auth/login', { email, password });
  if (r.status !== 200) throw new Error(`login ${email}: ${r.status}`);
  return r.data.token;
}

const owner = await login(process.env.NT_OWNER_EMAIL || 'owner@localhost.local', process.env.NT_OWNER_PASSWORD || 'change-me-now-please');
let other = null;
try {
  other = await login('demo-approver@localhost.local', process.env.NT_DEMO_APPROVER_PASSWORD || 'demo-approver-pass-123');
} catch {
  /* demo data not seeded */
}

// ---- ids for path parameters ----------------------------------------------------------------
const first = async (path) => list(await call(owner, 'GET', path))[0];
const allProjects = list(await call(owner, 'GET', '/projects'));
const project = allProjects.find((p) => p.slug === 'demo-shop') ?? allProjects[0] ?? {};
const ids = {
  projectId: project.id,
  serverId: (await first('/servers'))?.id,
  domainId: (await first('/domains'))?.id,
  userId: (await call(owner, 'GET', '/auth/me')).data?.id ?? (await call(owner, 'GET', '/auth/me')).data?.user?.id,
  teamId: (await first('/teams'))?.id,
  deploymentId: (await first(`/deployments?projectId=${project.id}`))?.id,
  incidentId: (await first('/incidents'))?.id,
  certificateId: (await first('/certificates'))?.id,
  databaseId: (await first(`/databases?projectId=${project.id}`))?.id,
  policyId: (await first(`/backups/policies?projectId=${project.id}`))?.id,
  reviewId: (await first('/access-reviews'))?.id,
  operationId: (await first('/operations'))?.id,
};
const pickId = (path, param) => {
  if (ids[param]) return ids[param];
  const seg = path.split('/')[1];
  const map = { projects: 'projectId', servers: 'serverId', domains: 'domainId', users: 'userId', teams: 'teamId', deployments: 'deploymentId', incidents: 'incidentId', certificates: 'certificateId', databases: 'databaseId', 'access-reviews': 'reviewId', operations: 'operationId', members: 'userId', activity: 'userId' };
  if (seg === 'backups' && path.includes('policies')) return ids.policyId;
  return ids[map[seg]] ?? null;
};
// Required query parameters some list routes need.
const QUERY = { type: () => 'project-summary', projectId: () => ids.projectId, serverId: () => ids.serverId, userId: () => ids.userId, from: () => new Date(Date.now() - 7 * 864e5).toISOString(), to: () => new Date().toISOString() };

// ---- 1. every GET as Owner -------------------------------------------------------------------
const rows = [];
for (const [rawPath, item] of Object.entries(spec.paths)) {
  const op = item.get;
  if (!op) continue;
  if (/stream/.test(rawPath)) {
    rows.push({ path: rawPath, status: 'SKIP', note: 'SSE stream' });
    continue;
  }
  let path = rawPath;
  let missing = false;
  for (const m of rawPath.matchAll(/\{(\w+)\}/g)) {
    const v = pickId(rawPath, m[1]);
    if (!v) missing = true;
    path = path.replace(m[0], v ?? '00000000-0000-4000-8000-000000000000');
  }
  const qs = new URLSearchParams();
  for (const p of op.parameters ?? []) if (p.in === 'query' && (p.required || (p.name === 'projectId' && rawPath === '/reports/preview')) && QUERY[p.name]) qs.set(p.name, QUERY[p.name]());
  const url = path + (qs.size ? `?${qs}` : '');
  const r = await call(owner, 'GET', url);
  rows.push({ path: url, status: r.status, note: r.error?.code ?? '', expected404: missing && r.status === 404 });
}

// ---- 2. auth boundaries ---------------------------------------------------------------------
const checks = [];
const expect = (name, ok, detail) => checks.push({ name, ok, detail });
for (const p of ['/servers', '/projects', '/audit/events', '/users']) {
  const r = await call(null, 'GET', p);
  expect(`anonymous GET ${p} -> 401`, r.status === 401, r.status);
}
const bad = await call('not-a-real-token', 'GET', '/projects');
expect('invalid token -> 401', bad.status === 401, bad.status);
const badLogin = await call(null, 'POST', '/auth/login', { email: 'owner@localhost.local', password: 'wrong-password' });
expect('wrong password -> 401', badLogin.status === 401, badLogin.status);
if (other) {
  const s = await call(other, 'POST', '/servers', { alias: 'demo-should-fail' });
  expect('non-owner POST /servers -> 403', s.status === 403, s.status);
  const projects = list(await call(other, 'GET', '/projects'));
  expect('non-owner sees no projects without grants', projects.length === 0, `${projects.length} visible`);
  if (ids.projectId) {
    const pd = await call(other, 'GET', `/projects/${ids.projectId}`);
    expect('non-owner GET out-of-scope project -> 403/404', [403, 404].includes(pd.status), pd.status);
  }
  const au = await call(other, 'GET', '/audit/events');
  expect('non-owner audit read -> 403', au.status === 403, au.status);
}
if (ids.domainId && project.environments) {
  const prod = project.environments.find((e) => e.code === 'production');
  const v = await call(owner, 'POST', `/domains/${ids.domainId}/vhost/apply`, { upstreamPort: 3001, webserver: 'nginx', environmentId: prod.id, reason: 'smoke test change', rollbackNote: 'restore previous vhost' });
  expect('high-risk vhost apply returns 202 approval required', v.status === 202 && v.data?.approvalRequired, v.status);
  if (v.data?.approvalId) {
    const self = await call(owner, 'POST', `/platform/approvals/${v.data.approvalId}/decision`, { decision: 'approve' });
    expect('requester cannot approve own request -> 403', self.status === 403, self.status);
    if (other) await call(other, 'POST', `/platform/approvals/${v.data.approvalId}/decision`, { decision: 'reject', note: 'smoke cleanup' });
  }
}

// ---- report ---------------------------------------------------------------------------------
const real = rows.filter((r) => !r.expected404);
const by = (s) => real.filter((r) => (typeof r.status === 'number' ? (s === '5xx' ? r.status >= 500 : s === '2xx' ? r.status < 300 : r.status >= 400 && r.status < 500) : s === 'skip'));
console.log(`GET routes: ${rows.length}  (404 with no seeded id: ${rows.length - real.length})  2xx ${by('2xx').length}  4xx ${by('4xx').length}  5xx ${by('5xx').length}  skipped ${by('skip').length}`);
for (const r of [...by('5xx'), ...by('4xx')]) console.log(`  ${r.status} ${r.path} ${r.note}`);
console.log(`\nBoundary checks: ${checks.filter((c) => c.ok).length}/${checks.length} passed`);
for (const c of checks) console.log(`  ${c.ok ? 'PASS' : 'FAIL'} ${c.name} (got ${c.detail})`);
process.exitCode = by('5xx').length || checks.some((c) => !c.ok) ? 1 : 0;
