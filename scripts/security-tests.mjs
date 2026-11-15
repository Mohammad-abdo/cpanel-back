/**
 * Live security tests (TASK-030, local only): IDOR, privilege escalation, session handling, mass
 * assignment, CSRF/CORS, security headers, error leakage, rate limiting and terminal tickets.
 * Needs the API running and demo data seeded. Creates one throwaway user (sec-test-*) per run.
 *   npm run test:security
 */
const API = process.env.NT_API || 'http://127.0.0.1:4000/api/v1';
if (!/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(API)) {
  console.error(`Refusing to run against non-local API: ${API}`);
  process.exit(1);
}
const OWNER_EMAIL = process.env.NT_OWNER_EMAIL || 'owner@localhost.local';
const OWNER_PASSWORD = process.env.NT_OWNER_PASSWORD || 'change-me-now-please';

async function call(token, method, path, body, headers = {}) {
  const res = await fetch(API + path, {
    method,
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* not JSON */
  }
  return { s: res.status, d: json?.data, e: json?.error, text, headers: res.headers };
}
const list = (r) => (Array.isArray(r.d) ? r.d : r.d?.items ?? []);
const results = [];
const check = (area, name, ok, got) => {
  results.push({ area, name, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'} [${area}] ${name}${ok ? '' : `  (got ${JSON.stringify(got).slice(0, 200)})`}`);
};
const denied = (r) => r.s === 403 || r.s === 404;

const owner = (await call(null, 'POST', '/auth/login', { email: OWNER_EMAIL, password: OWNER_PASSWORD })).d.token;
const email = `sec-test-${Date.now().toString(36)}@localhost.local`;
const password = 'sec-test-password-123';
const created = await call(owner, 'POST', '/users', { email, displayName: 'sec-test', password });
const userId = created.d?.id;
check('setup', 'throwaway user created', created.s === 201 && userId, created);
const login = () => call(null, 'POST', '/auth/login', { email, password });
const s1 = await login();
const user = s1.d.token;

// ---- data the user must NOT reach ----------------------------------------------------------
const projects = list(await call(owner, 'GET', '/projects'));
const project = projects.find((p) => p.slug === 'demo-shop') ?? projects[0];
const fullProject = (await call(owner, 'GET', `/projects/${project.id}`)).d;
const env = fullProject.environments[0];
const servers = list(await call(owner, 'GET', '/servers'));
const server = servers.find((s) => s.credential) ?? servers[0];
const deployment = list(await call(owner, 'GET', `/deployments?projectId=${project.id}`))[0];
const incident = list(await call(owner, 'GET', '/incidents'))[0];
const domain = list(await call(owner, 'GET', '/domains'))[0];

// ---- IDOR ------------------------------------------------------------------------------------
check('idor', 'project list is empty for a user without grants', list(await call(user, 'GET', '/projects')).length === 0, null);
check('idor', 'server list is empty for a user without grants', list(await call(user, 'GET', '/servers')).length === 0, null);
for (const [name, path] of [
  ['project by id', `/projects/${project.id}`],
  ['project overview', `/projects/${project.id}/overview`],
  ['server by id', `/servers/${server.id}`],
  ['server metrics', `/servers/${server.id}/metrics`],
  ['server files', `/servers/${server.id}/files`],
  ['server SSH info', `/servers/${server.id}/ssh/info`],
  ['server SSH login', `/servers/${server.id}/ssh`],
  ['environment variables', `/projects/${project.id}/environments/${env.id}/vars`],
  ['environment export', `/projects/${project.id}/environments/${env.id}/vars/export`],
  ...(deployment ? [['deployment by id', `/deployments/${deployment.id}`]] : []),
  ...(incident ? [['incident by id', `/incidents/${incident.id}`]] : []),
  ...(domain ? [['domain by id', `/domains/${domain.id}`]] : []),
  ['audit log', '/audit/events'],
  ['platform approvals', '/platform/approvals'],
]) {
  const r = await call(user, 'GET', path);
  check('idor', `${name} denied`, denied(r), { status: r.s, body: r.text.slice(0, 80) });
}
for (const [name, path] of [
  ['backup policies of another project', `/backups/policies?projectId=${project.id}`],
  ['databases of another project', `/databases?projectId=${project.id}`],
  ['logs of another project', `/logs/search?projectId=${project.id}`],
]) {
  const r = await call(user, 'GET', path);
  check('idor', `${name} denied or empty`, denied(r) || r.s === 400 || (r.s === 200 && list(r).length === 0), { status: r.s, n: list(r).length });
}

// ---- privilege escalation ----------------------------------------------------------------------
const selfGrant = await call(user, 'POST', '/rbac/grants', { userId, permissionKey: 'project.configure', resourceType: 'project', resourceId: project.id, environmentId: null });
check('escalation', 'cannot grant itself a permission', denied(selfGrant) || selfGrant.s === 401, selfGrant);
const makeOwner = await call(user, 'PATCH', `/users/${userId}`, { isOwner: true });
check('escalation', 'cannot make itself Owner', denied(makeOwner), makeOwner);
const newUser = await call(user, 'POST', '/users', { email: `x-${email}`, displayName: 'x', password: 'xxxxxxxxxxxx' });
check('escalation', 'cannot create users', denied(newUser), newUser);
const newServer = await call(user, 'POST', '/servers', { alias: 'sec-test-srv' });
check('escalation', 'cannot register servers', denied(newServer), newServer);
const sshAdd = await call(user, 'POST', '/servers/ssh', { alias: 'sec-test-ssh', host: '127.0.0.1', port: 2222, username: 'tester', password: 'secret-pass' });
check('escalation', 'cannot add a server by SSH', denied(sshAdd), sshAdd);
const setVar = await call(user, 'PUT', `/projects/${project.id}/environments/${env.id}/vars`, { vars: [{ key: 'X', value: '1' }] });
check('escalation', 'cannot write environment variables', denied(setVar), setVar);
const svc = await call(user, 'POST', `/servers/${server.id}/ssh/service`, { name: 'nginx', action: 'stop' });
check('escalation', 'cannot stop services', denied(svc), svc);
const review = await call(user, 'POST', '/access-reviews', { periodStart: new Date(Date.now() - 864e5).toISOString(), periodEnd: new Date().toISOString() });
check('escalation', 'cannot start access reviews', denied(review), review);
const anyApproval = list(await call(owner, 'GET', '/platform/approvals?status=pending'))[0];
if (anyApproval) {
  const dec = await call(user, 'POST', `/platform/approvals/${anyApproval.id}/decision`, { decision: 'approve' });
  check('escalation', 'cannot approve requests', denied(dec), dec);
}

// ---- mass assignment ---------------------------------------------------------------------------
const extra = await call(owner, 'POST', '/projects', { serverId: server.id, name: 'x', slug: `sec-${Date.now().toString(36)}`, type: 'node', environments: [{ code: 'production', displayName: 'P' }], ownerFlag: true, status: 'active' });
check('mass-assignment', 'unknown fields are rejected (strict validation)', extra.s === 400, extra);
const extraUser = await call(owner, 'PATCH', `/users/${userId}`, { passwordHash: 'x' });
check('mass-assignment', 'passwordHash cannot be set through the API', extraUser.s === 400, extraUser);

// ---- CSRF / CORS / headers / errors --------------------------------------------------------------
const loginRes = await call(null, 'POST', '/auth/login', { email: OWNER_EMAIL, password: OWNER_PASSWORD });
check('csrf', 'login sets no cookies (bearer tokens only, so no CSRF surface)', !loginRes.headers.get('set-cookie'), loginRes.headers.get('set-cookie'));
const pre = await fetch(`${API}/projects`, { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' } });
check('cors', 'no CORS access for a foreign origin', !pre.headers.get('access-control-allow-origin'), pre.headers.get('access-control-allow-origin'));
const h = (await call(user, 'GET', '/auth/me')).headers;
check('headers', 'nosniff, frame and CSP headers present', h.get('x-content-type-options') === 'nosniff' && Boolean(h.get('x-frame-options') || h.get('content-security-policy')), Object.fromEntries(h));
check('headers', 'no x-powered-by', !h.get('x-powered-by'), h.get('x-powered-by'));
const bad = await call(owner, 'POST', '/projects', '{"broken json', {});
check('errors', 'malformed JSON returns 400 without a stack trace', bad.s === 400 && !/at \w+ \(|node_modules|\.js:\d+/.test(bad.text), bad.text.slice(0, 120));
const unknown = await call(owner, 'GET', '/does-not-exist');
check('errors', 'unknown route returns 404 JSON', unknown.s === 404 && Boolean(unknown.e?.code), unknown);

// ---- sessions ------------------------------------------------------------------------------------
const tampered = user.slice(0, -2) + (user.endsWith('AA') ? 'BB' : 'AA');
check('session', 'tampered token rejected', (await call(tampered, 'GET', '/auth/me')).s === 401, null);
const s2 = await login();
const sessions = list(await call(s2.d.token, 'GET', '/auth/sessions'));
const other = sessions.find((x) => x.id === s1.d.sessionId) ?? sessions.find((x) => !x.current);
if (other) {
  const rv = await call(s2.d.token, 'DELETE', `/auth/sessions/${other.id}`);
  check('session', 'revoking a session invalidates its token', rv.s < 300 && (await call(user, 'GET', '/auth/me')).s === 401, rv);
}
await call(s2.d.token, 'POST', '/auth/logout', {});
check('session', 'logout invalidates the token', (await call(s2.d.token, 'GET', '/auth/me')).s === 401, null);

// ---- terminal tickets -------------------------------------------------------------------------
const wsBase = API.replace(/^http/, 'ws') + '/servers/terminal';
const tryWs = (url) =>
  new Promise((resolve) => {
    import('ws').then(({ default: WebSocket }) => {
      const ws = new WebSocket(url);
      ws.on('unexpected-response', (_q, res) => resolve(res.statusCode));
      ws.on('open', () => (ws.close(), resolve('opened')));
      ws.on('error', () => resolve('error'));
    });
  });
check('terminal', 'WebSocket without a ticket refused', (await tryWs(wsBase)) === 401, null);
check('terminal', 'WebSocket with a forged ticket refused', (await tryWs(`${wsBase}?ticket=forged-ticket-value`)) === 401, null);

// ---- rate limiting (throwaway email so real accounts are not locked) -----------------------------
const victim = `nobody-${Date.now().toString(36)}@localhost.local`;
let last = null;
for (let i = 0; i < 11; i++) last = await call(null, 'POST', '/auth/login', { email: victim, password: 'wrong-password' });
check('rate-limit', 'repeated failed logins are rate limited (429)', last.s === 429, last);

// ---- cleanup --------------------------------------------------------------------------------
await call(owner, 'PATCH', `/users/${userId}`, { status: 'disabled' });

const failed = results.filter((r) => !r.ok);
const areas = [...new Set(results.map((r) => r.area))].map((a) => `${a} ${results.filter((r) => r.area === a && r.ok).length}/${results.filter((r) => r.area === a).length}`);
console.log(`\n${results.length - failed.length}/${results.length} passed  (${areas.join(', ')})`);
process.exitCode = failed.length ? 1 : 0;
