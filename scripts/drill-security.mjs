/**
 * Live security drill (phase 08, local only): security sync, full incident lifecycle with evidence,
 * firewall change with approval, and an access review from start to completion.
 * Needs the API running and demo data seeded (npm run seed:demo). Creates drill rows in the local DB.
 *   npm run drill:security
 */
const API = process.env.NT_API || 'http://127.0.0.1:4000/api/v1';
if (!/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(API)) {
  console.error(`Refusing to run against non-local API: ${API}`);
  process.exit(1);
}
const call = async (t, m, p, b) => {
  const r = await fetch(API + p, { method: m, headers: { 'content-type': 'application/json', ...(t ? { authorization: 'Bearer ' + t } : {}) }, body: b ? JSON.stringify(b) : undefined });
  const j = await r.json().catch(() => null);
  return { s: r.status, d: j?.data, e: j?.error };
};
const login = async (e, p) => (await call(null, 'POST', '/auth/login', { email: e, password: p })).d.token;
const owner = await login('owner@localhost.local', 'change-me-now-please');
const appr = await login('demo-approver@localhost.local', 'demo-approver-pass-123');
const me = (await call(appr, 'GET', '/auth/me')).d;
const approverId = me?.id ?? me?.user?.id;
const results = [];
const check = (name, ok, got) => {
  results.push(ok);
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ok ? '' : `  (got ${JSON.stringify(got).slice(0, 160)})`}`);
};

// ---- TASK-026 security sync ----
const sync = await call(owner, 'POST', '/security/sync', { sinceMinutes: 60 });
check('security sync returns status + coverage notice', sync.s === 200 && sync.d?.status && /guarantee|not/i.test(sync.d?.notice ?? ''), sync);
const conn = await call(owner, 'GET', '/security/connection');
check('security connection reports simulated source', conn.s === 200 && conn.d?.simulated === true, conn.d);

// ---- TASK-027 incident lifecycle ----
const inc = (await call(owner, 'POST', '/incidents', { title: `demo-live-drill-${Date.now()}`, severity: 'medium' })).d;
check('incident created as detected', inc?.status === 'detected', inc);
const bad = await call(owner, 'POST', `/incidents/${inc.id}/transition`, { to: 'resolved', note: 'skip ahead' });
check('invalid transition detected -> resolved rejected (409)', bad.s === 409, bad);
const early = await call(owner, 'POST', `/incidents/${inc.id}/assign`, { userId: approverId });
check('assign before triage rejected (409)', early.s === 409, early);
await call(owner, 'POST', `/incidents/${inc.id}/transition`, { to: 'triaged', note: 'confirmed' });
const asg = await call(owner, 'POST', `/incidents/${inc.id}/assign`, { userId: approverId });
check('assign after triage -> assigned', asg.s === 200 && asg.d?.status === 'assigned', asg);
const notes = (await call(appr, 'GET', '/notifications?limit=20')).d;
const notifRows = Array.isArray(notes) ? notes : notes?.items ?? [];
check('assignee received an incident.assigned notification', notifRows.some((n) => n.kind === 'incident.assigned' && n.linkJson?.resourceId === inc.id), notifRows.slice(0, 2));
const ev = await call(owner, 'POST', `/incidents/${inc.id}/evidence`, { type: 'note', summary: 'token=abc123 observed in logs' });
check('evidence added', ev.s === 200 || ev.s === 201, ev);
const esc = await call(owner, 'POST', `/incidents/${inc.id}/escalate`, { severity: 'high', reason: 'more hosts affected' });
check('escalate medium -> high', esc.s === 200 && esc.d?.severity === 'high', esc);
const down = await call(owner, 'POST', `/incidents/${inc.id}/escalate`, { severity: 'medium', reason: 'lower' });
check('severity cannot be lowered (409)', down.s === 409 || down.s === 400, down);
for (const to of ['investigating', 'contained', 'resolved', 'closed']) {
  const r = await call(owner, 'POST', `/incidents/${inc.id}/transition`, { to, note: `moved to ${to} in live drill` });
  check(`transition -> ${to}`, r.s === 200 && r.d?.status === to, r);
}
const ver = await call(owner, 'GET', `/incidents/${inc.id}/evidence/verify`);
check('evidence hash chain verifies intact', ver.s === 200 && (ver.d?.ok ?? ver.d?.valid ?? ver.d?.intact) === true, ver.d);
const closedEv = await call(owner, 'POST', `/incidents/${inc.id}/evidence`, { type: 'note', summary: 'late' });
check('closed incident refuses evidence (409)', closedEv.s === 409, closedEv);
const tl = await call(owner, 'GET', `/incidents/${inc.id}/timeline`);
check('timeline has no raw secret', tl.s === 200 && !JSON.stringify(tl.d).includes('abc123'), tl.s);

// ---- TASK-028 firewall ----
const srv = (await call(owner, 'GET', '/servers')).d.find((x) => x.alias === 'demo-web-01');
const pv = await call(owner, 'POST', `/firewall/servers/${srv.id}/preview`, { changes: [{ op: 'allow', port: 8080, proto: 'tcp', source: '10.0.0.0/8', comment: 'live drill' }] });
check('firewall preview returns impact', pv.s === 200, pv);
const ssh = await call(owner, 'POST', `/firewall/servers/${srv.id}/preview`, { changes: [{ op: 'delete', port: 22, proto: 'tcp', source: 'any' }] });
check('removing SSH flagged as lockout risk', ssh.s === 422 || /lockout|ssh/i.test(JSON.stringify(ssh.d ?? ssh.e)), ssh);
const ws = new Date(Date.now() - 60000).toISOString();
const we = new Date(Date.now() + 30 * 60000).toISOString();
const body = { changes: [{ op: 'allow', port: 8080, proto: 'tcp', source: '10.0.0.0/8', comment: 'live drill' }], windowStart: ws, windowEnd: we, reason: 'live drill firewall change', rollbackNote: 'remove rule 8080' };
const a1 = await call(owner, 'POST', `/firewall/servers/${srv.id}/apply`, body);
check('firewall apply needs approval (202)', a1.s === 202 && a1.d?.approvalRequired, a1);
const selfAp = await call(owner, 'POST', `/platform/approvals/${a1.d.approvalId}/decision`, { decision: 'approve' });
check('self approval blocked (403)', selfAp.s === 403, selfAp);
await call(appr, 'POST', `/platform/approvals/${a1.d.approvalId}/decision`, { decision: 'approve', note: 'drill' });
const other = await call(owner, 'POST', `/firewall/servers/${srv.id}/apply`, { ...body, changes: [{ op: 'allow', port: 9090, proto: 'tcp', source: '10.0.0.0/8' }], approvalId: a1.d.approvalId });
check('approval bound to the exact change set (409 for a different change)', other.s === 409, other);
const a2 = await call(owner, 'POST', `/firewall/servers/${srv.id}/apply`, { ...body, approvalId: a1.d.approvalId });
check('approved firewall change applied', a2.s === 200 || a2.s === 201, a2);
const reuse = await call(owner, 'POST', `/firewall/servers/${srv.id}/apply`, { ...body, approvalId: a1.d.approvalId });
check('approval is single use (409)', reuse.s === 409, reuse);

// ---- TASK-028 access review end to end ----
const grant = await call(owner, 'POST', '/rbac/grants', { userId: approverId, permissionKey: 'server.metrics.read', resourceType: 'server', resourceId: srv.id, environmentId: null });
check('test grant created', grant.s === 201 || grant.s === 200, grant);
const rv = await call(owner, 'POST', '/access-reviews', { periodStart: new Date(Date.now() - 864e5).toISOString(), periodEnd: new Date().toISOString(), subjectUserId: approverId });
check('access review started', rv.s === 201 || rv.s === 200, rv);
const items = rv.d.findingsJson.items;
const inc1 = await call(owner, 'POST', `/access-reviews/${rv.d.id}/complete`);
check('complete refused while undecided (409)', inc1.s === 409, inc1);
const target = items.find((i) => i.grantId === grant.d.id);
const keepOthers = items.filter((i) => i.grantId !== grant.d.id && !i.ownGrant).map((i) => ({ grantId: i.grantId, decision: 'keep' }));
const dec = await call(owner, 'POST', `/access-reviews/${rv.d.id}/decisions`, { decisions: [{ grantId: target.grantId, decision: 'revoke', note: 'drill' }, ...keepOthers] });
check('decisions saved (revoke test grant)', dec.s === 200, dec);
const grantsAfter = (await call(owner, 'GET', `/rbac/grants?userId=${approverId}`)).d;
const rows = Array.isArray(grantsAfter) ? grantsAfter : grantsAfter?.items ?? [];
check('revoked grant no longer active', !rows.some((g) => g.id === grant.d.id && !g.revokedAt), rows.length);
const done = await call(owner, 'POST', `/access-reviews/${rv.d.id}/complete`);
check('review completed', done.s === 200 && done.d?.status === 'completed', done);

console.log(`\n${results.filter(Boolean).length}/${results.length} passed`);
process.exitCode = results.every(Boolean) ? 0 : 1;
