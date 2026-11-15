import { describe, expect, it, vi } from 'vitest';
import { createLogsService } from '../src/modules/logs/logs.service.js';
import { createStreamSession } from '../src/modules/logs/logs.stream.js';
import { redactText, redactDeep } from '../src/modules/logs/logs.redaction.js';
import { createErrorsService } from '../src/modules/monitoring/monitoring.errors.js';
import { createAlertsService } from '../src/modules/monitoring/monitoring.alerts.js';
import { createComparisonService } from '../src/modules/monitoring/monitoring.compare.js';
import { fakePrisma, U } from './phase3-helpers.js';

const OWNER = { id: U(1), isOwner: true };
const DEV = { id: U(2), isOwner: false };
const P1 = U(10);
const P2 = U(11);
const E1 = U(20);
const E2 = U(21);
const S1 = U(30);
const S2 = U(31);
const SERVER1 = U(40);
const SERVER2 = U(41);
let t = new Date('2026-03-01T12:00:00Z');
const clock = () => t;
const grant = (userId, key, resourceId, environmentId) => ({
  id: `${userId}${key}${resourceId}${environmentId}`, userId, permissionCode: key, resourceType: 'project',
  resourceId, environmentId, revokedAt: null, expiresAt: null,
});

function setup({ grants = [] } = {}) {
  const prisma = fakePrisma({
    project: [
      { id: P1, serverId: SERVER1, name: 'One', slug: 'one' },
      { id: P2, serverId: SERVER2, name: 'Two', slug: 'two' },
    ],
    projectEnvironment: [{ id: E1, projectId: P1, code: 'production' }, { id: E2, projectId: P2, code: 'production' }],
    logSource: [
      { id: S1, projectId: P1, serverId: null, kind: 'application', labelJson: { environmentId: E1 } },
      { id: S2, projectId: P2, serverId: null, kind: 'application', labelJson: { environmentId: E2 } },
    ],
    deployment: [{ id: U(50), projectId: P2, environmentId: E2, status: 'Success', createdAt: t, updatedAt: t }],
    resourceGrant: grants,
  });
  const auditService = { record: vi.fn().mockResolvedValue({}) };
  const errors = createErrorsService({ prisma, auditService });
  const logs = createLogsService({
    prisma, auditService, now: clock,
    onError: ({ entry, labels }) => errors.observe({ entry, labels }),
  });
  return { prisma, auditService, logs, errors };
}
const agent1 = { type: 'agent', serverId: SERVER1 };

describe('TASK-011 redaction and ingestion', () => {
  it('redacts tokens, passwords, JWTs, URLs with credentials and private keys', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghij';
    const samples = [
      'Authorization: Bearer abcdef1234567890',
      'password=hunter2 user=bob',
      `token ${jwt}`,
      'connect mysql://root:s3cretpw@db:3306/app',
      '{"api_key":"sk-abcdefghijklmnopqrstuv"}',
      'ghp_abcdefghijklmnopqrstuvwx',
      'cookie: session=abc123; other=1',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----',
    ];
    const out = samples.map(redactText).join('\n');
    for (const leak of ['abcdef1234567890', 'hunter2', jwt, 's3cretpw', 'sk-abcdefghij', 'ghp_abcdef', 'abc123', 'MIIE']) {
      expect(out).not.toContain(leak);
    }
    expect(out).toContain('user=bob');
    expect(redactDeep({ password: 'x', nested: { note: 'password=abc' }, ok: 1 })).toEqual({
      password: '[REDACTED]', nested: { note: 'password=[REDACTED]' }, ok: 1,
    });
  });

  it('injected error reaches the right project; tokens are absent from storage and display', async () => {
    const { logs, prisma } = setup();
    const res = await logs.ingest(
      { sourceId: S1, entries: [{ level: 'error', message: 'Login failed token=abc123secret for req', stack: 'Error\n    at x (a.js:1:2)', fields: { authorization: 'Bearer zzzzzzzz1111' } }] },
      agent1,
    );
    expect(res).toEqual({ accepted: 1, rejected: [] });
    const stored = logs.store.query({ projectId: P1 }, {});
    expect(stored[0].labels).toMatchObject({ projectId: P1, serverId: SERVER1, environmentId: E1, kind: 'application' });
    expect(JSON.stringify(stored)).not.toContain('abc123secret');
    expect(JSON.stringify(stored)).not.toContain('zzzzzzzz1111');
    expect(logs.store.query({ projectId: P2 }, {})).toHaveLength(0);
    expect(prisma.errorGroup.rows).toHaveLength(1);
    expect(prisma.errorGroup.rows[0].projectId).toBe(P1);
    const shown = await logs.search({ projectId: P1, environmentId: E1, limit: 10 }, OWNER);
    expect(JSON.stringify(shown)).not.toContain('abc123secret');
  });

  it('tenancy comes from the source: an agent of another server cannot write into the project', async () => {
    const { logs, auditService } = setup();
    await expect(
      logs.ingest({ sourceId: S1, entries: [{ level: 'info', message: 'x' }] }, { type: 'agent', serverId: SERVER2 }),
    ).rejects.toMatchObject({ code: 'SOURCE_FORBIDDEN' });
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ result: 'denied' }));
    await expect(logs.ingest({ sourceId: S1, entries: [{ level: 'info', message: 'x' }] }, { type: 'user', actor: DEV })).rejects.toMatchObject({ status: 403 });
  });

  it('rejects an entry whose deploymentId belongs to another project', async () => {
    const { logs } = setup();
    const res = await logs.ingest({ sourceId: S1, entries: [{ level: 'info', message: 'ok' }, { level: 'info', message: 'bad', deploymentId: U(50) }] }, agent1);
    expect(res.accepted).toBe(1);
    expect(res.rejected).toEqual([{ index: 1, reason: 'deployment-not-in-project' }]);
  });

  it('only the Owner registers sources; environment must belong to the project', async () => {
    const { logs } = setup();
    await expect(logs.registerSource({ projectId: P1, kind: 'web' }, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(logs.registerSource({ projectId: P1, environmentId: E2, kind: 'web' }, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_MISMATCH' });
    expect((await logs.registerSource({ projectId: P1, environmentId: E1, kind: 'web' }, OWNER)).kind).toBe('web');
  });
});

describe('TASK-012 scoped search, export and live stream', () => {
  async function seeded() {
    const ctx = setup({ grants: [grant(DEV.id, 'project.logs.read', P1, E1)] });
    await ctx.logs.ingest({ sourceId: S1, entries: [
      { level: 'error', message: 'db timeout', requestId: 'req-1', traceId: 'tr-1', timestamp: '2026-03-01T11:00:00.000Z' },
      { level: 'info', message: '=HYPERLINK("evil")', requestId: 'req-2', timestamp: '2026-03-01T11:01:00.000Z' },
    ] }, agent1);
    await ctx.logs.ingest({ sourceId: S2, entries: [{ level: 'error', message: 'other project secret event' }] }, { type: 'agent', serverId: SERVER2 });
    return ctx;
  }

  it('filters by level, request id and text, and never returns other projects', async () => {
    const { logs } = await seeded();
    const base = { projectId: P1, environmentId: E1, limit: 50 };
    expect((await logs.search({ ...base, minLevel: 'error' }, DEV)).items).toHaveLength(1);
    expect((await logs.search({ ...base, requestId: 'req-2' }, DEV)).items[0].message).toContain('HYPERLINK');
    expect((await logs.search({ ...base, traceId: 'tr-1' }, DEV)).items).toHaveLength(1);
    expect((await logs.search({ ...base, q: 'other project' }, DEV)).items).toHaveLength(0);
  });

  it('rejects cross-project, wrong-environment and environment-less search by non-owners', async () => {
    const { logs } = await seeded();
    await expect(logs.search({ projectId: P2, environmentId: E2, limit: 10 }, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(logs.search({ projectId: P1, environmentId: E2, limit: 10 }, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(logs.search({ projectId: P1, limit: 10 }, DEV)).rejects.toMatchObject({ code: 'ENVIRONMENT_REQUIRED' });
  });

  it('export is scoped, audited, neutralizes formulas and rejects cross-project', async () => {
    const { logs, auditService } = await seeded();
    const file = await logs.export({ projectId: P1, environmentId: E1, format: 'csv', limit: 100 }, DEV);
    expect(file.body).toContain("'=HYPERLINK");
    expect(file.body).not.toContain('other project secret');
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'logs.export', actorId: DEV.id }));
    await expect(logs.export({ projectId: P2, environmentId: E2, format: 'json', limit: 10 }, DEV)).rejects.toMatchObject({ status: 403 });
  });

  it('live stream delivers only authorized-project events and replays after reconnect', async () => {
    const { logs } = await seeded();
    const sent = [];
    const session = createStreamSession({ send: (m) => { sent.push(m); return true; } });
    const close = await logs.openStream({ projectId: P1, environmentId: E1, minLevel: 'error' }, DEV, session);
    await logs.ingest({ sourceId: S2, entries: [{ level: 'error', message: 'p2' }] }, { type: 'agent', serverId: SERVER2 });
    await logs.ingest({ sourceId: S1, entries: [{ level: 'error', message: 'live one' }] }, agent1);
    expect(sent.map((m) => m.data.message)).toEqual(['live one']);
    const lastSeq = sent.at(-1).id;
    close();
    await logs.ingest({ sourceId: S1, entries: [{ level: 'error', message: 'missed while offline' }] }, agent1);
    const again = [];
    const s2 = createStreamSession({ send: (m) => { again.push(m); return true; } });
    await logs.openStream({ projectId: P1, environmentId: E1, minLevel: 'error', lastEventId: lastSeq }, DEV, s2);
    expect(again.map((m) => m.data.message)).toEqual(['missed while offline']);
    await expect(logs.openStream({ projectId: P2, environmentId: E2 }, DEV, s2)).rejects.toMatchObject({ status: 403 });
  });

  it('backpressure: a slow consumer gets a bounded queue and a dropped notice', () => {
    const out = [];
    let accept = false;
    const session = createStreamSession({ maxQueue: 3, send: (m) => { out.push(m); return accept; } });
    for (let i = 1; i <= 10; i += 1) session.push({ seq: i });
    expect(out).toHaveLength(1); // first send returned false -> paused
    expect(session.pending).toBe(3);
    accept = true;
    session.resume();
    expect(out.map((m) => m.event)).toEqual(['log', 'dropped', 'log', 'log', 'log']);
    expect(out[1].data.dropped).toBe(6);
  });

  it('bookmarks are per user and scope-checked', async () => {
    const { logs } = await seeded();
    const b = await logs.createBookmark({ name: 'errors', projectId: P1, query: { environmentId: E1, minLevel: 'error' } }, DEV);
    expect((await logs.listBookmarks(DEV))).toHaveLength(1);
    expect((await logs.listBookmarks(OWNER))).toHaveLength(0);
    await expect(logs.deleteBookmark(b.id, OWNER)).rejects.toMatchObject({ status: 404 });
    await expect(logs.createBookmark({ name: 'x', projectId: P2, query: { environmentId: E2 } }, DEV)).rejects.toMatchObject({ status: 403 });
  });
});

describe('TASK-013 alerts, thresholds and deployment comparison', () => {
  async function alertSetup(threshold) {
    t = new Date('2026-03-01T12:00:00Z');
    const ctx = setup();
    const alerts = createAlertsService({ prisma: ctx.prisma, auditService: ctx.auditService, store: ctx.logs.store, now: clock });
    const rule = await alerts.createRule({ projectId: P1, severity: 'critical', threshold: { environmentId: E1, escalateAfterMinutes: 30, ...threshold } }, OWNER);
    return { ...ctx, alerts, rule };
  }
  const err = (ctx, minutesAgo, message = 'db timeout') =>
    ctx.logs.ingest({ sourceId: S1, entries: [{ level: 'error', message, timestamp: new Date(t.getTime() - minutesAgo * 60000).toISOString() }] }, agent1);

  it('repeated errors fire once, deduplicate, auto-resolve, and reopen', async () => {
    const ctx = await alertSetup({ kind: 'error_count', threshold: 3, windowMinutes: 10 });
    await err(ctx, 1); await err(ctx, 2);
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('ok');
    await err(ctx, 3);
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('created');
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('deduplicated');
    expect(ctx.prisma.alert.rows).toHaveLength(1);
    expect(ctx.prisma.alertEvent.rows).toHaveLength(1);
    t = new Date(t.getTime() + 60 * 60000); // errors age out of the window
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('resolved');
    await err(ctx, 1); await err(ctx, 2); await err(ctx, 3);
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('reopened');
    expect(ctx.prisma.alert.rows).toHaveLength(1);
  });

  it('intermittent rule needs errors across several buckets, not one burst', async () => {
    const ctx = await alertSetup({ kind: 'intermittent', windowMinutes: 30, buckets: 6, minBuckets: 3 });
    for (let i = 0; i < 20; i += 1) await err(ctx, 1);
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('ok');
    await err(ctx, 11); await err(ctx, 21);
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('created');
  });

  it('no-data fires only when a source exists and logs stop; unknown without sources', async () => {
    const ctx = await alertSetup({ kind: 'no_data', windowMinutes: 15 });
    await err(ctx, 1);
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('ok');
    t = new Date(t.getTime() + 30 * 60000);
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('created');
    ctx.prisma.logSource.rows.length = 0;
    ctx.prisma.alert.rows.length = 0;
    expect((await ctx.alerts.evaluateRule(ctx.rule)).action).toBe('unknown');
  });

  it('acknowledge, escalate and manual resolve are audited and scope-checked', async () => {
    const ctx = await alertSetup({ kind: 'error_count', threshold: 1, windowMinutes: 10 });
    ctx.prisma.user.rows.push({ id: OWNER.id, ownerFlag: true });
    await err(ctx, 1);
    const { alert } = await ctx.alerts.evaluateRule(ctx.rule);
    expect((await ctx.alerts.escalateDue(new Date(t.getTime() + 10 * 60000))).escalated).toEqual([]);
    expect((await ctx.alerts.escalateDue(new Date(t.getTime() + 31 * 60000))).escalated).toEqual([alert.id]);
    expect(ctx.prisma.notification.rows[0].kind).toBe('alert.escalated');
    await expect(ctx.alerts.acknowledge(alert.id, {}, DEV)).rejects.toMatchObject({ status: 403 });
    await ctx.alerts.acknowledge(alert.id, { note: 'looking' }, OWNER);
    expect(ctx.prisma.alert.rows[0].status).toBe('acknowledged');
    await expect(ctx.alerts.acknowledge(alert.id, {}, OWNER)).rejects.toMatchObject({ code: 'ALERT_NOT_ACKNOWLEDGEABLE' });
    await ctx.alerts.resolve(alert.id, {}, OWNER);
    expect(ctx.prisma.alert.rows[0].status).toBe('resolved');
    expect(ctx.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'alert.acknowledged', actorId: OWNER.id }));
    expect(ctx.prisma.alertEvent.rows.map((e) => e.toStatus)).toEqual(['firing', 'escalated', 'acknowledged', 'resolved']);
  });

  it('rules are Owner-only and environment must match the project', async () => {
    const ctx = await alertSetup({ kind: 'no_data', windowMinutes: 5 });
    await expect(ctx.alerts.createRule({ projectId: P1, severity: 'info', threshold: { kind: 'no_data', windowMinutes: 5, escalateAfterMinutes: 30 } }, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(ctx.alerts.createRule({ projectId: P1, severity: 'info', threshold: { kind: 'no_data', windowMinutes: 5, escalateAfterMinutes: 30, environmentId: E2 } }, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_MISMATCH' });
  });

  it('deployment comparison reports new/gone groups with no developer attribution', async () => {
    t = new Date('2026-03-01T12:00:00Z');
    const ctx = setup();
    ctx.prisma.deployment.rows.push({ id: U(51), projectId: P1, environmentId: E1, status: 'Success', commitSha: 'abc1234', initiatedById: DEV.id, createdAt: t, updatedAt: t });
    const at = (m) => new Date(t.getTime() + m * 60000).toISOString();
    await ctx.logs.ingest({ sourceId: S1, entries: [
      { level: 'error', message: 'old failure 12', timestamp: at(-5) },
      { level: 'error', message: 'new failure 987', timestamp: at(5) },
      { level: 'error', message: 'new failure 654', timestamp: at(6) },
    ] }, agent1);
    const cmp = createComparisonService({ prisma: ctx.prisma, store: ctx.logs.store, now: clock });
    const out = await cmp.compareDeployment(U(51), { windowMinutes: 30 }, OWNER);
    expect(out.totals).toEqual({ before: 1, after: 2 });
    expect(out.groups.find((g) => g.title.startsWith('new failure'))).toMatchObject({ change: 'new', after: 2 });
    expect(out.groups.find((g) => g.title.startsWith('old failure'))).toMatchObject({ change: 'gone' });
    expect(JSON.stringify(out)).not.toContain(DEV.id);
    expect(out.attributionNote).toMatch(/does not identify who/);
    await expect(cmp.compareDeployment(U(51), {}, DEV)).rejects.toMatchObject({ status: 403 });
  });
});
