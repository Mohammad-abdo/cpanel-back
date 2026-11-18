import { describe, expect, it } from 'vitest';
import { createProjectReportsService, resolveRange } from '../src/modules/project-reports/project-reports.service.js';
import { csvCell, deltaPct, percentile, toCsv, computeScore, buildRecommendations } from '../src/modules/project-reports/project-reports.metrics.js';
import { projectReportQuerySchema, projectReportExportQuerySchema } from '../src/modules/project-reports/project-reports.validator.js';
import { fakePrisma, U } from './phase3-helpers.js';

const OWNER = { id: U(1), isOwner: true };
const ALICE = { id: U(2), isOwner: false };
const OUTSIDER = { id: U(3), isOwner: false };
const P1 = U(10);
const E1 = U(20);
const NOW = new Date('2026-06-30T12:00:00Z');
const d = (s) => new Date(s);

function seed() {
  return fakePrisma({
    project: [{ id: P1, serverId: U(40), name: 'One', slug: 'one', type: 'node', status: 'active', archivedAt: null }],
    projectMember: [{ projectId: P1, userId: ALICE.id }],
    projectEnvironment: [{ id: E1, projectId: P1, code: 'production', displayName: 'Production' }],
    user: [{ id: ALICE.id, displayName: 'Alice', email: 'alice@x.test', passwordHash: 'HASH' }],
    deployment: [
      { id: U(50), projectId: P1, environmentId: E1, status: 'Success', initiatedById: ALICE.id, correlationId: 'c1', createdAt: d('2026-06-20T10:00:00Z'), updatedAt: d('2026-06-20T10:01:40Z') },
      { id: U(51), projectId: P1, environmentId: E1, status: 'Success', initiatedById: ALICE.id, correlationId: 'c2', createdAt: d('2026-06-21T10:00:00Z'), updatedAt: d('2026-06-21T10:03:20Z') },
      { id: U(52), projectId: P1, environmentId: E1, status: 'Failed', initiatedById: ALICE.id, correlationId: 'c3', createdAt: d('2026-06-22T10:00:00Z'), updatedAt: d('2026-06-22T10:00:30Z') },
      { id: U(53), projectId: P1, environmentId: E1, status: 'Failed', initiatedById: ALICE.id, correlationId: 'c4', createdAt: d('2026-06-23T10:00:00Z'), updatedAt: d('2026-06-23T10:00:30Z') },
      { id: U(54), projectId: P1, environmentId: E1, status: 'Success', initiatedById: null, createdAt: d('2026-05-10T10:00:00Z'), updatedAt: d('2026-05-10T10:01:00Z') },
    ],
    deploymentStep: [
      { id: U(60), deploymentId: U(52), name: 'build', status: 'Failed' },
      { id: U(61), deploymentId: U(53), name: 'build', status: 'Failed' },
    ],
    operationJob: [{ id: U(62), correlationId: 'c1', action: 'deployment.run', payloadJson: { branch: 'main', token: 'SECRET-TOKEN' } }],
    securityIncident: [
      { id: U(70), projectId: P1, status: 'closed', severity: 'critical', title: '=cmd|calc', detectedAt: d('2026-06-24T10:00:00Z'), closedAt: d('2026-06-24T11:00:00Z') },
      { id: U(71), projectId: P1, status: 'investigating', severity: 'warning', title: 'Slow', detectedAt: d('2026-06-25T10:00:00Z'), closedAt: null },
    ],
    uptimeMonitor: [{ id: U(72), projectId: P1, name: 'web', status: 'up' }],
    uptimeCheck: [
      ...Array.from({ length: 9 }, (_, i) => ({ id: U(100 + i), monitorId: U(72), checkedAt: d('2026-06-26T10:0' + i + ':00Z'), ok: true, responseMs: 100 })),
      { id: U(120), monitorId: U(72), checkedAt: d('2026-06-26T11:00:00Z'), ok: false, responseMs: null },
    ],
    backupPolicy: [{ id: U(80), projectId: P1, archivedAt: null }],
    backupRun: [
      { id: U(81), policyId: U(80), status: 'success', verificationStatus: 'verified', createdAt: d('2026-06-28T02:00:00Z') },
      { id: U(82), policyId: U(80), status: 'failed', createdAt: d('2026-06-27T02:00:00Z') },
    ],
    domain: [{ id: U(90), projectId: P1, name: 'a.test', status: 'active', archivedAt: null, createdAt: d('2026-01-01T00:00:00Z') }],
    sslCertificate: [{ id: U(91), domainId: U(90), expiresAt: d('2026-07-05T12:00:00Z'), status: 'active' }],
    auditEvent: [
      { id: U(92), actorId: ALICE.id, action: 'project.env.set', resourceType: 'project', resourceId: P1, result: 'success', occurredAt: d('2026-06-25T10:00:00Z'), afterJson: { name: 'DATABASE_URL', value: 'mysql://root:hunter2@h/db' } },
      { id: U(93), actorId: ALICE.id, action: 'project.member.add', resourceType: 'project', resourceId: P1, result: 'success', occurredAt: d('2026-06-25T11:00:00Z'), afterJson: { password: 'hunter2' } },
    ],
    logEntry: [
      { id: U(94), projectId: P1, severity: 'error', occurredAt: d('2026-06-26T10:00:00Z'), message: 'password=hunter2' },
      { id: U(95), projectId: P1, severity: 'warn', occurredAt: d('2026-06-26T10:00:00Z'), message: 'w' },
    ],
    serverSnapshot: [
      { id: U(96), serverId: U(40), capturedAt: d('2026-06-26T10:00:00Z'), summaryJson: { cpuPercent: 20, memPercent: 40, diskPercent: 60 } },
      { id: U(97), serverId: U(40), capturedAt: d('2026-06-26T12:00:00Z'), summaryJson: { cpuPercent: 40, memPercent: 60, diskPercent: 62 } },
    ],
  });
}

describe('project report aggregation', () => {
  const svc = () => createProjectReportsService({ prisma: seed(), now: () => NOW });

  it('computes deployment stats, percentiles, deltas', async () => {
    const r = await svc().getReport(P1, {}, ALICE);
    expect(r.summary.deployments.value).toBe(4);
    expect(r.summary.deployments.previous).toBe(1);
    expect(r.summary.deployments.delta).toBe(300);
    expect(r.summary.deploySuccessRate.value).toBe(50);
    expect(r.summary.buildMedianSec.value).toBe(100);
    expect(r.summary.buildP95Sec.value).toBe(200);
    expect(r.breakdowns.failuresByStep[0]).toEqual({ key: 'build', count: 2 });
    expect(r.recommendations.some((x) => x.id === 'repeated_step_failure')).toBe(true);
    expect(r.breakdowns.deploymentsByBranch.find((b) => b.key === 'main').count).toBe(1);
  });

  it('computes MTTR, uptime, backups, cert expiry and availability', async () => {
    const r = await svc().getReport(P1, {}, ALICE);
    expect(r.summary.mttrMinutes.value).toBe(60);
    expect(r.summary.incidents.value).toBe(2);
    expect(r.summary.uptimePct.value).toBe(90);
    expect(r.summary.backupSuccessRate.value).toBe(50);
    expect(r.summary.certDaysToExpiry.value).toBe(5);
    expect(r.recommendations.map((x) => x.id)).toContain('cert_expiring');
    expect(r.availability.resources).toBe(true);
    expect(r.series.find((s) => s.date === '2026-06-26').cpuAvg).toBe(30);
    expect(r.health.score).toBeGreaterThanOrEqual(0);
    expect(r.health.factors.every((f) => 'detail' in f)).toBe(true);
  });

  it('flags missing data instead of failing', async () => {
    const empty = fakePrisma({ project: [{ id: P1, serverId: U(40), name: 'One', slug: 'one', archivedAt: null }] });
    const r = await createProjectReportsService({ prisma: empty, now: () => NOW }).getReport(P1, {}, OWNER);
    expect(r.availability.deployments).toBe(false);
    expect(r.reasons.uptime).toMatch(/uptime monitor/i);
    expect(r.recommendations.map((x) => x.id)).toContain('no_uptime_check');
    expect(r.summary.deploySuccessRate.value).toBeNull();
  });

  it('paginates and filters the timeline', async () => {
    const r = await svc().getReport(P1, { timelineLimit: 2, timelinePage: 1 }, ALICE);
    expect(r.timeline).toHaveLength(2);
    expect(r.timelineMeta.total).toBeGreaterThan(2);
    const only = await svc().getReport(P1, { timelineType: 'incident' }, ALICE);
    expect(only.timeline.every((t) => t.type === 'incident')).toBe(true);
  });

  it('rejects ranges over 180 days and inverted ranges', () => {
    expect(() => resolveRange({ from: '2026-01-01', to: '2026-12-31' }, NOW)).toThrow(/Maximum/);
    expect(() => resolveRange({ from: '2026-06-10', to: '2026-06-01' }, NOW)).toThrow(/before/);
    expect(resolveRange({}, NOW).days).toBe(30);
  });

  it('answers 404 outside scope and 401 without actor', async () => {
    await expect(svc().getReport(P1, {}, OUTSIDER)).rejects.toMatchObject({ status: 404 });
    await expect(svc().getReport(U(999), {}, OWNER)).rejects.toMatchObject({ status: 404 });
    await expect(svc().exportReport(P1, {}, OUTSIDER)).rejects.toMatchObject({ status: 404 });
    await expect(svc().getReport(P1, {}, null)).rejects.toMatchObject({ status: 401 });
    const fleet = await svc().projectsOverview({}, OUTSIDER);
    expect(fleet.projects).toHaveLength(0);
    expect((await svc().projectsOverview({}, ALICE)).projects).toHaveLength(1);
  });

  it('never leaks secret values in JSON or CSV exports', async () => {
    const json = await svc().exportReport(P1, { format: 'json' }, ALICE);
    expect(json.body).not.toContain('hunter2');
    expect(json.body).not.toContain('SECRET-TOKEN');
    expect(json.body).not.toContain('passwordHash');
    expect(json.body).not.toContain('alice@x.test');
    expect(json.body).toContain('DATABASE_URL');
    const csv = await svc().exportReport(P1, { format: 'csv', section: 'timeline' }, ALICE);
    expect(csv.body).not.toContain('hunter2');
    expect(csv.contentType).toMatch(/text\/csv/);
    const inc = await svc().exportReport(P1, { format: 'csv', section: 'incidents' }, ALICE);
    expect(inc.body).toContain("'=cmd|calc");
  });
});

describe('metrics helpers', () => {
  it('percentile and delta', () => {
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95)).toBe(10);
    expect(percentile([5, 1, 3], 50)).toBe(3);
    expect(percentile([], 50)).toBeNull();
    expect(deltaPct(150, 100)).toBe(50);
    expect(deltaPct(5, 0)).toBeNull();
    expect(deltaPct(0, 0)).toBe(0);
  });
  it('csv escaping and formula guard', () => {
    for (const c of ['=1+1', '+1', '-1+2', '@SUM(A1)']) expect(csvCell(c).startsWith("'")).toBe(true);
    expect(csvCell(-5)).toBe('-5');
    expect(csvCell('a,"b"')).toBe('"a,""b"""');
    expect(csvCell('line\nbreak')).toBe('"line\nbreak"');
    expect(toCsv(['a', 'b'], [{ a: 1, b: '=x' }])).toBe("a,b\r\n1,'=x\r\n");
  });
  it('score ignores unavailable factors and recommends actions', () => {
    const facts = {
      rangeDays: 30,
      deployments: { total: 0, successRate: null, lastDays: 90 },
      uptime: { monitors: 0, checks: 0, pct: null },
      backups: { policies: 0, lastSuccessDays: null, lastVerifiedDays: null },
      certificates: { minDaysLeft: null },
      incidents: { total: 0, open: 0, critical: 0 },
      alerts: { total: 0, critical: 0, openCritical: 0 },
      logs: { available: false, errors: 0 },
      domains: { total: 0 },
      cron: { total: 0, successRate: null },
      failuresByStep: [],
    };
    const s = computeScore(facts, NOW);
    expect(s.factors.filter((f) => !f.available).length).toBeGreaterThan(2);
    expect(s.stalePenalty).toBeGreaterThan(0);
    const ids = buildRecommendations(facts).map((r) => r.id);
    expect(ids).toEqual(expect.arrayContaining(['backup_policy_missing', 'no_uptime_check', 'stale_deploy']));
  });
  it('validators bound inputs', () => {
    expect(projectReportQuerySchema.safeParse({ timelineLimit: '500' }).success).toBe(false);
    expect(projectReportQuerySchema.safeParse({ granularity: 'week', compare: 'false' }).data.compare).toBe(false);
    expect(projectReportExportQuerySchema.safeParse({ format: 'xml' }).success).toBe(false);
    expect(projectReportQuerySchema.safeParse({ evil: 1 }).success).toBe(false);
  });
});
