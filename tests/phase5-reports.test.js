import { describe, expect, it, vi } from 'vitest';
import { createReportsService } from '../src/modules/reports/reports.service.js';
import { buildReport } from '../src/modules/reports/reports.metrics.js';
import { csvRenderer, createRendererRegistry } from '../src/modules/reports/reports.render.js';
import { lastDue, parseCron, periodFor } from '../src/modules/reports/reports.schedule.js';
import { fakePrisma, U } from './phase3-helpers.js';

const OWNER = { id: U(1), isOwner: true };
const ALICE = { id: U(2), isOwner: false };
const BOB = { id: U(3), isOwner: false };
const P1 = U(10);
const P2 = U(11);
const E1 = U(20);
const day = (d, h = 10) => new Date(Date.UTC(2026, 2, d, h));
const FROM = '2026-03-02T00:00:00.000Z';
const TO = '2026-03-09T00:00:00.000Z';
const grant = (userId, projectId, over = {}) => ({
  id: `g-${userId}-${projectId}`, userId, permissionCode: 'report.team.export', resourceType: 'project',
  resourceId: projectId, environmentId: null, revokedAt: null, expiresAt: null, createdAt: day(1), ...over,
});

function fixture({ grants = [], clock = day(9, 7) } = {}) {
  const prisma = fakePrisma({
    project: [{ id: P1, serverId: U(40), name: 'One' }, { id: P2, serverId: U(41), name: 'Two' }],
    user: [
      { id: OWNER.id, displayName: 'Owner', status: 'active', ownerFlag: true },
      { id: ALICE.id, displayName: 'Alice', status: 'active', ownerFlag: false },
      { id: BOB.id, displayName: 'Bob', status: 'active', ownerFlag: false },
    ],
    deployment: [
      { id: 'd0', projectId: P1, environmentId: E1, status: 'Success', initiatedById: ALICE.id, createdAt: new Date('2026-02-28T10:00:00Z') },
      { id: 'd1', projectId: P1, environmentId: E1, status: 'Success', initiatedById: ALICE.id, createdAt: day(3) },
      { id: 'd2', projectId: P1, environmentId: E1, status: 'Success', initiatedById: BOB.id, createdAt: day(4) },
      { id: 'd3', projectId: P1, environmentId: E1, status: 'Failed', initiatedById: ALICE.id, createdAt: day(5) },
      { id: 'd4', projectId: P1, environmentId: E1, status: 'Success', initiatedById: ALICE.id, createdAt: day(6) },
      { id: 'd5', projectId: P1, environmentId: E1, status: 'Success', initiatedById: ALICE.id, createdAt: new Date(TO) }, // boundary: excluded
      { id: 'dx', projectId: P2, environmentId: U(21), status: 'Failed', initiatedById: ALICE.id, createdAt: day(5) },
    ],
    operationJob: [
      { id: 'o1', action: 'deployment.run', resourceType: 'project', resourceId: P1, status: 'FAILED', initiatorId: ALICE.id, approverId: BOB.id, createdAt: day(5) },
      { id: 'o2', action: 'deployment.run', resourceType: 'project', resourceId: P1, status: 'SUCCESS', initiatorId: ALICE.id, approverId: null, createdAt: day(6) },
    ],
    operationExecution: [
      { id: 'x1', operationJobId: 'o1', attemptId: 'attempt-1' }, { id: 'x2', operationJobId: 'o1', attemptId: 'attempt-2' }, { id: 'x3', operationJobId: 'o1', attemptId: 'attempt-3' },
    ],
    approvalRequest: [{ id: 'a1', resourceType: 'project', resourceId: P1, requesterId: ALICE.id, approverId: BOB.id, status: 'APPROVED', createdAt: day(5) }],
    auditEvent: [
      { id: 'u1', actorId: ALICE.id, action: 'operation.enqueue', resourceType: 'project', resourceId: P1, result: 'denied', occurredAt: day(7) },
      { id: 'u2', actorId: ALICE.id, action: 'project.configure', resourceType: 'project', resourceId: P1, result: 'success', occurredAt: day(7) },
    ],
    securityEvent: [{ id: 's1', serverId: U(40), severity: 'high', category: 'ssh', occurredAt: day(4) }],
    resourceGrant: grants,
  });
  const auditService = { record: vi.fn().mockResolvedValue({}) };
  let current = clock;
  const svc = createReportsService({ prisma, auditService, now: () => current });
  return { prisma, svc, auditService, setNow: (d) => { current = d; } };
}

const metric = (r, key) => r.metrics.find((m) => m.key === key);
const params = (over = {}) => ({ type: 'deployment-success', projectId: P1, from: FROM, to: TO, ...over });

describe('TASK-015 report metrics', () => {
  it('recomputes fixture aggregates with lineage to the original events', async () => {
    const { svc } = fixture();
    const r = await svc.preview(params(), OWNER);
    expect(metric(r, 'deployments.total').value).toBe(4);
    expect(metric(r, 'deployments.success').value).toBe(3);
    expect(metric(r, 'deployments.failed').value).toBe(1);
    expect(metric(r, 'deployments.successRate')).toMatchObject({ value: 75, numerator: 3, denominator: 4 });
    expect(metric(r, 'deployments.total').lineage.map((l) => l.id).sort()).toEqual(['d1', 'd2', 'd3', 'd4']);
    expect(metric(r, 'deployments.total').lineage.every((l) => l.source === 'deployment')).toBe(true);
  });

  it('period boundaries are half-open and project scoped', async () => {
    const { svc } = fixture();
    const r = await svc.preview(params(), OWNER);
    const ids = metric(r, 'deployments.total').lineage.map((l) => l.id);
    expect(ids).not.toContain('d0'); // before from
    expect(ids).not.toContain('d5'); // exactly at to
    expect(ids).not.toContain('dx'); // other project
  });

  it('zero denominator is N/A, not 0 or NaN', async () => {
    const { svc } = fixture();
    const r = await svc.preview(params({ from: '2026-01-01T00:00:00.000Z', to: '2026-01-08T00:00:00.000Z' }), OWNER);
    expect(metric(r, 'deployments.successRate')).toMatchObject({ value: null, display: 'N/A' });
  });

  it('retries do not double count: one operation with three executions counts once; duplicate rows collapse', async () => {
    const { svc } = fixture();
    const r = await svc.preview(params({ type: 'failed-operations' }), OWNER);
    expect(metric(r, 'operations.failed').value).toBe(1);
    expect(metric(r, 'operations.total').value).toBe(2);
    const dup = { id: 'd1', status: 'Success', environmentId: E1 };
    const report = buildReport('deployment-success', { operations: [], deployments: [dup, dup, dup], approvals: [], audits: [], activities: [], grants: [], incidents: [], securityEvents: [] }, {});
    expect(metric(report, 'deployments.total').value).toBe(1);
  });

  it('individual report keeps initiator and approver separate', async () => {
    const { svc } = fixture();
    const alice = await svc.preview({ type: 'individual-activity', userId: ALICE.id, from: FROM, to: TO }, ALICE);
    expect(metric(alice, 'deployments.initiated').value).toBe(4); // d1, d3, d4 and dx (individual reports span projects)
    expect(metric(alice, 'operations.initiated').value).toBe(2);
    expect(metric(alice, 'operations.approved').value).toBe(0);
    expect(metric(alice, 'denials').value).toBe(1);
    expect(metric(alice, 'changes.total').value).toBe(1);
    const bob = await svc.preview({ type: 'individual-activity', userId: BOB.id, from: FROM, to: TO }, OWNER);
    expect(metric(bob, 'operations.approved').value).toBe(1);
    expect(metric(bob, 'operations.initiated').value).toBe(0);
    expect(metric(bob, 'approvals.decided').value).toBe(1);
  });

  it('project-level reports: contribution, changes, security, workload, access', async () => {
    const { svc } = fixture({ grants: [grant(ALICE.id, P1, { grantedById: OWNER.id, createdAt: day(3) })] });
    const base = { projectId: P1, from: FROM, to: TO };
    const contribution = await svc.preview({ type: 'project-contribution', ...base }, OWNER);
    const alice = contribution.breakdowns[0].rows.find((r) => r.key === ALICE.id);
    expect(alice).toMatchObject({ label: 'Alice', value: 3 });
    expect(metric(await svc.preview({ type: 'changes', ...base }, OWNER), 'changes.total').value).toBe(1);
    expect(metric(await svc.preview({ type: 'security', ...base }, OWNER), 'security.events').value).toBe(1);
    const work = await svc.preview({ type: 'workload', ...base }, OWNER);
    expect(work.breakdowns[0].rows.find((r) => r.key === ALICE.id).value).toBe(2);
    const acc = await svc.preview({ type: 'access', ...base }, OWNER);
    expect(metric(acc, 'grants.created').value).toBe(1);
    expect(metric(acc, 'grants.active').value).toBe(1);
  });

  it('authorization: scoped grant allows its project only; individual reports are self or Owner', async () => {
    const { svc, auditService } = fixture({ grants: [grant(BOB.id, P1)] });
    await expect(svc.preview(params(), ALICE)).rejects.toMatchObject({ status: 403 });
    expect((await svc.preview(params(), BOB)).type).toBe('deployment-success');
    await expect(svc.preview(params({ projectId: P2 }), BOB)).rejects.toMatchObject({ status: 403 });
    await expect(svc.preview({ type: 'individual-activity', userId: ALICE.id, from: FROM, to: TO }, BOB)).rejects.toMatchObject({ status: 403 });
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ result: 'denied', actorId: ALICE.id }));
    await expect(svc.preview(params({ from: TO, to: FROM }), OWNER)).rejects.toMatchObject({ code: 'PERIOD_INVALID' });
  });

  it('notes state that failure timing does not prove who caused it', async () => {
    const { svc } = fixture();
    expect((await svc.preview(params(), OWNER)).notes.join(' ')).toMatch(/does not prove who caused/);
  });
});

describe('TASK-016 renderers and scheduled summaries', () => {
  it('CSV carries every metric figure from the report (render parity) and neutralizes formulas', async () => {
    const { svc } = fixture();
    const report = await svc.preview(params(), OWNER);
    const csv = csvRenderer.render(report);
    for (const m of report.metrics) {
      expect(csv).toContain(`"${m.key}","${m.label}","${m.value === null ? 'N/A' : m.value}"`);
    }
    const evil = csvRenderer.render({ type: 't', period: {}, metrics: [{ key: 'k', label: '=cmd()', value: 1, unit: 'count' }], breakdowns: [] });
    expect(evil).toContain("\"'=cmd()\"");
  });

  it('PDF and Excel are REQUIRES DECISION (501) until a renderer is registered', async () => {
    const { svc } = fixture();
    await expect(svc.createRun({ ...params(), formats: ['pdf'] }, OWNER)).rejects.toMatchObject({ status: 501, code: 'FORMAT_REQUIRES_DECISION' });
    const pdf = { format: 'pdf', contentType: 'application/pdf', extension: 'pdf', render: () => 'PDF' };
    expect(createRendererRegistry([pdf]).get('pdf').extension).toBe('pdf');
    expect(createRendererRegistry().formats()).toEqual(['csv', 'json']);
  });

  it('on-demand run stores artifacts that are downloadable by authorized users and audited', async () => {
    const { svc, auditService } = fixture();
    const { run, artifacts } = await svc.createRun({ ...params(), formats: ['csv', 'json'] }, OWNER);
    expect(artifacts.map((a) => a.format)).toEqual(['csv', 'json']);
    const file = await svc.downloadArtifact(artifacts[0].id, OWNER);
    expect(file.contentType).toMatch(/csv/);
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'report.download' }));
    expect((await svc.getRun(run.id, OWNER)).artifacts).toHaveLength(2);
  });

  it('expired artifacts and users without scope are rejected on download', async () => {
    const { svc, setNow } = fixture({ grants: [grant(BOB.id, P1)] });
    const { artifacts } = await svc.createRun(params(), OWNER);
    await expect(svc.downloadArtifact(artifacts[0].id, ALICE)).rejects.toMatchObject({ status: 403 });
    expect((await svc.downloadArtifact(artifacts[0].id, BOB)).filename).toBe('deployment-success.csv');
    setNow(day(30));
    await expect(svc.downloadArtifact(artifacts[0].id, OWNER)).rejects.toMatchObject({ status: 410, code: 'ARTIFACT_EXPIRED' });
  });

  const schedule = (svc, over = {}) =>
    svc.createSchedule({ type: 'project-summary', projectId: P1, period: 'weekly', cron: '0 6 * * 1', recipients: [BOB.id], formats: ['csv'], ...over }, OWNER);

  it('only authorized recipients can be scheduled; bad cron and PDF are rejected', async () => {
    const { svc } = fixture({ grants: [grant(BOB.id, P1)] });
    await expect(schedule(svc, { recipients: [ALICE.id] })).rejects.toMatchObject({ code: 'RECIPIENT_NOT_AUTHORIZED' });
    await expect(schedule(svc, { cron: '*/5 * * * *' })).rejects.toMatchObject({ code: 'CRON_INVALID' });
    await expect(schedule(svc, { formats: ['xlsx'] })).rejects.toMatchObject({ status: 501 });
    expect((await schedule(svc)).enabled).toBe(true);
  });

  it('scheduled run is idempotent per period (retry deduplication) and notifies recipients', async () => {
    const { svc, prisma } = fixture({ grants: [grant(BOB.id, P1)] });
    const s = await schedule(svc);
    prisma.reportSchedule.rows[0].createdAt = day(1);
    const at = day(9, 7);
    const first = await svc.runSchedule(prisma.reportSchedule.rows[0], at);
    const retry = await svc.runSchedule(prisma.reportSchedule.rows[0], at);
    expect(first.action).toBe('created');
    expect(retry).toMatchObject({ action: 'duplicate', runId: first.runId });
    expect(prisma.reportRun.rows).toHaveLength(1);
    expect(prisma.notification.rows).toHaveLength(1);
    expect(prisma.reportRun.rows[0]).toMatchObject({ periodStart: new Date(FROM), periodEnd: new Date(TO) });
    const later = await svc.runSchedule(prisma.reportSchedule.rows[0], day(16, 7));
    expect(later.action).toBe('created'); // next week is a new period
    expect(s.id).toBeTruthy();
  });

  it('revoked recipient is skipped and audited; all revoked means no run', async () => {
    const { svc, prisma, auditService } = fixture({ grants: [grant(BOB.id, P1)] });
    await schedule(svc);
    const row = prisma.reportSchedule.rows[0];
    row.createdAt = day(1);
    prisma.resourceGrant.rows[0].revokedAt = day(8);
    const out = await svc.runSchedule(row, day(9, 7));
    expect(out).toMatchObject({ action: 'no-recipients', revoked: [BOB.id] });
    expect(prisma.reportRun.rows).toHaveLength(0);
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'report.schedule.recipient_rejected' }));
  });

  it('a revoked recipient cannot download an earlier artifact', async () => {
    const { svc, prisma } = fixture({ grants: [grant(BOB.id, P1)] });
    await schedule(svc);
    const row = prisma.reportSchedule.rows[0];
    row.createdAt = day(1);
    const out = await svc.runSchedule(row, day(9, 7));
    const art = prisma.reportArtifact.rows.find((a) => a.reportRunId === out.runId);
    expect((await svc.downloadArtifact(art.id, BOB)).body).toContain('deployments.total');
    prisma.resourceGrant.rows[0].revokedAt = day(9, 8);
    await expect(svc.downloadArtifact(art.id, BOB)).rejects.toMatchObject({ status: 403 });
  });

  it('does not backfill periods before the schedule existed; disabled schedules do not run', async () => {
    const { svc, prisma } = fixture({ grants: [grant(BOB.id, P1)] });
    await schedule(svc);
    const row = prisma.reportSchedule.rows[0];
    row.createdAt = day(9, 12); // created after the Monday 06:00 due instant
    expect((await svc.runSchedule(row, day(9, 13))).action).toBe('not-due');
    row.createdAt = day(1);
    await svc.setScheduleEnabled(row.id, false, OWNER);
    expect((await svc.runSchedule(row, day(9, 13))).action).toBe('disabled');
  });

  it('cron helpers resolve the last due instant and report period in UTC', () => {
    expect(parseCron('0 6 * * 1')).toMatchObject({ h: 6, m: 0, dow: 1 });
    expect(parseCron('* * * * *')).toBeNull();
    expect(lastDue('0 6 * * 1', day(9, 7)).toISOString()).toBe('2026-03-09T06:00:00.000Z');
    expect(lastDue('0 6 * * 1', day(9, 5)).toISOString()).toBe('2026-03-02T06:00:00.000Z');
    const w = periodFor('weekly', new Date('2026-03-09T06:00:00Z'));
    expect([w.from.toISOString(), w.to.toISOString()]).toEqual([FROM, TO]);
    const m = periodFor('monthly', new Date('2026-04-01T06:00:00Z'));
    expect([m.from.toISOString(), m.to.toISOString()]).toEqual(['2026-03-01T00:00:00.000Z', '2026-04-01T00:00:00.000Z']);
  });
});
