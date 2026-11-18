import { AppError } from '../../common/errors/app-error.js';
import { createProjectAccess } from '../projects/projects.access.js';
import { MAX_RANGE_DAYS } from './project-reports.validator.js';
import {
  DAY_MS,
  bucketKey,
  bucketKeys,
  buildRecommendations,
  computeScore,
  countBy,
  dayKey,
  daysBetween,
  deltaPct,
  isFailure,
  isRolledBack,
  isSuccess,
  median,
  percentile,
  rate,
  round,
  toCsv,
} from './project-reports.metrics.js';

const CAP = 20000;
const OPEN_ALERT = ['firing', 'acknowledged', 'escalated'];
const SAFE_NAME = /^[A-Za-z0-9_.:\-/ ]{1,80}$/;

/** Returns [] and records the section as unavailable when a query fails (stale client, missing table). */
function makeSafe(missing) {
  return async (label, fn) => {
    try {
      return (await fn()) ?? [];
    } catch {
      missing.push(label);
      return [];
    }
  };
}

const inRange = (d, from, to) => {
  const t = new Date(d).getTime();
  return t >= from.getTime() && t < to.getTime();
};

/** Resolves and validates the reporting window. Max 180 days; default last 30 days ending now. */
export function resolveRange({ from, to } = {}, now) {
  const end = to ? new Date(to) : new Date(now);
  const start = from ? new Date(from) : new Date(end.getTime() - 30 * DAY_MS);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || start >= end) {
    throw new AppError(400, 'INVALID_RANGE', 'from must be before to');
  }
  if (end.getTime() - start.getTime() > MAX_RANGE_DAYS * DAY_MS) {
    throw new AppError(400, 'RANGE_TOO_LARGE', `Maximum report range is ${MAX_RANGE_DAYS} days`);
  }
  const span = end.getTime() - start.getTime();
  return { from: start, to: end, prevFrom: new Date(start.getTime() - span), prevTo: start, days: Math.max(1, Math.ceil(span / DAY_MS)) };
}

/** Whitelisted, secret-free label from audit before/after JSON: a resource name only, never values. */
function safeName(a) {
  for (const j of [a.afterJson, a.beforeJson]) {
    if (j && typeof j === 'object') {
      for (const k of ['name', 'key', 'hostname', 'domain', 'label']) {
        if (typeof j[k] === 'string' && SAFE_NAME.test(j[k])) return j[k];
      }
    }
  }
  return null;
}

function auditType(action) {
  if (/^project\.env/.test(action)) return 'config';
  if (/^(domain|dns|caddy|ssl|cert)/.test(action)) return 'domain';
  if (/^(project\.(member|team)|member|team|access|grant)/.test(action)) return 'team';
  if (/^(backup|restore|db\.restore)/.test(action)) return 'backup';
  if (/^(deploy|deployment|approval)/.test(action)) return 'deployment';
  if (/^(incident)/.test(action)) return 'incident';
  if (/^(cron|preview|deploy_hook|project\.(configure|deploy_settings|archive|create|decommission))/.test(action)) return 'config';
  return 'other';
}

export function createProjectReportsService({ prisma, now = () => new Date() }) {
  const access = createProjectAccess({ prisma, now });

  async function loadProject(id, actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const project = await prisma.project.findUnique({ where: { id } });
    if (!project || !(await access.canView(actor, id))) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
    return project;
  }

  /** Reads stored data only (no SSH) and assembles everything for one project and window. */
  async function compute(project, range, { env, granularity = 'day', compare = true } = {}) {
    const missing = [];
    const safe = makeSafe(missing);
    const nowDate = now();
    const pid = project.id;
    const span = { gte: compare ? range.prevFrom : range.from, lt: range.to };

    const environments = await safe('environments', () => prisma.projectEnvironment.findMany({ where: { projectId: pid } }));
    const envRow = env ? environments.find((e) => e.id === env || e.code === env) : null;
    if (env && !envRow) throw new AppError(400, 'ENVIRONMENT_NOT_FOUND', 'Environment does not belong to the project');
    const envFilter = envRow ? { environmentId: envRow.id } : {};
    const envName = new Map(environments.map((e) => [e.id, e.code]));

    const [deploysAll, domains, policies, monitors, cronJobs, previews, incidentsAll, alertsAll, errorGroups, provisioning, members] =
      await Promise.all([
        safe('deployments', () => prisma.deployment.findMany({ where: { projectId: pid, createdAt: span, ...envFilter }, orderBy: { createdAt: 'desc' }, take: CAP })),
        safe('domains', () => prisma.domain.findMany({ where: { projectId: pid, archivedAt: null } })),
        safe('backups', () => prisma.backupPolicy.findMany({ where: { projectId: pid, archivedAt: null } })),
        safe('uptime', () => prisma.uptimeMonitor.findMany({ where: { projectId: pid } })),
        safe('cron', () => prisma.cronJob.findMany({ where: { projectId: pid, archivedAt: null } })),
        safe('previews', () => prisma.previewEnvironment.findMany({ where: { projectId: pid }, take: 500 })),
        safe('incidents', () => prisma.securityIncident.findMany({ where: { projectId: pid, detectedAt: span }, take: 2000 })),
        safe('alerts', () => prisma.alert.findMany({ where: { projectId: pid, createdAt: span }, take: 5000 })),
        safe('errorGroups', () => prisma.errorGroup.findMany({ where: { projectId: pid, lastSeenAt: { gte: range.from, lt: range.to } }, take: 500 })),
        safe('provisioning', () => prisma.provisioningRun.findMany({ where: { projectId: pid, createdAt: span }, take: 200 })),
        safe('members', () => prisma.projectMember.findMany({ where: { projectId: pid } })),
      ]);

    const deployIds = deploysAll.map((d) => d.id);
    const domainIds = domains.map((d) => d.id);
    const policyIds = policies.map((p) => p.id);
    const monitorIds = monitors.map((m) => m.id);
    const cronIds = cronJobs.map((c) => c.id);
    const correlationIds = deploysAll.map((d) => d.correlationId).filter(Boolean);

    const [steps, approvals, opJobs, certs, backupRunsAll, restoreRuns, checksAll, cronRunsAll, logRows, snapshots, auditRows, approvalReqs, deliveries, hooks] =
      await Promise.all([
        safe('deployment steps', () => (deployIds.length ? prisma.deploymentStep.findMany({ where: { deploymentId: { in: deployIds } }, take: CAP }) : [])),
        safe('approvals', () => (deployIds.length ? prisma.deploymentApproval.findMany({ where: { deploymentId: { in: deployIds } }, take: 5000 }) : [])),
        safe('operation jobs', () => (correlationIds.length ? prisma.operationJob.findMany({ where: { correlationId: { in: correlationIds } }, take: CAP }) : [])),
        safe('certificates', () => (domainIds.length ? prisma.sslCertificate.findMany({ where: { domainId: { in: domainIds } } }) : [])),
        safe('backup runs', () => (policyIds.length ? prisma.backupRun.findMany({ where: { policyId: { in: policyIds }, createdAt: span }, orderBy: { createdAt: 'desc' }, take: 5000 }) : [])),
        safe('restore runs', () => prisma.restoreRun.findMany({ where: { createdAt: span }, take: 2000 })),
        safe('uptime checks', () => (monitorIds.length ? prisma.uptimeCheck.findMany({ where: { monitorId: { in: monitorIds }, checkedAt: { gte: range.from, lt: range.to } }, orderBy: { checkedAt: 'asc' }, take: CAP }) : [])),
        safe('cron runs', () => (cronIds.length ? prisma.cronRun.findMany({ where: { jobId: { in: cronIds }, startedAt: span }, orderBy: { startedAt: 'desc' }, take: 5000 }) : [])),
        safe('logs', () => prisma.logEntry.findMany({ where: { projectId: pid, occurredAt: { gte: range.from, lt: range.to }, severity: { in: ['error', 'warn', 'warning', 'fatal', 'critical'] }, ...envFilter }, take: CAP })),
        safe('server snapshots', () => prisma.serverSnapshot.findMany({ where: { serverId: project.serverId, capturedAt: { gte: range.from, lt: range.to } }, orderBy: { capturedAt: 'asc' }, take: CAP })),
        safe('audit', () => prisma.auditEvent.findMany({ where: { resourceId: { in: [pid, ...domainIds, ...cronIds] }, occurredAt: span }, orderBy: { occurredAt: 'desc' }, take: 5000 })),
        safe('approval requests', () => prisma.approvalRequest.findMany({ where: { resourceType: 'project', resourceId: pid, createdAt: span }, take: 2000 })),
        safe('webhook deliveries', () => prisma.webhookDelivery.findMany({ where: { projectId: pid, createdAt: span }, take: 5000 })),
        safe('deploy hooks', () => prisma.deployHook.findMany({ where: { projectId: pid }, take: 200 })),
      ]);

    const inCur = (d) => inRange(d, range.from, range.to);
    const inPrev = (d) => inRange(d, range.prevFrom, range.prevTo);
    const policyOf = new Set(policyIds);
    const backupRuns = backupRunsAll.filter((r) => policyOf.has(r.policyId));
    const checks = checksAll;

    const userIds = new Set();
    for (const d of deploysAll) if (d.initiatedById) userIds.add(d.initiatedById);
    for (const a of auditRows) if (a.actorId) userIds.add(a.actorId);
    for (const a of approvals) if (a.approverId) userIds.add(a.approverId);
    const users = userIds.size ? await safe('users', () => prisma.user.findMany({ where: { id: { in: [...userIds] } } })) : [];
    const nameOf = new Map(users.map((u) => [u.id, u.displayName || `user-${String(u.id).slice(0, 6)}`]));
    const actorName = (id) => (id ? nameOf.get(id) ?? `user-${String(id).slice(0, 6)}` : 'system');

    // ---- deployments -----------------------------------------------------------------
    const stepsBy = new Map();
    for (const s of steps) {
      if (!stepsBy.has(s.deploymentId)) stepsBy.set(s.deploymentId, []);
      stepsBy.get(s.deploymentId).push(s);
    }
    const jobByCorr = new Map(opJobs.map((j) => [j.correlationId, j]));
    const durationSec = (d) => {
      const ss = (stepsBy.get(d.id) ?? []).filter((s) => s.startedAt && s.finishedAt);
      if (ss.length) {
        const a = Math.min(...ss.map((s) => new Date(s.startedAt).getTime()));
        const b = Math.max(...ss.map((s) => new Date(s.finishedAt).getTime()));
        return Math.max(0, (b - a) / 1000);
      }
      if (isSuccess(d.status) || isFailure(d.status) || isRolledBack(d.status)) {
        return Math.max(0, (new Date(d.updatedAt).getTime() - new Date(d.createdAt).getTime()) / 1000);
      }
      return null;
    };
    const decorate = (d) => {
      const job = jobByCorr.get(d.correlationId);
      const payload = job?.payloadJson && typeof job.payloadJson === 'object' ? job.payloadJson : {};
      return {
        id: d.id,
        status: d.status,
        environment: envName.get(d.environmentId) ?? null,
        commitSha: d.commitSha ? String(d.commitSha).slice(0, 12) : null,
        branch: typeof payload.branch === 'string' ? payload.branch : null,
        trigger: typeof payload.trigger === 'string' ? payload.trigger : job?.action === 'deployment.rollback' ? 'rollback' : d.initiatedById ? 'manual' : 'automation',
        author: d.initiatedById ? actorName(d.initiatedById) : 'system',
        createdAt: d.createdAt,
        durationSec: durationSec(d),
        rollbackOfId: d.rollbackOfId ?? null,
      };
    };
    const curDeploys = deploysAll.filter((d) => inCur(d.createdAt)).map(decorate);
    const prevDeploys = deploysAll.filter((d) => inPrev(d.createdAt)).map(decorate);
    const depStats = (list) => {
      const done = list.filter((d) => isSuccess(d.status) || isFailure(d.status) || isRolledBack(d.status));
      const ok = done.filter((d) => isSuccess(d.status)).length;
      const durs = list.filter((d) => isSuccess(d.status)).map((d) => d.durationSec).filter((x) => x != null);
      return {
        total: list.length,
        succeeded: ok,
        failed: list.filter((d) => isFailure(d.status)).length,
        rolledBack: list.filter((d) => isRolledBack(d.status)).length,
        successRate: rate(ok, done.length),
        buildMedianSec: round(median(durs), 1),
        buildP95Sec: round(percentile(durs, 95), 1),
      };
    };
    const dc = depStats(curDeploys);
    const dp = depStats(prevDeploys);
    const lastDeploy = deploysAll[0] ?? null;
    const failedDeployIds = new Set(curDeploys.filter((d) => isFailure(d.status)).map((d) => d.id));
    const failureSteps = steps.filter((s) => failedDeployIds.has(s.deploymentId) && isFailure(s.status));
    const failuresByStep = countBy(failureSteps, (s) => s.name);

    // ---- incidents & MTTR ------------------------------------------------------------
    const curInc = incidentsAll.filter((i) => inCur(i.detectedAt));
    const prevInc = incidentsAll.filter((i) => inPrev(i.detectedAt));
    const mttrMin = (list) => {
      const d = list.filter((i) => i.closedAt).map((i) => (new Date(i.closedAt).getTime() - new Date(i.detectedAt).getTime()) / 60000);
      return d.length ? round(d.reduce((a, b) => a + b, 0) / d.length, 1) : null;
    };
    const incOpen = curInc.filter((i) => !i.closedAt && String(i.status).toLowerCase() !== 'closed').length;

    // ---- alerts ----------------------------------------------------------------------
    const curAlerts = alertsAll.filter((a) => inCur(a.createdAt));
    const prevAlerts = alertsAll.filter((a) => inPrev(a.createdAt));

    // ---- uptime ----------------------------------------------------------------------
    const upPct = (list) => (list.length ? round((list.filter((c) => c.ok).length / list.length) * 100, 2) : null);
    const curChecks = checks.filter((c) => inCur(c.checkedAt));
    const prevChecks = checks.filter((c) => inPrev(c.checkedAt));

    // ---- backups ---------------------------------------------------------------------
    const bk = backupRuns.filter((r) => inCur(r.createdAt));
    const bkPrev = backupRuns.filter((r) => inPrev(r.createdAt));
    const allSuccess = backupRunsAll.filter((r) => isSuccess(r.status));
    const lastSuccess = allSuccess.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0] ?? null;
    const verified = backupRuns.filter((r) => isSuccess(r.verificationStatus)).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0] ?? null;

    // ---- certs & domains -------------------------------------------------------------
    const expiries = certs.filter((c) => c.expiresAt).map((c) => ({ id: c.id, domainId: c.domainId, expiresAt: c.expiresAt, status: c.status }));
    const minDays = expiries.length ? Math.floor((Math.min(...expiries.map((c) => new Date(c.expiresAt).getTime())) - nowDate.getTime()) / DAY_MS) : null;
    const domainName = new Map(domains.map((d) => [d.id, d.name]));

    // ---- cron ------------------------------------------------------------------------
    const cr = cronRunsAll.filter((r) => inCur(r.startedAt));
    const crPrev = cronRunsAll.filter((r) => inPrev(r.startedAt));
    const crDone = cr.filter((r) => isSuccess(r.status) || isFailure(r.status));
    const crPrevDone = crPrev.filter((r) => isSuccess(r.status) || isFailure(r.status));

    // ---- logs ------------------------------------------------------------------------
    const logsCur = logRows.filter((l) => inCur(l.occurredAt));
    const isErr = (l) => ['error', 'fatal', 'critical'].includes(String(l.severity).toLowerCase());
    const errors = logsCur.filter(isErr).length;
    const warns = logsCur.length - errors;

    // ---- series ----------------------------------------------------------------------
    const keys = bucketKeys(range.from, range.to, granularity);
    const series = new Map(
      keys.map((k) => [
        k,
        { date: k, deploys: { success: 0, failed: 0, rolledBack: 0, other: 0 }, durations: [], uptimeOk: 0, uptimeTotal: 0, cpu: [], mem: [], disk: [], errors: 0, warns: 0, alerts: { critical: 0, warning: 0, info: 0 }, incidents: 0 },
      ]),
    );
    const at = (d) => series.get(bucketKey(d, granularity));
    for (const d of curDeploys) {
      const b = at(d.createdAt);
      if (!b) continue;
      if (isSuccess(d.status)) b.deploys.success++;
      else if (isFailure(d.status)) b.deploys.failed++;
      else if (isRolledBack(d.status)) b.deploys.rolledBack++;
      else b.deploys.other++;
      if (isSuccess(d.status) && d.durationSec != null) b.durations.push(d.durationSec);
    }
    for (const c of curChecks) {
      const b = at(c.checkedAt);
      if (!b) continue;
      b.uptimeTotal++;
      if (c.ok) b.uptimeOk++;
    }
    for (const s of snapshots) {
      const b = at(s.capturedAt);
      const j = s.summaryJson;
      if (!b || !j) continue;
      if (Number.isFinite(j.cpuPercent)) b.cpu.push(j.cpuPercent);
      if (Number.isFinite(j.memPercent)) b.mem.push(j.memPercent);
      if (Number.isFinite(j.diskPercent)) b.disk.push(j.diskPercent);
    }
    for (const l of logsCur) {
      const b = at(l.occurredAt);
      if (!b) continue;
      if (isErr(l)) b.errors++;
      else b.warns++;
    }
    for (const a of curAlerts) {
      const b = at(a.createdAt);
      if (b) b.alerts[['critical', 'warning', 'info'].includes(a.severity) ? a.severity : 'info']++;
    }
    for (const i of curInc) {
      const b = at(i.detectedAt);
      if (b) b.incidents++;
    }
    const avg = (a) => (a.length ? round(a.reduce((x, y) => x + y, 0) / a.length, 1) : null);
    const seriesOut = [...series.values()].map((b) => ({
      date: b.date,
      deployments: b.deploys,
      buildMedianSec: round(median(b.durations), 1),
      buildP95Sec: round(percentile(b.durations, 95), 1),
      uptimePct: b.uptimeTotal ? round((b.uptimeOk / b.uptimeTotal) * 100, 2) : null,
      cpuAvg: avg(b.cpu),
      cpuMax: b.cpu.length ? round(Math.max(...b.cpu), 1) : null,
      memAvg: avg(b.mem),
      memMax: b.mem.length ? round(Math.max(...b.mem), 1) : null,
      diskAvg: avg(b.disk),
      errors: b.errors,
      warns: b.warns,
      alerts: b.alerts,
      incidents: b.incidents,
    }));

    // ---- breakdowns ------------------------------------------------------------------
    const auditCur = auditRows.filter((a) => inCur(a.occurredAt) && !/^auth\./.test(a.action));
    const breakdowns = {
      deploymentsByEnvironment: countBy(curDeploys, (d) => d.environment ?? 'unknown'),
      deploymentsByBranch: countBy(curDeploys, (d) => d.branch ?? 'unknown'),
      deploymentsByAuthor: countBy(curDeploys, (d) => d.author),
      deploymentsByTrigger: countBy(curDeploys, (d) => d.trigger),
      failuresByStep,
      incidentsBySeverity: countBy(curInc, (i) => i.severity),
      incidentsByStatus: countBy(curInc, (i) => i.status),
      alertsBySeverity: countBy(curAlerts, (a) => a.severity),
      topErrors: errorGroups
        .sort((a, b) => (b.count ?? 0) - (a.count ?? 0))
        .slice(0, 10)
        .map((g) => ({ fingerprint: String(g.fingerprint).slice(0, 16), count: g.count ?? 0, firstSeenAt: g.firstSeenAt, lastSeenAt: g.lastSeenAt })),
      auditByActor: countBy(auditCur, (a) => actorName(a.actorId)).slice(0, 10),
      auditByAction: countBy(auditCur, (a) => a.action).slice(0, 10),
    };

    // ---- facts for score / recommendations --------------------------------------------
    const facts = {
      rangeDays: range.days,
      deployments: { ...dc, lastDays: lastDeploy ? daysBetween(lastDeploy.createdAt, nowDate) : null },
      uptime: { monitors: monitors.length, checks: curChecks.length, pct: upPct(curChecks) },
      backups: {
        policies: policies.length,
        lastSuccessDays: lastSuccess ? daysBetween(lastSuccess.createdAt, nowDate) : null,
        lastVerifiedDays: verified ? daysBetween(verified.createdAt, nowDate) : null,
      },
      certificates: { minDaysLeft: minDays },
      incidents: { total: curInc.length, open: incOpen, critical: curInc.filter((i) => i.severity === 'critical').length },
      alerts: {
        total: curAlerts.length,
        critical: curAlerts.filter((a) => a.severity === 'critical').length,
        openCritical: curAlerts.filter((a) => a.severity === 'critical' && OPEN_ALERT.includes(a.status)).length,
      },
      logs: { available: logRows.length > 0, errors },
      domains: { total: domains.length },
      cron: { total: cronJobs.length, successRate: rate(crDone.filter((r) => isSuccess(r.status)).length, crDone.length) },
      failuresByStep,
    };
    const health = computeScore(facts, nowDate);
    const recommendations = buildRecommendations(facts);

    const kpi = (value, previous, unit) => ({ value, previous: compare ? previous : null, delta: compare ? deltaPct(value, previous) : null, unit });
    const successOf = (l) => l.filter((r) => isSuccess(r.status)).length;
    const summary = {
      deployments: kpi(dc.total, dp.total, 'count'),
      deploySuccessRate: kpi(dc.successRate, dp.successRate, '%'),
      deploysFailed: kpi(dc.failed, dp.failed, 'count'),
      deploysRolledBack: kpi(dc.rolledBack, dp.rolledBack, 'count'),
      buildMedianSec: kpi(dc.buildMedianSec, dp.buildMedianSec, 's'),
      buildP95Sec: kpi(dc.buildP95Sec, dp.buildP95Sec, 's'),
      deployFrequencyPerWeek: kpi(round((dc.total / range.days) * 7, 2), round((dp.total / range.days) * 7, 2), '/week'),
      incidents: kpi(curInc.length, prevInc.length, 'count'),
      mttrMinutes: kpi(mttrMin(curInc), mttrMin(prevInc), 'min'),
      uptimePct: kpi(upPct(curChecks), upPct(prevChecks), '%'),
      errorLogs: kpi(errors, logRows.filter((l) => inPrev(l.occurredAt) && isErr(l)).length, 'count'),
      warnLogs: kpi(warns, null, 'count'),
      alerts: kpi(curAlerts.length, prevAlerts.length, 'count'),
      alertsCritical: kpi(facts.alerts.critical, prevAlerts.filter((a) => a.severity === 'critical').length, 'count'),
      backupSuccessRate: kpi(rate(successOf(bk), bk.length), rate(successOf(bkPrev), bkPrev.length), '%'),
      lastVerifiedRestoreDays: kpi(facts.backups.lastVerifiedDays, null, 'days'),
      certDaysToExpiry: kpi(minDays, null, 'days'),
      domains: kpi(domains.length, null, 'count'),
      cronSuccessRate: kpi(facts.cron.successRate, rate(successOf(crPrevDone), crPrevDone.length), '%'),
      previews: kpi(previews.filter((p) => inCur(p.createdAt)).length, previews.filter((p) => inPrev(p.createdAt)).length, 'count'),
    };

    // ---- sections ---------------------------------------------------------------------
    const sections = {
      reliability: {
        monitors: monitors.map((m) => ({ id: m.id, name: m.name, status: m.status, intervalSec: m.intervalSec, lastCheckedAt: m.lastCheckedAt })),
        incidents: curInc.map((i) => ({ id: i.id, title: i.title, severity: i.severity, status: i.status, detectedAt: i.detectedAt, closedAt: i.closedAt, durationMin: i.closedAt ? round((new Date(i.closedAt) - new Date(i.detectedAt)) / 60000, 1) : null })),
        downtimeStrip: seriesOut.map((s) => ({ date: s.date, uptimePct: s.uptimePct })),
        responseP95Ms: round(percentile(curChecks.map((c) => c.responseMs).filter((x) => x != null), 95), 0),
      },
      performance: {
        serverId: project.serverId,
        note: 'Resource figures are server-wide snapshots; the server may host other projects.',
        snapshots: snapshots.length,
      },
      security: {
        approvals: {
          total: approvals.filter((a) => inCur(a.createdAt)).length,
          approved: approvals.filter((a) => inCur(a.createdAt) && /approv/i.test(a.decision)).length,
          rejected: approvals.filter((a) => inCur(a.createdAt) && /reject|den/i.test(a.decision)).length,
          requests: approvalReqs.filter((a) => inCur(a.createdAt)).length,
        },
        certificates: expiries.map((c) => ({ domain: domainName.get(c.domainId) ?? null, expiresAt: c.expiresAt, status: c.status, daysLeft: Math.floor((new Date(c.expiresAt) - nowDate) / DAY_MS) })),
        accessChanges: auditCur.filter((a) => auditType(a.action) === 'team').length,
        configChanges: auditCur.filter((a) => auditType(a.action) === 'config').length,
      },
      backups: {
        policies: policies.map((p) => ({ id: p.id, frequency: p.frequency, retentionDays: p.retentionDays, rpoMinutes: p.rpoMinutes, rtoMinutes: p.rtoMinutes })),
        runs: bk.length,
        succeeded: successOf(bk),
        failed: bk.filter((r) => isFailure(r.status)).length,
        verified: bk.filter((r) => isSuccess(r.verificationStatus)).length,
        lastSuccessAt: lastSuccess?.createdAt ?? null,
        lastVerifiedAt: verified?.createdAt ?? null,
        restores: restoreRuns.length,
        recent: bk.slice(0, 10).map((r) => ({ id: r.id, status: r.status, verificationStatus: r.verificationStatus ?? null, createdAt: r.createdAt })),
      },
      domains: {
        total: domains.length,
        list: domains.map((d) => ({ name: d.name, status: d.status })),
        certificates: expiries.length,
        expiringSoon: expiries.filter((c) => new Date(c.expiresAt) - nowDate < 14 * DAY_MS).length,
      },
      automation: {
        cronJobs: cronJobs.length,
        cronEnabled: cronJobs.filter((c) => c.enabled).length,
        cronRuns: cr.length,
        cronFailed: cr.filter((r) => isFailure(r.status)).length,
        cronSuccessRate: facts.cron.successRate,
        webhookDeliveries: deliveries.filter((d) => inCur(d.createdAt)).length,
        webhookOutcomes: countBy(deliveries.filter((d) => inCur(d.createdAt)), (d) => d.outcome),
        deployHooks: hooks.filter((h) => !h.revokedAt).length,
        deployHookUses: hooks.reduce((n, h) => n + (h.useCount ?? 0), 0),
        previewsActive: previews.filter((p) => p.status === 'active').length,
        previewsTotal: previews.length,
        provisioningRuns: provisioning.filter((p) => inCur(p.createdAt)).length,
      },
      team: {
        members: members.length,
        deployersByAuthor: breakdowns.deploymentsByAuthor,
        activeActors: breakdowns.auditByActor,
        accessChanges: auditCur.filter((a) => auditType(a.action) === 'team').length,
      },
      recentDeployments: curDeploys.slice(0, 20),
    };

    // ---- timeline ---------------------------------------------------------------------
    const timeline = [];
    const ev = (type, at_, title, extra = {}) => timeline.push({ type, at: new Date(at_).toISOString(), title, ...extra });
    for (const d of curDeploys) ev('deployment', d.createdAt, `Deployment ${d.status}${d.environment ? ` (${d.environment})` : ''}`, { status: d.status, actor: d.author, ref: d.id });
    for (const a of approvals.filter((x) => inCur(x.createdAt))) ev('approval', a.createdAt, `Deployment approval: ${a.decision}`, { actor: actorName(a.approverId), ref: a.deploymentId });
    for (const a of approvalReqs.filter((x) => inCur(x.createdAt))) ev('approval', a.createdAt, `Approval request ${a.status}${a.action ? `: ${a.action}` : ''}`, { ref: a.id });
    for (const i of curInc) {
      ev('incident', i.detectedAt, `Incident opened: ${i.title}`, { severity: i.severity, ref: i.id });
      if (i.closedAt) ev('incident', i.closedAt, `Incident closed: ${i.title}`, { severity: i.severity, ref: i.id });
    }
    for (const r of bk) ev('backup', r.createdAt, `Backup ${r.status}${r.verificationStatus ? ` (${r.verificationStatus})` : ''}`, { status: r.status, ref: r.id });
    for (const r of restoreRuns.filter((x) => inCur(x.createdAt))) ev('backup', r.createdAt, `Restore ${r.status}`, { status: r.status, ref: r.id });
    for (const d of domains.filter((x) => inCur(x.createdAt))) ev('domain', d.createdAt, `Domain added: ${d.name}`, { ref: d.id });
    for (const r of cr.filter((x) => isFailure(x.status))) ev('automation', r.startedAt, 'Cron run failed', { status: r.status, ref: r.id });
    for (const p of previews.filter((x) => inCur(x.createdAt))) ev('automation', p.createdAt, `Preview environment #${p.prNumber} ${p.status}`, { ref: p.id });
    for (const p of provisioning) if (inCur(p.createdAt)) ev('provisioning', p.createdAt, `Provisioning run ${p.status}`, { status: p.status, ref: p.id });
    for (const a of auditCur) {
      const type = auditType(a.action);
      if (type === 'deployment') continue;
      const name = safeName(a);
      ev(type, a.occurredAt, `${a.action}${name ? ` (${name})` : ''}`, { actor: actorName(a.actorId), status: a.result, ref: a.id });
    }
    timeline.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));

    const availability = {
      deployments: deploysAll.length > 0,
      uptime: monitors.length > 0 && checks.length > 0,
      uptimeMonitors: monitors.length > 0,
      resources: snapshots.length > 0,
      logs: logRows.length > 0,
      incidents: incidentsAll.length > 0,
      alerts: alertsAll.length > 0,
      backups: policies.length > 0,
      certificates: certs.length > 0,
      domains: domains.length > 0,
      cron: cronJobs.length > 0,
      previews: previews.length > 0,
      audit: auditRows.length > 0,
      timeline: timeline.length > 0,
    };
    const reasons = {
      deployments: availability.deployments ? null : 'No deployments recorded in the selected range.',
      uptime: availability.uptime ? null : monitors.length ? 'No uptime checks ran in this range.' : 'No uptime monitor is configured for this project.',
      resources: availability.resources ? null : 'No server snapshots in range. Is the agent reporting?',
      logs: availability.logs ? null : 'No warn/error log entries ingested. Register a log source to enable this.',
      incidents: availability.incidents ? null : 'No incidents recorded in this range.',
      backups: availability.backups ? null : 'No backup policy is configured.',
      certificates: availability.certificates ? null : 'No certificates are tracked for this project.',
      cron: availability.cron ? null : 'No cron jobs are configured.',
      previews: availability.previews ? null : 'No preview environments exist.',
      audit: availability.audit ? null : 'No audit events recorded for this project in range.',
    };

    return {
      project: { id: project.id, name: project.name, slug: project.slug, status: project.status },
      environment: envRow ? { id: envRow.id, code: envRow.code } : null,
      environments: environments.map((e) => ({ id: e.id, code: e.code, displayName: e.displayName })),
      range: { from: range.from.toISOString(), to: range.to.toISOString(), days: range.days, granularity, compare },
      previousRange: compare ? { from: range.prevFrom.toISOString(), to: range.prevTo.toISOString() } : null,
      generatedAt: nowDate.toISOString(),
      summary,
      health,
      recommendations,
      series: seriesOut,
      breakdowns,
      sections,
      timeline,
      availability,
      reasons,
      unavailableSources: [...new Set(missing)],
    };
  }

  const paginate = (report, { timelinePage = 1, timelineLimit = 50, timelineType } = {}) => {
    const all = timelineType ? report.timeline.filter((t) => t.type === timelineType) : report.timeline;
    const types = countBy(report.timeline, (t) => t.type);
    const start = (timelinePage - 1) * timelineLimit;
    return {
      ...report,
      timeline: all.slice(start, start + timelineLimit),
      timelineMeta: { total: all.length, page: timelinePage, limit: timelineLimit, types },
    };
  };

  function section(report, name) {
    const flat = (obj) => Object.entries(obj).map(([metric, v]) => ({ metric, value: v.value, previous: v.previous, deltaPct: v.delta, unit: v.unit }));
    switch (name) {
      case 'summary':
        return { columns: ['metric', 'value', 'previous', 'deltaPct', 'unit'], rows: flat(report.summary) };
      case 'daily':
        return {
          columns: ['date', 'deploysSuccess', 'deploysFailed', 'deploysRolledBack', 'buildMedianSec', 'buildP95Sec', 'uptimePct', 'cpuAvg', 'memAvg', 'diskAvg', 'errors', 'warns', 'incidents'],
          rows: report.series.map((s) => ({ date: s.date, deploysSuccess: s.deployments.success, deploysFailed: s.deployments.failed, deploysRolledBack: s.deployments.rolledBack, buildMedianSec: s.buildMedianSec, buildP95Sec: s.buildP95Sec, uptimePct: s.uptimePct, cpuAvg: s.cpuAvg, memAvg: s.memAvg, diskAvg: s.diskAvg, errors: s.errors, warns: s.warns, incidents: s.incidents })),
        };
      case 'deployments':
        return { columns: ['id', 'status', 'environment', 'branch', 'commitSha', 'trigger', 'author', 'createdAt', 'durationSec'], rows: report.sections.recentDeployments };
      case 'incidents':
        return { columns: ['id', 'title', 'severity', 'status', 'detectedAt', 'closedAt', 'durationMin'], rows: report.sections.reliability.incidents };
      case 'errors':
        return { columns: ['fingerprint', 'count', 'firstSeenAt', 'lastSeenAt'], rows: report.breakdowns.topErrors };
      case 'audit':
        return { columns: ['key', 'count'], rows: [...report.breakdowns.auditByActor.map((r) => ({ key: `actor:${r.key}`, count: r.count })), ...report.breakdowns.auditByAction.map((r) => ({ key: `action:${r.key}`, count: r.count }))] };
      case 'recommendations':
        return { columns: ['id', 'severity', 'title', 'detail', 'hint'], rows: report.recommendations };
      default:
        return { columns: ['type', 'at', 'title', 'actor', 'status', 'severity', 'ref'], rows: report.timeline };
    }
  }

  return {
    async getReport(id, query = {}, actor) {
      const project = await loadProject(id, actor);
      const range = resolveRange(query, now());
      const report = await compute(project, range, { env: query.env, granularity: query.granularity ?? 'day', compare: query.compare ?? true });
      return paginate(report, query);
    },

    async exportReport(id, query = {}, actor) {
      const project = await loadProject(id, actor);
      const range = resolveRange(query, now());
      const report = await compute(project, range, { env: query.env, granularity: query.granularity ?? 'day', compare: query.compare ?? true });
      const stamp = dayKey(now());
      if ((query.format ?? 'json') === 'json') {
        return { contentType: 'application/json; charset=utf-8', filename: `${project.slug}-report-${stamp}.json`, body: JSON.stringify(report, null, 2) };
      }
      const s = section(report, query.section ?? 'summary');
      return { contentType: 'text/csv; charset=utf-8', filename: `${project.slug}-report-${query.section ?? 'summary'}-${stamp}.csv`, body: toCsv(s.columns, s.rows) };
    },

    /** Fleet ranking by health score, scope-filtered. Lowest scores first so attention goes where it is needed. */
    async projectsOverview({ days = 30, limit = 50 } = {}, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const visible = await access.visibleProjectIds(actor);
      const projects = await prisma.project.findMany({
        where: { archivedAt: null, ...(visible ? { id: { in: visible } } : {}) },
        take: limit,
        orderBy: { name: 'asc' },
      });
      const end = now();
      const range = resolveRange({ from: new Date(end.getTime() - days * DAY_MS), to: end }, end);
      const rows = [];
      for (const p of projects) {
        const r = await compute(p, range, { compare: true, granularity: 'day' });
        rows.push({
          project: r.project,
          score: r.health.score,
          grade: r.health.grade,
          deployments: r.summary.deployments.value,
          deploySuccessRate: r.summary.deploySuccessRate.value,
          uptimePct: r.summary.uptimePct.value,
          incidents: r.summary.incidents.value,
          topRecommendation: r.recommendations[0] ? { id: r.recommendations[0].id, severity: r.recommendations[0].severity, title: r.recommendations[0].title } : null,
          sparkline: r.series.slice(-14).map((s) => s.deployments.success + s.deployments.failed + s.deployments.rolledBack + s.deployments.other),
        });
      }
      rows.sort((a, b) => (a.score ?? 101) - (b.score ?? 101));
      return { days, generatedAt: end.toISOString(), projects: rows };
    },
  };
}
