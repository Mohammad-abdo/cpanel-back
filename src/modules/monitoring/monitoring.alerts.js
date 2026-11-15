import { PERMISSIONS } from '@nodeteam/permission-catalog';
import { AppError } from '../../common/errors/app-error.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { notifyOwners } from '../notifications/notifications.service.js';

const OPEN = ['firing', 'acknowledged', 'escalated'];

/**
 * Alert lifecycle: firing -> (escalated) -> acknowledged -> resolved. Deduplicated by rule fingerprint;
 * a resolved alert reopens when its condition fires again. Rule kinds: error_count, intermittent, no_data.
 */
export function createAlertsService({ prisma, now = () => new Date(), auditService = null, store, rbac = null }) {
  const access = rbac ?? createRbacService({ prisma, now });
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function authorize(actor, projectId, environmentId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (actor.isOwner) return;
    if (!environmentId) throw new AppError(400, 'ENVIRONMENT_REQUIRED', 'Environment scope required');
    const ok = await access.can(actor, {
      permissionKey: PERMISSIONS.PROJECT_LOGS_READ,
      resourceType: 'project',
      resourceId: projectId,
      environmentId,
    });
    if (!ok) throw new AppError(403, 'FORBIDDEN', 'No access for this project and environment');
  }

  async function transition(alert, rule, toStatus, { actorId = null, note } = {}) {
    const fromStatus = alert.status;
    await prisma.alert.update({ where: { id: alert.id }, data: { status: toStatus } });
    alert.status = toStatus;
    await prisma.alertEvent.create({ data: { alertId: alert.id, fromStatus, toStatus, at: now() } });
    await audit({
      actorId,
      action: `alert.${toStatus}`,
      resourceType: 'project',
      resourceId: rule?.scopeId ?? null,
      environmentId: rule?.thresholdJson?.environmentId ?? null,
      result: 'success',
      after: { alertId: alert.id, fromStatus, toStatus, note: note ?? null },
    });
  }

  async function ruleOf(alert) {
    return alert.ruleId ? prisma.metricRule.findUnique({ where: { id: alert.ruleId } }) : null;
  }

  /** Returns { firing, detail } or { state: 'unknown' } when there is nothing to judge (no sources). */
  async function condition(rule, at) {
    const t = rule.thresholdJson ?? {};
    const projectId = rule.scopeId;
    const environmentId = t.environmentId;
    const from = new Date(at.getTime() - t.windowMinutes * 60000);
    if (t.kind === 'error_count') {
      const n = store.query({ projectId, environmentId, minLevel: 'error', from, to: at }, { limit: 100000 }).length;
      return { firing: n >= t.threshold, detail: { errors: n, threshold: t.threshold } };
    }
    if (t.kind === 'intermittent') {
      const bucketMs = Math.max(60000, Math.floor((t.windowMinutes * 60000) / t.buckets));
      const rows = store.query({ projectId, environmentId, minLevel: 'error', from, to: at }, { limit: 100000 });
      const hit = new Set(rows.map((e) => Math.floor(new Date(e.ts).getTime() / bucketMs)));
      return { firing: hit.size >= t.minBuckets, detail: { bucketsWithErrors: hit.size, minBuckets: t.minBuckets } };
    }
    // no_data: only meaningful when a log source is registered for the project
    const sources = await prisma.logSource.count({ where: { projectId } });
    if (sources === 0) return { state: 'unknown', firing: false, detail: { reason: 'no log source registered' } };
    const any = store.query({ projectId, environmentId, from, to: at }, { limit: 1 });
    return { firing: any.length === 0, detail: { silentForMinutes: t.windowMinutes } };
  }

  const svc = {
    async createRule(input, actor) {
      if (!actor?.isOwner) throw new AppError(403, 'FORBIDDEN', 'Only the Owner can create alert rules');
      const project = await prisma.project.findUnique({ where: { id: input.projectId } });
      if (!project) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      if (input.threshold.environmentId) {
        const env = await prisma.projectEnvironment.findUnique({ where: { id: input.threshold.environmentId } });
        if (!env || env.projectId !== project.id) {
          throw new AppError(400, 'ENVIRONMENT_MISMATCH', 'Environment does not belong to the project');
        }
      }
      const rule = await prisma.metricRule.create({
        data: {
          scopeType: 'project',
          scopeId: input.projectId,
          metric: `log.${input.threshold.kind}`,
          thresholdJson: input.threshold,
          severity: input.severity,
        },
      });
      await audit({
        actorId: actor.id,
        action: 'alert.rule.create',
        resourceType: 'project',
        resourceId: input.projectId,
        result: 'success',
        after: { ruleId: rule.id, metric: rule.metric },
      });
      return rule;
    },

    async listRules({ projectId }, actor) {
      const rules = await prisma.metricRule.findMany({ where: { scopeType: 'project', scopeId: projectId } });
      const out = [];
      for (const r of rules) {
        try {
          await authorize(actor, projectId, r.thresholdJson?.environmentId);
          out.push(r);
        } catch {
          // rules outside the actor's scope stay hidden
        }
      }
      return out;
    },

    /** Evaluates one rule at `at`, applying dedup, reopen and auto-resolve. */
    async evaluateRule(rule, at = now()) {
      const result = await condition(rule, at);
      const fingerprint = `rule:${rule.id}`;
      const existing = await prisma.alert.findFirst({ where: { fingerprint } });
      if (result.state === 'unknown') return { action: 'unknown', ...result };
      if (result.firing) {
        if (!existing) {
          const alert = await prisma.alert.create({
            data: { ruleId: rule.id, severity: rule.severity, status: 'firing', fingerprint },
          });
          await prisma.alertEvent.create({ data: { alertId: alert.id, fromStatus: null, toStatus: 'firing', at } });
          await notifyOwners(
            { type: 'alert.opened', title: `Alert firing (${rule.severity})`, resourceType: 'alert', resourceId: alert.id },
            { prisma },
          );
          await audit({
            action: 'alert.firing',
            resourceType: 'project',
            resourceId: rule.scopeId,
            environmentId: rule.thresholdJson?.environmentId ?? null,
            result: 'success',
            after: { alertId: alert.id, ...result.detail },
          });
          return { action: 'created', alert, detail: result.detail };
        }
        if (existing.status === 'resolved') {
          await transition(existing, rule, 'firing', { note: 'reopened' });
          return { action: 'reopened', alert: existing, detail: result.detail };
        }
        return { action: 'deduplicated', alert: existing, detail: result.detail };
      }
      if (existing && OPEN.includes(existing.status)) {
        await transition(existing, rule, 'resolved', { note: 'condition cleared' });
        return { action: 'resolved', alert: existing, detail: result.detail };
      }
      return { action: 'ok', detail: result.detail };
    },

    async evaluateAll(at = now()) {
      const rules = await prisma.metricRule.findMany({ where: { scopeType: 'project' } });
      const out = [];
      for (const rule of rules) out.push({ ruleId: rule.id, ...(await svc.evaluateRule(rule, at)) });
      return out;
    },

    /** Escalates alerts that stayed unacknowledged past their rule's escalateAfterMinutes. */
    async escalateDue(at = now()) {
      const firing = await prisma.alert.findMany({ where: { status: 'firing' } });
      const escalated = [];
      for (const alert of firing) {
        const rule = await ruleOf(alert);
        const minutes = rule?.thresholdJson?.escalateAfterMinutes ?? 30;
        const events = await prisma.alertEvent.findMany({ where: { alertId: alert.id, toStatus: 'firing' } });
        const since = events.map((e) => new Date(e.at).getTime()).sort((a, b) => b - a)[0] ?? new Date(alert.createdAt).getTime();
        if (at.getTime() - since < minutes * 60000) continue;
        await transition(alert, rule, 'escalated', { note: `unacknowledged for ${minutes} minutes` });
        const owners = await prisma.user.findMany({ where: { ownerFlag: true } });
        for (const o of owners) {
          await prisma.notification.create({
            data: {
              userId: o.id,
              kind: 'alert.escalated',
              title: 'Alert escalated',
              body: `Alert ${alert.id} was not acknowledged`,
              linkJson: { alertId: alert.id },
            },
          });
        }
        escalated.push(alert.id);
      }
      return { escalated };
    },

    async list({ projectId, environmentId, status }, actor) {
      await authorize(actor, projectId, environmentId);
      const rules = await prisma.metricRule.findMany({ where: { scopeType: 'project', scopeId: projectId } });
      const scoped = rules.filter((r) => !environmentId || r.thresholdJson?.environmentId === environmentId);
      const alerts = await prisma.alert.findMany({
        where: { ruleId: { in: scoped.map((r) => r.id) }, ...(status ? { status } : {}) },
        orderBy: { createdAt: 'desc' },
      });
      return alerts.map((a) => ({ ...a, rule: scoped.find((r) => r.id === a.ruleId) ?? null }));
    },

    async acknowledge(alertId, input, actor) {
      const alert = await prisma.alert.findUnique({ where: { id: alertId } });
      if (!alert) throw new AppError(404, 'ALERT_NOT_FOUND', 'Alert not found');
      const rule = await ruleOf(alert);
      await authorize(actor, rule?.scopeId, rule?.thresholdJson?.environmentId);
      if (!['firing', 'escalated'].includes(alert.status)) {
        throw new AppError(409, 'ALERT_NOT_ACKNOWLEDGEABLE', `Alert is ${alert.status}`);
      }
      await transition(alert, rule, 'acknowledged', { actorId: actor.id, note: input?.note });
      return alert;
    },

    async resolve(alertId, input, actor) {
      const alert = await prisma.alert.findUnique({ where: { id: alertId } });
      if (!alert) throw new AppError(404, 'ALERT_NOT_FOUND', 'Alert not found');
      const rule = await ruleOf(alert);
      await authorize(actor, rule?.scopeId, rule?.thresholdJson?.environmentId);
      if (!OPEN.includes(alert.status)) throw new AppError(409, 'ALERT_NOT_OPEN', `Alert is ${alert.status}`);
      await transition(alert, rule, 'resolved', { actorId: actor.id, note: input?.note });
      return alert;
    },
  };
  return svc;
}
