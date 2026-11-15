import { PERMISSIONS } from '../../common/permission-catalog.js';
import { AppError } from '../../common/errors/app-error.js';
import { collectFacts } from '../activity/activity.service.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { createMemoryArtifactStore, createFileArtifactStore } from './reports.artifacts.js';
import { buildReport, REPORT_TYPES } from './reports.metrics.js';
import { createRendererRegistry } from './reports.render.js';
import { lastDue, parseCron, periodFor } from './reports.schedule.js';

const DAY = 86400000;

export function createReportsService({
  prisma,
  now = () => new Date(),
  auditService = null,
  rbac = null,
  // Durable disk store when a real Prisma client is wired (API runtime); mocks (tests) get memory.
  artifactStore = typeof prisma?.$connect === 'function' ? createFileArtifactStore() : createMemoryArtifactStore(),
  renderers = createRendererRegistry(),
  artifactTtlMs = 7 * DAY,
}) {
  const access = rbac ?? createRbacService({ prisma, now });
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  /** Owner, or exact project grant for report.team.export. Individual reports: the subject or the Owner. */
  async function isAuthorized(actor, { type, projectId, userId }) {
    if (!actor?.id) return false;
    if (actor.isOwner) return true;
    if (type === 'individual-activity') return Boolean(userId) && actor.id === userId;
    if (!projectId) return false;
    return access.can(actor, {
      permissionKey: PERMISSIONS.REPORT_TEAM_EXPORT,
      resourceType: 'project',
      resourceId: projectId,
      environmentId: null,
    });
  }

  async function authorize(actor, params) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!REPORT_TYPES.includes(params.type)) throw new AppError(400, 'REPORT_TYPE_INVALID', 'Unknown report type');
    if (params.type === 'individual-activity' && !params.userId) {
      throw new AppError(400, 'USER_REQUIRED', 'userId is required for individual reports');
    }
    if (params.type !== 'individual-activity' && !params.projectId) {
      throw new AppError(400, 'PROJECT_REQUIRED', 'projectId is required for this report');
    }
    if (!(await isAuthorized(actor, params))) {
      await audit({
        actorId: actor.id,
        action: 'report.generate',
        resourceType: 'project',
        resourceId: params.projectId ?? null,
        result: 'denied',
        after: { type: params.type },
      });
      throw new AppError(403, 'FORBIDDEN', 'Not authorized for this report');
    }
  }

  /** Fills kind/projectId/paramsJson from the legacy packed fields (code = kind:slug, paramsSchemaJson) when the new columns are empty. */
  function withDefinitionFields(row) {
    const packed = row.paramsSchemaJson ?? {};
    return {
      ...row,
      kind: row.kind ?? packed.kind ?? (row.code?.includes(':') ? row.code.split(':')[0] : row.code ?? null),
      projectId: row.projectId ?? packed.projectId ?? null,
      paramsJson: row.paramsJson ?? packed.params ?? {},
    };
  }

  async function ensureDefinition(type) {
    const existing = await prisma.reportDefinition.findFirst({ where: { code: type } });
    if (existing) return existing;
    return prisma.reportDefinition.create({ data: { code: type, name: type.replace(/-/g, ' ') } });
  }

  async function compute(params) {
    const from = new Date(params.from);
    const to = new Date(params.to);
    if (!(from < to)) throw new AppError(400, 'PERIOD_INVALID', 'from must be before to');
    const facts = await collectFacts(prisma, { projectId: params.projectId, userId: params.userId, from, to });
    const users = await prisma.user.findMany({ where: {} });
    const names = new Map(users.map((u) => [u.id, u.displayName ?? u.id]));
    return buildReport(params.type, facts, {
      from, to, userId: params.userId ?? null, projectId: params.projectId ?? null, label: (id) => names.get(id) ?? id,
    });
  }

  /** Renders and stores one artifact per format. Throws before creating a run if a format is unavailable. */
  async function generate(params, { requestedById, formats, keyPrefix }) {
    const chosen = formats.map((f) => renderers.get(f));
    const report = await compute(params);
    const definition = await ensureDefinition(params.type);
    const run = await prisma.reportRun.create({
      data: {
        definitionId: definition.id,
        requestedById: requestedById ?? null,
        status: 'completed',
        periodStart: new Date(params.from),
        periodEnd: new Date(params.to),
      },
    });
    const artifacts = [];
    for (const r of chosen) {
      const ref = `${keyPrefix ?? `run-${run.id}`}/${r.format}.${r.extension}`;
      await artifactStore.put(ref, r.render(report), {
        contentType: r.contentType,
        filename: `${params.type}.${r.extension}`,
        expiresAt: new Date(now().getTime() + artifactTtlMs),
        params: { type: params.type, projectId: params.projectId ?? null, userId: params.userId ?? null },
      });
      artifacts.push(await prisma.reportArtifact.create({ data: { reportRunId: run.id, format: r.format, locationRef: ref } }));
    }
    return { run, artifacts, report };
  }

  const svc = {
    async listDefinitions({ limit }) {
      const rows = await prisma.reportDefinition.findMany({ take: limit, orderBy: { name: 'asc' }, include: { schedules: true } });
      return rows.map(withDefinitionFields);
    },

    /** Registers a named definition in kind/projectId/paramsJson (code = kind:slug stays the unique key). */
    async createDefinition(input, actor) {
      const userId = input.paramsJson?.userId;
      await authorize(actor, { type: input.kind, projectId: input.projectId, userId });
      const slug = input.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      const code = `${input.kind}:${slug}`;
      if (await prisma.reportDefinition.findFirst({ where: { code } })) throw new AppError(409, 'REPORT_DEFINITION_EXISTS', 'A definition with this name already exists');
      // paramsSchemaJson is still written for backward compatibility with readers of the packed form.
      const legacy = { code, name: input.name, paramsSchemaJson: { kind: input.kind, projectId: input.projectId ?? null, params: input.paramsJson ?? {} } };
      let row;
      let schemaPending = false;
      try {
        row = await prisma.reportDefinition.create({ data: { ...legacy, kind: input.kind, projectId: input.projectId ?? null, paramsJson: input.paramsJson ?? {} } });
      } catch (err) {
        // Stale generated client: retry with the legacy packed fields only and flag it.
        if (!/Unknown argument/i.test(String(err?.message))) throw err;
        row = await prisma.reportDefinition.create({ data: legacy });
        schemaPending = true;
      }
      await audit({ actorId: actor.id, action: 'report.definition.create', resourceType: 'project', resourceId: input.projectId ?? null, result: 'success', after: { definitionId: row.id, code, kind: input.kind } });
      return withDefinitionFields(schemaPending ? { ...row, schemaPending: true } : row);
    },

    /** Live aggregate with event lineage; nothing is stored. */
    async preview(params, actor) {
      await authorize(actor, params);
      return compute(params);
    },

    async createRun(params, actor) {
      await authorize(actor, params);
      const out = await generate(params, { requestedById: actor.id, formats: params.formats ?? ['csv'] });
      await audit({
        actorId: actor.id,
        action: 'report.generate',
        resourceType: 'project',
        resourceId: params.projectId ?? null,
        result: 'success',
        after: { runId: out.run.id, type: params.type, formats: params.formats },
      });
      return out;
    },

    async getRun(id, actor) {
      const run = await prisma.reportRun.findUnique({ where: { id } });
      if (!run) throw new AppError(404, 'REPORT_RUN_NOT_FOUND', 'Report run not found');
      if (run.requestedById !== actor?.id && !actor?.isOwner) {
        const artifact = (await prisma.reportArtifact.findMany({ where: { reportRunId: id } }))[0];
        const meta = artifact ? await artifactStore.get(artifact.locationRef) : null;
        if (!meta || !(await isAuthorized(actor, meta.params))) throw new AppError(403, 'FORBIDDEN', 'Not authorized for this report');
      }
      const artifacts = await prisma.reportArtifact.findMany({ where: { reportRunId: id } });
      return { ...run, artifacts };
    },

    /** Authorization is re-checked on every download, so revoked recipients are rejected. */
    async downloadArtifact(artifactId, actor) {
      const artifact = await prisma.reportArtifact.findUnique({ where: { id: artifactId } });
      if (!artifact) throw new AppError(404, 'ARTIFACT_NOT_FOUND', 'Artifact not found');
      const stored = await artifactStore.get(artifact.locationRef);
      if (!stored) throw new AppError(404, 'ARTIFACT_NOT_FOUND', 'Artifact content is no longer available');
      await authorize(actor, stored.params);
      if (new Date(stored.expiresAt) <= now()) throw new AppError(410, 'ARTIFACT_EXPIRED', 'Artifact has expired');
      await audit({
        actorId: actor.id,
        action: 'report.download',
        resourceType: 'report_artifact',
        resourceId: artifactId,
        result: 'success',
      });
      return { contentType: stored.contentType, filename: stored.filename, body: stored.body };
    },

    // ─── TASK-016: scheduled summaries ──────────────────────────────

    async createSchedule(input, actor) {
      const params = { type: input.type, projectId: input.projectId, userId: input.userId };
      await authorize(actor, params);
      if (!parseCron(input.cron)) throw new AppError(400, 'CRON_INVALID', 'Unsupported cron expression');
      for (const f of input.formats) renderers.get(f); // reject PDF/Excel until a renderer is approved
      const recipients = [...new Set(input.recipients)];
      for (const userId of recipients) {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        const recipient = user && !user.disabledAt && user.status === 'active' ? { id: user.id, isOwner: user.ownerFlag } : null;
        if (!recipient || !(await isAuthorized(recipient, params))) {
          throw new AppError(400, 'RECIPIENT_NOT_AUTHORIZED', 'Every recipient must be authorized for this report');
        }
      }
      const definition = await ensureDefinition(input.type);
      const schedule = await prisma.reportSchedule.create({
        data: {
          definitionId: definition.id,
          cron: input.cron,
          enabled: true,
          recipientsJson: { recipients, params: { ...params, period: input.period }, formats: input.formats, createdById: actor.id },
        },
      });
      await audit({
        actorId: actor.id,
        action: 'report.schedule.create',
        resourceType: 'project',
        resourceId: input.projectId ?? null,
        result: 'success',
        after: { scheduleId: schedule.id, recipients: recipients.length, cron: input.cron },
      });
      return schedule;
    },

    async listSchedules(actor) {
      const rows = await prisma.reportSchedule.findMany({ where: {}, take: 200 });
      const out = [];
      for (const s of rows) {
        if (actor?.isOwner || s.recipientsJson?.createdById === actor?.id || (await isAuthorized(actor, s.recipientsJson?.params ?? {}))) out.push(s);
      }
      return out;
    },

    async setScheduleEnabled(id, enabled, actor) {
      const s = await prisma.reportSchedule.findUnique({ where: { id } });
      if (!s) throw new AppError(404, 'SCHEDULE_NOT_FOUND', 'Schedule not found');
      if (!actor?.isOwner && s.recipientsJson?.createdById !== actor?.id) throw new AppError(403, 'FORBIDDEN', 'Not allowed');
      const updated = await prisma.reportSchedule.update({ where: { id }, data: { enabled } });
      await audit({ actorId: actor.id, action: enabled ? 'report.schedule.enable' : 'report.schedule.disable', resourceType: 'report_schedule', resourceId: id, result: 'success' });
      return updated;
    },

    /**
     * Executes one schedule for its most recent due period. Idempotent per (schedule, period): a retry
     * returns the existing run. Recipients are re-validated now; revoked ones are skipped and audited.
     */
    async runSchedule(schedule, at = now()) {
      if (!schedule.enabled) return { action: 'disabled' };
      const cfg = schedule.recipientsJson ?? {};
      const due = lastDue(schedule.cron, at);
      if (!due) return { action: 'invalid-cron' };
      if (schedule.createdAt && due < new Date(schedule.createdAt)) return { action: 'not-due' }; // no backfill
      const { from, to } = periodFor(cfg.params.period, due);
      const key = `sched-${schedule.id}-${from.toISOString()}`;
      const dup = await prisma.reportArtifact.findFirst({ where: { locationRef: { startsWith: key } } });
      if (dup) return { action: 'duplicate', runId: dup.reportRunId };

      const params = { ...cfg.params, from: from.toISOString(), to: to.toISOString() };
      const keep = [];
      const revoked = [];
      for (const userId of cfg.recipients ?? []) {
        const user = await prisma.user.findUnique({ where: { id: userId } });
        const recipient = user && !user.disabledAt && user.status === 'active' ? { id: user.id, isOwner: user.ownerFlag } : null;
        if (recipient && (await isAuthorized(recipient, params))) keep.push(userId);
        else revoked.push(userId);
      }
      if (revoked.length > 0) {
        await audit({
          action: 'report.schedule.recipient_rejected',
          resourceType: 'report_schedule',
          resourceId: schedule.id,
          result: 'denied',
          after: { recipients: revoked },
        });
      }
      if (keep.length === 0) return { action: 'no-recipients', revoked };
      const out = await generate(params, { requestedById: null, formats: cfg.formats ?? ['csv'], keyPrefix: key });
      for (const userId of keep) {
        await prisma.notification.create({
          data: {
            userId,
            kind: 'report.ready',
            title: `Scheduled report ready: ${params.type}`,
            linkJson: { runId: out.run.id, artifactIds: out.artifacts.map((a) => a.id) },
          },
        });
      }
      await audit({
        action: 'report.schedule.run',
        resourceType: 'report_schedule',
        resourceId: schedule.id,
        result: 'success',
        after: { runId: out.run.id, delivered: keep.length, skipped: revoked.length },
      });
      return { action: 'created', runId: out.run.id, delivered: keep, skipped: revoked };
    },

    /** Worker entry point: runs every enabled schedule that is due. */
    async runDue(at = now()) {
      const rows = await prisma.reportSchedule.findMany({ where: { enabled: true }, take: 500 });
      const results = [];
      for (const s of rows) results.push({ scheduleId: s.id, ...(await svc.runSchedule(s, at)) });
      return results;
    },
  };
  return svc;
}
