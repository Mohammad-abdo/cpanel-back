import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { isSystemActor, SYSTEM_ACTOR } from '../../common/system-actor.js';
import { sha256 } from '../platform/platform.crypto.js';
import { CRON_COMMANDS, buildCronScript, commandFor, parseCronOutput, redactOutput } from './cron.commands.js';
import { nextRun, nextRuns, parseCron } from './cron.parser.js';

/** Custom (non-allowlisted) commands are High risk: see ACTION_RISK in platform.risk.js. */
export const CRON_CUSTOM_ACTION = 'cron.custom.command';
export const MAX_JOBS_PER_PROJECT = 50;
const OVERLAP_GRACE_MS = 60_000;
const DUE_BATCH = 50;
const DUE_CONCURRENCY = 5;

const schemaRequired = () => new AppError(501, 'SCHEMA_REQUIRED', 'Cron tables are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');
const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|CronJob|CronRun/i;

export function createCronService({ prisma, auditService = null, rbac = null, platform = null, serverAccessService = null, now = () => new Date() }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'project', ...event }) : null);
  const scope = createScope({ prisma, now });
  const inflight = new Set();

  const jobs = () => {
    if (!prisma?.cronJob) throw schemaRequired();
    return prisma.cronJob;
  };
  const runsTable = () => {
    if (!prisma?.cronRun) throw schemaRequired();
    return prisma.cronRun;
  };
  async function guard(fn) {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (STALE.test(String(e?.message))) throw schemaRequired();
      throw e;
    }
  }

  async function loadProject(projectId) {
    const p = await prisma.project.findUnique({ where: { id: projectId } });
    if (!p || p.archivedAt) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
    return p;
  }

  /** Owner, or project.configure on any environment of the project. Everyone else is denied. */
  async function requireWrite(actor, projectId) {
    if (isSystemActor(actor) || actor?.isOwner) return;
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (rbac?.can) {
      const envs = (await prisma.projectEnvironment?.findMany?.({ where: { projectId } })) ?? [];
      for (const env of envs) {
        if (await rbac.can(actor, { permissionKey: 'project.configure', resourceType: 'project', resourceId: projectId, environmentId: env.id })) return;
      }
    }
    throw new AppError(403, 'FORBIDDEN', 'You need project.configure on this project to manage cron jobs');
  }

  async function requireVisible(actor, projectId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    await scope.requireProject(actor, projectId, 'PROJECT_NOT_FOUND', 'Project not found');
    return loadProject(projectId);
  }

  async function loadJob(projectId, jobId) {
    const j = await guard(() => jobs().findUnique({ where: { id: jobId } }));
    if (!j || j.projectId !== projectId || j.archivedAt) throw new AppError(404, 'CRON_JOB_NOT_FOUND', 'Cron job not found');
    return j;
  }

  const view = (j) => ({
    id: j.id,
    projectId: j.projectId,
    serverId: j.serverId,
    name: j.name,
    schedule: j.schedule,
    commandKey: j.commandKey,
    custom: !j.commandKey,
    customCommand: j.commandKey ? null : j.customCommand,
    workDir: j.workDir,
    enabled: j.enabled,
    timeoutSec: j.timeoutSec,
    nextRunAt: j.nextRunAt,
    lastRunAt: j.lastRunAt,
    lastStatus: j.lastStatus,
    createdAt: j.createdAt,
  });

  const nextFor = (schedule, enabled, from = now()) => (enabled ? nextRun(schedule, from) : null);

  /** Gate for custom commands. `binding` ties an approval to the exact command + schedule + dir (+ job for run-now). */
  async function gateCustom({ projectId, binding, input, command, actor, verb }) {
    if (isSystemActor(actor)) throw new AppError(403, 'FORBIDDEN', 'System jobs cannot approve custom commands');
    if (!platform?.gate) throw new AppError(500, 'GATE_UNAVAILABLE', 'Approval service is not wired');
    return platform.gate(
      {
        action: CRON_CUSTOM_ACTION,
        binding: sha256(binding),
        resourceType: 'project',
        resourceId: projectId,
        approvalId: input.approvalId,
        reason: input.reason,
        impact: [`${verb} custom cron command on the project server`, `Command: ${command.slice(0, 200)}`, 'The command runs with the SSH login of this server'],
        rollbackPlan: input.rollbackNote,
        context: { verb },
      },
      actor,
    );
  }

  /** Runs one job over SSH and records a CronRun. Used by the schedule tick and by run-now. */
  async function execute(job, { trigger, actorId = null }) {
    if (!serverAccessService?.runRemote) throw new AppError(500, 'SSH_UNAVAILABLE', 'Server access is not wired');
    const t0 = now();
    // Overlap prevention: in this process and across processes (a recent `running` row).
    const recent = await runsTable().findFirst({ where: { jobId: job.id, status: 'running', startedAt: { gte: new Date(t0.getTime() - (job.timeoutSec * 1000 + OVERLAP_GRACE_MS)) } } });
    if (inflight.has(job.id) || recent) {
      if (trigger === 'manual') throw new AppError(409, 'CRON_ALREADY_RUNNING', 'This job is still running');
      await runsTable().create({ data: { jobId: job.id, status: 'skipped', trigger, startedAt: t0, finishedAt: t0, outputTail: 'Skipped: previous run still active', actorId } });
      return { status: 'skipped' };
    }
    inflight.add(job.id);
    let run;
    try {
      run = await runsTable().create({ data: { jobId: job.id, status: 'running', trigger, startedAt: t0, actorId } });
      let status = 'failure';
      let exitCode = null;
      let output = '';
      try {
        const script = buildCronScript({ workDir: job.workDir, command: commandFor(job), timeoutSec: job.timeoutSec });
        const res = await serverAccessService.runRemote(job.serverId, ({ run: exec }) => exec(script, { timeoutMs: (job.timeoutSec + 20) * 1000, maxBytes: 128 * 1024 }));
        const parsed = parseCronOutput(res.stdout);
        exitCode = parsed.exitCode ?? res.code ?? null;
        output = parsed.output;
        if (res.timedOut || exitCode === 124 || exitCode === 137) status = 'timeout';
        else status = exitCode === 0 ? 'success' : 'failure';
      } catch (e) {
        output = `Execution error: ${e?.code ?? e?.message ?? 'unknown'}`;
      }
      const finished = now();
      const tail = redactOutput(output);
      await runsTable().update({ where: { id: run.id }, data: { status, exitCode, finishedAt: finished, outputTail: tail } });
      await jobs().update({ where: { id: job.id }, data: { lastRunAt: t0, lastStatus: status } });
      await audit({ actorId: actorId ?? undefined, action: 'cron.run', resourceId: job.projectId, result: status === 'success' ? 'success' : 'failure', after: { jobId: job.id, trigger, status, exitCode } });
      return { status, exitCode, runId: run.id, outputTail: tail };
    } finally {
      inflight.delete(job.id);
    }
  }

  return {
    commands: () => Object.entries(CRON_COMMANDS).map(([key, v]) => ({ key, label: v.label, command: v.command })),

    previewSchedule({ schedule, count = 5 }) {
      parseCron(schedule);
      return { schedule, timezone: 'UTC', next: nextRuns(schedule, now(), count).map((d) => d.toISOString()) };
    },

    async list(projectId, actor) {
      await requireVisible(actor, projectId);
      const rows = await guard(() => jobs().findMany({ where: { projectId, archivedAt: null }, orderBy: { createdAt: 'asc' }, take: 200 }));
      return rows.map(view);
    },

    async create(projectId, input, actor) {
      await requireWrite(actor, projectId);
      const project = await loadProject(projectId);
      const count = await guard(() => jobs().count({ where: { projectId, archivedAt: null } }));
      if (count >= MAX_JOBS_PER_PROJECT) throw new AppError(409, 'CRON_LIMIT', `A project can have at most ${MAX_JOBS_PER_PROJECT} cron jobs`);
      const custom = !input.commandKey;
      if (custom) {
        const gate = await gateCustom({ projectId, binding: JSON.stringify({ v: 'create', projectId, s: input.schedule, c: input.customCommand, d: input.workDir }), input, command: input.customCommand, actor, verb: 'Create' });
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      }
      const t = now();
      const row = await guard(() =>
        jobs().create({
          data: {
            projectId,
            serverId: project.serverId,
            name: input.name,
            schedule: input.schedule,
            commandKey: input.commandKey ?? null,
            customCommand: custom ? input.customCommand : null,
            workDir: input.workDir,
            enabled: input.enabled,
            timeoutSec: input.timeoutSec,
            nextRunAt: nextFor(input.schedule, input.enabled, t),
            approvalId: custom ? input.approvalId ?? null : null,
            createdById: actor.id ?? null,
          },
        }),
      );
      await audit({ actorId: actor.id, action: 'cron.create', resourceId: projectId, result: 'success', after: { jobId: row.id, schedule: row.schedule, commandKey: row.commandKey, custom, enabled: row.enabled } });
      return view(row);
    },

    async update(projectId, jobId, input, actor) {
      await requireWrite(actor, projectId);
      const job = await loadJob(projectId, jobId);
      const next = { ...job, ...Object.fromEntries(Object.entries(input).filter(([k]) => ['name', 'schedule', 'workDir', 'enabled', 'timeoutSec'].includes(k))) };
      if (input.commandKey) {
        next.commandKey = input.commandKey;
        next.customCommand = null;
      } else if (input.customCommand) {
        next.commandKey = null;
        next.customCommand = input.customCommand;
      }
      const customChanged = !next.commandKey && (input.customCommand !== undefined || input.workDir !== undefined || input.schedule !== undefined);
      if (customChanged) {
        const gate = await gateCustom({ projectId, binding: JSON.stringify({ v: 'update', jobId, s: next.schedule, c: next.customCommand, d: next.workDir }), input, command: next.customCommand, actor, verb: 'Change' });
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      }
      const row = await guard(() =>
        jobs().update({
          where: { id: jobId },
          data: {
            name: next.name,
            schedule: next.schedule,
            commandKey: next.commandKey,
            customCommand: next.customCommand,
            workDir: next.workDir,
            enabled: next.enabled,
            timeoutSec: next.timeoutSec,
            nextRunAt: nextFor(next.schedule, next.enabled),
          },
        }),
      );
      await audit({ actorId: actor.id, action: 'cron.update', resourceId: projectId, result: 'success', before: { jobId, schedule: job.schedule, enabled: job.enabled }, after: { jobId, schedule: row.schedule, enabled: row.enabled, custom: !row.commandKey } });
      return view(row);
    },

    async remove(projectId, jobId, actor) {
      await requireWrite(actor, projectId);
      await loadJob(projectId, jobId);
      await guard(() => jobs().update({ where: { id: jobId }, data: { archivedAt: now(), enabled: false, nextRunAt: null } }));
      await audit({ actorId: actor.id, action: 'cron.delete', resourceId: projectId, result: 'success', after: { jobId } });
      return { removed: true };
    },

    async runs(projectId, jobId, { limit = 25 } = {}, actor) {
      await requireVisible(actor, projectId);
      await loadJob(projectId, jobId);
      const rows = await guard(() => runsTable().findMany({ where: { jobId }, orderBy: { startedAt: 'desc' }, take: limit }));
      return rows.map((r) => ({ id: r.id, status: r.status, trigger: r.trigger, startedAt: r.startedAt, finishedAt: r.finishedAt, exitCode: r.exitCode, outputTail: r.outputTail }));
    },

    /** Manual run. Allowlisted commands run directly (project.configure); custom commands need a fresh approval. */
    async runNow(projectId, jobId, input, actor) {
      await requireWrite(actor, projectId);
      const job = await loadJob(projectId, jobId);
      if (!job.commandKey) {
        const gate = await gateCustom({ projectId, binding: JSON.stringify({ v: 'run', jobId, s: job.schedule, c: job.customCommand, d: job.workDir }), input: input ?? {}, command: job.customCommand, actor, verb: 'Run now' });
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      }
      return guard(() => execute(job, { trigger: 'manual', actorId: actor.id }));
    },

    /**
     * Worker tick: claims every due enabled job (compare-and-set on nextRunAt so two workers never run the same slot),
     * then runs them with bounded concurrency. Errors in one job never stop the others.
     */
    async runDue(at = now()) {
      const due = await guard(() => jobs().findMany({ where: { enabled: true, archivedAt: null, nextRunAt: { lte: at } }, orderBy: { nextRunAt: 'asc' }, take: DUE_BATCH }));
      const claimed = [];
      for (const j of due) {
        const claim = await jobs().updateMany({ where: { id: j.id, nextRunAt: j.nextRunAt }, data: { nextRunAt: nextRun(j.schedule, at) } });
        if (claim.count === 1) claimed.push(j);
      }
      const results = [];
      for (let i = 0; i < claimed.length; i += DUE_CONCURRENCY) {
        const batch = claimed.slice(i, i + DUE_CONCURRENCY);
        const settled = await Promise.allSettled(batch.map((j) => execute(j, { trigger: 'schedule', actorId: null })));
        settled.forEach((s, k) => results.push({ jobId: batch[k].id, status: s.status === 'fulfilled' ? s.value.status : 'error' }));
      }
      return results;
    },

    execute,
    SYSTEM_ACTOR,
  };
}
