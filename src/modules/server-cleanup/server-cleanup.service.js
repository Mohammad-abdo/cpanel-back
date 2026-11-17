import { AppError } from '../../common/errors/app-error.js';
import { isSystemActor } from '../../common/system-actor.js';
import { sha256 } from '../platform/platform.crypto.js';
import { CLEANUP_TASKS, applyScript, enabledTasks, parseCleanupOutput, previewScript } from './server-cleanup.scripts.js';

export const CLEANUP_ACTION = 'server.cleanup.apply';

export function createServerCleanupService({ prisma, auditService = null, platform = null, serverAccessService = null, env = process.env }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'server', ...event }) : null);

  function requireOwner(actor) {
    if (isSystemActor(actor)) throw new AppError(403, 'OWNER_ONLY', 'Cleanup cannot run from a scheduled job');
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can clean up a server');
  }
  async function loadServer(serverId) {
    const s = await prisma.server.findUnique({ where: { id: serverId } });
    if (!s || s.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
    return s;
  }
  /** Per-task allowlist: unknown keys never reach a script, disabled tasks (docker prune by default) are refused. */
  function assertAllowed(tasks) {
    const enabled = new Map(enabledTasks(env).map((t) => [t.key, t.enabled]));
    for (const t of tasks) {
      if (!CLEANUP_TASKS[t]) throw new AppError(422, 'CLEANUP_TASK_UNKNOWN', `Unknown cleanup task ${t}`);
      if (!enabled.get(t)) throw new AppError(409, 'CLEANUP_TASK_DISABLED', `Cleanup task ${t} is disabled on this panel`);
    }
  }
  const remote = (serverId, script, timeoutMs) => {
    if (!serverAccessService?.runRemote) throw new AppError(500, 'SSH_UNAVAILABLE', 'Server access is not wired');
    return serverAccessService.runRemote(serverId, async ({ run }) => {
      const res = await run(script, { timeoutMs, maxBytes: 128 * 1024 });
      if (res.timedOut) throw new AppError(504, 'CLEANUP_TIMEOUT', 'The cleanup command timed out');
      return res;
    });
  };

  return {
    async tasks(serverId, actor) {
      requireOwner(actor);
      await loadServer(serverId);
      return enabledTasks(env);
    },

    /** Dry run: sizes only, nothing is deleted. */
    async preview(serverId, { tasks }, actor) {
      requireOwner(actor);
      await loadServer(serverId);
      assertAllowed(tasks);
      const res = await remote(serverId, previewScript(tasks), 90_000);
      const parsed = parseCleanupOutput(res.stdout);
      const rows = tasks.map((t) => ({ task: t, label: CLEANUP_TASKS[t].label, risk: CLEANUP_TASKS[t].risk, bytes: parsed[t]?.bytes ?? null, items: parsed[t]?.items ?? [], unavailable: parsed[t]?.unavailable ?? null }));
      return { tasks: rows, totalBytes: rows.reduce((n, r) => n + (r.bytes ?? 0), 0), dryRun: true };
    },

    async apply(serverId, { tasks, reason, rollbackNote, approvalId }, actor) {
      requireOwner(actor);
      await loadServer(serverId);
      assertAllowed(tasks);
      if (!platform?.gate) throw new AppError(500, 'GATE_UNAVAILABLE', 'Approval service is not wired');
      const sorted = [...tasks].sort();
      const gate = await platform.gate(
        {
          action: CLEANUP_ACTION,
          binding: sha256(JSON.stringify({ serverId, tasks: sorted })),
          resourceType: 'server',
          resourceId: serverId,
          approvalId,
          reason,
          impact: sorted.map((t) => `${CLEANUP_TASKS[t].label} will be deleted (not recoverable)`),
          rollbackPlan: rollbackNote,
          context: { tasks: sorted },
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      const before = parseCleanupOutput((await remote(serverId, previewScript(sorted), 90_000)).stdout);
      const res = await remote(serverId, applyScript(sorted), 300_000);
      const after = parseCleanupOutput(res.stdout);
      const results = sorted.map((t) => ({ task: t, ok: after[t]?.status === 'ok', estimatedFreedBytes: before[t]?.bytes ?? null }));
      const ok = results.every((r) => r.ok);
      await audit({ actorId: actor.id, action: 'server.cleanup', resourceId: serverId, result: ok ? 'success' : 'failure', before: { tasks: sorted, sizes: Object.fromEntries(sorted.map((t) => [t, before[t]?.bytes ?? null])) }, after: { results } });
      return { applied: true, ok, results };
    },
  };
}
