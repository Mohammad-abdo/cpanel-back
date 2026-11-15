import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { sha256 } from '../platform/platform.crypto.js';

/** select -> validate -> impact preview -> approval -> safety backup -> restore -> health -> audit */
export const RESTORE_TRANSITIONS = Object.freeze({
  selected: ['validated', 'failed'],
  validated: ['awaiting_approval', 'failed'],
  awaiting_approval: ['approved', 'rejected', 'failed'],
  approved: ['safety_backup', 'failed'],
  safety_backup: ['restoring', 'failed'],
  restoring: ['health_check', 'failed'],
  health_check: ['completed', 'failed'],
  completed: [],
  failed: [],
  rejected: [],
});

export function createRestoresService({ prisma, now = () => new Date(), auditService = null, rbac = null, platform = null, adapters = null, backups = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function authorize(actor, projectId, environmentId) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const env = await prisma.projectEnvironment.findUnique({ where: { id: environmentId } });
    if (!env || env.projectId !== projectId) throw new AppError(409, 'ENVIRONMENT_PROJECT_MISMATCH', 'Environment does not belong to this project');
    await assertCan(rbac, actor, { permissionKey: PERM.BACKUP_RESTORE, resourceType: 'project', resourceId: projectId, environmentId });
  }

  async function move(run, to, extra = {}) {
    if (!RESTORE_TRANSITIONS[run.status]?.includes(to)) {
      throw new AppError(409, 'INVALID_RESTORE_TRANSITION', `Cannot move restore from ${run.status} to ${to}`);
    }
    const updated = await prisma.restoreRun.update({ where: { id: run.id }, data: { status: to, ...extra } });
    return { ...run, ...updated };
  }

  const scope = createScope({ prisma, now });

  async function loadArtifact(artifactId) {
    const a = await prisma.backupArtifact.findUnique({ where: { id: artifactId }, include: { backupRun: { include: { policy: true } } } });
    if (!a) throw new AppError(404, 'ARTIFACT_NOT_FOUND', 'Restore point not found');
    return a;
  }

  return {
    async listRestorePoints({ projectId, limit }, actor) {
      const projectClause = await scope.projectClause(actor, projectId);
      const runs = await prisma.backupRun.findMany({ where: { status: 'retained', verificationStatus: 'verified', policy: { projectId: projectClause ?? projectId } }, take: limit, orderBy: { finishedAt: 'desc' }, include: { artifacts: true, policy: true } });
      return runs.map((r) => ({ runId: r.id, finishedAt: r.finishedAt, environmentId: r.policy.environmentId, artifacts: r.artifacts.filter((a) => a.kind !== 'manifest').map((a) => ({ id: a.id, kind: a.kind, checksum: a.checksum })) }));
    },

    async get(id, actor) {
      const run = await prisma.restoreRun.findUnique({ where: { id } });
      if (!run) throw new AppError(404, 'RESTORE_NOT_FOUND', 'Restore not found');
      if (!actor?.isOwner) {
        const artifact = await prisma.backupArtifact.findUnique({ where: { id: run.artifactId }, include: { backupRun: { include: { policy: true } } } });
        if (!(await scope.canSeeProject(actor, artifact?.backupRun?.policy?.projectId))) throw new AppError(404, 'RESTORE_NOT_FOUND', 'Restore not found');
      }
      return run;
    },

    /** Steps select, validate and impact preview, then opens the approval request. Nothing is restored. */
    async request(input, actor) {
      const artifact = await loadArtifact(input.artifactId);
      const { policy } = artifact.backupRun;
      if (artifact.kind === 'manifest') throw new AppError(422, 'NOT_RESTORABLE', 'A manifest cannot be restored');
      if (policy.environmentId && policy.environmentId !== input.targetEnvironmentId) {
        throw new AppError(409, 'ENVIRONMENT_MISMATCH', 'Backup belongs to a different environment than the restore target');
      }
      await authorize(actor, policy.projectId, input.targetEnvironmentId);
      if (artifact.backupRun.status !== 'retained' || artifact.backupRun.verificationStatus !== 'verified') {
        throw new AppError(409, 'BACKUP_NOT_RESTORABLE', 'Only verified, retained backup sets can be restored');
      }
      try {
        await backups.verifyArtifactBytes(artifact);
      } catch (err) {
        await audit({ actorId: actor.id, action: 'restore.request', resourceType: 'backup_artifact', resourceId: artifact.id, environmentId: input.targetEnvironmentId, result: 'denied', metadata: { code: err.code } });
        throw new AppError(422, 'CORRUPT_BACKUP', `Restore point failed validation: ${err.code ?? 'unreadable'}`);
      }
      const preview = await adapters.backupEngine.impact({ mode: input.mode, kind: artifact.kind, projectId: policy.projectId });
      const run = await prisma.restoreRun.create({ data: { artifactId: artifact.id, status: 'selected', isolatedTrial: input.mode === 'isolated' } });
      let state = await move(run, 'validated');
      const action = input.mode === 'inplace' ? 'backup.restore.inplace' : 'backup.restore.isolated';
      const impact = [
        input.mode === 'inplace' ? `Overwrites live ${artifact.kind} data of the target environment` : `Restores ${artifact.kind} into an isolated trial area; production is untouched`,
        `Estimated downtime ${preview.estimatedDowntimeSeconds ?? 'UNKNOWN'}s`,
        input.mode === 'inplace' ? 'A safety backup of current data is taken first' : 'No safety backup needed for isolated trial',
      ];
      const gate = await platform.gate({ action, resourceType: 'restore_run', resourceId: run.id, reason: input.reason, impact, rollbackPlan: input.rollbackNote, context: { environmentId: input.targetEnvironmentId, mode: input.mode, kind: artifact.kind, preview } }, actor);
      state = await move(state, 'awaiting_approval', { correlationId: gate.approval.id });
      await audit({ actorId: actor.id, action: 'restore.request', resourceType: 'restore_run', resourceId: run.id, environmentId: input.targetEnvironmentId, result: 'success', after: { mode: input.mode, kind: artifact.kind } });
      return { approvalRequired: true, approval: gate.approval, restoreId: state.id, preview };
    },

    async execute(id, input, actor) {
      // Mutation path: authorization happens below (authorize + requester check), not read visibility.
      const run = await prisma.restoreRun.findUnique({ where: { id } });
      if (!run) throw new AppError(404, 'RESTORE_NOT_FOUND', 'Restore not found');
      const artifact = await loadArtifact(run.artifactId);
      const { policy } = artifact.backupRun;
      if (policy.environmentId && policy.environmentId !== input.environmentId) throw new AppError(409, 'ENVIRONMENT_MISMATCH', 'Restore target environment mismatch');
      await authorize(actor, policy.projectId, input.environmentId);
      if (run.status !== 'awaiting_approval') throw new AppError(409, 'INVALID_RESTORE_TRANSITION', `Restore is ${run.status}, not awaiting approval`);
      const mode = run.isolatedTrial ? 'isolated' : 'inplace';
      const action = mode === 'inplace' ? 'backup.restore.inplace' : 'backup.restore.isolated';
      const gate = await platform.gate({ action, resourceType: 'restore_run', resourceId: id, approvalId: run.correlationId }, actor);
      let state = await move(run, 'approved', { approvedById: gate.approval.approverId });
      let safetyBackupRunId = null;
      const fail = async (code, message) => {
        if (RESTORE_TRANSITIONS[state.status]?.includes('failed')) await move(state, 'failed');
        await audit({ actorId: actor.id, action: 'restore.execute', resourceType: 'restore_run', resourceId: id, environmentId: input.environmentId, result: 'failure', metadata: { code, stage: state.status, safetyBackupRunId } });
        const e = new AppError(502, code, message);
        e.handled = true;
        throw e;
      };
      try {
        state = await move(state, 'safety_backup');
        if (mode === 'inplace') {
          // Required: never overwrite live data without a verified copy of what is there now.
          const res = await backups.runBackup(policy.id, { environmentId: input.environmentId, kinds: [artifact.kind === 'manifest' ? 'db' : artifact.kind], trigger: 'pre-deploy' }, actor);
          safetyBackupRunId = res.run.id;
        }
        state = await move(state, 'restoring');
        const { plain } = await backups.verifyArtifactBytes(artifact);
        const result = await adapters.backupEngine.restore({ mode, projectId: policy.projectId, items: [{ kind: artifact.kind, bytes: plain }] });
        // Compare restored data with the backed-up content.
        if (!result.restored || result.checksums?.[artifact.kind] !== sha256(plain)) {
          return await fail('RESTORE_MISMATCH', 'Restored data does not match the backup content');
        }
        state = await move(state, 'health_check');
        const health = await adapters.backupEngine.health({ mode, projectId: policy.projectId });
        if (!health.healthy) return await fail('RESTORE_HEALTH_FAILED', safetyBackupRunId ? `Health check failed; roll back using safety backup ${safetyBackupRunId}` : 'Health check failed');
      } catch (err) {
        if (err.handled) throw err;
        return await fail(err.code ?? 'RESTORE_FAILED', err.message ?? 'Restore failed');
      }
      state = await move(state, 'completed');
      await audit({ actorId: actor.id, action: 'restore.execute', resourceType: 'restore_run', resourceId: id, environmentId: input.environmentId, result: 'success', after: { mode, kind: artifact.kind, safetyBackupRunId, approverId: state.approvedById } });
      return { restore: state, mode, safetyBackupRunId, simulated: Boolean(adapters.simulated) };
    },
  };
}
