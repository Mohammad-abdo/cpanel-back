import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { decrypt, encrypt, sha256 } from '../platform/platform.crypto.js';

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

export function createRestoresService({
  prisma,
  now = () => new Date(),
  auditService = null,
  rbac = null,
  platform = null,
  adapters = null,
  backups = null,
  serverAccessService = null,
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
}) {
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

  function instanceAuth(row) {
    if (!row?.adminUsername || !row?.adminSecretEnc) return null;
    return {
      username: row.adminUsername,
      password: decrypt(Buffer.from(row.adminSecretEnc), credentialKey()).toString('utf8'),
    };
  }

  /**
   * Managed MySQL/Postgres with server + saved login. Used for in-place live restore only
   * (isolated trials never write production).
   */
  async function findLiveManagedDb(policy) {
    if (!prisma.managedDatabase?.findMany) return null;
    const rows = await prisma.managedDatabase.findMany({
      where: { projectId: policy.projectId, environmentId: policy.environmentId },
      include: { instance: true },
      take: 20,
    });
    return (
      rows.find((r) => {
        const inst = r.instance;
        return (
          inst?.serverId &&
          (inst.engine === 'mysql' || inst.engine === 'postgres') &&
          inst.adminUsername &&
          inst.adminSecretEnc
        );
      }) ?? null
    );
  }

  async function liveRestoreDb(policy, plain, actor) {
    const live = await findLiveManagedDb(policy);
    if (!live || !serverAccessService?.dbRestore || !actor?.isOwner) return null;
    const auth = instanceAuth(live.instance);
    if (!auth) return null;
    await serverAccessService.dbRestore(
      live.instance.serverId,
      {
        engine: live.instance.engine,
        db: live.dbName,
        auth,
        bytes: Buffer.isBuffer(plain) ? plain : Buffer.from(plain),
        confirm: live.dbName,
      },
      actor,
    );
    return {
      restored: true,
      checksums: { db: sha256(plain) },
      simulated: false,
      source: 'ssh-live',
      live,
    };
  }

  async function liveHealth(policy, actor, live) {
    if (!live || !serverAccessService?.dbBrowse || !actor?.isOwner) return null;
    const auth = instanceAuth(live.instance);
    if (!auth) return null;
    try {
      await serverAccessService.dbBrowse(
        live.instance.serverId,
        { engine: live.instance.engine, action: 'schemas', auth },
        actor,
      );
      return { healthy: true, source: 'ssh-live' };
    } catch {
      return { healthy: false, source: 'ssh-live' };
    }
  }

  /**
   * In-place restore of every data artifact from a safety backup. Prefers live SSH for db when
   * available so rollback undoes a live restore; otherwise simulated adapter.
   */
  async function rollbackFromSafety(safetyRunId, policy, actor) {
    try {
      const artifacts = (await prisma.backupArtifact.findMany({ where: { backupRunId: safetyRunId } })).filter((a) => a.kind !== 'manifest');
      if (!artifacts.length) return false;
      const items = [];
      for (const a of artifacts) items.push({ kind: a.kind, bytes: (await backups.verifyArtifactBytes(a)).plain });
      const dbOnly = items.length === 1 && items[0].kind === 'db';
      if (dbOnly) {
        const live = await liveRestoreDb(policy, items[0].bytes, actor);
        if (live) return Boolean(live.restored);
      }
      const result = await adapters.backupEngine.restore({ mode: 'inplace', projectId: policy.projectId, items });
      return Boolean(result.restored) && items.every((i) => result.checksums?.[i.kind] === sha256(i.bytes));
    } catch {
      return false;
    }
  }

  /**
   * In-place config restore into panel ProjectEnvVar. Only non-secret values that were not
   * redacted at backup time are written; secrets stay untouched (backup stored [REDACTED]).
   */
  async function panelRestoreConfig(policy, plain, actor) {
    if (!prisma.projectEnvVar?.upsert || !policy.environmentId) return null;
    let payload;
    try {
      payload = JSON.parse(Buffer.isBuffer(plain) ? plain.toString('utf8') : String(plain));
    } catch {
      return null;
    }
    if (!Array.isArray(payload?.vars)) return null;
    const restorables = payload.vars.filter(
      (v) =>
        v &&
        typeof v.key === 'string' &&
        v.key &&
        !v.isSecret &&
        typeof v.value === 'string' &&
        v.value !== '[REDACTED]' &&
        v.value !== '[UNREADABLE]',
    );
    for (const v of restorables) {
      const valueEnc = encrypt(v.value, credentialKey());
      await prisma.projectEnvVar.upsert({
        where: { environmentId_key: { environmentId: policy.environmentId, key: v.key } },
        create: {
          environmentId: policy.environmentId,
          key: v.key,
          valueEnc,
          isSecret: false,
          updatedById: actor.id ?? null,
        },
        update: { valueEnc, isSecret: false, updatedById: actor.id ?? null },
      });
    }
    return {
      restored: true,
      checksums: { config: sha256(plain) },
      simulated: false,
      source: 'panel-env',
      live: null,
      restoredKeys: restorables.map((v) => v.key),
    };
  }

  async function applyRestore({ mode, policy, kind, plain, actor }) {
    // Isolated trial never writes the live server database or panel env store.
    if (mode === 'inplace' && kind === 'db' && actor?.isOwner) {
      const live = await liveRestoreDb(policy, plain, actor);
      if (live) return live;
    }
    if (mode === 'inplace' && kind === 'config') {
      const panel = await panelRestoreConfig(policy, plain, actor);
      if (panel) return panel;
    }
    const result = await adapters.backupEngine.restore({
      mode,
      projectId: policy.projectId,
      items: [{ kind, bytes: plain }],
    });
    return { ...result, simulated: Boolean(adapters.simulated), source: 'adapter', live: null };
  }

  return {
    async listRestorePoints({ projectId, limit }, actor) {
      const projectClause = await scope.projectClause(actor, projectId);
      const runs = await prisma.backupRun.findMany({
        where: { status: 'retained', verificationStatus: 'verified', policy: { projectId: projectClause ?? projectId } },
        take: limit,
        orderBy: { finishedAt: 'desc' },
        include: { artifacts: true, policy: true },
      });
      return runs.map((r) => ({
        runId: r.id,
        finishedAt: r.finishedAt,
        environmentId: r.policy.environmentId,
        artifacts: r.artifacts.filter((a) => a.kind !== 'manifest').map((a) => ({ id: a.id, kind: a.kind, checksum: a.checksum })),
      }));
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
        await audit({
          actorId: actor.id,
          action: 'restore.request',
          resourceType: 'backup_artifact',
          resourceId: artifact.id,
          environmentId: input.targetEnvironmentId,
          result: 'denied',
          metadata: { code: err.code },
        });
        throw new AppError(422, 'CORRUPT_BACKUP', `Restore point failed validation: ${err.code ?? 'unreadable'}`);
      }
      const preview = await adapters.backupEngine.impact({ mode: input.mode, kind: artifact.kind, projectId: policy.projectId });
      const run = await prisma.restoreRun.create({ data: { artifactId: artifact.id, status: 'selected', isolatedTrial: input.mode === 'isolated' } });
      let state = await move(run, 'validated');
      const action = input.mode === 'inplace' ? 'backup.restore.inplace' : 'backup.restore.isolated';
      const impact = [
        input.mode === 'inplace'
          ? `Overwrites live ${artifact.kind} data of the target environment`
          : `Restores ${artifact.kind} into an isolated trial area; production is untouched`,
        `Estimated downtime ${preview.estimatedDowntimeSeconds ?? 'UNKNOWN'}s`,
        input.mode === 'inplace' ? 'A safety backup of current data is taken first' : 'No safety backup needed for isolated trial',
      ];
      const gate = await platform.gate(
        {
          action,
          resourceType: 'restore_run',
          resourceId: run.id,
          reason: input.reason,
          impact,
          rollbackPlan: input.rollbackNote,
          context: { environmentId: input.targetEnvironmentId, mode: input.mode, kind: artifact.kind, preview },
        },
        actor,
      );
      state = await move(state, 'awaiting_approval', { correlationId: gate.approval.id });
      await audit({
        actorId: actor.id,
        action: 'restore.request',
        resourceType: 'restore_run',
        resourceId: run.id,
        environmentId: input.targetEnvironmentId,
        result: 'success',
        after: { mode: input.mode, kind: artifact.kind },
      });
      return { approvalRequired: true, approval: gate.approval, restoreId: state.id, preview };
    },

    async execute(id, input, actor) {
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
      let usedLive = false;
      let usedPanel = false;
      const fail = async (code, message, extra = {}) => {
        if (RESTORE_TRANSITIONS[state.status]?.includes('failed')) await move(state, 'failed');
        await audit({
          actorId: actor.id,
          action: 'restore.execute',
          resourceType: 'restore_run',
          resourceId: id,
          environmentId: input.environmentId,
          result: 'failure',
          metadata: { code, stage: state.status, safetyBackupRunId, live: usedLive, ...extra },
        });
        const e = new AppError(502, code, message);
        e.handled = true;
        Object.assign(e, extra);
        throw e;
      };
      try {
        state = await move(state, 'safety_backup');
        if (mode === 'inplace') {
          const res = await backups.runBackup(
            policy.id,
            { environmentId: input.environmentId, kinds: [artifact.kind === 'manifest' ? 'db' : artifact.kind], trigger: 'pre-deploy' },
            actor,
          );
          safetyBackupRunId = res.run.id;
        }
        state = await move(state, 'restoring');
        const { plain } = await backups.verifyArtifactBytes(artifact);
        const result = await applyRestore({ mode, policy, kind: artifact.kind, plain, actor });
        usedLive = result.source === 'ssh-live';
        usedPanel = result.source === 'panel-env';
        if (!result.restored || result.checksums?.[artifact.kind] !== sha256(plain)) {
          return await fail('RESTORE_MISMATCH', 'Restored data does not match the backup content');
        }
        state = await move(state, 'health_check');
        // Panel config restore is verified by checksum match above; treat as healthy without adapter.
        const health = usedPanel
          ? { healthy: true, source: 'panel-env' }
          : ((usedLive ? await liveHealth(policy, actor, result.live) : null) ??
            (await adapters.backupEngine.health({ mode, projectId: policy.projectId })));
        if (!health.healthy) {
          if (!safetyBackupRunId) return await fail('RESTORE_HEALTH_FAILED', 'Health check failed', { rolledBack: false });
          const rolledBack = await rollbackFromSafety(safetyBackupRunId, policy, actor);
          return await fail(
            'RESTORE_HEALTH_FAILED',
            rolledBack
              ? `Health check failed; previous data was restored automatically from safety backup ${safetyBackupRunId}`
              : `Health check failed and automatic rollback failed; roll back manually using safety backup ${safetyBackupRunId}`,
            { rolledBack },
          );
        }
      } catch (err) {
        if (err.handled) throw err;
        return await fail(err.code ?? 'RESTORE_FAILED', err.message ?? 'Restore failed');
      }
      state = await move(state, 'completed');
      await audit({
        actorId: actor.id,
        action: 'restore.execute',
        resourceType: 'restore_run',
        resourceId: id,
        environmentId: input.environmentId,
        result: 'success',
        after: {
          mode,
          kind: artifact.kind,
          safetyBackupRunId,
          approverId: state.approvedById,
          live: usedLive,
          panelConfig: usedPanel,
        },
      });
      return {
        restore: state,
        mode,
        safetyBackupRunId,
        simulated: usedLive || usedPanel ? false : Boolean(adapters.simulated),
        live: usedLive,
        panelConfig: usedPanel,
      };
    },
  };
}
