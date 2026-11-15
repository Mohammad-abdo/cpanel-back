import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { decrypt, encrypt, sha256 } from '../platform/platform.crypto.js';

/** Scheduled -> Queued -> Snapshot/Dump -> Encrypt -> Upload -> Verify -> Retain (required.md section 11). */
export const BACKUP_TRANSITIONS = Object.freeze({
  scheduled: ['queued', 'failed'],
  queued: ['snapshot', 'failed'],
  snapshot: ['encrypt', 'failed'],
  encrypt: ['upload', 'failed'],
  upload: ['verify', 'failed'],
  verify: ['retained', 'failed'],
  retained: ['expired'],
  failed: [],
  expired: [],
});
export const ACTIVE_STATES = ['scheduled', 'queued', 'snapshot', 'encrypt', 'upload', 'verify'];
/** Retention never leaves fewer verified sets than this, so a compromised app cannot wipe every backup. */
export const MIN_VERIFIED_KEEP = 3;
const DAY = 86400000;

export function createBackupsService({ prisma, now = () => new Date(), auditService = null, rbac = null, platform = null, adapters = null, encryptionKey = () => process.env.BACKUP_ENCRYPTION_KEY }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function authorize(actor, projectId, environmentId, permissionKey = PERM.BACKUP_CREATE) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const env = await prisma.projectEnvironment.findUnique({ where: { id: environmentId } });
    if (!env || env.projectId !== projectId) throw new AppError(409, 'ENVIRONMENT_PROJECT_MISMATCH', 'Environment does not belong to this project');
    await assertCan(rbac, actor, { permissionKey, resourceType: 'project', resourceId: projectId, environmentId });
  }

  const scope = createScope({ prisma, now });
  async function loadVisiblePolicy(id, actor) {
    const p = await loadPolicy(id);
    if (!(await scope.canSeeProject(actor, p.projectId))) throw new AppError(404, 'POLICY_NOT_FOUND', 'Backup policy not found');
    return p;
  }

  async function loadPolicy(id) {
    const p = await prisma.backupPolicy.findUnique({ where: { id } });
    if (!p || p.archivedAt) throw new AppError(404, 'POLICY_NOT_FOUND', 'Backup policy not found');
    return p;
  }

  async function advance(run, to, extra = {}) {
    if (!BACKUP_TRANSITIONS[run.status]?.includes(to)) {
      throw new AppError(409, 'INVALID_BACKUP_TRANSITION', `Cannot move backup from ${run.status} to ${to}`);
    }
    const updated = await prisma.backupRun.update({ where: { id: run.id }, data: { status: to, ...extra } });
    return { ...run, ...updated };
  }

  /** Download, compare ciphertext checksum, then authenticate-decrypt. Detects tampering and truncation. */
  async function verifyArtifactBytes(artifact) {
    const bytes = await adapters.backupEngine.download({ locationRef: artifact.locationRef });
    if (!bytes) throw new AppError(422, 'ARTIFACT_MISSING', 'Artifact is missing from offsite storage');
    if (sha256(bytes) !== artifact.checksum) throw new AppError(422, 'CHECKSUM_MISMATCH', 'Artifact checksum does not match; it may be corrupt or tampered');
    const plain = decrypt(bytes, encryptionKey());
    return { bytes, plain };
  }

  return {
    verifyArtifactBytes,

    async listPolicies({ projectId, limit }, actor) {
      const projectClause = await scope.projectClause(actor, projectId);
      return prisma.backupPolicy.findMany({ where: { archivedAt: null, ...(projectClause ? { projectId: projectClause } : {}) }, take: limit, orderBy: { createdAt: 'desc' } });
    },

    async listRuns({ policyId, limit }, actor) {
      const projectClause = await scope.projectClause(actor);
      return prisma.backupRun.findMany({ where: { ...(policyId ? { policyId } : {}), ...(projectClause ? { policy: { projectId: projectClause } } : {}) }, take: limit, orderBy: { createdAt: 'desc' }, include: { artifacts: true } });
    },

    async createPolicy(input, actor) {
      await authorize(actor, input.projectId, input.environmentId);
      const row = await prisma.backupPolicy.create({
        data: { projectId: input.projectId, environmentId: input.environmentId, frequency: input.frequency, retentionDays: input.retentionDays, encryption: input.encryption, destinationCategory: input.destinationCategory, rpoMinutes: input.rpoMinutes, rtoMinutes: input.rtoMinutes },
      });
      await audit({ actorId: actor.id, action: 'backup.policy.create', resourceType: 'backup_policy', resourceId: row.id, environmentId: input.environmentId, result: 'success', after: { frequency: input.frequency, retentionDays: input.retentionDays } });
      return row;
    },

    /** RPO status: age of the newest verified, retained run against the policy objective. */
    async rpoStatus(policyId, actor) {
      const policy = await loadVisiblePolicy(policyId, actor);
      const last = await prisma.backupRun.findFirst({ where: { policyId, status: 'retained', verificationStatus: 'verified' }, orderBy: { finishedAt: 'desc' } });
      if (!last) return { status: 'no_verified_backup', rpoMinutes: policy.rpoMinutes, rtoMinutes: policy.rtoMinutes };
      const ageMin = Math.floor((now().getTime() - new Date(last.finishedAt).getTime()) / 60000);
      return { status: ageMin <= policy.rpoMinutes ? 'within_rpo' : 'rpo_breached', ageMinutes: ageMin, rpoMinutes: policy.rpoMinutes, rtoMinutes: policy.rtoMinutes, lastRunId: last.id };
    },

    async runBackup(policyId, input, actor) {
      const policy = await loadPolicy(policyId);
      if (policy.environmentId && policy.environmentId !== input.environmentId) {
        throw new AppError(409, 'ENVIRONMENT_MISMATCH', 'Policy belongs to a different environment');
      }
      await authorize(actor, policy.projectId, input.environmentId);
      if (await prisma.backupRun.findFirst({ where: { policyId, status: { in: ACTIVE_STATES } } })) {
        throw new AppError(409, 'BACKUP_IN_PROGRESS', 'A backup is already running for this policy');
      }
      let run = await prisma.backupRun.create({ data: { policyId, status: 'scheduled', startedAt: now() } });
      const uploaded = [];
      const stage = async (to) => {
        run = await advance(run, to);
      };
      try {
        await stage('queued');
        await stage('snapshot');
        const parts = [];
        for (const kind of input.kinds) {
          const d = await adapters.backupEngine.dump({ kind, ref: policy.projectId });
          // A database dump taken while writes continue must come from a consistent snapshot.
          if (kind === 'db' && !d.consistent) throw new AppError(500, 'SNAPSHOT_INCONSISTENT', 'Database dump was not taken from a consistent snapshot');
          parts.push({ kind, plain: d.bytes, method: d.method });
        }
        await stage('encrypt');
        const key = encryptionKey(); // throws if the key is missing; nothing is uploaded unencrypted
        const encrypted = parts.map((p) => ({ ...p, cipher: encrypt(p.plain, key) }));
        const manifest = {
          runId: run.id,
          trigger: input.trigger,
          createdAt: now().toISOString(),
          entries: encrypted.map((e) => ({ kind: e.kind, method: e.method, plainChecksum: sha256(e.plain), checksum: sha256(e.cipher), sizeBytes: e.cipher.length })),
        };
        encrypted.push({ kind: 'manifest', cipher: encrypt(JSON.stringify(manifest), key) });
        await stage('upload');
        const artifacts = [];
        for (const e of encrypted) {
          const res = await adapters.backupEngine.upload({ name: `${policyId}/${run.id}/${e.kind}.enc`, bytes: e.cipher });
          uploaded.push(res.locationRef);
          artifacts.push({ backupRunId: run.id, kind: e.kind, locationRef: res.locationRef, checksum: sha256(e.cipher), sizeBytes: BigInt(e.cipher.length) });
        }
        await stage('verify');
        const saved = [];
        for (const a of artifacts) {
          saved.push(await prisma.backupArtifact.create({ data: a }));
          await verifyArtifactBytes(a);
        }
        const kinds = new Set(saved.map((s) => s.kind));
        const missing = [...input.kinds, 'manifest'].filter((k) => !kinds.has(k));
        if (missing.length) throw new AppError(500, 'MANIFEST_INCOMPLETE', `Backup set is incomplete: ${missing.join(', ')}`);
        await stage('retained');
        run = { ...run, ...(await prisma.backupRun.update({ where: { id: run.id }, data: { finishedAt: now(), verificationStatus: 'verified' } })) };
        await audit({ actorId: actor.id, action: 'backup.run', resourceType: 'backup_policy', resourceId: policyId, environmentId: input.environmentId, result: 'success', after: { runId: run.id, kinds: input.kinds, trigger: input.trigger } });
        return { run, artifacts: saved.map((s) => ({ id: s.id, kind: s.kind, checksum: s.checksum })), simulated: Boolean(adapters.simulated) };
      } catch (err) {
        for (const ref of uploaded) await adapters.backupEngine.remove({ locationRef: ref }).catch(() => {});
        const failedFrom = run.status;
        if (BACKUP_TRANSITIONS[run.status]?.includes('failed')) {
          await prisma.backupRun.update({ where: { id: run.id }, data: { status: 'failed', finishedAt: now(), verificationStatus: 'failed' } });
        }
        await audit({ actorId: actor.id, action: 'backup.run', resourceType: 'backup_policy', resourceId: policyId, environmentId: input.environmentId, result: 'failure', metadata: { failedStage: failedFrom, code: err.code ?? 'ERROR' } });
        throw err instanceof AppError ? err : new AppError(502, 'BACKUP_FAILED', `Backup failed during ${failedFrom}`);
      }
    },

    /** Re-verify a stored artifact against offsite storage (checksum then authenticated decryption). */
    async verifyArtifact(artifactId, actor) {
      const artifact = await prisma.backupArtifact.findUnique({ where: { id: artifactId }, include: { backupRun: { include: { policy: true } } } });
      if (!artifact) throw new AppError(404, 'ARTIFACT_NOT_FOUND', 'Artifact not found');
      const policy = artifact.backupRun.policy;
      await authorize(actor, policy.projectId, policy.environmentId, PERM.BACKUP_CREATE);
      try {
        await verifyArtifactBytes(artifact);
        await audit({ actorId: actor.id, action: 'backup.verify', resourceType: 'backup_artifact', resourceId: artifactId, result: 'success' });
        return { ok: true, artifactId };
      } catch (err) {
        await prisma.backupRun.update({ where: { id: artifact.backupRunId }, data: { verificationStatus: 'failed' } });
        await audit({ actorId: actor.id, action: 'backup.verify', resourceType: 'backup_artifact', resourceId: artifactId, result: 'failure', metadata: { code: err.code } });
        throw err;
      }
    },

    /** Dry run. Candidates are expired retained runs, minus the newest MIN_VERIFIED_KEEP verified sets. */
    /** Read endpoint: out-of-scope policies answer 404. */
    async planRetention(policyId, actor) {
      await loadVisiblePolicy(policyId, actor);
      return this._plan(policyId);
    },

    async _plan(policyId) {
      const policy = await loadPolicy(policyId);
      const runs = await prisma.backupRun.findMany({ where: { policyId, status: 'retained' }, orderBy: { finishedAt: 'desc' } });
      const verified = runs.filter((r) => r.verificationStatus === 'verified');
      const protectedIds = new Set(verified.slice(0, MIN_VERIFIED_KEEP).map((r) => r.id));
      const cutoff = now().getTime() - (policy.retentionDays ?? 30) * DAY;
      const candidates = runs.filter((r) => new Date(r.finishedAt).getTime() < cutoff && !protectedIds.has(r.id));
      // Never remove more than half of all verified sets in one pass.
      const cap = Math.floor(verified.length / 2);
      const limited = cap > 0 ? candidates.slice(-cap) : [];
      return { policyId, retentionDays: policy.retentionDays, keep: runs.filter((r) => !limited.includes(r)).map((r) => r.id), remove: limited.map((r) => r.id), protected: [...protectedIds] };
    },

    async applyRetention(policyId, input, actor) {
      const policy = await loadPolicy(policyId);
      if (policy.environmentId && policy.environmentId !== input.environmentId) {
        throw new AppError(409, 'ENVIRONMENT_MISMATCH', 'Policy belongs to a different environment');
      }
      await authorize(actor, policy.projectId, input.environmentId);
      const plan = await this._plan(policyId);
      const gate = await platform.gate(
        { action: 'backup.retention.apply', binding: sha256(plan.remove.join(',')), resourceType: 'backup_policy', resourceId: policyId, approvalId: input.approvalId, reason: input.reason, impact: [`Delete ${plan.remove.length} expired backup set(s)`, `${plan.protected.length} newest verified set(s) are always kept`], rollbackPlan: input.rollbackNote, context: { environmentId: input.environmentId } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      let deleted = 0;
      for (const runId of plan.remove) {
        const artifacts = await prisma.backupArtifact.findMany({ where: { backupRunId: runId } });
        for (const a of artifacts) await adapters.backupEngine.remove({ locationRef: a.locationRef });
        await prisma.backupArtifact.deleteMany({ where: { backupRunId: runId } });
        await advance({ id: runId, status: 'retained' }, 'expired');
        deleted += 1;
      }
      await audit({ actorId: actor.id, action: 'backup.retention.apply', resourceType: 'backup_policy', resourceId: policyId, environmentId: input.environmentId, result: 'success', after: { deleted } });
      return { deleted, kept: plan.keep.length };
    },
  };
}
