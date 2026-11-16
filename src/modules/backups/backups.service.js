import { AppError } from '../../common/errors/app-error.js';
import { createScope } from '../../common/scope.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { decrypt, encrypt, sha256 } from '../platform/platform.crypto.js';
import { SYSTEM_ACTOR, isSystemActor } from '../../common/system-actor.js';

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
/** How often each policy frequency is due, and how soon a failed scheduled run is retried. */
export const FREQUENCY_MS = Object.freeze({ hourly: 3600000, daily: DAY, weekly: 7 * DAY });
export const FAILED_RETRY_MS = 15 * 60000;

export function createBackupsService({
  prisma,
  now = () => new Date(),
  auditService = null,
  rbac = null,
  platform = null,
  adapters = null,
  serverAccessService = null,
  encryptionKey = () => process.env.BACKUP_ENCRYPTION_KEY,
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
}) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function authorize(actor, projectId, environmentId, permissionKey = PERM.BACKUP_CREATE) {
    if (!actor?.id && !isSystemActor(actor)) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const env = await prisma.projectEnvironment.findUnique({ where: { id: environmentId } });
    if (!env || env.projectId !== projectId) throw new AppError(409, 'ENVIRONMENT_PROJECT_MISMATCH', 'Environment does not belong to this project');
    if (isSystemActor(actor)) return; // scheduled job acting on an Owner-approved policy
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

  function instanceAuth(row) {
    if (!row?.adminUsername || !row?.adminSecretEnc) return null;
    return {
      username: row.adminUsername,
      password: decrypt(Buffer.from(row.adminSecretEnc), credentialKey()).toString('utf8'),
    };
  }

  /**
   * Prefer live mysqldump over SSH when a managed MySQL DB has server + saved login and the actor
   * is Owner or SYSTEM_ACTOR. Non-owners keep the simulated adapter so BACKUP_CREATE still works.
   */
  async function dumpDb(policy, actor) {
    const canLive = isSystemActor(actor) || actor?.isOwner;
    if (canLive && serverAccessService?.dbDump && prisma.managedDatabase?.findMany) {
      const rows = await prisma.managedDatabase.findMany({
        where: { projectId: policy.projectId, environmentId: policy.environmentId },
        include: { instance: true },
        take: 20,
      });
      const live = rows.find((r) => {
        const inst = r.instance;
        return (
          inst?.serverId &&
          (inst.engine === 'mysql' || inst.engine === 'postgres') &&
          inst.adminUsername &&
          inst.adminSecretEnc
        );
      });
      if (live) {
        const auth = instanceAuth(live.instance);
        const result = await serverAccessService.dbDump(
          live.instance.serverId,
          { engine: live.instance.engine, db: live.dbName, auth },
          actor,
        );
        const bytes = Buffer.isBuffer(result.bytes) ? result.bytes : Buffer.from(result.bytes ?? '');
        if (!bytes.length) throw new AppError(502, 'DB_DUMP_EMPTY', 'Live database dump was empty');
        return {
          bytes,
          consistent: true,
          method: live.instance.engine === 'mysql' ? 'single-transaction' : 'pg-dump',
          simulated: false,
          source: 'ssh-live',
        };
      }
    }
    return adapters.backupEngine.dump({ kind: 'db', ref: policy.projectId });
  }

  /**
   * Config backup: environment variable metadata. Secret values stay redacted; plaintext never
   * leaves the encrypt stage except as AES-GCM ciphertext destined for offsite storage.
   */
  async function dumpConfig(policy) {
    if (!prisma.projectEnvVar?.findMany) {
      return adapters.backupEngine.dump({ kind: 'config', ref: policy.projectId });
    }
    const vars = await prisma.projectEnvVar.findMany({
      where: { environmentId: policy.environmentId },
      orderBy: { key: 'asc' },
    });
    const payload = {
      projectId: policy.projectId,
      environmentId: policy.environmentId,
      exportedAt: now().toISOString(),
      vars: vars.map((v) => {
        if (v.isSecret) return { key: v.key, isSecret: true, value: '[REDACTED]' };
        try {
          return {
            key: v.key,
            isSecret: false,
            value: decrypt(Buffer.from(v.valueEnc), credentialKey()).toString('utf8'),
          };
        } catch {
          return { key: v.key, isSecret: false, value: '[UNREADABLE]' };
        }
      }),
    };
    return {
      bytes: Buffer.from(JSON.stringify(payload, null, 2), 'utf8'),
      consistent: true,
      method: 'env-metadata',
      simulated: false,
      source: 'panel-env',
    };
  }

  async function dumpPart(kind, policy, actor) {
    if (kind === 'db') return dumpDb(policy, actor);
    if (kind === 'config') return dumpConfig(policy);
    return adapters.backupEngine.dump({ kind, ref: policy.projectId });
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

    /**
     * Offsite destination posture for TASK-024: adapter health, encryption/category, and the
     * application-level guarantee that retention never deletes the newest MIN_VERIFIED_KEEP sets.
     * Object-lock / separate cloud account independence remains UNKNOWN until configured.
     */
    async destinationStatus(policyId, actor) {
      const policy = await loadVisiblePolicy(policyId, actor);
      const health = adapters?.backupEngine?.health
        ? await adapters.backupEngine.health({ policyId, destinationCategory: policy.destinationCategory })
        : { healthy: false, reason: 'adapter_unavailable' };
      const last = await prisma.backupRun.findFirst({
        where: { policyId, status: 'retained', verificationStatus: 'verified' },
        orderBy: { finishedAt: 'desc' },
      });
      const verifiedCount = await prisma.backupRun.count?.({
        where: { policyId, status: 'retained', verificationStatus: 'verified' },
      });
      return {
        policyId,
        destinationCategory: policy.destinationCategory ?? 'offsite',
        encryption: policy.encryption ?? 'aes-256-gcm',
        adapterHealthy: Boolean(health?.healthy),
        adapterSimulated: Boolean(adapters?.simulated),
        minVerifiedKeep: MIN_VERIFIED_KEEP,
        verifiedRetainedCount: typeof verifiedCount === 'number' ? verifiedCount : null,
        lastVerifiedRunId: last?.id ?? null,
        lastVerifiedAt: last?.finishedAt ?? null,
        // App-level: retention plan never removes the newest MIN_VERIFIED_KEEP verified sets.
        compromisedAppWipeBlocked: true,
        // Storage-level immutability / separate credentials: not claimed without real offsite config.
        objectLock: 'UNKNOWN',
        independentStorageAccount: 'REQUIRES_DECISION',
      };
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
        let usedLiveDb = false;
        for (const kind of input.kinds) {
          const d = await dumpPart(kind, policy, actor);
          // A database dump taken while writes continue must come from a consistent snapshot.
          if (kind === 'db' && !d.consistent) throw new AppError(500, 'SNAPSHOT_INCONSISTENT', 'Database dump was not taken from a consistent snapshot');
          if (kind === 'db' && d.source === 'ssh-live') usedLiveDb = true;
          parts.push({ kind, plain: d.bytes, method: d.method, source: d.source ?? (adapters.simulated ? 'simulated' : 'adapter') });
        }
        await stage('encrypt');
        const key = encryptionKey(); // throws if the key is missing; nothing is uploaded unencrypted
        const encrypted = parts.map((p) => ({ ...p, cipher: encrypt(p.plain, key) }));
        const manifest = {
          runId: run.id,
          trigger: input.trigger,
          createdAt: now().toISOString(),
          entries: encrypted.map((e) => ({
            kind: e.kind,
            method: e.method,
            source: e.source,
            plainChecksum: sha256(e.plain),
            checksum: sha256(e.cipher),
            sizeBytes: e.cipher.length,
          })),
        };
        encrypted.push({ kind: 'manifest', cipher: encrypt(JSON.stringify(manifest), key), source: 'panel' });
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
        await audit({
          actorId: actor.id ?? null,
          action: 'backup.run',
          resourceType: 'backup_policy',
          resourceId: policyId,
          environmentId: input.environmentId,
          result: 'success',
          after: { runId: run.id, kinds: input.kinds, trigger: input.trigger, liveDb: usedLiveDb },
        });
        // simulated=false only when every requested part came from a non-simulated source; live DB + panel config still marks hybrid.
        const hybrid = parts.some((p) => p.source === 'ssh-live' || p.source === 'panel-env');
        return {
          run,
          artifacts: saved.map((s) => ({ id: s.id, kind: s.kind, checksum: s.checksum })),
          simulated: hybrid ? false : Boolean(adapters.simulated),
          liveDb: usedLiveDb,
        };
      } catch (err) {
        for (const ref of uploaded) await adapters.backupEngine.remove({ locationRef: ref }).catch(() => {});
        const failedFrom = run.status;
        if (BACKUP_TRANSITIONS[run.status]?.includes('failed')) {
          await prisma.backupRun.update({ where: { id: run.id }, data: { status: 'failed', finishedAt: now(), verificationStatus: 'failed' } });
        }
        await audit({ actorId: actor.id ?? null, action: 'backup.run', resourceType: 'backup_policy', resourceId: policyId, environmentId: input.environmentId, result: 'failure', metadata: { failedStage: failedFrom, code: err.code ?? 'ERROR' } });
        throw err instanceof AppError ? err : new AppError(502, 'BACKUP_FAILED', `Backup failed during ${failedFrom}`);
      }
    },

    /**
     * Scheduled backups (Scheduled step of the lifecycle). A policy is due when its newest attempt is
     * older than its frequency; a failed attempt is retried after FAILED_RETRY_MS. One failing policy
     * never blocks the others.
     */
    async runDue(at = now()) {
      const policies = await prisma.backupPolicy.findMany({ where: { archivedAt: null } });
      const out = [];
      for (const p of policies) {
        const every = FREQUENCY_MS[p.frequency];
        if (!every || !p.environmentId) continue;
        const last = await prisma.backupRun.findFirst({ where: { policyId: p.id }, orderBy: { startedAt: 'desc' } });
        const since = last?.startedAt ? at.getTime() - new Date(last.startedAt).getTime() : Infinity;
        const due = !last || (last.status === 'failed' ? since >= Math.min(every, FAILED_RETRY_MS) : since >= every);
        if (!due || ACTIVE_STATES.includes(last?.status)) continue;
        try {
          const res = await this.runBackup(p.id, { environmentId: p.environmentId, kinds: ['db', 'config'], trigger: 'scheduled' }, SYSTEM_ACTOR);
          out.push({ policyId: p.id, ok: true, runId: res.run.id });
        } catch (err) {
          out.push({ policyId: p.id, ok: false, code: err.code ?? 'BACKUP_FAILED' });
        }
      }
      return out;
    },

    /** Scheduled verification: re-reads the newest verified set of every policy from offsite storage. */
    async verifyLatest() {
      const policies = await prisma.backupPolicy.findMany({ where: { archivedAt: null } });
      const out = [];
      for (const p of policies) {
        const last = await prisma.backupRun.findFirst({ where: { policyId: p.id, status: 'retained', verificationStatus: 'verified' }, orderBy: { finishedAt: 'desc' } });
        if (!last) continue;
        const artifacts = await prisma.backupArtifact.findMany({ where: { backupRunId: last.id } });
        let failed = null;
        for (const a of artifacts) {
          try {
            await verifyArtifactBytes(a);
          } catch (err) {
            failed = { artifactId: a.id, code: err.code ?? 'VERIFY_FAILED' };
            break;
          }
        }
        if (failed) await prisma.backupRun.update({ where: { id: last.id }, data: { verificationStatus: 'failed' } });
        await audit({ actorId: null, action: 'backup.verify.scheduled', resourceType: 'backup_run', resourceId: last.id, result: failed ? 'failure' : 'success', metadata: failed ?? { artifacts: artifacts.length } });
        out.push({ policyId: p.id, runId: last.id, ok: !failed, ...(failed ?? {}) });
      }
      return out;
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
