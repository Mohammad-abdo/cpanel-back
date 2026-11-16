import { describe, expect, it, vi } from 'vitest';
import { BACKUP_TRANSITIONS, MIN_VERIFIED_KEEP, createBackupsService } from '../src/modules/backups/backups.service.js';
import { createPolicyBodySchema } from '../src/modules/backups/backups.validator.js';
import { decrypt, encrypt } from '../src/modules/platform/platform.crypto.js';
import { BACKUP_POLICY, DEV, ENV_PROD, ENV_STAGING, KEY, OWNER, PROJECT, U, approve, backupPrisma, makeCtx } from './phase6-helpers.js';
import { SYSTEM_ACTOR, isSystemActor } from '../src/common/system-actor.js';

const POLICY = U(90);
const NOW = new Date('2026-06-01T12:00:00Z');
const policy = { id: POLICY, projectId: PROJECT, environmentId: ENV_PROD, retentionDays: 30, rpoMinutes: 1440, rtoMinutes: 120, archivedAt: null };

function setup(opts = {}) {
  const extra = backupPrisma(opts);
  const ctx = makeCtx({ now: () => NOW, grants: opts.grants ?? [] });
  Object.assign(ctx.prisma, extra);
  const svc = createBackupsService({ ...ctx, encryptionKey: opts.key === undefined ? () => KEY : () => opts.key });
  return { ...ctx, svc, extra };
}
const run = { environmentId: ENV_PROD, kinds: ['db', 'config'], trigger: 'manual' };

describe('backups: lifecycle', () => {
  it('runs the full state machine and ends retained+verified with a manifest', async () => {
    const t = setup();
    const res = await t.svc.runBackup(POLICY, run, OWNER);
    expect(res.run.status).toBe('retained');
    expect(res.run.verificationStatus).toBe('verified');
    expect(res.artifacts.map((a) => a.kind).sort()).toEqual(['config', 'db', 'manifest']);
    expect(t.adapters.calls.filter((c) => c.name === 'backup.dump')).toHaveLength(2);
  });
  it('stores only ciphertext and the manifest lists every artifact', async () => {
    const t = setup();
    await t.svc.runBackup(POLICY, run, OWNER);
    const up = [...t.extra.artStore.values()];
    const dbArt = up.find((a) => a.kind === 'db');
    const bytes = await t.adapters.backupEngine.download({ locationRef: dbArt.locationRef });
    expect(bytes.toString()).not.toContain('simulated-db-dump');
    expect(decrypt(bytes, KEY).toString()).toContain('simulated-db-dump');
    const man = JSON.parse(decrypt(await t.adapters.backupEngine.download({ locationRef: up.find((a) => a.kind === 'manifest').locationRef }), KEY));
    expect(man.entries.map((e) => e.kind).sort()).toEqual(['config', 'db']);
    expect(man.entries.find((e) => e.kind === 'db').method).toBe('single-transaction');
  });
  it('fails closed without an encryption key and uploads nothing', async () => {
    const t = setup({ key: '' });
    await expect(t.svc.runBackup(POLICY, run, OWNER)).rejects.toMatchObject({ code: 'ENCRYPTION_KEY_MISSING' });
    expect(t.adapters.calls.some((c) => c.name === 'backup.upload')).toBe(false);
    expect([...t.extra.runStore.values()][0].status).toBe('failed');
  });
  it('handles a dump failure', async () => {
    const t = setup();
    t.adapters.backupEngine.dump = vi.fn(async () => { throw new Error('mysqldump exit 2'); });
    await expect(t.svc.runBackup(POLICY, run, OWNER)).rejects.toMatchObject({ code: 'BACKUP_FAILED' });
    expect([...t.extra.runStore.values()][0].status).toBe('failed');
  });
  it('rejects a database dump that is not a consistent snapshot (concurrent writes)', async () => {
    const t = setup();
    t.adapters.backupEngine.dump = vi.fn(async () => ({ bytes: Buffer.from('x'), consistent: false }));
    await expect(t.svc.runBackup(POLICY, run, OWNER)).rejects.toMatchObject({ code: 'SNAPSHOT_INCONSISTENT' });
  });
  it('cleans up partial uploads when an upload fails', async () => {
    const t = setup();
    const real = t.adapters.backupEngine.upload;
    let n = 0;
    t.adapters.backupEngine.upload = vi.fn(async (a) => { if (++n === 2) throw new Error('net'); return real(a); });
    await expect(t.svc.runBackup(POLICY, run, OWNER)).rejects.toMatchObject({ code: 'BACKUP_FAILED' });
    expect(t.adapters.calls.some((c) => c.name === 'backup.remove')).toBe(true);
    expect([...t.extra.runStore.values()][0].verificationStatus).toBe('failed');
  });
  it('refuses a concurrent run, wrong environment and unauthorized users', async () => {
    const t = setup({ runs: [{ id: U(1), policyId: POLICY, status: 'upload' }] });
    await expect(t.svc.runBackup(POLICY, run, OWNER)).rejects.toMatchObject({ code: 'BACKUP_IN_PROGRESS' });
    const t2 = setup();
    await expect(t2.svc.runBackup(POLICY, { ...run, environmentId: ENV_STAGING }, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_MISMATCH' });
    await expect(t2.svc.runBackup(POLICY, run, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('transition table forbids skipping stages', () => {
    expect(BACKUP_TRANSITIONS.queued).not.toContain('retained');
    expect(BACKUP_TRANSITIONS.failed).toEqual([]);
  });
  it('policy validator forces offsite + aes-256-gcm', () => {
    const base = { projectId: PROJECT, environmentId: ENV_PROD, frequency: 'daily', retentionDays: 30, rpoMinutes: 60, rtoMinutes: 60 };
    expect(createPolicyBodySchema.safeParse(base).success).toBe(true);
    expect(createPolicyBodySchema.safeParse({ ...base, destinationCategory: 'local' }).success).toBe(false);
    expect(createPolicyBodySchema.safeParse({ ...base, encryption: 'none' }).success).toBe(false);
  });
});

describe('backups: verification', () => {
  it('detects a tampered artifact (checksum mismatch) and marks the run failed', async () => {
    const t = setup();
    const res = await t.svc.runBackup(POLICY, run, OWNER);
    const art = [...t.extra.artStore.values()].find((a) => a.kind === 'db');
    const good = await t.adapters.backupEngine.download({ locationRef: art.locationRef });
    const bad = Buffer.from(good);
    bad[bad.length - 1] ^= 0xff;
    await t.adapters.backupEngine.upload({ name: art.locationRef.replace('sim://offsite/', ''), bytes: bad });
    await expect(t.svc.verifyArtifact(art.id, OWNER)).rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
    expect(t.extra.runStore.get(res.run.id).verificationStatus).toBe('failed');
  });
  it('detects a forged artifact whose checksum was also rewritten (GCM auth)', async () => {
    const t = setup();
    await t.svc.runBackup(POLICY, run, OWNER);
    const art = [...t.extra.artStore.values()].find((a) => a.kind === 'db');
    const good = await t.adapters.backupEngine.download({ locationRef: art.locationRef });
    const bad = Buffer.from(good);
    bad[bad.length - 1] ^= 0xff;
    await t.adapters.backupEngine.upload({ name: art.locationRef.replace('sim://offsite/', ''), bytes: bad });
    const { sha256 } = await import('../src/modules/platform/platform.crypto.js');
    art.checksum = sha256(bad);
    await expect(t.svc.verifyArtifact(art.id, OWNER)).rejects.toMatchObject({ code: 'CIPHERTEXT_TAMPERED' });
  });
  it('detects a missing artifact and denies unauthorized verification', async () => {
    const t = setup();
    await t.svc.runBackup(POLICY, run, OWNER);
    const art = [...t.extra.artStore.values()].find((a) => a.kind === 'config');
    await t.adapters.backupEngine.remove({ locationRef: art.locationRef });
    await expect(t.svc.verifyArtifact(art.id, OWNER)).rejects.toMatchObject({ code: 'ARTIFACT_MISSING' });
    await expect(t.svc.verifyArtifact(art.id, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('reports RPO status', async () => {
    const fresh = setup({ runs: [{ id: U(1), policyId: POLICY, status: 'retained', verificationStatus: 'verified', finishedAt: new Date(NOW - 3600000) }] });
    expect((await fresh.svc.rpoStatus(POLICY, OWNER)).status).toBe('within_rpo');
    const stale = setup({ runs: [{ id: U(1), policyId: POLICY, status: 'retained', verificationStatus: 'verified', finishedAt: new Date(NOW - 5 * 86400000) }] });
    expect((await stale.svc.rpoStatus(POLICY, OWNER)).status).toBe('rpo_breached');
    expect((await setup().svc.rpoStatus(POLICY, OWNER)).status).toBe('no_verified_backup');
  });
});

describe('backups: destination posture (TASK-024)', () => {
  it('reports offsite health, min keep and honest UNKNOWN object-lock', async () => {
    const t = setup({
      runs: [{ id: U(1), policyId: POLICY, status: 'retained', verificationStatus: 'verified', finishedAt: new Date(NOW - 3600000) }],
    });
    const status = await t.svc.destinationStatus(POLICY, OWNER);
    expect(status).toMatchObject({
      destinationCategory: 'offsite',
      encryption: expect.any(String),
      adapterHealthy: true,
      adapterSimulated: true,
      minVerifiedKeep: MIN_VERIFIED_KEEP,
      verifiedRetainedCount: 1,
      lastVerifiedRunId: U(1),
      compromisedAppWipeBlocked: true,
      objectLock: 'UNKNOWN',
      independentStorageAccount: 'REQUIRES_DECISION',
    });
  });
  it('hides out-of-scope policies as 404', async () => {
    const t = setup();
    t.prisma.projectMember = { findMany: vi.fn(async () => []) };
    await expect(t.svc.destinationStatus(POLICY, DEV)).rejects.toMatchObject({ status: 404, code: 'POLICY_NOT_FOUND' });
  });
});

describe('backups: retention', () => {
  const mkRuns = (n, ageDays) => Array.from({ length: n }, (_, i) => ({ id: U(200 + i), policyId: POLICY, status: 'retained', verificationStatus: 'verified', finishedAt: new Date(NOW - (ageDays + i) * 86400000) }));
  it('always protects the newest verified sets and caps deletion at half', async () => {
    const t = setup({ runs: mkRuns(6, 40) });
    const plan = await t.svc.planRetention(POLICY, OWNER);
    expect(plan.protected).toHaveLength(MIN_VERIFIED_KEEP);
    expect(plan.remove.length).toBeLessThanOrEqual(3);
    expect(plan.remove.some((id) => plan.protected.includes(id))).toBe(false);
  });
  it('never deletes when only protected sets remain (compromised app cannot wipe all)', async () => {
    const t = setup({ runs: mkRuns(3, 400) });
    const plan = await t.svc.planRetention(POLICY, OWNER);
    expect(plan.remove).toEqual([]);
  });
  it('applyRetention enforces the policy environment (remediation 2)', async () => {
    const t = setup({ runs: mkRuns(6, 40), artifacts: [] });
    const body = { environmentId: ENV_STAGING, reason: 'scheduled retention', rollbackNote: 'x' };
    await expect(t.svc.applyRetention(POLICY, body, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_MISMATCH' });
  });
  it('apply needs approval, then deletes offsite objects and expires runs', async () => {
    const runs = mkRuns(6, 40);
    const artifacts = runs.map((r, i) => ({ id: U(300 + i), backupRunId: r.id, kind: 'db', locationRef: `sim://offsite/x${i}` }));
    const t = setup({ runs, artifacts });
    const body = { environmentId: ENV_PROD, reason: 'scheduled retention', rollbackNote: 'sets are offsite immutable copies' };
    const first = await t.svc.applyRetention(POLICY, body, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.adapters.calls.some((c) => c.name === 'backup.remove')).toBe(false);
    await approve(t, first.approval.id);
    const done = await t.svc.applyRetention(POLICY, { ...body, approvalId: first.approval.id }, OWNER);
    expect(done.deleted).toBeGreaterThan(0);
    expect([...t.extra.runStore.values()].filter((r) => r.status === 'expired')).toHaveLength(done.deleted);
  });
});

describe('backups: scheduled runs and verification', () => {
  const daily = { ...BACKUP_POLICY, frequency: 'daily' };
  function sched(runs = []) {
    const extra = backupPrisma({ runs }, daily);
    const ctx = makeCtx({ now: () => NOW });
    Object.assign(ctx.prisma, extra);
    return { ...ctx, extra, svc: createBackupsService({ ...ctx, encryptionKey: () => KEY }) };
  }
  const ago = (ms) => new Date(NOW.getTime() - ms);

  it('runs a due policy as the system actor with trigger scheduled', async () => {
    const t = sched();
    const out = await t.svc.runDue(NOW);
    expect(out).toEqual([expect.objectContaining({ policyId: POLICY, ok: true })]);
    const made = [...t.extra.runStore.values()][0];
    expect(made.status).toBe('retained');
    const ev = t.auditService.record.mock.calls.map((c) => c[0]).find((e) => e.action === 'backup.run');
    expect(ev).toMatchObject({ actorId: null, result: 'success', after: expect.objectContaining({ trigger: 'scheduled' }) });
  });
  it('skips a policy whose last run is newer than its frequency', async () => {
    const t = sched([{ id: U(700), policyId: POLICY, status: 'retained', startedAt: ago(3600000) }]);
    expect(await t.svc.runDue(NOW)).toEqual([]);
  });
  it('retries a failed run after 15 minutes, not before', async () => {
    const early = sched([{ id: U(701), policyId: POLICY, status: 'failed', startedAt: ago(5 * 60000) }]);
    expect(await early.svc.runDue(NOW)).toEqual([]);
    const later = sched([{ id: U(702), policyId: POLICY, status: 'failed', startedAt: ago(20 * 60000) }]);
    expect((await later.svc.runDue(NOW))[0]).toMatchObject({ ok: true });
  });
  it('reports a failing policy without throwing', async () => {
    const t = sched();
    t.adapters.backupEngine.dump = vi.fn(async () => { throw new Error('disk full'); });
    expect(await t.svc.runDue(NOW)).toEqual([expect.objectContaining({ ok: false, code: 'BACKUP_FAILED' })]);
  });
  it('scheduled verification flags a corrupted newest set', async () => {
    const t = sched();
    await t.svc.runDue(NOW);
    expect((await t.svc.verifyLatest())[0]).toMatchObject({ ok: true });
    const db = [...t.extra.artStore.values()].find((a) => a.kind === 'db');
    await t.adapters.backupEngine.upload({ name: db.locationRef.replace('sim://offsite/', ''), bytes: Buffer.from('tampered') });
    const res = await t.svc.verifyLatest();
    expect(res[0]).toMatchObject({ ok: false, code: 'CHECKSUM_MISMATCH' });
    expect([...t.extra.runStore.values()][0].verificationStatus).toBe('failed');
  });
  it('only the exact system actor bypasses the user check', async () => {
    const t = sched();
    await expect(t.svc.runBackup(POLICY, run, { id: null, isOwner: true, system: true })).rejects.toMatchObject({ code: 'AUTH_REQUIRED' });
    await expect(t.svc.runBackup(POLICY, run, SYSTEM_ACTOR)).resolves.toBeTruthy();
  });
});

describe('backups: live SSH dump hybrid', () => {
  const SERVER = U(40);
  const INSTANCE = U(41);
  const DB_ROW = {
    id: U(42),
    projectId: PROJECT,
    environmentId: ENV_PROD,
    dbName: 'app_prod',
    instance: {
      id: INSTANCE,
      serverId: SERVER,
      engine: 'mysql',
      name: 'mysql-main',
      adminUsername: 'root',
      adminSecretEnc: encrypt('secret-db-pass', KEY),
    },
  };

  function setupLive(opts = {}) {
    const extra = backupPrisma(opts);
    const ctx = makeCtx({ now: () => NOW, grants: opts.grants ?? [] });
    Object.assign(ctx.prisma, extra, {
      managedDatabase: {
        findMany: vi.fn(async () => (opts.noManaged ? [] : [DB_ROW])),
      },
      projectEnvVar: {
        findMany: vi.fn(async () => [
          { key: 'APP_URL', isSecret: false, valueEnc: encrypt('https://app.test', KEY) },
          { key: 'API_TOKEN', isSecret: true, valueEnc: encrypt('super-secret', KEY) },
        ]),
      },
    });
    const dbDump = vi.fn(async (_serverId, args, actor) => {
      expect(isSystemActor(actor) || actor?.isOwner).toBe(true);
      expect(args).toMatchObject({ engine: 'mysql', db: 'app_prod', auth: { username: 'root' } });
      expect(args.auth.password).toBe('secret-db-pass');
      return { bytes: Buffer.from('-- live mysqldump\nCREATE TABLE t(id int);\n'), filename: 'x.sql', size: 40 };
    });
    const svc = createBackupsService({
      ...ctx,
      encryptionKey: () => KEY,
      credentialKey: () => KEY,
      serverAccessService: { dbDump },
    });
    return { ...ctx, svc, extra, dbDump };
  }

  it('Owner run uses SSH mysqldump when managed DB login exists and records liveDb', async () => {
    const t = setupLive();
    const res = await t.svc.runBackup(POLICY, run, OWNER);
    expect(res.liveDb).toBe(true);
    expect(res.simulated).toBe(false);
    expect(t.dbDump).toHaveBeenCalledTimes(1);
    expect(t.adapters.calls.filter((c) => c.name === 'backup.dump' && c.arg?.kind === 'db')).toHaveLength(0);
    const up = [...t.extra.artStore.values()];
    const dbArt = up.find((a) => a.kind === 'db');
    expect(decrypt(await t.adapters.backupEngine.download({ locationRef: dbArt.locationRef }), KEY).toString()).toContain('live mysqldump');
    const man = JSON.parse(
      decrypt(await t.adapters.backupEngine.download({ locationRef: up.find((a) => a.kind === 'manifest').locationRef }), KEY),
    );
    expect(man.entries.find((e) => e.kind === 'db')).toMatchObject({ method: 'single-transaction', source: 'ssh-live' });
    expect(man.entries.find((e) => e.kind === 'config')).toMatchObject({ method: 'env-metadata', source: 'panel-env' });
    const configPlain = decrypt(await t.adapters.backupEngine.download({ locationRef: up.find((a) => a.kind === 'config').locationRef }), KEY).toString();
    expect(configPlain).toContain('https://app.test');
    expect(configPlain).toContain('[REDACTED]');
    expect(configPlain).not.toContain('super-secret');
  });

  it('SYSTEM_ACTOR scheduled path can call live dump (Owner bypass for jobs)', async () => {
    const t = setupLive();
    const res = await t.svc.runBackup(POLICY, { ...run, trigger: 'scheduled' }, SYSTEM_ACTOR);
    expect(res.liveDb).toBe(true);
    expect(t.dbDump).toHaveBeenCalledTimes(1);
  });

  it('non-Owner with backup grant keeps simulated dump even when login exists', async () => {
    const t = setupLive({
      grants: [{ userId: DEV.id, permissionKey: 'project.backup.create', resourceId: PROJECT, environmentId: ENV_PROD }],
    });
    const res = await t.svc.runBackup(POLICY, run, DEV);
    expect(res.liveDb).toBe(false);
    expect(t.dbDump).not.toHaveBeenCalled();
    expect(t.adapters.calls.some((c) => c.name === 'backup.dump')).toBe(true);
  });

  it('falls back to simulated dump when no managed live target exists', async () => {
    const t = setupLive({ noManaged: true });
    const res = await t.svc.runBackup(POLICY, run, OWNER);
    expect(res.liveDb).toBe(false);
    expect(t.dbDump).not.toHaveBeenCalled();
    expect(t.adapters.calls.some((c) => c.name === 'backup.dump' && c.arg?.kind === 'db')).toBe(true);
  });

  it('uploads kind uses SSH archiveTree when discoveredPath exists', async () => {
    const extra = backupPrisma();
    const ctx = makeCtx({ now: () => NOW });
    Object.assign(ctx.prisma, extra, {
      managedDatabase: { findMany: vi.fn(async () => []) },
      project: {
        findUnique: vi.fn(async () => ({
          id: PROJECT,
          serverId: SERVER,
          runtime: { metaJson: { discoveredPath: '/var/www/shop' } },
        })),
      },
      projectEnvVar: { findMany: vi.fn(async () => []) },
    });
    const archiveTree = vi.fn(async () => ({ bytes: Buffer.from('PK-fake-archive'), size: 16 }));
    const svc = createBackupsService({
      ...ctx,
      encryptionKey: () => KEY,
      credentialKey: () => KEY,
      serverAccessService: { archiveTree },
    });
    const res = await svc.runBackup(POLICY, { environmentId: ENV_PROD, kinds: ['uploads'], trigger: 'manual' }, OWNER);
    expect(res.simulated).toBe(false);
    expect(archiveTree).toHaveBeenCalledWith(SERVER, { path: '/var/www/shop' }, OWNER);
    const man = JSON.parse(
      decrypt(
        await ctx.adapters.backupEngine.download({
          locationRef: [...extra.artStore.values()].find((a) => a.kind === 'manifest').locationRef,
        }),
        KEY,
      ),
    );
    expect(man.entries.find((e) => e.kind === 'uploads')).toMatchObject({ method: 'tar-gz-excludes', source: 'ssh-archive' });
  });
});
