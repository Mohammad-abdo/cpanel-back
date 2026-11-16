import { describe, expect, it, vi } from 'vitest';
import { RESTORE_TRANSITIONS, createRestoresService } from '../src/modules/restores/restores.service.js';
import { createBackupsService } from '../src/modules/backups/backups.service.js';
import { encrypt, sha256 } from '../src/modules/platform/platform.crypto.js';
import { APPROVER, DEV, ENV_PROD, ENV_STAGING, KEY, OWNER, PROJECT, U, approve, backupPrisma, makeCtx } from './phase6-helpers.js';

const NOW = new Date('2026-06-01T12:00:00Z');
const SERVER = U(40);
const LIVE_DB = {
  id: U(42),
  projectId: PROJECT,
  environmentId: ENV_PROD,
  dbName: 'app_prod',
  instance: {
    id: U(41),
    serverId: SERVER,
    engine: 'mysql',
    name: 'mysql-main',
    adminUsername: 'root',
    adminSecretEnc: encrypt('secret-db-pass', KEY),
  },
};

async function setup(grants = [], opts = {}) {
  const ctx = makeCtx({ now: () => NOW, grants });
  const extra = backupPrisma();
  const restoreStore = new Map();
  let n = 900;
  extra.restoreRun = {
    create: vi.fn(async ({ data }) => { const r = { id: U(++n), approvedById: null, correlationId: null, ...data }; restoreStore.set(r.id, r); return r; }),
    findUnique: vi.fn(async ({ where }) => restoreStore.get(where.id) ?? null),
    update: vi.fn(async ({ where, data }) => { Object.assign(restoreStore.get(where.id), data); return restoreStore.get(where.id); }),
  };
  Object.assign(ctx.prisma, extra, {
    managedDatabase: {
      findMany: vi.fn(async () => (opts.liveDb === false ? [] : opts.liveDb ? [LIVE_DB] : [])),
    },
  });
  const dbRestore = vi.fn(async () => ({ restored: true, engine: 'mysql', db: 'app_prod', size: 32 }));
  const dbBrowse = vi.fn(async () => ({ engine: 'mysql', schemas: ['app_prod'] }));
  const serverAccessService = opts.serverAccess ?? (opts.liveDb ? { dbRestore, dbBrowse } : null);
  const backups = createBackupsService({
    ...ctx,
    encryptionKey: () => KEY,
    credentialKey: () => KEY,
    serverAccessService: opts.liveDb
      ? { dbDump: vi.fn(async () => ({ bytes: Buffer.from('-- safety\n'), size: 10 })) }
      : null,
  });
  const restores = createRestoresService({
    ...ctx,
    backups,
    credentialKey: () => KEY,
    serverAccessService,
  });
  const made = await backups.runBackup(extra.backupPolicy.findUnique ? U(90) : null, { environmentId: ENV_PROD, kinds: ['db', 'config'], trigger: 'manual' }, OWNER);
  const dbArtifact = [...extra.artStore.values()].find((a) => a.kind === 'db');
  const manifest = [...extra.artStore.values()].find((a) => a.kind === 'manifest');
  return { ...ctx, extra, backups, restores, made, dbArtifact, manifest, restoreStore, dbRestore, dbBrowse, serverAccessService };
}
const req = (t, over = {}) => ({ artifactId: t.dbArtifact.id, mode: 'isolated', targetEnvironmentId: ENV_PROD, reason: 'recovery drill', rollbackNote: 'discard trial area', ...over });

describe('restores: request and approval', () => {
  it('validates, previews impact and waits for approval without restoring', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t), OWNER);
    expect(r.approvalRequired).toBe(true);
    expect(r.preview).toBeDefined();
    expect(t.restoreStore.get(r.restoreId).status).toBe('awaiting_approval');
    expect(t.adapters.calls.some((c) => c.name === 'backup.restore')).toBe(false);
  });
  it('execute without approval is refused and leaves state untouched', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t), OWNER);
    await expect(t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_APPROVED' });
    expect(t.restoreStore.get(r.restoreId).status).toBe('awaiting_approval');
  });
  it('isolated restore: approved, restored, data compared, health checked, audited', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t), OWNER);
    await approve(t, r.approval.id);
    const done = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER);
    expect(done.restore.status).toBe('completed');
    expect(done.restore.approvedById).toBe(APPROVER.id);
    expect(done.safetyBackupRunId).toBeNull();
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'restore.execute', result: 'success' }));
    await expect(t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER)).rejects.toMatchObject({ code: 'INVALID_RESTORE_TRANSITION' });
  });
  it('in-place restore takes a safety backup first', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t, { mode: 'inplace' }), OWNER);
    expect(r.approval.impactJson.riskTier).toBe('critical');
    await approve(t, r.approval.id);
    const before = t.adapters.calls.filter((c) => c.name === 'backup.dump').length;
    const done = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER);
    expect(done.safetyBackupRunId).toBeTruthy();
    const names = t.adapters.calls.map((c) => c.name);
    expect(t.adapters.calls.filter((c) => c.name === 'backup.dump').length).toBe(before + 1);
    expect(names.lastIndexOf('backup.dump')).toBeLessThan(names.lastIndexOf('backup.restore'));
  });
  it('aborts the restore when the safety backup fails', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t, { mode: 'inplace' }), OWNER);
    await approve(t, r.approval.id);
    t.adapters.backupEngine.dump = vi.fn(async () => { throw new Error('disk full'); });
    await expect(t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER)).rejects.toBeTruthy();
    expect(t.restoreStore.get(r.restoreId).status).toBe('failed');
    expect(t.adapters.calls.some((c) => c.name === 'backup.restore')).toBe(false);
  });
});

describe('restores: rejections', () => {
  it('rejects a corrupt backup set at validation', async () => {
    const t = await setup();
    const bad = Buffer.from(await t.adapters.backupEngine.download({ locationRef: t.dbArtifact.locationRef }));
    bad[20] ^= 0xff;
    await t.adapters.backupEngine.upload({ name: t.dbArtifact.locationRef.replace('sim://offsite/', ''), bytes: bad });
    await expect(t.restores.request(req(t), OWNER)).rejects.toMatchObject({ code: 'CORRUPT_BACKUP' });
    expect(t.restoreStore.size).toBe(0);
  });
  it('rejects staging backup into production and cross-environment actors', async () => {
    const t = await setup();
    await expect(t.restores.request(req(t, { targetEnvironmentId: ENV_STAGING }), OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_MISMATCH' });
    await expect(t.restores.request(req(t), DEV)).rejects.toMatchObject({ status: 403 });
    const staged = await setup([{ userId: DEV.id, permissionKey: 'project.backup.restore', resourceId: PROJECT, environmentId: ENV_STAGING }]);
    await expect(staged.restores.request(req(staged), DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('rejects manifests, unverified sets and unknown restore points', async () => {
    const t = await setup();
    await expect(t.restores.request(req(t, { artifactId: t.manifest.id }), OWNER)).rejects.toMatchObject({ code: 'NOT_RESTORABLE' });
    t.extra.runStore.get(t.made.run.id).verificationStatus = 'failed';
    await expect(t.restores.request(req(t), OWNER)).rejects.toMatchObject({ code: 'BACKUP_NOT_RESTORABLE' });
    await expect(t.restores.request(req(t, { artifactId: U(77) }), OWNER)).rejects.toMatchObject({ code: 'ARTIFACT_NOT_FOUND' });
  });
  it('fails on data mismatch and on failed health check', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t), OWNER);
    await approve(t, r.approval.id);
    t.adapters.backupEngine.restore = vi.fn(async () => ({ restored: true, checksums: { db: sha256('different') } }));
    await expect(t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER)).rejects.toMatchObject({ code: 'RESTORE_MISMATCH' });
    expect(t.restoreStore.get(r.restoreId).status).toBe('failed');

    const h = await setup();
    const r2 = await h.restores.request(req(h, { mode: 'inplace' }), OWNER);
    await approve(h, r2.approval.id);
    h.adapters.backupEngine.health = vi.fn(async () => ({ healthy: false }));
    await expect(h.restores.execute(r2.restoreId, { environmentId: ENV_PROD }, OWNER)).rejects.toMatchObject({ code: 'RESTORE_HEALTH_FAILED' });
    expect(h.restoreStore.get(r2.restoreId).status).toBe('failed');
  });
  it('only the requester can execute and transitions cannot skip approval', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t), OWNER);
    await approve(t, r.approval.id);
    await expect(t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, APPROVER)).rejects.toMatchObject({ status: 403 });
    expect(RESTORE_TRANSITIONS.validated).not.toContain('restoring');
    expect(RESTORE_TRANSITIONS.awaiting_approval).not.toContain('restoring');
  });
  it('lists only verified restore points', async () => {
    const t = await setup();
    t.extra.backupRun.findMany = vi.fn(async () => [{ id: 'r', finishedAt: NOW, policy: { environmentId: ENV_PROD }, artifacts: [...t.extra.artStore.values()] }]);
    const pts = await t.restores.listRestorePoints({ projectId: PROJECT, limit: 5 });
    expect(pts[0].artifacts.map((a) => a.kind)).not.toContain('manifest');
  });
});

describe('restores: panel config in-place', () => {
  it('restores non-secret env vars from a config artifact into the panel', async () => {
    const t = await setup();
    const configArt = [...t.extra.artStore.values()].find((a) => a.kind === 'config');
    // Replace stored config ciphertext with a panel-env shaped payload.
    const { encrypt: enc } = await import('../src/modules/platform/platform.crypto.js');
    const plain = Buffer.from(
      JSON.stringify({
        projectId: PROJECT,
        environmentId: ENV_PROD,
        vars: [
          { key: 'APP_URL', isSecret: false, value: 'https://restored.test' },
          { key: 'API_TOKEN', isSecret: true, value: '[REDACTED]' },
        ],
      }),
    );
    const cipher = enc(plain, KEY);
    await t.adapters.backupEngine.upload({ name: configArt.locationRef.replace('sim://offsite/', ''), bytes: cipher });
    const { sha256: hash } = await import('../src/modules/platform/platform.crypto.js');
    configArt.checksum = hash(cipher);

    const upserts = [];
    t.prisma.projectEnvVar = {
      upsert: vi.fn(async ({ where, create, update }) => {
        upserts.push({ where, create, update });
        return { id: U(88), ...create };
      }),
    };

    const r = await t.restores.request(req(t, { artifactId: configArt.id, mode: 'inplace' }), OWNER);
    await approve(t, r.approval.id);
    const done = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER);
    expect(done.panelConfig).toBe(true);
    expect(done.simulated).toBe(false);
    expect(upserts).toHaveLength(1);
    expect(upserts[0].where.environmentId_key.key).toBe('APP_URL');
    expect(t.adapters.calls.filter((c) => c.name === 'backup.restore')).toHaveLength(0);
  });
});

describe('restores: live SSH in-place', () => {
  it('Owner in-place db restore uses SSH when managed login exists', async () => {
    const t = await setup([], { liveDb: true });
    const r = await t.restores.request(req(t, { mode: 'inplace' }), OWNER);
    await approve(t, r.approval.id);
    const done = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER);
    expect(done.live).toBe(true);
    expect(done.simulated).toBe(false);
    expect(t.dbRestore).toHaveBeenCalled();
    expect(t.dbBrowse).toHaveBeenCalled();
    // Primary restore should not use the simulated adapter when live succeeds.
    expect(t.adapters.calls.filter((c) => c.name === 'backup.restore')).toHaveLength(0);
  });

  it('isolated restore never calls live SSH even when login exists', async () => {
    const t = await setup([], { liveDb: true });
    const r = await t.restores.request(req(t, { mode: 'isolated' }), OWNER);
    await approve(t, r.approval.id);
    const done = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER);
    expect(done.live).toBe(false);
    expect(t.dbRestore).not.toHaveBeenCalled();
    expect(t.adapters.calls.some((c) => c.name === 'backup.restore')).toBe(true);
  });

  it('live health failure rolls back via SSH restore of the safety dump', async () => {
    const t = await setup([], { liveDb: true });
    const r = await t.restores.request(req(t, { mode: 'inplace' }), OWNER);
    await approve(t, r.approval.id);
    t.dbBrowse.mockRejectedValueOnce(new Error('down')).mockResolvedValue({ schemas: ['app_prod'] });
    const err = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER).catch((e) => e);
    expect(err).toMatchObject({ code: 'RESTORE_HEALTH_FAILED', rolledBack: true });
    // First call: failed restore target; second: safety rollback.
    expect(t.dbRestore).toHaveBeenCalledTimes(2);
  });
});

describe('restores: automatic rollback', () => {
  it('in-place restore with failed health check restores the safety backup automatically', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t, { mode: 'inplace' }), OWNER);
    await approve(t, r.approval.id);
    t.adapters.backupEngine.health = vi.fn(async () => ({ healthy: false }));
    const err = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER).catch((e) => e);
    expect(err).toMatchObject({ code: 'RESTORE_HEALTH_FAILED', rolledBack: true });
    const restores = t.adapters.calls.filter((c) => c.name === 'backup.restore');
    expect(restores).toHaveLength(2); // the restore, then the rollback
    expect(restores[1].arg.mode).toBe('inplace');
    const ev = t.auditService.record.mock.calls.map((c) => c[0]).find((e) => e.action === 'restore.execute');
    expect(ev.metadata).toMatchObject({ rolledBack: true, safetyBackupRunId: expect.any(String) });
  });
  it('reports a failed rollback so the operator rolls back manually', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t, { mode: 'inplace' }), OWNER);
    await approve(t, r.approval.id);
    t.adapters.backupEngine.health = vi.fn(async () => ({ healthy: false }));
    const real = t.adapters.backupEngine.restore;
    let n = 0;
    t.adapters.backupEngine.restore = vi.fn(async (input) => (++n === 1 ? real(input) : { restored: false }));
    const err = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER).catch((e) => e);
    expect(err).toMatchObject({ code: 'RESTORE_HEALTH_FAILED', rolledBack: false });
    expect(err.message).toMatch(/roll back manually/);
  });
  it('isolated restore never rolls back (production untouched)', async () => {
    const t = await setup();
    const r = await t.restores.request(req(t), OWNER);
    await approve(t, r.approval.id);
    t.adapters.backupEngine.health = vi.fn(async () => ({ healthy: false }));
    const err = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER).catch((e) => e);
    expect(err).toMatchObject({ code: 'RESTORE_HEALTH_FAILED', rolledBack: false });
    expect(t.adapters.calls.filter((c) => c.name === 'backup.restore')).toHaveLength(1);
  });
});
