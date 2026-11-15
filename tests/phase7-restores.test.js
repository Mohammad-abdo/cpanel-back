import { describe, expect, it, vi } from 'vitest';
import { RESTORE_TRANSITIONS, createRestoresService } from '../src/modules/restores/restores.service.js';
import { createBackupsService } from '../src/modules/backups/backups.service.js';
import { sha256 } from '../src/modules/platform/platform.crypto.js';
import { APPROVER, DEV, ENV_PROD, ENV_STAGING, KEY, OWNER, PROJECT, U, approve, backupPrisma, makeCtx } from './phase6-helpers.js';

const NOW = new Date('2026-06-01T12:00:00Z');

async function setup(grants = []) {
  const ctx = makeCtx({ now: () => NOW, grants });
  const extra = backupPrisma();
  const restoreStore = new Map();
  let n = 900;
  extra.restoreRun = {
    create: vi.fn(async ({ data }) => { const r = { id: U(++n), approvedById: null, correlationId: null, ...data }; restoreStore.set(r.id, r); return r; }),
    findUnique: vi.fn(async ({ where }) => restoreStore.get(where.id) ?? null),
    update: vi.fn(async ({ where, data }) => { Object.assign(restoreStore.get(where.id), data); return restoreStore.get(where.id); }),
  };
  Object.assign(ctx.prisma, extra);
  const backups = createBackupsService({ ...ctx, encryptionKey: () => KEY });
  const restores = createRestoresService({ ...ctx, backups });
  const made = await backups.runBackup(extra.backupPolicy.findUnique ? U(90) : null, { environmentId: ENV_PROD, kinds: ['db', 'config'], trigger: 'manual' }, OWNER);
  const dbArtifact = [...extra.artStore.values()].find((a) => a.kind === 'db');
  const manifest = [...extra.artStore.values()].find((a) => a.kind === 'manifest');
  return { ...ctx, extra, backups, restores, made, dbArtifact, manifest, restoreStore };
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
