import { describe, expect, it, vi } from 'vitest';
import { BACKUP_TRANSITIONS, MIN_VERIFIED_KEEP, createBackupsService } from '../src/modules/backups/backups.service.js';
import { createPolicyBodySchema } from '../src/modules/backups/backups.validator.js';
import { decrypt } from '../src/modules/platform/platform.crypto.js';
import { DEV, ENV_PROD, ENV_STAGING, KEY, OWNER, PROJECT, U, approve, backupPrisma, makeCtx } from './phase6-helpers.js';

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
