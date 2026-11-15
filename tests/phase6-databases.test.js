import { describe, expect, it, vi } from 'vitest';
import { createDatabasesService } from '../src/modules/databases/databases.service.js';
import { createDatabaseBodySchema, createUserBodySchema } from '../src/modules/databases/databases.validator.js';
import { DEV, ENV_PROD, ENV_STAGING, OWNER, PROJECT, U, approve, makeCtx } from './phase6-helpers.js';

const DB_ID = U(50);
const NOW = new Date('2026-06-01T12:00:00Z');
const dbRow = (over = {}) => ({ id: DB_ID, projectId: PROJECT, environmentId: ENV_PROD, dbName: 'shop_prod', instance: { name: 'mysql-main' }, users: [], ...over });

function setup({ db = dbRow(), run, grants = [] } = {}) {
  const ctx = makeCtx({
    grants,
    now: () => NOW,
    prismaExtra: {
      projectEnvironment: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: PROJECT })) },
      databaseInstance: { findUnique: vi.fn(async () => ({ id: U(60), name: 'mysql-main', engine: 'mysql' })), findMany: vi.fn(async () => []) },
      managedDatabase: {
        findUnique: vi.fn(async () => db),
        findFirst: vi.fn(async () => null),
        create: vi.fn(async ({ data }) => ({ id: DB_ID, ...data })),
        delete: vi.fn(async () => ({})),
        findMany: vi.fn(async () => [dbRow({ users: [{ id: 'u', username: 'app', privilegesJson: {}, secretLeak: 'x' }] })]),
      },
      databaseUser: { create: vi.fn(async ({ data }) => ({ id: U(70), ...data })) },
      backupRun: { findUnique: vi.fn(async () => run ?? null) },
    },
  });
  return { ...ctx, svc: createDatabasesService(ctx) };
}
const mk = { projectId: PROJECT, environmentId: ENV_PROD, instanceId: U(60), dbName: 'shop_prod', reason: 'new app', rollbackNote: 'drop empty db' };
const goodRun = { id: U(80), status: 'retained', verificationStatus: 'verified', finishedAt: new Date(NOW.getTime() - 3600000), policy: { projectId: PROJECT } };

describe('databases: create', () => {
  it('requires approval then creates', async () => {
    const t = setup();
    const first = await t.svc.create(mk, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.adapters.calls.some((c) => c.name === 'db.create')).toBe(false);
    await approve(t, first.approval.id);
    const row = await t.svc.create({ ...mk, approvalId: first.approval.id }, OWNER);
    expect(row.dbName).toBe('shop_prod');
  });
  it('denies staging grant on production and reserved names', async () => {
    const t = setup({ grants: [{ userId: DEV.id, permissionKey: 'project.database.manage', resourceId: PROJECT, environmentId: ENV_STAGING }] });
    await expect(t.svc.create(mk, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.create({ ...mk, dbName: 'mysql' }, OWNER)).rejects.toMatchObject({ code: 'DB_NAME_RESERVED' });
  });
  it('validators are strict', () => {
    expect(createDatabaseBodySchema.safeParse({ ...mk, dbName: 'Bad-Name' }).success).toBe(false);
    expect(createUserBodySchema.safeParse({ environmentId: ENV_PROD, username: 'app_user', level: 'admin' }).success).toBe(false);
  });
  it('listing never returns anything but scope metadata for users', async () => {
    const t = setup();
    const rows = await t.svc.list({ limit: 10 });
    expect(rows[0].users[0]).toEqual({ id: 'u', username: 'app', privilegesJson: {} });
  });
});

describe('databases: scoped users', () => {
  const body = { environmentId: ENV_PROD, username: 'shop_app', level: 'readwrite', reason: 'app access', rollbackNote: 'drop user' };
  it('grants only on the database, returns the password once and never stores or audits it', async () => {
    const t = setup();
    const first = await t.svc.createUser(DB_ID, body, OWNER);
    await approve(t, first.approval.id);
    const res = await t.svc.createUser(DB_ID, { ...body, approvalId: first.approval.id }, OWNER);
    expect(res.password.length).toBeGreaterThan(16);
    const stored = JSON.stringify(t.prisma.databaseUser.create.mock.calls);
    expect(stored).not.toContain(res.password);
    expect(JSON.stringify(t.auditService.record.mock.calls)).not.toContain(res.password);
    const call = t.adapters.calls.find((c) => c.name === 'db.user').arg;
    expect(call.scope).toBe('shop_prod.*');
    expect(call.grantOption).toBe(false);
    expect(call.grants).not.toContain('DROP');
    expect(JSON.stringify(t.adapters.calls)).not.toContain(res.password);
  });
  it('blocks cross-environment access', async () => {
    const t = setup();
    await expect(t.svc.createUser(DB_ID, { ...body, environmentId: ENV_STAGING }, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_MISMATCH' });
  });
  it('denies unauthorized users and duplicates', async () => {
    const t = setup();
    await expect(t.svc.createUser(DB_ID, body, DEV)).rejects.toMatchObject({ status: 403 });
    const t2 = setup({ db: dbRow({ users: [{ username: 'shop_app' }] }) });
    await expect(t2.svc.createUser(DB_ID, body, OWNER)).rejects.toMatchObject({ code: 'DB_USER_EXISTS' });
  });
});

describe('databases: drop', () => {
  const body = { environmentId: ENV_PROD, confirmName: 'shop_prod', safetyBackupRunId: goodRun.id, reason: 'decommission', rollbackNote: 'restore from backup' };
  it('requires a fresh verified safety backup', async () => {
    for (const bad of [null, { ...goodRun, verificationStatus: 'failed' }, { ...goodRun, finishedAt: new Date(NOW.getTime() - 48 * 3600000) }, { ...goodRun, policy: { projectId: U(99) } }, { ...goodRun, status: 'failed' }]) {
      const t = setup({ run: bad });
      await expect(t.svc.drop(DB_ID, body, OWNER)).rejects.toMatchObject({ code: 'SAFETY_BACKUP_REQUIRED' });
    }
  });
  it('requires the confirmation name and approval, then drops', async () => {
    const t = setup({ run: goodRun });
    await expect(t.svc.drop(DB_ID, { ...body, confirmName: 'other' }, OWNER)).rejects.toMatchObject({ code: 'CONFIRM_NAME_MISMATCH' });
    const first = await t.svc.drop(DB_ID, body, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.prisma.managedDatabase.delete).not.toHaveBeenCalled();
    await approve(t, first.approval.id);
    const done = await t.svc.drop(DB_ID, { ...body, approvalId: first.approval.id }, OWNER);
    expect(done.dropped).toBe(true);
  });
});
