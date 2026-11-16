import { describe, expect, it, vi } from 'vitest';
import {
  createDatabaseSql,
  createScopedUserSql,
  dropDatabaseSql,
  mysqlAdminCmd,
  mysqlStringLiteral,
} from '../src/modules/server-access/db-live.scan.js';
import { createDatabasesService } from '../src/modules/databases/databases.service.js';
import { DEV, ENV_PROD, KEY, OWNER, PROJECT, U, approve, makeCtx } from './phase6-helpers.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';

describe('db-live admin SQL builders (TASK-022)', () => {
  it('builds CREATE/DROP DATABASE with safe identifiers', () => {
    expect(createDatabaseSql('shop_prod')).toContain('`shop_prod`');
    expect(createDatabaseSql('shop_prod')).toMatch(/utf8mb4/);
    expect(dropDatabaseSql('shop_prod')).toBe('DROP DATABASE IF EXISTS `shop_prod`');
    expect(() => createDatabaseSql('bad-name!')).toThrow();
  });

  it('builds scoped user grants without GRANT OPTION and escapes password', () => {
    const sql = createScopedUserSql({
      username: 'shop_app',
      password: "p'ass\\word",
      host: '127.0.0.1',
      dbName: 'shop_prod',
      grants: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
    });
    expect(sql).toContain('CREATE USER IF NOT EXISTS');
    expect(sql).toContain('GRANT SELECT, INSERT, UPDATE, DELETE ON `shop_prod`.*');
    expect(sql).toContain('FLUSH PRIVILEGES');
    expect(sql).not.toMatch(/GRANT OPTION/i);
    expect(sql).toContain(mysqlStringLiteral("p'ass\\word"));
    expect(() => createScopedUserSql({ username: 'x', password: 'y', dbName: 'shop_prod', grants: ['DROP'] })).toThrow();
  });

  it('mysqlAdminCmd never puts the password on a mysql argv flag', () => {
    const cmd = mysqlAdminCmd('SELECT 1', { username: 'root', password: 'secret-value' });
    expect(cmd).toContain('--defaults-extra-file=');
    expect(cmd).not.toMatch(/mysql[^;]*-psecret/);
    expect(cmd).not.toMatch(/--password=secret/);
    expect(cmd).toContain("printf 'password=%s\\n'");
  });
});

describe('databases service live vs simulated provision (TASK-022)', () => {
  const DB_ID = U(50);
  const INST = U(60);
  const SERVER = U(90);
  const mk = { projectId: PROJECT, environmentId: ENV_PROD, instanceId: INST, dbName: 'shop_prod', reason: 'new app', rollbackNote: 'drop empty db' };

  function setup({ instance, actorGrants = [] } = {}) {
    const dbManage = vi.fn(async () => ({ ok: true, simulated: false, op: 'createDatabase' }));
    const ctx = makeCtx({
      grants: actorGrants,
      prismaExtra: {
        projectEnvironment: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: PROJECT })) },
        databaseInstance: {
          findUnique: vi.fn(async () => instance),
        },
        managedDatabase: {
          findFirst: vi.fn(async () => null),
          create: vi.fn(async ({ data }) => ({ id: DB_ID, ...data })),
          findUnique: vi.fn(async () => ({
            id: DB_ID,
            projectId: PROJECT,
            environmentId: ENV_PROD,
            dbName: 'shop_prod',
            instance,
            users: [],
          })),
        },
        databaseUser: { create: vi.fn(async ({ data }) => ({ id: U(70), ...data })) },
      },
    });
    const svc = createDatabasesService({
      ...ctx,
      serverAccessService: { dbManage },
      credentialKey: () => KEY,
    });
    return { ...ctx, svc, dbManage };
  }

  it('uses simulated adapter when instance has no server link', async () => {
    const t = setup({ instance: { id: INST, name: 'mysql-main', engine: 'mysql', serverId: null } });
    const first = await t.svc.create(mk, OWNER);
    await approve(t, first.approval.id);
    const row = await t.svc.create({ ...mk, approvalId: first.approval.id }, OWNER);
    expect(row.simulated).toBe(true);
    expect(t.dbManage).not.toHaveBeenCalled();
    expect(t.adapters.calls.some((c) => c.name === 'db.create')).toBe(true);
  });

  it('routes Owner create to SSH dbManage when server + login are present', async () => {
    const secretEnc = encrypt('lab-password', KEY);
    const t = setup({
      instance: {
        id: INST,
        name: 'mysql-main',
        engine: 'mysql',
        serverId: SERVER,
        adminUsername: 'root',
        adminSecretEnc: secretEnc,
      },
    });
    const first = await t.svc.create(mk, OWNER);
    await approve(t, first.approval.id);
    const row = await t.svc.create({ ...mk, approvalId: first.approval.id }, OWNER);
    expect(row.simulated).toBe(false);
    expect(t.dbManage).toHaveBeenCalledWith(
      SERVER,
      expect.objectContaining({ op: 'createDatabase', dbName: 'shop_prod', engine: 'mysql', auth: expect.objectContaining({ username: 'root' }) }),
      OWNER,
    );
    // Password is handed to SSH for one remote run; it must not appear in audit metadata.
    expect(JSON.stringify(t.auditService.record.mock.calls)).not.toContain('lab-password');
  });

  it('rejects non-Owner live provision even after approval', async () => {
    const secretEnc = encrypt('lab-password', KEY);
    const t = setup({
      instance: {
        id: INST,
        name: 'mysql-main',
        engine: 'mysql',
        serverId: SERVER,
        adminUsername: 'root',
        adminSecretEnc: secretEnc,
      },
      actorGrants: [{ userId: DEV.id, permissionKey: 'project.database.manage', resourceId: PROJECT, environmentId: ENV_PROD }],
    });
    const first = await t.svc.create(mk, DEV);
    await approve(t, first.approval.id);
    await expect(t.svc.create({ ...mk, approvalId: first.approval.id }, DEV)).rejects.toMatchObject({ code: 'LIVE_DB_OWNER_REQUIRED' });
    expect(t.dbManage).not.toHaveBeenCalled();
  });
});
