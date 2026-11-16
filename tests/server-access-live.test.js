import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createServerAccessService, MAX_DB_DUMP_BYTES, scrubSqlPreview } from '../src/modules/server-access/server-access.service.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';
import { createFakePrisma } from './http/fake-prisma.js';
import { createFakeSsh, liveResponder, pm2ActionOutput } from './server-access-fake-ssh.js';

const KEY = 'c'.repeat(64);
const OWNER = { id: randomUUID(), isOwner: true };
const DEV = { id: randomUUID(), isOwner: false };
const AUTH = { username: 'root', password: 'db-admin-pw-123' };

async function setup(over = {}) {
  const prisma = createFakePrisma();
  const server = await prisma.server.create({ data: { alias: 'web-1', status: 'online', archivedAt: null } });
  await prisma.serverCredential.create({
    data: { serverId: server.id, host: 'fake.invalid', port: 22, username: 'tester', authType: 'password', secretEnc: encrypt(Buffer.from('ssh-pw', 'utf8'), KEY), hostKeySha256: 'SHA256:fake-host-key' },
  });
  const ssh = createFakeSsh({ respond: liveResponder(over) });
  const auditService = { record: vi.fn(async () => ({})) };
  // PM2 stop/restart/reload are approval-gated; these tests cover the SSH behaviour behind the gate, so the gate
  // is stubbed open here. The real gate flow (202, mismatch, replay, self-approval) is in pm2-restore-gate.test.js.
  const platform = { gate: vi.fn(async () => ({ proceed: true, approval: null })) };
  const svc = createServerAccessService({ prisma, connector: ssh.connector, auditService, credentialKey: () => KEY, platform });
  return { prisma, server, serverId: server.id, ssh, auditService, svc };
}
const audits = (t) => t.auditService.record.mock.calls.map((c) => c[0]);

describe('server PM2 (fake ssh)', () => {
  it('lists processes and reports counts', async () => {
    const t = await setup();
    const res = await t.svc.pm2List(t.serverId, OWNER);
    expect(res).toMatchObject({ total: 2, online: 1, pm2Bin: '/usr/bin/pm2' });
    expect(res.processes.map((p) => p.name)).toEqual(['shop-api', 'worker']);
  });
  it('404 PM2_NOT_FOUND when pm2 is missing', async () => {
    const t = await setup({ respond: ({ script }) => (script.includes('jlist') ? { stdout: '##meta\nx\npm2=missing\n##pm2\n[]\n' } : null) });
    await expect(t.svc.pm2List(t.serverId, OWNER)).rejects.toMatchObject({ status: 404, code: 'PM2_NOT_FOUND' });
  });
  it('controls a process, passes the name as a quoted argument and audits', async () => {
    const t = await setup();
    const res = await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'restart' }, OWNER);
    expect(res).toMatchObject({ ok: true, exitCode: 0, action: 'restart' });
    expect(t.ssh.calls.at(-1).command).toBe('bash -s -- "shop-api"');
    expect(audits(t).find((e) => e.action === 'server.pm2.restart')).toMatchObject({ result: 'success', after: { name: 'shop-api', exitCode: 0 } });
  });
  it('maps a failing PM2 exit to 502 and audits a failure', async () => {
    const t = await setup({ respond: ({ script }) => (/pm2_exec stop/.test(script) ? { stdout: pm2ActionOutput('Process not found', 1) } : null) });
    await expect(t.svc.pm2Control(t.serverId, { name: 'ghost', action: 'stop' }, OWNER)).rejects.toMatchObject({ status: 502, code: 'PM2_ACTION_FAILED' });
    expect(audits(t).find((e) => e.action === 'server.pm2.stop').result).toBe('failure');
  });
  it('rejects injection in names, bad actions and non-owners', async () => {
    const t = await setup();
    await expect(t.svc.pm2Control(t.serverId, { name: 'a; rm -rf /', action: 'restart' }, OWNER)).rejects.toBeTruthy();
    await expect(t.svc.pm2Control(t.serverId, { name: 'ok', action: 'nuke' }, OWNER)).rejects.toMatchObject({ code: 'PM2_ACTION_INVALID' });
    await expect(t.svc.pm2Control(t.serverId, { name: 'ok', action: 'restart' }, DEV)).rejects.toMatchObject({ status: 403, code: 'OWNER_ONLY' });
    await expect(t.svc.pm2List(t.serverId, DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    expect(t.ssh.connector.connect).not.toHaveBeenCalled();
  });
});

describe('inspectSite (fake ssh)', () => {
  it('returns matched PM2 processes and logs for a project path', async () => {
    const t = await setup();
    const res = await t.svc.inspectSite(t.serverId, { path: '/var/www/shop', name: 'Shop', slug: 'shop' }, OWNER);
    expect(res.running).toBe(true);
    expect(res.processes.map((p) => p.name)).toEqual(['shop-api']);
    expect(res.logs.lines).toContain('listening on 3000');
  });
  it('rejects unsafe paths and non-owners before connecting', async () => {
    const t = await setup();
    await expect(t.svc.inspectSite(t.serverId, { path: '../etc' }, OWNER)).rejects.toMatchObject({ code: 'PATH_INVALID' });
    await expect(t.svc.inspectSite(t.serverId, { path: '/var/www/shop' }, DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    expect(t.ssh.connector.connect).not.toHaveBeenCalled();
  });
});

describe('live DB browse and query (fake ssh)', () => {
  it('lists schemas without system databases, then tables/columns/rows', async () => {
    const t = await setup();
    const schemas = await t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'schemas', auth: AUTH }, OWNER);
    expect(schemas).toMatchObject({ engine: 'mysql', schemas: ['shop_db'], usedLogin: true });
    const rows = await t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'rows', db: 'shop_db', table: 'users', limit: 5, auth: AUTH }, OWNER);
    expect(rows.rows).toEqual([{ id: '1', name: 'Ada' }, { id: '2', name: null }]);
    const tables = await t.svc.dbBrowse(t.serverId, { engine: 'postgres', action: 'tables', db: 'shop_db', auth: AUTH }, OWNER);
    expect(tables.db).toBe('shop_db');
    const cols = await t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'columns', db: 'shop_db', table: 'users', auth: AUTH }, OWNER);
    expect(cols.table).toBe('users');
  });
  it('rejects bad identifiers, engines and actions (422) and non-owners (403)', async () => {
    const t = await setup();
    await expect(t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'rows', db: 'a;b', table: 'users' }, OWNER)).rejects.toMatchObject({ status: 422 });
    await expect(t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'rows', db: 'x', table: 'u; drop' }, OWNER)).rejects.toMatchObject({ status: 422 });
    await expect(t.svc.dbBrowse(t.serverId, { engine: 'oracle', action: 'schemas' }, OWNER)).rejects.toMatchObject({ code: 'DB_ENGINE_INVALID' });
    await expect(t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'drop' }, OWNER)).rejects.toMatchObject({ code: 'DB_ACTION_INVALID' });
    await expect(t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'schemas' }, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('maps CLI failure with no output to 502 DB_LIVE_FAILED', async () => {
    const t = await setup({ respond: ({ command }) => (/mysql/.test(command) ? { code: 1, stderr: 'Access denied' } : null) });
    await expect(t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'schemas', auth: AUTH }, OWNER)).rejects.toMatchObject({ status: 502, code: 'DB_LIVE_FAILED' });
  });
  it('allows only one SQL statement and labels writes', async () => {
    const t = await setup();
    await expect(t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'query', sql: 'select 1; drop table t', auth: AUTH }, OWNER)).rejects.toMatchObject({ code: 'DB_SQL_MULTI' });
    const read = await t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'query', sql: 'SELECT * FROM users', auth: AUTH }, OWNER);
    expect(read.mutating).toBe(false);
    const write = await t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'query', sql: 'DELETE FROM users WHERE id = 1', auth: AUTH }, OWNER);
    expect(write.mutating).toBe(true);
    expect(audits(t).map((e) => e.action)).toEqual(['server.db.query.read', 'server.db.query.write']);
  });
  it('redacts secrets from the audited sqlPreview', async () => {
    const t = await setup();
    await t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'query', sql: "CREATE USER 'bob'@'%' IDENTIFIED BY 'S3cretPw!'", auth: AUTH }, OWNER);
    await t.svc.dbBrowse(t.serverId, { engine: 'mysql', action: 'query', sql: "UPDATE users SET password = 'hunter2' WHERE id = 1", auth: AUTH }, OWNER);
    const text = JSON.stringify(audits(t));
    expect(text).not.toContain('S3cretPw!');
    expect(text).not.toContain('hunter2');
    expect(text).toContain('[REDACTED]');
    expect(text).not.toContain(AUTH.password);
  });
  it('scrubSqlPreview keeps benign SQL and caps length', () => {
    expect(scrubSqlPreview('SELECT 1')).toBe('SELECT 1');
    expect(scrubSqlPreview(`SELECT '${'x'.repeat(500)}'`).length).toBe(200);
  });
});

describe('live DB dump (fake ssh)', () => {
  it('dumps over SFTP, cleans the temp file, audits size and hash', async () => {
    const t = await setup();
    const res = await t.svc.dbDump(t.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH }, OWNER);
    expect(res.bytes.toString()).toContain('CREATE TABLE');
    expect(res.filename).toMatch(/^mysql-shop_db-.*\.sql$/);
    expect([...t.ssh.files.keys()].filter((k) => k.startsWith('/tmp/nt-dump-'))).toEqual([]);
    const ev = audits(t).find((e) => e.action === 'server.db.dump');
    expect(ev.after).toMatchObject({ engine: 'mysql', db: 'shop_db', size: res.size });
    expect(ev.after.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(ev)).not.toContain(AUTH.password);
  });
  it('requires a saved MySQL login (409) and refuses non-owners', async () => {
    const t = await setup();
    await expect(t.svc.dbDump(t.serverId, { engine: 'mysql', db: 'shop_db' }, OWNER)).rejects.toMatchObject({ status: 409, code: 'DB_LOGIN_REQUIRED' });
    await expect(t.svc.dbDump(t.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH }, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('enforces the 80 MB size cap (413) and rejects an empty dump', async () => {
    const big = await setup({ dumpFile: { size: MAX_DB_DUMP_BYTES + 1, data: Buffer.alloc(0) } });
    await expect(big.svc.dbDump(big.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH }, OWNER)).rejects.toMatchObject({ status: 413, code: 'DB_DUMP_TOO_LARGE' });
    expect([...big.ssh.files.keys()].filter((k) => k.startsWith('/tmp/nt-dump-'))).toEqual([]);
    const empty = await setup({ dumpFile: { data: Buffer.alloc(0) } });
    await expect(empty.svc.dbDump(empty.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH }, OWNER)).rejects.toMatchObject({ code: 'DB_DUMP_EMPTY' });
  });
  it('surfaces remote dump failure as 502', async () => {
    const t = await setup({ respond: ({ command }) => (/mysqldump/.test(command) ? { code: 2, stderr: '__NT_ERR__boom' } : null) });
    await expect(t.svc.dbDump(t.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH }, OWNER)).rejects.toMatchObject({ status: 502, code: 'DB_DUMP_FAILED' });
  });
});

describe('live DB restore (fake ssh)', () => {
  const bytes = Buffer.from('CREATE TABLE t (id int);\n');
  it('restores when the typed confirmation equals the db name, then removes the upload', async () => {
    const t = await setup();
    const res = await t.svc.dbRestore(t.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH, bytes, confirm: 'shop_db' }, OWNER);
    expect(res).toMatchObject({ restored: true, db: 'shop_db', size: bytes.length });
    expect([...t.ssh.files.keys()].filter((k) => k.startsWith('/tmp/nt-restore-'))).toEqual([]);
    expect(audits(t).find((e) => e.action === 'server.db.restore')).toMatchObject({ result: 'success' });
  });
  it('accepts ALL only when no db is targeted', async () => {
    const t = await setup();
    expect((await t.svc.dbRestore(t.serverId, { engine: 'mysql', auth: AUTH, bytes, confirm: 'ALL' }, OWNER)).restored).toBe(true);
  });
  it('typed-confirm failure is 422 CONFIRM_MISMATCH and touches nothing', async () => {
    const t = await setup();
    for (const [db, confirm] of [['shop_db', 'wrong'], ['shop_db', 'ALL'], [null, 'shop_db'], ['shop_db', undefined]]) {
      await expect(t.svc.dbRestore(t.serverId, { engine: 'mysql', db, auth: AUTH, bytes, confirm }, OWNER)).rejects.toMatchObject({ status: 422, code: 'CONFIRM_MISMATCH' });
    }
    expect(t.ssh.connector.connect).not.toHaveBeenCalled();
    expect(audits(t)).toEqual([]);
  });
  it('rejects payloads under 8 bytes and over the 80 MB cap, before connecting', async () => {
    const t = await setup();
    await expect(t.svc.dbRestore(t.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH, bytes: Buffer.from('abc'), confirm: 'shop_db' }, OWNER)).rejects.toMatchObject({ code: 'DUMP_INVALID' });
    await expect(t.svc.dbRestore(t.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH, bytes: Buffer.alloc(MAX_DB_DUMP_BYTES + 1, 97), confirm: 'shop_db' }, OWNER)).rejects.toMatchObject({ status: 413, code: 'DB_DUMP_TOO_LARGE' });
    expect(t.ssh.connector.connect).not.toHaveBeenCalled();
  });
  it('requires a MySQL login (409) and refuses non-owners (403)', async () => {
    const t = await setup();
    await expect(t.svc.dbRestore(t.serverId, { engine: 'mysql', db: 'shop_db', bytes, confirm: 'shop_db' }, OWNER)).rejects.toMatchObject({ status: 409, code: 'DB_LOGIN_REQUIRED' });
    await expect(t.svc.dbRestore(t.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH, bytes, confirm: 'shop_db' }, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('maps remote failure to 502 and still removes the upload', async () => {
    const t = await setup({ respond: ({ command }) => (/nt-restore/.test(command) ? { code: 1, stderr: 'ERROR 1064' } : null) });
    await expect(t.svc.dbRestore(t.serverId, { engine: 'mysql', db: 'shop_db', auth: AUTH, bytes, confirm: 'shop_db' }, OWNER)).rejects.toMatchObject({ status: 502, code: 'DB_RESTORE_FAILED' });
    expect([...t.ssh.files.keys()].filter((k) => k.startsWith('/tmp/nt-restore-'))).toEqual([]);
  });
});

describe('inventory scan and import (fake ssh)', () => {
  it('scan is read-only on the panel side, parses candidates and audits counts', async () => {
    const t = await setup();
    const inv = await t.svc.scanInventory(t.serverId, OWNER);
    expect(inv.projects.map((p) => p.path).sort()).toEqual(['/var/www/api.example.com', '/var/www/shop.example.com']);
    expect(inv.domains.map((d) => d.name)).toContain('shop.example.com');
    expect(inv.databases[0]).toMatchObject({ engine: 'mysql', schemas: ['shop_db'] });
    expect(inv.debug).toMatchObject({ exitCode: 0, timedOut: false });
    expect(audits(t).find((e) => e.action === 'server.inventory.scan').after.projects).toBe(2);
    expect(t.prisma.project.rows).toHaveLength(0);
  });
  it('scan refuses non-owner is 403 and 409 without a login', async () => {
    const t = await setup();
    await expect(t.svc.scanInventory(t.serverId, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.scanInventory(randomUUID(), OWNER)).rejects.toMatchObject({ status: 409, code: 'SSH_CREDENTIAL_NOT_FOUND' });
  });
  it('imports everything, is idempotent, and archives earlier junk discoveries', async () => {
    const t = await setup();
    const junk = await t.prisma.project.create({ data: { serverId: t.serverId, name: 'lodash', slug: 'lodash', type: 'custom', status: 'discovered', archivedAt: null } });
    await t.prisma.projectRuntime.create({ data: { projectId: junk.id, runtime: null, processManager: 'none', metaJson: { discoveredPath: '/var/www/x/node_modules/lodash' } } });
    const first = await t.svc.importInventory(t.serverId, { importAll: true }, OWNER);
    expect(first.cleaned).toBe(1);
    expect(t.prisma.project.rows.find((p) => p.id === junk.id).status).toBe('archived');
    expect(first.created.projects).toHaveLength(2);
    expect(first.created.domains.map((d) => d.name)).toEqual(['shop.example.com']);
    expect(first.created.databases).toHaveLength(1);
    expect(t.prisma.projectRuntime.rows.some((r) => r.metaJson?.discoveredPath === '/var/www/shop.example.com')).toBe(true);
    const second = await t.svc.importInventory(t.serverId, { importAll: true }, OWNER);
    expect(second.created.projects).toHaveLength(0);
    expect(second.skipped.projects.every((s) => s.reason === 'already-known')).toBe(true);
    expect(t.prisma.project.rows.filter((p) => p.status === 'discovered')).toHaveLength(2);
    expect(audits(t).filter((e) => e.action === 'server.inventory.import')).toHaveLength(2);
  });
  it('honours a selection and 404s for an archived/unknown server', async () => {
    const t = await setup();
    const res = await t.svc.importInventory(t.serverId, { projects: ['/var/www/shop.example.com'], domains: [], databases: [] }, OWNER);
    expect(res.created.projects).toHaveLength(1);
    expect(res.created.domains).toHaveLength(0);
    expect(res.skipped.databases[0].reason).toBe('not-selected');
    await expect(t.svc.importInventory(randomUUID(), { importAll: true }, OWNER)).rejects.toMatchObject({ status: 404, code: 'SERVER_NOT_FOUND' });
  });
});
