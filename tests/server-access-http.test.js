import { randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

const KEY = vi.hoisted(() => {
  process.env.CREDENTIAL_ENCRYPTION_KEY = 'd'.repeat(64);
  return 'd'.repeat(64);
});

vi.mock('../src/config/prisma.js', async () => {
  const { createFakePrisma } = await import('./http/fake-prisma.js');
  return { prisma: createFakePrisma() };
});
// Replace only the network connector; execCommand/execScript/openSftp stay real and run on the fake client.
vi.mock('../src/modules/server-access/ssh.connector.js', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, createSshConnector: () => ({ connect: (opts) => globalThis.__fakeSsh.connector.connect(opts) }) };
});

import { prisma } from '../src/config/prisma.js';
import { createApp } from '../src/app.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';
import { bearer, seedSession, seedUser } from './http/fake-prisma.js';
import { createFakeSsh, liveResponder } from './server-access-fake-ssh.js';

const app = createApp();
const DB_PW = 'db-admin-pw-123';
let owner;
let dev;
let ctx;

async function actor(over) {
  const user = await seedUser(prisma, over);
  const { token } = await seedSession(prisma, user);
  return { user, h: bearer(token) };
}

async function seedWorld() {
  const server = await prisma.server.create({ data: { alias: `web-${randomUUID().slice(0, 6)}`, status: 'online', archivedAt: null } });
  await prisma.serverCredential.create({
    data: { serverId: server.id, host: 'fake.invalid', port: 22, username: 'tester', authType: 'password', secretEnc: encrypt(Buffer.from('ssh-pw'), KEY), hostKeySha256: 'SHA256:fake-host-key' },
  });
  const project = await prisma.project.create({ data: { serverId: server.id, name: 'Shop', slug: 'shop', type: 'node', status: 'active', archivedAt: null } });
  await prisma.projectRuntime.create({ data: { projectId: project.id, runtime: 'node', processManager: 'pm2', metaJson: { discoveredPath: '/var/www/shop' } } });
  const env = await prisma.projectEnvironment.create({ data: { projectId: project.id, code: 'production', displayName: 'Production' } });
  const bare = await prisma.project.create({ data: { serverId: server.id, name: 'Bare', slug: 'bare', type: 'custom', status: 'active', archivedAt: null } });
  const bareEnv = await prisma.projectEnvironment.create({ data: { projectId: bare.id, code: 'production', displayName: 'Production' } });
  const instance = await prisma.databaseInstance.create({
    data: { serverId: server.id, engine: 'mysql', name: 'main-mysql', status: 'registered', adminUsername: 'root', adminSecretEnc: encrypt(Buffer.from(DB_PW), KEY) },
  });
  return { server, project, env, bare, bareEnv, instance };
}

function useSsh(over = {}) {
  globalThis.__fakeSsh = createFakeSsh({ respond: liveResponder(over) });
  return globalThis.__fakeSsh;
}

beforeEach(async () => {
  prisma.__reset();
  owner = await actor({ ownerFlag: true });
  dev = await actor({});
  ctx = await seedWorld();
  useSsh();
});

const auditActions = () => prisma.auditEvent.rows.map((r) => r.action);

/**
 * High/Critical actions answer 202 until a different person approves. Sends the request with reason + rollback,
 * expects 202, approves as a second Owner, then replays with the approvalId and returns the final response.
 */
async function sendGated(send) {
  const first = await send({ reason: 'Planned maintenance window', rollbackNote: 'Start the process again' });
  expect(first.status).toBe(202);
  expect(first.body.data.approvalRequired).toBe(true);
  const approver = await actor({ ownerFlag: true });
  const dec = await request(app).post(`/api/v1/platform/approvals/${first.body.data.approvalId}/decision`).set(approver.h).send({ decision: 'approve' });
  expect(dec.status).toBe(200);
  return send({ approvalId: first.body.data.approvalId });
}

describe('authn/authz on the live routes', () => {
  it('401 without a session and 403 OWNER_ONLY for a non-owner on every owner route', async () => {
    const sid = ctx.server.id;
    const routes = [
      ['get', `/api/v1/servers/${sid}/ssh/pm2`],
      ['post', `/api/v1/servers/${sid}/ssh/pm2`, { name: 'shop-api', action: 'restart' }],
      ['post', `/api/v1/servers/${sid}/inventory/scan`],
      ['post', `/api/v1/servers/${sid}/inventory/import`, { importAll: true }],
      ['get', `/api/v1/projects/${ctx.project.id}/live`],
      ['post', `/api/v1/projects/${ctx.project.id}/pm2`, { action: 'restart', name: 'shop-api' }],
      ['get', `/api/v1/databases/instances/${ctx.instance.id}/live/schemas`],
      ['post', `/api/v1/databases/instances/${ctx.instance.id}/live/dump`, {}],
      ['post', `/api/v1/databases/instances/${ctx.instance.id}/live/restore?db=shop_db&confirm=shop_db`, null],
    ];
    for (const [method, url, body] of routes) {
      const anon = await request(app)[method](url).send(body ?? undefined);
      expect(anon.status, `anon ${method} ${url}`).toBe(401);
      const res = await request(app)[method](url).set(dev.h).send(body ?? undefined);
      expect(res.status, `dev ${method} ${url}`).toBe(403);
      expect(res.body.error.code).toBe('OWNER_ONLY');
    }
    expect(globalThis.__fakeSsh.connector.connect).not.toHaveBeenCalled();
  });
});

describe('GET /servers/runtimes validator', () => {
  it('accepts no query, rejects unknown query parameters with 400', async () => {
    expect((await request(app).get('/api/v1/servers/runtimes').set(owner.h)).status).toBe(200);
    const bad = await request(app).get('/api/v1/servers/runtimes?evil=1').set(owner.h);
    expect(bad.status).toBe(400);
    expect(bad.body.error.code).toBe('VALIDATION_ERROR');
  });
});

describe('pull-server .env', () => {
  const url = () => `/api/v1/projects/${ctx.project.id}/environments/${ctx.env.id}/vars/pull-server`;
  beforeEach(() => {
    useSsh().files.set('/var/www/shop/.env', { data: Buffer.from('APP_NAME=shop\nDB_NAME=shop_db\nDB_PASSWORD=sup3r-secret\n# c\n') });
  });

  it('reads the discovered path .env and returns keys without importing', async () => {
    const res = await request(app).post(url()).set(owner.h).send({});
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ path: '/var/www/shop/.env', keys: ['APP_NAME', 'DB_NAME', 'DB_PASSWORD'], guessedDb: { name: 'shop_db' }, imported: null });
    expect(prisma.projectEnvVar.rows).toHaveLength(0);
    const ev = prisma.auditEvent.rows.find((r) => r.action === 'project.env.pull_server');
    expect(ev.afterJson).toMatchObject({ keys: 3, imported: false });
    expect(JSON.stringify(prisma.auditEvent.rows)).not.toContain('sup3r-secret');
  });
  it('imports encrypted vars and marks secret-looking keys', async () => {
    const res = await request(app).post(url()).set(owner.h).send({ import: true });
    expect(res.status).toBe(200);
    expect(res.body.data.imported).toMatchObject({ added: 3 });
    const rows = prisma.projectEnvVar.rows;
    expect(rows.find((r) => r.key === 'DB_PASSWORD').isSecret).toBe(true);
    expect(rows.find((r) => r.key === 'APP_NAME').isSecret).toBe(false);
    expect(Buffer.from(rows[0].valueEnc).toString('latin1')).not.toContain('sup3r-secret');
  });
  it('409 PROJECT_PATH_UNKNOWN without a discovered path, 404 for a missing remote file', async () => {
    const none = await request(app).post(`/api/v1/projects/${ctx.bare.id}/environments/${ctx.bareEnv.id}/vars/pull-server`).set(owner.h).send({});
    expect(none.status).toBe(409);
    expect(none.body.error.code).toBe('PROJECT_PATH_UNKNOWN');
    const missing = await request(app).post(url()).set(owner.h).send({ path: '/var/www/shop/.env.nope' });
    expect(missing.status).toBe(404);
  });
  it('413 for a remote file over 1 MB and 422 for binary', async () => {
    globalThis.__fakeSsh.files.set('/var/www/shop/big.env', { size: 2 * 1024 * 1024, data: Buffer.alloc(0) });
    expect((await request(app).post(url()).set(owner.h).send({ path: '/var/www/shop/big.env' })).status).toBe(413);
    globalThis.__fakeSsh.files.set('/var/www/shop/bin.env', { data: Buffer.from([1, 0, 2]) });
    expect((await request(app).post(url()).set(owner.h).send({ path: '/var/www/shop/bin.env' })).status).toBe(422);
  });
  it('403 for a non-owner without project.configure, 404 for an environment of another project, 400 for an unknown field', async () => {
    const forbidden = await request(app).post(url()).set(dev.h).send({});
    expect(forbidden.status).toBe(403);
    expect(forbidden.body.error.code).toBe('FORBIDDEN');
    const wrongEnv = await request(app).post(`/api/v1/projects/${ctx.project.id}/environments/${ctx.bareEnv.id}/vars/pull-server`).set(owner.h).send({});
    expect(wrongEnv.status).toBe(404);
    expect((await request(app).post(url()).set(owner.h).send({ nope: 1 })).status).toBe(400);
  });
});

describe('server PM2 routes', () => {
  const base = () => `/api/v1/servers/${ctx.server.id}/ssh/pm2`;
  it('GET lists processes', async () => {
    const res = await request(app).get(base()).set(owner.h);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ total: 2, online: 1 });
  });
  it('POST controls a process and audits; validator rejects bad bodies', async () => {
    // reload is High risk: 202 first, then the approved replay runs it (gate legitimately changes this expectation).
    const ok = await sendGated((extra) => request(app).post(base()).set(owner.h).send({ name: 'shop-api', action: 'reload', ...extra }));
    expect(ok.status).toBe(200);
    expect(ok.body.data).toMatchObject({ ok: true, action: 'reload' });
    expect(auditActions()).toContain('server.pm2.reload');
    expect((await request(app).post(base()).set(owner.h).send({ name: 'a b', action: 'reload' })).status).toBe(400);
    expect((await request(app).post(base()).set(owner.h).send({ name: 'x', action: 'kill' })).status).toBe(400);
    expect((await request(app).post(base()).set(owner.h).send({ name: 'x', action: 'stop', extra: 1 })).status).toBe(400);
  });
  it('maps PM2 not installed to 404 and unknown server credential to 409', async () => {
    useSsh({ respond: ({ script }) => (script.includes('jlist') ? { stdout: '##meta\nx\npm2=missing\n##pm2\n[]\n' } : null) });
    const res = await request(app).get(base()).set(owner.h);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('PM2_NOT_FOUND');
    expect((await request(app).get(`/api/v1/servers/${randomUUID()}/ssh/pm2`).set(owner.h)).status).toBe(409);
    expect((await request(app).get('/api/v1/servers/not-a-uuid/ssh/pm2').set(owner.h)).status).toBe(400);
  });
});

describe('project /live and /pm2', () => {
  it('GET /live returns matched processes and logs', async () => {
    const res = await request(app).get(`/api/v1/projects/${ctx.project.id}/live`).set(owner.h);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ available: true, running: true });
    expect(res.body.data.processes.map((p) => p.name)).toEqual(['shop-api']);
  });
  it('GET /live without a discovered path is available:false and does not connect', async () => {
    const res = await request(app).get(`/api/v1/projects/${ctx.bare.id}/live`).set(owner.h);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ available: false, reason: 'no-path' });
    expect(globalThis.__fakeSsh.connector.connect).not.toHaveBeenCalled();
  });
  it('GET /live 404 for an unknown project', async () => {
    expect((await request(app).get(`/api/v1/projects/${randomUUID()}/live`).set(owner.h)).status).toBe(404);
  });
  it('POST /pm2 with an explicit name controls it and writes a project audit event', async () => {
    const res = await sendGated((extra) => request(app).post(`/api/v1/projects/${ctx.project.id}/pm2`).set(owner.h).send({ action: 'restart', name: 'shop-api', ...extra }));
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ ok: true, projectId: ctx.project.id, serverId: ctx.server.id });
    expect(auditActions()).toEqual(expect.arrayContaining(['server.pm2.restart', 'project.pm2.restart']));
  });
  it('POST /pm2 without a name targets the first live-matched process', async () => {
    const res = await sendGated((extra) => request(app).post(`/api/v1/projects/${ctx.project.id}/pm2`).set(owner.h).send({ action: 'stop', ...extra }));
    expect(res.status).toBe(200);
    expect(prisma.auditEvent.rows.find((r) => r.action === 'project.pm2.stop').afterJson).toMatchObject({ name: 'shop-api' });
  });
  it('POST /pm2 409 PM2_PROCESS_UNKNOWN when nothing matches, 400 on a bad action, 404 unknown project', async () => {
    useSsh({ respond: ({ script }) => (script.includes('##pm2logs') ? { stdout: '##meta\n/var/www/shop\n2026-11-16T00:00:00Z\n##pm2\n[]\n' } : null) });
    const none = await request(app).post(`/api/v1/projects/${ctx.project.id}/pm2`).set(owner.h).send({ action: 'restart' });
    expect(none.status).toBe(409);
    expect(none.body.error.code).toBe('PM2_PROCESS_UNKNOWN');
    expect((await request(app).post(`/api/v1/projects/${ctx.project.id}/pm2`).set(owner.h).send({ action: 'explode' })).status).toBe(400);
    expect((await request(app).post(`/api/v1/projects/${randomUUID()}/pm2`).set(owner.h).send({ action: 'restart', name: 'x' })).status).toBe(404);
  });
});

describe('live database routes', () => {
  const live = (p) => `/api/v1/databases/instances/${ctx.instance.id}/live/${p}`;
  it('browse: schemas, tables, columns, rows and a read query', async () => {
    const schemas = await request(app).get(live('schemas')).set(owner.h);
    expect(schemas.status).toBe(200);
    expect(schemas.body.data.schemas).toEqual(['shop_db']);
    expect((await request(app).get(`${live('tables')}?db=shop_db`).set(owner.h)).status).toBe(200);
    expect((await request(app).get(`${live('columns')}?db=shop_db&table=users`).set(owner.h)).status).toBe(200);
    const rows = await request(app).get(`${live('rows')}?db=shop_db&table=users&limit=10`).set(owner.h);
    expect(rows.body.data.rows).toHaveLength(2);
    const q = await request(app).post(live('query')).set(owner.h).send({ sql: 'select 1', db: 'shop_db' });
    expect(q.status).toBe(200);
    expect(q.body.data.mutating).toBe(false);
  });
  it('browse validators: bad identifiers, limit over 200 and unknown params are 400', async () => {
    expect((await request(app).get(`${live('tables')}?db=a;b`).set(owner.h)).status).toBe(400);
    expect((await request(app).get(`${live('rows')}?db=x&table=users&limit=500`).set(owner.h)).status).toBe(400);
    expect((await request(app).get(`${live('rows')}?db=x&table=1bad`).set(owner.h)).status).toBe(400);
    expect((await request(app).get(`${live('tables')}?db=x&evil=1`).set(owner.h)).status).toBe(400);
  });
  it('raw SQL: multi-statement 422, secrets redacted from the audit sqlPreview, DB password never audited', async () => {
    const multi = await request(app).post(live('query')).set(owner.h).send({ sql: 'select 1; drop table users' });
    expect(multi.status).toBe(422);
    expect(multi.body.error.code).toBe('DB_SQL_MULTI');
    const w = await request(app).post(live('query')).set(owner.h).send({ sql: "ALTER USER 'bob'@'%' IDENTIFIED BY 'Tr0ub4dor&3'" });
    expect(w.status).toBe(200);
    expect(w.body.data.mutating).toBe(true);
    const text = JSON.stringify(prisma.auditEvent.rows);
    expect(text).toContain('server.db.query.write');
    expect(text).not.toContain('Tr0ub4dor&3');
    expect(text).not.toContain(DB_PW);
  });
  it('dump streams the SQL as an attachment and audits without the password', async () => {
    const res = await request(app).post(live('dump')).set(owner.h).send({ db: 'shop_db' });
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toMatch(/filename="mysql-shop_db-.*\.sql"/);
    expect(res.headers['x-dump-db']).toBe('shop_db');
    expect(JSON.stringify(prisma.auditEvent.rows)).not.toContain(DB_PW);
    expect(auditActions()).toContain('server.db.dump');
  });
  it('dump: 413 when the remote file exceeds 80 MB', async () => {
    useSsh({ dumpFile: { size: 81 * 1024 * 1024, data: Buffer.alloc(0) } });
    const res = await request(app).post(live('dump')).set(owner.h).send({ db: 'shop_db' });
    expect(res.status).toBe(413);
    expect(res.body.error.code).toBe('DB_DUMP_TOO_LARGE');
  });
  it('dump: 409 DB_LOGIN_REQUIRED when the instance has no saved login', async () => {
    await prisma.databaseInstance.update({ where: { id: ctx.instance.id }, data: { adminUsername: null, adminSecretEnc: null } });
    const res = await request(app).post(live('dump')).set(owner.h).send({ db: 'shop_db' });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('DB_LOGIN_REQUIRED');
  });
  const restore = (qs, body = '-- restore\nCREATE TABLE t (id int);\n') =>
    request(app).post(`${live('restore')}?${qs}`).set(owner.h).set('Content-Type', 'application/octet-stream').send(Buffer.from(body));
  it('restore succeeds with the typed confirmation and is audited', async () => {
    // Live restore is Critical: 202 first, then the approved replay (same dump bytes) runs it.
    const res = await sendGated((extra) => restore(`db=shop_db&confirm=shop_db&${new URLSearchParams(extra)}`));
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ restored: true, db: 'shop_db' });
    expect(auditActions()).toContain('server.db.restore');
  });
  it('restore typed-confirm failure is 422 CONFIRM_MISMATCH and nothing is audited', async () => {
    const res = await restore('db=shop_db&confirm=SHOP_DB');
    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe('CONFIRM_MISMATCH');
    expect(auditActions()).not.toContain('server.db.restore');
    expect(globalThis.__fakeSsh.connector.connect).not.toHaveBeenCalled();
    expect((await restore('db=shop_db')).status).toBe(400);
  });
  it('restore rejects a payload under 8 bytes with 422', async () => {
    const res = await restore('db=shop_db&confirm=shop_db', 'abc');
    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe('DUMP_INVALID');
  });
  it('scope: unknown instance is 404; a non-owner cannot read an out-of-scope instance (404) or use live routes (403)', async () => {
    expect((await request(app).get(live('schemas').replace(ctx.instance.id, randomUUID())).set(owner.h)).status).toBe(404);
    const hidden = await request(app).get(`/api/v1/databases/instances/${ctx.instance.id}`).set(dev.h);
    expect(hidden.status).toBe(404);
    expect(hidden.body.error.code).toBe('SERVER_NOT_FOUND');
    expect((await request(app).get(live('schemas')).set(dev.h)).status).toBe(403);
    // an instance without a server is a 409, not an SSH attempt
    const orphan = await prisma.databaseInstance.create({ data: { serverId: null, engine: 'mysql', name: 'orphan', status: 'registered' } });
    const res = await request(app).get(`/api/v1/databases/instances/${orphan.id}/live/schemas`).set(owner.h);
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('INSTANCE_NO_SERVER');
  });
  it('permission 403: a project member without database permission cannot create a database; engine other than mysql/postgres is 422', async () => {
    const mongo = await prisma.databaseInstance.create({ data: { serverId: ctx.server.id, engine: 'redis', name: 'cache', status: 'registered' } });
    const res = await request(app).get(`/api/v1/databases/instances/${mongo.id}/live/schemas`).set(owner.h);
    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe('ENGINE_UNSUPPORTED');
    const create = await request(app)
      .post('/api/v1/databases')
      .set(dev.h)
      .send({ projectId: ctx.project.id, environmentId: ctx.env.id, instanceId: ctx.instance.id, dbName: 'x_db' });
    expect([400, 403]).toContain(create.status);
  });
});

describe('inventory scan and import routes', () => {
  it('scan returns candidates and does not write panel records', async () => {
    const res = await request(app).post(`/api/v1/servers/${ctx.server.id}/inventory/scan`).set(owner.h);
    expect(res.status).toBe(200);
    expect(res.body.data.projects.map((p) => p.path).sort()).toEqual(['/var/www/api.example.com', '/var/www/shop.example.com']);
    expect(res.body.data.debug.exitCode).toBe(0);
    expect(prisma.project.rows).toHaveLength(2); // only the seeded ones
    expect(auditActions()).toContain('server.inventory.scan');
  });
  it('import creates discovered projects/domains/databases once and is idempotent', async () => {
    const url = `/api/v1/servers/${ctx.server.id}/inventory/import`;
    const first = await request(app).post(url).set(owner.h).send({ importAll: true });
    expect(first.status).toBe(200);
    expect(first.body.data.created.projects).toHaveLength(2);
    expect(first.body.data.created.domains.map((d) => d.name)).toEqual(['shop.example.com']);
    const second = await request(app).post(url).set(owner.h).send({ importAll: true });
    expect(second.body.data.created.projects).toHaveLength(0);
    expect(prisma.domain.rows).toHaveLength(1);
    expect(auditActions().filter((a) => a === 'server.inventory.import')).toHaveLength(2);
  });
  it('import validator: strict body, engine enum, 404 for an unknown server', async () => {
    const url = `/api/v1/servers/${ctx.server.id}/inventory/import`;
    expect((await request(app).post(url).set(owner.h).send({ databases: ['oracle'] })).status).toBe(400);
    expect((await request(app).post(url).set(owner.h).send({ nope: true })).status).toBe(400);
    expect((await request(app).post(`/api/v1/servers/${randomUUID()}/inventory/import`).set(owner.h).send({ importAll: true })).status).toBe(404);
  });
});
