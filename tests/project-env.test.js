import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createProjectEnvService, looksSecret, parseDotenv, toDotenv } from '../src/modules/project-env/project-env.service.js';
import { setVarsBodySchema } from '../src/modules/project-env/project-env.validator.js';
import { makeRbac } from './phase6-helpers.js';

const KEY = 'b'.repeat(64);
const OWNER = { id: randomUUID(), isOwner: true };
const DEV = { id: randomUUID(), isOwner: false };
const PROJECT = randomUUID();
const SERVER = randomUUID();
const STG = randomUUID();
const PROD = randomUUID();

function setup(grants = [], { serverAccess = null, key = KEY } = {}) {
  const envs = new Map([
    [STG, { id: STG, projectId: PROJECT, code: 'staging', displayName: 'Staging' }],
    [PROD, { id: PROD, projectId: PROJECT, code: 'production', displayName: 'Production' }],
  ]);
  const project = { id: PROJECT, serverId: SERVER, archivedAt: null };
  const vars = new Map();
  const k = (environmentId, key2) => `${environmentId}:${key2}`;
  const prisma = {
    vars,
    project: { findUnique: vi.fn(async () => project) },
    projectEnvironment: {
      findUnique: vi.fn(async ({ where }) => (envs.has(where.id) ? { ...envs.get(where.id), project } : null)),
      findFirst: vi.fn(async ({ where }) => [...envs.values()].find((e) => e.projectId === where.projectId && e.code === where.code) ?? null),
      create: vi.fn(async ({ data }) => {
        const e = { id: randomUUID(), ...data };
        envs.set(e.id, e);
        return e;
      }),
    },
    projectEnvVar: {
      findMany: vi.fn(async ({ where }) => [...vars.values()].filter((v) => v.environmentId === where.environmentId).sort((a, b) => a.key.localeCompare(b.key))),
      findUnique: vi.fn(async ({ where }) => vars.get(k(where.environmentId_key.environmentId, where.environmentId_key.key)) ?? null),
      upsert: vi.fn(async ({ where, create, update }) => {
        const id = k(where.environmentId_key.environmentId, where.environmentId_key.key);
        const row = vars.get(id) ? Object.assign(vars.get(id), update) : { id, ...create };
        vars.set(id, row);
        return row;
      }),
      delete: vi.fn(async ({ where }) => vars.delete(where.id)),
    },
  };
  const auditService = { record: vi.fn(async () => ({})) };
  const svc = createProjectEnvService({ prisma, rbac: makeRbac(grants), auditService, serverAccess, credentialKey: () => key });
  return { prisma, auditService, svc };
}
const grant = (permissionKey, environmentId) => ({ userId: DEV.id, permissionKey, resourceId: PROJECT, environmentId });

describe('dotenv parsing', () => {
  it('parses export, comments, quotes and escapes; round-trips', () => {
    const { vars, errors } = parseDotenv('# comment\nexport APP_ENV=production\nDB_PASSWORD="p@ss word#1"\nNAME=\'single\'\nMULTI="a\\nb"\nINLINE=value # note\nbad line\n');
    expect(vars).toEqual([
      { key: 'APP_ENV', value: 'production' },
      { key: 'DB_PASSWORD', value: 'p@ss word#1' },
      { key: 'NAME', value: 'single' },
      { key: 'MULTI', value: 'a\nb' },
      { key: 'INLINE', value: 'value' },
    ]);
    expect(errors).toEqual([7]);
    expect(parseDotenv(toDotenv(vars)).vars).toEqual(vars);
  });
  it('detects secret-looking keys', () => {
    expect(['DB_PASSWORD', 'STRIPE_SECRET', 'API_KEY', 'JWT_TOKEN', 'DATABASE_URL', 'APP_KEY'].every(looksSecret)).toBe(true);
    expect(['APP_ENV', 'PORT', 'NODE_ENV'].some(looksSecret)).toBe(false);
  });
  it('validator rejects bad keys', () => {
    expect(setVarsBodySchema.safeParse({ vars: [{ key: '1BAD', value: 'x' }] }).success).toBe(false);
    expect(setVarsBodySchema.safeParse({ vars: [{ key: 'GOOD_KEY', value: 'x' }] }).success).toBe(true);
  });
});

describe('environment variables', () => {
  it('stores values encrypted, masks secrets, reveals on request, audits keys only', async () => {
    const t = setup();
    await t.svc.set(PROJECT, PROD, { vars: [{ key: 'APP_ENV', value: 'production' }, { key: 'DB_PASSWORD', value: 'hunter2', isSecret: true }] }, OWNER);
    const stored = [...t.prisma.vars.values()].map((v) => Buffer.from(v.valueEnc).toString('latin1')).join('');
    expect(stored).not.toContain('hunter2');
    const list = await t.svc.list(PROJECT, PROD, OWNER);
    expect(list.vars).toEqual([
      expect.objectContaining({ key: 'APP_ENV', value: 'production', isSecret: false }),
      expect.objectContaining({ key: 'DB_PASSWORD', value: null, isSecret: true }),
    ]);
    expect((await t.svc.reveal(PROJECT, PROD, 'DB_PASSWORD', OWNER)).value).toBe('hunter2');
    expect(JSON.stringify(t.auditService.record.mock.calls)).not.toContain('hunter2');
  });
  it('imports .env text, marks secrets, exports and deletes', async () => {
    const t = setup();
    const res = await t.svc.importText(PROJECT, STG, { text: 'APP_ENV=staging\nSTRIPE_SECRET=sk_test_1\n' }, OWNER);
    expect(res).toMatchObject({ added: 2, updated: 0 });
    expect((await t.svc.list(PROJECT, STG, OWNER)).vars.find((v) => v.key === 'STRIPE_SECRET').isSecret).toBe(true);
    expect((await t.svc.exportText(PROJECT, STG, OWNER)).text).toBe('APP_ENV=staging\nSTRIPE_SECRET=sk_test_1\n');
    await t.svc.remove(PROJECT, STG, 'APP_ENV', OWNER);
    expect((await t.svc.list(PROJECT, STG, OWNER)).vars.map((v) => v.key)).toEqual(['STRIPE_SECRET']);
  });
  it('staging access never exposes production', async () => {
    const t = setup([grant('project.env.metadata.read', STG), grant('project.configure', STG)]);
    await t.svc.set(PROJECT, PROD, { vars: [{ key: 'DB_PASSWORD', value: 'prod-secret', isSecret: true }] }, OWNER);
    await expect(t.svc.list(PROJECT, PROD, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.reveal(PROJECT, PROD, 'DB_PASSWORD', DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.exportText(PROJECT, PROD, DEV)).rejects.toMatchObject({ status: 403 });
    await t.svc.set(PROJECT, STG, { vars: [{ key: 'A', value: '1' }] }, DEV);
    expect((await t.svc.list(PROJECT, STG, DEV)).canEdit).toBe(true);
  });
  it('read-only users see values of normal variables but cannot reveal or edit', async () => {
    const t = setup([grant('project.env.metadata.read', PROD)]);
    await t.svc.set(PROJECT, PROD, { vars: [{ key: 'A', value: '1' }, { key: 'S', value: 'x', isSecret: true }] }, OWNER);
    const list = await t.svc.list(PROJECT, PROD, DEV);
    expect(list.canEdit).toBe(false);
    await expect(t.svc.reveal(PROJECT, PROD, 'S', DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.set(PROJECT, PROD, { vars: [{ key: 'A', value: '2' }] }, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('fails closed without a key, rejects another project environment', async () => {
    const t = setup([], { key: '' });
    await expect(t.svc.set(PROJECT, PROD, { vars: [{ key: 'A', value: '1' }] }, OWNER)).rejects.toMatchObject({ code: 'ENCRYPTION_KEY_MISSING' });
    const u = setup();
    await expect(u.svc.list(randomUUID(), PROD, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_NOT_FOUND' });
  });
  it('writes the .env file to the server through server access', async () => {
    const serverAccess = { write: vi.fn(async (serverId, { path }) => ({ path, size: 1 })) };
    const t = setup([], { serverAccess });
    await t.svc.set(PROJECT, PROD, { vars: [{ key: 'A', value: '1' }] }, OWNER);
    expect(await t.svc.writeToServer(PROJECT, PROD, { path: '/var/www/app/.env' }, OWNER)).toEqual({ path: '/var/www/app/.env', count: 1 });
    expect(serverAccess.write).toHaveBeenCalledWith(SERVER, { path: '/var/www/app/.env', content: 'A=1\n' }, OWNER);
  });
  it('adds environments to a project (Owner) and refuses duplicates', async () => {
    const t = setup();
    const env = await t.svc.addEnvironment(PROJECT, { code: 'development', displayName: 'Development' }, OWNER);
    expect(env.code).toBe('development');
    await expect(t.svc.addEnvironment(PROJECT, { code: 'staging', displayName: 'Staging' }, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_EXISTS' });
    await expect(t.svc.addEnvironment(PROJECT, { code: 'qa', displayName: 'QA' }, DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
  });
});
