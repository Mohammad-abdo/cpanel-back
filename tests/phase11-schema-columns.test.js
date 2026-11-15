import { describe, expect, it, vi } from 'vitest';
import { createDatabasesService } from '../src/modules/databases/databases.service.js';
import { createInstanceBodySchema } from '../src/modules/databases/databases.validator.js';
import { createReportsService } from '../src/modules/reports/reports.service.js';
import { createCertificatesService } from '../src/modules/certificates/certificates.service.js';
import { OWNER, PROJECT, ENV_PROD, U, approve, makeCtx, makeRbac } from './phase6-helpers.js';

const unknownArg = () => Object.assign(new Error('Unknown argument `host`. Available options are listed in green.'), { name: 'PrismaClientValidationError' });

describe('databases: instance host/port/adminSecretRef', () => {
  const input = { engine: 'mysql', name: 'my-main', host: '10.0.0.5', port: 3306, adminSecretRef: 'vault:db/my-main-admin', reason: 'new instance', rollbackNote: 'remove row' };
  async function run(create) {
    const ctx = makeCtx({ prismaExtra: { databaseInstance: { findFirst: vi.fn(async () => null), create } } });
    const svc = createDatabasesService(ctx);
    const first = await svc.createInstance(input, OWNER);
    await approve(ctx, first.approval.id);
    return svc.createInstance({ ...input, approvalId: first.approval.id }, OWNER);
  }

  it('stores the new columns', async () => {
    const create = vi.fn(async ({ data }) => ({ id: U(60), ...data }));
    const row = await run(create);
    expect(create.mock.calls[0][0].data).toMatchObject({ host: '10.0.0.5', port: 3306, adminSecretRef: 'vault:db/my-main-admin' });
    expect(row.schemaPending).toBeUndefined();
  });

  it('retries without new fields on a stale client and flags schemaPending', async () => {
    const create = vi.fn(async ({ data }) => {
      if ('host' in data) throw unknownArg();
      return { id: U(60), ...data };
    });
    const row = await run(create);
    expect(create).toHaveBeenCalledTimes(2);
    expect(row).toMatchObject({ name: 'my-main', schemaPending: true });
    expect(row.host).toBeUndefined();
  });

  it('validator accepts references and rejects secret-looking values', () => {
    expect(createInstanceBodySchema.safeParse(input).success).toBe(true);
    expect(createInstanceBodySchema.safeParse({ ...input, adminSecretRef: 'p@ss word!' }).success).toBe(false);
    expect(createInstanceBodySchema.safeParse({ ...input, port: 70000 }).success).toBe(false);
  });
});

describe('reports: definition kind/projectId/paramsJson', () => {
  const body = { name: 'Weekly summary', kind: 'project-summary', projectId: PROJECT, paramsJson: {} };
  const svcWith = (create, findMany = vi.fn(async () => [])) =>
    createReportsService({
      prisma: { reportDefinition: { findFirst: vi.fn(async () => null), create, findMany } },
      rbac: makeRbac(),
      auditService: { record: vi.fn(async () => ({})) },
    });

  it('writes the new columns', async () => {
    const create = vi.fn(async ({ data }) => ({ id: U(70), ...data }));
    const row = await svcWith(create).createDefinition(body, OWNER);
    expect(create.mock.calls[0][0].data).toMatchObject({ kind: 'project-summary', projectId: PROJECT, paramsJson: {} });
    expect(row.kind).toBe('project-summary');
  });

  it('falls back on a stale client with schemaPending and derived fields', async () => {
    const create = vi.fn(async ({ data }) => {
      if ('kind' in data) throw unknownArg();
      return { id: U(70), ...data };
    });
    const row = await svcWith(create).createDefinition(body, OWNER);
    expect(create).toHaveBeenCalledTimes(2);
    expect(row).toMatchObject({ schemaPending: true, kind: 'project-summary', projectId: PROJECT });
  });

  it('reads legacy packed rows', async () => {
    const legacy = { id: U(71), code: 'project-summary:old', name: 'Old', paramsSchemaJson: { kind: 'project-summary', projectId: PROJECT, params: { formats: ['csv'] } } };
    const rows = await svcWith(vi.fn(), vi.fn(async () => [legacy])).listDefinitions({ limit: 10 });
    expect(rows[0]).toMatchObject({ kind: 'project-summary', projectId: PROJECT, paramsJson: { formats: ['csv'] } });
  });
});

describe('certificates: issue without approval creates nothing (regression)', () => {
  // Root cause of "issued but GET /certificates is empty": ssl.issue is a high-risk action. The first POST
  // answers 202 approvalRequired and creates NO certificate; the list is correctly empty until an
  // approved request is replayed with approvalId.
  const DOMAIN_ID = U(20);
  it('list stays empty until the approved retry, then shows the certificate', async () => {
    const store = new Map();
    const ctx = makeCtx({
      prismaExtra: {
        domain: { findUnique: vi.fn(async () => ({ id: DOMAIN_ID, name: 'app.example.com', projectId: PROJECT, status: 'active', archivedAt: null })) },
        projectEnvironment: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: PROJECT })) },
        sslCertificate: {
          findMany: vi.fn(async () => [...store.values()]),
          create: vi.fn(async ({ data }) => { const r = { id: U(40), ...data }; store.set(r.id, r); return r; }),
          update: vi.fn(async ({ where, data }) => Object.assign(store.get(where.id), data)),
        },
      },
    });
    const svc = createCertificatesService(ctx);
    const body = { environmentId: ENV_PROD, challenge: 'http-01', wildcard: false, reason: 'go live', rollbackNote: 'serve over http' };
    const first = await svc.issue(DOMAIN_ID, body, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(await svc.list({ limit: 50 }, OWNER)).toEqual([]);
    await approve(ctx, first.approval.id);
    await svc.issue(DOMAIN_ID, { ...body, approvalId: first.approval.id }, OWNER);
    const rows = await svc.list({ limit: 50 }, OWNER);
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe('active');
  });
});
