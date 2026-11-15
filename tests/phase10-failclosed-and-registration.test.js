import { describe, expect, it, vi } from 'vitest';
import { createProjectsService } from '../src/modules/projects/projects.service.js';
import { createDeploymentsService } from '../src/modules/deployments/deployments.service.js';
import { createLogsService } from '../src/modules/logs/logs.service.js';
import { createDatabasesService } from '../src/modules/databases/databases.service.js';
import { createInstanceBodySchema } from '../src/modules/databases/databases.validator.js';
import { createReportsService } from '../src/modules/reports/reports.service.js';
import { createDefinitionBodySchema } from '../src/modules/reports/reports.validator.js';
import { DEV, OWNER, U, approve, makeCtx, makeRbac } from './phase6-helpers.js';

const P_IN = U(10);
const P_OUT = U(11);

function scopePrisma() {
  return {
    projectMember: { findMany: vi.fn(async () => [{ projectId: P_IN }]), findFirst: vi.fn(async () => null) },
    resourceGrant: { findMany: vi.fn(async () => []), findFirst: vi.fn(async () => null) },
    userRole: { findMany: vi.fn(async () => []) },
    project: {
      findUnique: vi.fn(async ({ where }) => ({ id: where.id, name: 'p', environments: [] })),
      findMany: vi.fn(async () => []),
    },
    deployment: {
      findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: P_OUT, correlationId: 'c' })),
      findMany: vi.fn(async () => []),
    },
    logSource: { findMany: vi.fn(async () => []) },
  };
}

describe('fail-closed reads (review finding #10)', () => {
  it('projects, deployments and logs reject a missing actor with 401', async () => {
    const prisma = scopePrisma();
    const projects = createProjectsService({ prisma });
    const deployments = createDeploymentsService({ prisma });
    const logs = createLogsService({ prisma, rbac: makeRbac() });
    for (const call of [
      () => projects.list({ limit: 10 }, undefined),
      () => projects.getById(P_IN, null),
      () => deployments.list({ limit: 10 }, undefined),
      () => deployments.getById(U(40), null),
      () => logs.listSources({ limit: 10 }, undefined),
    ]) {
      await expect(call()).rejects.toMatchObject({ status: 401 });
    }
    expect(prisma.project.findMany).not.toHaveBeenCalled();
    expect(prisma.deployment.findMany).not.toHaveBeenCalled();
    expect(prisma.logSource.findMany).not.toHaveBeenCalled();
  });

  it('answers 404 for out-of-scope ids and filters lists to visible projects', async () => {
    const prisma = scopePrisma();
    const projects = createProjectsService({ prisma });
    const deployments = createDeploymentsService({ prisma });
    const logs = createLogsService({ prisma, rbac: makeRbac() });
    await expect(projects.getById(P_OUT, DEV)).rejects.toMatchObject({ status: 404 });
    await expect(deployments.getById(U(40), DEV)).rejects.toMatchObject({ status: 404 });
    await expect(deployments.list({ projectId: P_OUT, limit: 5 }, DEV)).rejects.toMatchObject({ status: 404 });
    await expect(logs.listSources({ projectId: P_OUT, limit: 5 }, DEV)).rejects.toMatchObject({ status: 404 });
    await projects.list({ limit: 5 }, DEV);
    expect(prisma.project.findMany.mock.calls[0][0].where.id).toEqual({ in: [P_IN] });
    await projects.list({ limit: 5 }, OWNER);
    expect(prisma.project.findMany.mock.calls[1][0].where.id).toBeUndefined();
  });
});

describe('databases: register instance', () => {
  const input = { engine: 'postgres', name: 'pg-main', reason: 'new instance', rollbackNote: 'remove row' };
  function setup(grants = []) {
    const ctx = makeCtx({
      grants,
      prismaExtra: {
        databaseInstance: { findFirst: vi.fn(async () => null), create: vi.fn(async ({ data }) => ({ id: U(60), ...data })) },
      },
    });
    return { ...ctx, svc: createDatabasesService(ctx) };
  }

  it('gates on approval, then creates and audits', async () => {
    const t = setup();
    const first = await t.svc.createInstance(input, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.prisma.databaseInstance.create).not.toHaveBeenCalled();
    await approve(t, first.approval.id);
    const row = await t.svc.createInstance({ ...input, approvalId: first.approval.id }, OWNER);
    expect(row).toMatchObject({ engine: 'postgres', name: 'pg-main' });
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'db.instance.register', result: 'success' }));
  });

  it('denies a non-owner without permission, allows with the grant, rejects no actor', async () => {
    const denied = setup();
    await expect(denied.svc.createInstance(input, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(denied.svc.createInstance(input, null)).rejects.toMatchObject({ status: 401 });
    const allowed = setup([{ userId: DEV.id, permissionKey: 'project.database.manage', resourceId: 'platform', environmentId: null }]);
    expect((await allowed.svc.createInstance(input, DEV)).approvalRequired).toBe(true);
  });

  it('validator rejects unknown keys (no plaintext credentials) and bad engines', () => {
    expect(createInstanceBodySchema.safeParse({ engine: 'mysql', name: 'my-main' }).success).toBe(true);
    expect(createInstanceBodySchema.safeParse({ engine: 'mysql', name: 'my-main', password: 'x' }).success).toBe(false);
    expect(createInstanceBodySchema.safeParse({ engine: 'oracle', name: 'my-main' }).success).toBe(false);
  });
});

describe('reports: definitions', () => {
  function setup(grants = []) {
    const rbac = makeRbac(grants);
    const auditService = { record: vi.fn(async () => ({})) };
    const prisma = {
      reportDefinition: { findFirst: vi.fn(async () => null), create: vi.fn(async ({ data }) => ({ id: U(70), ...data })) },
    };
    return { prisma, auditService, svc: createReportsService({ prisma, rbac, auditService }) };
  }
  const body = { name: 'Weekly summary', kind: 'project-summary', projectId: P_IN, paramsJson: {} };

  it('creates for Owner and audits; stores kind/project in paramsSchemaJson', async () => {
    const t = setup();
    const row = await t.svc.createDefinition(body, OWNER);
    expect(row.code).toBe('project-summary:weekly-summary');
    expect(row.paramsSchemaJson).toMatchObject({ kind: 'project-summary', projectId: P_IN });
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'report.definition.create' }));
  });

  it('requires report.team.export on the project for non-owners and rejects duplicates', async () => {
    const t = setup();
    await expect(t.svc.createDefinition(body, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.svc.createDefinition(body, null)).rejects.toMatchObject({ status: 401 });
    const ok = setup([{ userId: DEV.id, permissionKey: 'report.team.export', resourceId: P_IN, environmentId: null }]);
    await expect(ok.svc.createDefinition(body, DEV)).resolves.toMatchObject({ name: 'Weekly summary' });
    ok.prisma.reportDefinition.findFirst.mockResolvedValueOnce({ id: 'x' });
    await expect(ok.svc.createDefinition(body, DEV)).rejects.toMatchObject({ status: 409 });
  });

  it('validator enforces per-kind params and strict keys', () => {
    expect(createDefinitionBodySchema.safeParse(body).success).toBe(true);
    expect(createDefinitionBodySchema.safeParse({ ...body, projectId: undefined }).success).toBe(false);
    expect(createDefinitionBodySchema.safeParse({ ...body, extra: 1 }).success).toBe(false);
    expect(createDefinitionBodySchema.safeParse({ ...body, kind: 'nope' }).success).toBe(false);
    expect(createDefinitionBodySchema.safeParse({ ...body, paramsJson: { sql: 'x' } }).success).toBe(false);
    expect(createDefinitionBodySchema.safeParse({ name: 'Mine', kind: 'individual-activity', paramsJson: {} }).success).toBe(false);
    expect(createDefinitionBodySchema.safeParse({ name: 'Mine', kind: 'individual-activity', paramsJson: { userId: U(2) } }).success).toBe(true);
  });
});
