import { describe, expect, it, vi } from 'vitest';
import { createScope } from '../src/common/scope.js';
import { createServersService } from '../src/modules/servers/servers.service.js';
import { createIncidentsService } from '../src/modules/incidents/incidents.service.js';
import { createDomainsService } from '../src/modules/domains/domains.service.js';

const OWNER = { id: 'o', isOwner: true };
const MEMBER = { id: 'm', isOwner: false };
const STRANGER = { id: 's', isOwner: false };

function prismaFor() {
  return {
    projectMember: { findMany: vi.fn(async ({ where }) => (where.userId === 'm' ? [{ projectId: 'p1' }] : [])) },
    resourceGrant: { findMany: vi.fn(async ({ where }) => (where.userId === 'm' && where.resourceType === 'server' ? [{ resourceId: 'srvX' }] : [])) },
    project: { findMany: vi.fn(async ({ where }) => where.id.in.map(() => ({ serverId: 'srv1' }))) },
  };
}

describe('scope helper', () => {
  it('Owner is unrestricted and runs no queries', async () => {
    const prisma = prismaFor();
    const scope = createScope({ prisma });
    expect(await scope.projectIds(OWNER)).toBeNull();
    expect(await scope.projectClause(OWNER)).toBeUndefined();
    expect(prisma.projectMember.findMany).not.toHaveBeenCalled();
  });

  it('member sees own project, its server and explicit server grants only', async () => {
    const scope = createScope({ prisma: prismaFor() });
    expect(await scope.projectIds(MEMBER)).toEqual(['p1']);
    expect((await scope.serverIds(MEMBER)).sort()).toEqual(['srv1', 'srvX']);
    expect(await scope.projectClause(MEMBER, 'p2')).toEqual({ in: [] });
    expect(await scope.projectClause(MEMBER, 'p1')).toBe('p1');
  });

  it('stranger and missing actor see nothing; out-of-scope ids answer 404', async () => {
    const scope = createScope({ prisma: prismaFor() });
    expect(await scope.projectIds(STRANGER)).toEqual([]);
    expect(await scope.projectIds(undefined)).toEqual([]);
    await expect(scope.requireProject(STRANGER, 'p1')).rejects.toMatchObject({ status: 404 });
    await expect(scope.requireServer(MEMBER, 'srv9')).rejects.toMatchObject({ status: 404 });
    await expect(scope.requireServer(MEMBER, 'srv1')).resolves.toBeUndefined();
  });
});

describe('service-level isolation', () => {
  it('servers.getById returns 404 for a stranger and list is filtered by id', async () => {
    const findMany = vi.fn().mockResolvedValue([]);
    const prisma = { ...prismaFor(), server: { findMany, findUnique: vi.fn() } };
    const svc = createServersService({ prisma });
    await expect(svc.getById('srv1', STRANGER)).rejects.toMatchObject({ status: 404, code: 'SERVER_NOT_FOUND' });
    await svc.list({ limit: 5 }, MEMBER);
    expect(findMany.mock.calls[0][0].where.id.in.sort()).toEqual(['srv1', 'srvX']);
    await svc.list({ limit: 5 }, OWNER);
    expect(findMany.mock.calls[1][0].where.id).toBeUndefined();
  });

  it('incidents: project-less incidents are Owner-only and other projects return 404', async () => {
    const rows = { a: { id: 'a', projectId: 'p1', assignments: [] }, b: { id: 'b', projectId: 'p2', assignments: [] }, c: { id: 'c', projectId: null, assignments: [] } };
    const prisma = { ...prismaFor(), securityIncident: { findUnique: vi.fn(async ({ where }) => rows[where.id] ?? null), findMany: vi.fn().mockResolvedValue([]) } };
    const svc = createIncidentsService({ prisma });
    await expect(svc.get('a', MEMBER)).resolves.toMatchObject({ id: 'a' });
    await expect(svc.get('b', MEMBER)).rejects.toMatchObject({ status: 404 });
    await expect(svc.get('c', MEMBER)).rejects.toMatchObject({ status: 404 });
    await expect(svc.get('c', OWNER)).resolves.toMatchObject({ id: 'c' });
    await svc.list({ limit: 5 }, MEMBER);
    expect(prisma.securityIncident.findMany.mock.calls[0][0].where.projectId).toEqual({ in: ['p1'] });
  });

  it('domains: stranger gets 404 on get, and list carries a visibility filter', async () => {
    const findMany = vi.fn().mockResolvedValue([]);
    const prisma = { ...prismaFor(), domain: { findMany, findUnique: vi.fn(async () => ({ id: 'd', projectId: 'p2', serverId: null })) } };
    const svc = createDomainsService({ prisma });
    await expect(svc.getById('d', MEMBER)).rejects.toMatchObject({ status: 404 });
    await svc.list({ limit: 5 }, MEMBER);
    expect(findMany.mock.calls[0][0].where.OR[0]).toEqual({ projectId: { in: ['p1'] } });
  });
});
