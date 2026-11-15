import { describe, expect, it } from 'vitest';
import { createProjectsService } from '../src/modules/projects/projects.service.js';
import { fakePrisma, U } from './phase3-helpers.js';

const OWNER = { id: U(1), isOwner: true };
const ALICE = { id: U(2), isOwner: false };
const OUTSIDER = { id: U(3), isOwner: false };
const P1 = U(10);
const E1 = U(20);
const NOW = new Date('2026-06-01T12:00:00Z');

function seed() {
  return fakePrisma({
    server: [{ id: U(40), alias: 'web-01', hostname: 'web-01.test', status: 'healthy' }],
    project: [{ id: P1, serverId: U(40), name: 'One', slug: 'one', type: 'node', status: 'active', archivedAt: null }],
    projectMember: [{ projectId: P1, userId: ALICE.id, projectRole: 'dev', createdAt: NOW }],
    user: [{ id: ALICE.id, email: 'a@x.test', displayName: 'Alice', status: 'active', passwordHash: 'HASH' }],
    deployment: [
      { id: U(50), projectId: P1, environmentId: E1, status: 'Success', createdAt: new Date('2026-05-31T10:00:00Z'), updatedAt: new Date('2026-05-31T10:05:00Z') },
      { id: U(51), projectId: P1, environmentId: E1, status: 'Failed', createdAt: new Date('2026-06-01T09:00:00Z'), updatedAt: new Date('2026-06-01T09:02:00Z') },
    ],
    alert: [
      { id: U(60), projectId: P1, status: 'firing' },
      { id: U(61), projectId: P1, status: 'resolved' },
    ],
    errorGroup: [{ id: U(62), projectId: P1, count: 7, lastSeenAt: new Date('2026-06-01T08:00:00Z') }],
    backupPolicy: [{ id: U(63), projectId: P1, archivedAt: null }],
    backupRun: [{ id: U(64), policyId: U(63), status: 'success', createdAt: new Date('2026-06-01T02:00:00Z'), finishedAt: new Date('2026-06-01T02:10:00Z') }],
    domain: [{ id: U(65), projectId: P1, archivedAt: null }],
    sslCertificate: [{ id: U(66), domainId: U(65), expiresAt: new Date('2026-06-21T12:00:00Z'), status: 'active' }],
    managedDatabase: [{ id: U(67), projectId: P1, environmentId: E1 }],
    healthCheck: [{ id: U(68), projectId: P1, status: 'healthy' }],
  });
}

describe('project detail read endpoints', () => {
  const svc = () => createProjectsService({ prisma: seed(), now: () => NOW });

  it('overview aggregates real project data for a member', async () => {
    const o = await svc().overview(P1, {}, ALICE);
    expect(o.server.alias).toBe('web-01');
    expect(o.deployments.last.status).toBe('Failed');
    expect(o.deployments.total).toBe(2);
    expect(o.alerts.open).toBe(1);
    expect(o.errors).toMatchObject({ groups: 1, occurrences: 7 });
    expect(o.backups.last.status).toBe('success');
    expect(o.certificates.daysLeft).toBe(20);
    expect(o.health.status).toBe('healthy');
    expect(o.counts).toEqual({ domains: 1, databases: 1, members: 1 });
  });

  it('overview answers 404 for out-of-scope and unknown projects', async () => {
    await expect(svc().overview(P1, {}, OUTSIDER)).rejects.toMatchObject({ status: 404 });
    await expect(svc().overview(U(99), {}, OWNER)).rejects.toMatchObject({ status: 404 });
  });

  it('members lists display details without credentials', async () => {
    const rows = await svc().members(P1, ALICE);
    expect(rows).toEqual([expect.objectContaining({ userId: ALICE.id, displayName: 'Alice', projectRole: 'dev' })]);
    expect(JSON.stringify(rows)).not.toContain('HASH');
    await expect(svc().members(P1, OUTSIDER)).rejects.toMatchObject({ status: 404 });
  });
});
