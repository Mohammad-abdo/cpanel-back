import { describe, expect, it } from 'vitest';
import { createProjectsService } from '../src/modules/projects/projects.service.js';
import { createScope } from '../src/common/scope.js';
import { projectMemberBodySchema, projectTeamBodySchema } from '../src/modules/projects/projects.validator.js';
import { fakePrisma, U } from './phase3-helpers.js';

const OWNER = { id: U(1), isOwner: true };
const LEAD = { id: U(2), isOwner: false };
const DEV = { id: U(3), isOwner: false };
const OUT = { id: U(4), isOwner: false };
const TEAMMATE = { id: U(5), isOwner: false };
const INACTIVE = U(6);
const P1 = U(10);
const T1 = U(30);

function seed(extra = {}) {
  return fakePrisma({
    project: [{ id: P1, name: 'One', serverId: U(40), archivedAt: null }],
    projectMember: [
      { projectId: P1, userId: LEAD.id, projectRole: 'lead' },
      { projectId: P1, userId: DEV.id, projectRole: 'developer' },
    ],
    user: [
      { id: LEAD.id, status: 'active', displayName: 'Lead' },
      { id: DEV.id, status: 'active', displayName: 'Dev' },
      { id: OUT.id, status: 'active', displayName: 'Out' },
      { id: TEAMMATE.id, status: 'active', displayName: 'Mate', email: 'm@x.test' },
      { id: INACTIVE, status: 'suspended' },
    ],
    team: [{ id: T1, name: 'Core', slug: 'core', archivedAt: null }],
    teamMember: [{ teamId: T1, userId: TEAMMATE.id, teamRole: 'member' }],
    ...extra,
  });
}
const make = (prisma = seed()) => {
  const events = [];
  const svc = createProjectsService({ prisma, auditService: { record: async (e) => events.push(e) } });
  return { svc, prisma, events };
};
const code = (p) => p.then(() => null, (e) => e.code ?? e.status);

describe('project members management', () => {
  it('owner adds a member, audits and notifies', async () => {
    const { svc, prisma, events } = make();
    await svc.addMember(P1, { userId: OUT.id, projectRole: 'lead' }, OWNER);
    expect(prisma.projectMember.rows.some((m) => m.userId === OUT.id && m.projectRole === 'lead')).toBe(true);
    expect(events[0].action).toBe('project.member.add');
    expect(prisma.notification.rows[0].userId).toBe(OUT.id);
  });

  it('lead may add developer/viewer but not lead', async () => {
    const { svc } = make();
    await svc.addMember(P1, { userId: OUT.id, projectRole: 'viewer' }, LEAD);
    expect(await code(svc.addMember(P1, { userId: TEAMMATE.id, projectRole: 'lead' }, LEAD))).toBe('FORBIDDEN');
  });

  it('lead cannot remove or demote another lead, nor change self', async () => {
    const { svc } = make(seed({ projectMember: [
      { projectId: P1, userId: LEAD.id, projectRole: 'lead' },
      { projectId: P1, userId: DEV.id, projectRole: 'lead' },
    ] }));
    expect(await code(svc.removeMember(P1, DEV.id, LEAD))).toBe('FORBIDDEN');
    expect(await code(svc.changeRole(P1, DEV.id, { projectRole: 'viewer' }, LEAD))).toBe('FORBIDDEN');
    expect(await code(svc.changeRole(P1, LEAD.id, { projectRole: 'viewer' }, LEAD))).toBe('FORBIDDEN');
  });

  it('developer cannot manage; outsider gets 404', async () => {
    const { svc } = make();
    expect(await code(svc.addMember(P1, { userId: OUT.id, projectRole: 'viewer' }, DEV))).toBe('FORBIDDEN');
    expect(await code(svc.addMember(P1, { userId: DEV.id, projectRole: 'viewer' }, OUT))).toBe('PROJECT_NOT_FOUND');
    expect(await code(svc.removeMember(P1, DEV.id, OUT))).toBe('PROJECT_NOT_FOUND');
  });

  it('rejects inactive and duplicate users; lead removes developer', async () => {
    const { svc } = make();
    expect(await code(svc.addMember(P1, { userId: INACTIVE, projectRole: 'viewer' }, OWNER))).toBe('USER_NOT_ACTIVE');
    expect(await code(svc.addMember(P1, { userId: DEV.id, projectRole: 'viewer' }, OWNER))).toBe('ALREADY_MEMBER');
    await svc.removeMember(P1, DEV.id, LEAD);
  });

  it('project.configure grant holder may manage', async () => {
    const prisma = seed({ projectEnvironment: [{ id: U(20), projectId: P1 }], resourceGrant: [{ userId: OUT.id, permissionCode: 'project.configure', resourceType: 'project', resourceId: P1, environmentId: U(20), revokedAt: null, expiresAt: null }] });
    const { svc } = make(prisma);
    await svc.addMember(P1, { userId: TEAMMATE.id, projectRole: 'lead' }, OUT);
  });

  it('validators are strict', () => {
    expect(projectMemberBodySchema.safeParse({ userId: U(1), projectRole: 'owner' }).success).toBe(false);
    expect(projectMemberBodySchema.safeParse({ userId: U(1), projectRole: 'viewer', x: 1 }).success).toBe(false);
    expect(projectTeamBodySchema.safeParse({ teamId: T1 }).success).toBe(true);
  });
});

describe('project team links', () => {
  it('owner links, lists members, unlinks', async () => {
    const { svc, events } = make();
    await svc.linkTeam(P1, { teamId: T1 }, OWNER);
    expect(await code(svc.linkTeam(P1, { teamId: T1 }, OWNER))).toBe('ALREADY_LINKED');
    const r = await svc.teams(P1, OWNER);
    expect(r.teams[0].members[0]).toMatchObject({ userId: TEAMMATE.id, teamRole: 'member' });
    await svc.unlinkTeam(P1, T1, OWNER);
    expect((await svc.teams(P1, OWNER)).teams).toHaveLength(0);
    expect(events.map((e) => e.action)).toEqual(['project.team.link', 'project.team.unlink']);
  });

  it('lead cannot link teams', async () => {
    const { svc } = make();
    expect(await code(svc.linkTeam(P1, { teamId: T1 }, LEAD))).toBe('FORBIDDEN');
  });

  it('stale client without projectTeam delegate answers 501 SCHEMA_REQUIRED', async () => {
    const real = seed();
    const stale = new Proxy(real, { get: (t, n) => (n === 'projectTeam' ? undefined : t[n]) });
    const { svc } = make(stale);
    const e = await svc.linkTeam(P1, { teamId: T1 }, OWNER).catch((x) => x);
    expect([e.status, e.code]).toEqual([501, 'SCHEMA_REQUIRED']);
    const e2 = await createProjectsService({ prisma: new Proxy(real, { get: (t, n) => (n === 'projectTeam' ? { findMany: async () => { throw new Error('Unknown argument `projectId`'); } } : t[n]) }) }).teams(P1, OWNER).catch((x) => x);
    expect(e2.code).toBe('SCHEMA_REQUIRED');
  });
});

describe('scope: team-linked project visibility', () => {
  it('team members see linked projects; others and stale clients do not', async () => {
    const prisma = seed({ projectTeam: [{ projectId: P1, teamId: T1 }] });
    const scope = createScope({ prisma });
    expect(await scope.canSeeProject(TEAMMATE, P1)).toBe(true);
    expect(await scope.canSeeProject(OUT, P1)).toBe(false);
    expect(await scope.projectIds(OWNER)).toBeNull();
    expect(await scope.projectIds({})).toEqual([]);
    const stale = new Proxy(prisma, { get: (t, n) => (n === 'projectTeam' ? undefined : t[n]) });
    expect(await createScope({ prisma: stale }).canSeeProject(TEAMMATE, P1)).toBe(false);
  });
});
