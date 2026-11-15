import { describe, expect, it, vi } from 'vitest';
import { createMembersService } from '../src/modules/members/members.service.js';
import { createActivityService } from '../src/modules/activity/activity.service.js';
import { fakeModel, fakePrisma, U } from './phase3-helpers.js';

const OWNER = { id: U(1), isOwner: true };
const ALICE = { id: U(2), isOwner: false };
const BOB = { id: U(3), isOwner: false };
const P1 = U(10);
const E1 = U(20);
const D = (s) => new Date(`2026-03-${s}T10:00:00Z`);

function seed() {
  return fakePrisma({
    user: [
      { id: ALICE.id, email: 'a@x.test', displayName: 'Alice', status: 'active', passwordHash: 'HASH', timezone: 'UTC', locale: 'en', createdAt: D('01') },
      { id: BOB.id, email: 'b@x.test', displayName: 'Bob', status: 'active', timezone: 'UTC', locale: 'en', createdAt: D('01') },
    ],
    project: [{ id: P1, serverId: U(40), name: 'One', slug: 'one' }],
    projectMember: [{ projectId: P1, userId: ALICE.id, projectRole: 'dev' }],
    teamMember: [{ teamId: U(60), userId: ALICE.id, teamRole: 'member' }],
    // one operation: Alice initiated, Bob approved (separate roles)
    operationJob: [{ id: U(70), action: 'deployment.rollback', resourceType: 'project', resourceId: P1, environmentId: E1, status: 'SUCCESS', initiatorId: ALICE.id, approverId: BOB.id, correlationId: U(71), createdAt: D('05') }],
    deployment: [{ id: U(72), projectId: P1, environmentId: E1, status: 'Success', initiatedById: ALICE.id, correlationId: U(71), createdAt: D('05') }],
    approvalRequest: [{ id: U(73), resourceType: 'project', resourceId: P1, requesterId: ALICE.id, approverId: BOB.id, status: 'APPROVED', createdAt: D('05'), decidedAt: D('06') }],
    auditEvent: [
      { id: U(74), actorId: ALICE.id, action: 'operation.enqueue', resourceType: 'project', resourceId: P1, result: 'denied', correlationId: U(75), occurredAt: D('07') },
      { id: U(76), actorId: ALICE.id, action: 'project.configure', resourceType: 'project', resourceId: P1, result: 'success', correlationId: U(77), occurredAt: D('08') },
    ],
    activityEvent: [
      { id: U(78), actorId: null, category: 'git', action: 'git.push', resourceType: 'project', resourceId: P1, projectId: P1, result: 'success', source: 'github', metadata: { externalIdentity: { provider: 'github', id: 'alice-gh' } }, occurredAt: D('09') },
      { id: U(79), actorId: null, category: 'ssh', action: 'ssh.login', resourceType: 'server', projectId: P1, result: 'success', source: 'ssh', metadata: { externalIdentity: { provider: 'ssh', id: 'root-ghost' } }, occurredAt: D('09') },
    ],
  });
}

describe('TASK-014 member profile and timeline', () => {
  it('timeline keeps initiator and approver roles separate and links original events', async () => {
    const svc = createMembersService({ prisma: seed() });
    const alice = await svc.timeline(ALICE.id, { limit: 50 }, ALICE);
    const bob = await svc.timeline(BOB.id, { limit: 50 }, OWNER);
    const op = (rows) => rows.filter((e) => e.source === 'operation');
    expect(op(alice).map((e) => e.role)).toEqual(['initiator']);
    expect(op(bob).map((e) => e.role)).toEqual(['approver']);
    expect(bob.find((e) => e.source === 'approval')).toMatchObject({ role: 'approver', link: { source: 'approval', id: U(73) } });
    expect(alice.every((e) => e.link.id && e.link.source)).toBe(true);
  });

  it('denials and config changes appear as their own categories', async () => {
    const svc = createMembersService({ prisma: seed() });
    const t = await svc.timeline(ALICE.id, { limit: 50 }, OWNER);
    expect(t.find((e) => e.category === 'denial').result).toBe('denied');
    expect(t.find((e) => e.category === 'config').action).toBe('project.configure');
    expect((await svc.timeline(ALICE.id, { category: 'denial', limit: 50 }, OWNER)).every((e) => e.category === 'denial')).toBe(true);
  });

  it('unmapped GitHub/SSH events are Unattributed and never guessed; mapping resolves them', async () => {
    const prisma = seed();
    const store = [];
    const identityStore = {
      list: async () => store,
      upsert: async (i) => { const r = { id: U(90), ...i, status: 'mapped' }; store.push(r); return r; },
      remove: async () => ({}),
    };
    const audit = { record: vi.fn() };
    const svc = createMembersService({ prisma, identityStore, auditService: audit });
    const before = await svc.listUnattributed({ limit: 50 }, OWNER);
    expect(before).toHaveLength(2);
    expect(before.every((e) => e.attribution === 'unattributed')).toBe(true);
    expect((await svc.timeline(ALICE.id, { limit: 50 }, OWNER)).some((e) => e.source === 'activity')).toBe(false);

    await svc.mapIdentity({ provider: 'github', externalId: 'alice-gh', userId: ALICE.id }, OWNER);
    const after = await svc.timeline(ALICE.id, { limit: 50 }, OWNER);
    expect(after.find((e) => e.source === 'activity')).toMatchObject({ attribution: 'mapped-external', actorId: ALICE.id });
    expect((await svc.listUnattributed({ limit: 50 }, OWNER)).map((e) => e.externalIdentity.id)).toEqual(['root-ghost']);
    expect(audit.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'identity.map', actorId: OWNER.id }));
  });

  it('identity mapping is Owner-only and reports SCHEMA_REQUIRED when the table is missing', async () => {
    const base = seed();
    const prisma = new Proxy(base, { get: (t, k) => (k === 'externalIdentity' ? undefined : t[k]) });
    const svc = createMembersService({ prisma });
    await expect(svc.mapIdentity({ provider: 'github', externalId: 'x', userId: ALICE.id }, ALICE)).rejects.toMatchObject({ status: 403 });
    await expect(svc.mapIdentity({ provider: 'github', externalId: 'x', userId: ALICE.id }, OWNER)).rejects.toMatchObject({ code: 'SCHEMA_REQUIRED' });
    await expect(svc.listUnattributed({ limit: 5 }, ALICE)).rejects.toMatchObject({ status: 403 });
  });

  it('profile is visible to self and Owner only, hides the password hash, and carries last activity', async () => {
    const svc = createMembersService({ prisma: seed() });
    await expect(svc.profile(ALICE.id, BOB)).rejects.toMatchObject({ status: 403 });
    await expect(svc.timeline(ALICE.id, { limit: 5 }, BOB)).rejects.toMatchObject({ status: 403 });
    const p = await svc.profile(ALICE.id, ALICE);
    expect(JSON.stringify(p)).not.toContain('HASH');
    expect(p.projects).toEqual([{ projectId: P1, projectRole: 'dev' }]);
    expect(new Date(p.lastActivityAt).toISOString()).toBe(D('08').toISOString());
    expect(p.eventCounts.denial).toBe(1);
    expect(p.privacyNote).toMatch(/keystrokes/);
  });

  it('period boundaries are half-open', async () => {
    const svc = createMembersService({ prisma: seed() });
    const exact = await svc.timeline(ALICE.id, { from: D('01'), to: D('05'), limit: 50 }, OWNER);
    expect(exact.some((e) => e.source === 'deployment')).toBe(false); // event exactly at `to` is excluded
    const incl = await svc.timeline(ALICE.id, { from: D('05'), to: D('06'), limit: 50 }, OWNER);
    expect(incl.some((e) => e.source === 'deployment')).toBe(true);
  });

  it('project timeline needs project visibility and redacts recorded activity metadata', async () => {
    const prisma = seed();
    const activity = createActivityService({ prisma });
    await activity.record({ actorId: ALICE.id, projectId: P1, category: 'config', action: 'config.update', resourceType: 'project', result: 'success', metadata: { apiToken: 'leak' } });
    expect(JSON.stringify(prisma.activityEvent.rows.at(-1))).not.toContain('leak');
    expect((await activity.projectTimeline({ projectId: P1, limit: 50 }, ALICE)).length).toBeGreaterThan(0);
    await expect(activity.projectTimeline({ projectId: P1, limit: 50 }, BOB)).rejects.toMatchObject({ status: 403 });
    void fakeModel;
  });
});
