import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import request from 'supertest';

vi.mock('../../src/config/prisma.js', async () => {
  const { createFakePrisma } = await import('./fake-prisma.js');
  return { prisma: createFakePrisma() };
});

import { prisma } from '../../src/config/prisma.js';
import { createApp } from '../../src/app.js';
import { bearer, seedSession, seedUser, sha } from './fake-prisma.js';

const app = createApp();
const actor = async (over = {}) => {
  const user = await seedUser(prisma, over);
  const { token } = await seedSession(prisma, user);
  return { user, token };
};
const auth = (a) => bearer(a.token);

describe('agents', () => {
  const seedEnrollment = async (over = {}) => {
    const server = await prisma.server.create({ data: { alias: `srv-${randomUUID().slice(0, 6)}`, status: 'unknown', archivedAt: null } });
    const token = `enroll-${randomUUID()}`;
    await prisma.agentEnrollment.create({
      data: { serverId: server.id, tokenHash: sha(token), expiresAt: new Date(Date.now() + 3600_000), usedAt: null, ...over },
    });
    return { server, token };
  };

  it('enroll with an unknown token is 401 ENROLLMENT_INVALID', async () => {
    const res = await request(app).post('/api/v1/agents/enroll').send({ token: 'x'.repeat(32) });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('ENROLLMENT_INVALID');
  });

  it('enroll with an expired token is 401', async () => {
    const { token } = await seedEnrollment({ expiresAt: new Date(Date.now() - 1000) });
    expect((await request(app).post('/api/v1/agents/enroll').send({ token })).status).toBe(401);
  });

  it('enroll rejects short tokens with 400', async () => {
    expect((await request(app).post('/api/v1/agents/enroll').send({ token: 'short' })).status).toBe(400);
  });

  it('enroll succeeds once; reusing the token is 401; the agent key then reports (202) and bad payloads are 400', async () => {
    const { token, server } = await seedEnrollment();
    const ok = await request(app).post('/api/v1/agents/enroll').send({ token, hostname: 'host-1' });
    expect(ok.status).toBe(201);
    const { agentId, agentKey, serverId } = ok.body.data;
    expect(serverId).toBe(server.id);
    expect(JSON.stringify(ok.body)).not.toMatch(/certFingerprint/);

    const reuse = await request(app).post('/api/v1/agents/enroll').send({ token });
    expect(reuse.status).toBe(401);

    const creds = { Authorization: `Agent ${agentId}.${agentKey}` };
    const good = await request(app)
      .post('/api/v1/agents/report')
      .set(creds)
      .send({ cpuPercent: 10, memPercent: 20, diskPercent: 96, services: [{ name: 'nginx', manager: 'nginx' }], ports: [{ port: 80, proto: 'tcp' }] });
    expect(good.status).toBe(202);
    expect(good.body.data).toEqual({ accepted: true, status: 'critical' });
    expect(prisma.server.rows.find((s) => s.id === server.id).status).toBe('critical');

    const bad = await request(app).post('/api/v1/agents/report').set(creds).send({ cpuPercent: 'high', memPercent: 20, diskPercent: 30 });
    expect(bad.status).toBe(400);
    expect(bad.body.error.code).toBe('VALIDATION_ERROR');
    const extra = await request(app).post('/api/v1/agents/report').set(creds).send({ cpuPercent: 1, memPercent: 1, diskPercent: 1, root: true });
    expect(extra.status).toBe(400);

    const wrongKey = await request(app).post('/api/v1/agents/report').set({ Authorization: `Agent ${agentId}.wrong` }).send({ cpuPercent: 1, memPercent: 1, diskPercent: 1 });
    expect(wrongKey.status).toBe(401);
    expect(wrongKey.body.error.code).toBe('AGENT_AUTH_INVALID');
  });

  it('report without agent credentials is 401, and a user Bearer token is not accepted', async () => {
    const body = { cpuPercent: 1, memPercent: 1, diskPercent: 1 };
    const none = await request(app).post('/api/v1/agents/report').send(body);
    expect(none.status).toBe(401);
    expect(none.body.error.code).toBe('AGENT_AUTH_REQUIRED');
    const owner = await actor({ ownerFlag: true });
    expect((await request(app).post('/api/v1/agents/report').set(auth(owner)).send(body)).status).toBe(401);
  });

  it('revoking an agent is Owner-only and a revoked agent can no longer report', async () => {
    const { token } = await seedEnrollment();
    const { agentId, agentKey } = (await request(app).post('/api/v1/agents/enroll').send({ token })).body.data;
    const row = prisma.serverAgent.rows.find((a) => a.agentPublicId === agentId);
    const member = await actor();
    expect((await request(app).delete(`/api/v1/agents/${row.id}`).set(auth(member))).status).toBe(403);
    const owner = await actor({ ownerFlag: true });
    expect((await request(app).delete(`/api/v1/agents/${row.id}`).set(auth(owner))).status).toBe(200);
    const res = await request(app).post('/api/v1/agents/report').set({ Authorization: `Agent ${agentId}.${agentKey}` }).send({ cpuPercent: 1, memPercent: 1, diskPercent: 1 });
    expect(res.status).toBe(401);
  });
});

describe('servers', () => {
  it('create is Owner-only: non-owner 403 FORBIDDEN, owner 201, duplicate alias 409', async () => {
    const member = await actor();
    const owner = await actor({ ownerFlag: true });
    const denied = await request(app).post('/api/v1/servers').set(auth(member)).send({ alias: 'web-main' });
    expect(denied.status).toBe(403);
    expect(denied.body.error.code).toBe('FORBIDDEN');
    expect(prisma.server.rows.find((s) => s.alias === 'web-main')).toBeUndefined();
    const ok = await request(app).post('/api/v1/servers').set(auth(owner)).send({ alias: 'web-main', hostname: 'web.example.test' });
    expect(ok.status).toBe(201);
    expect(ok.body.data.alias).toBe('web-main');
    expect((await request(app).post('/api/v1/servers').set(auth(owner)).send({ alias: 'web-main' })).status).toBe(409);
    expect((await request(app).post('/api/v1/servers').set(auth(owner)).send({ alias: 'Bad Alias!' })).status).toBe(400);
  });

  it('enrollment issuing is Owner-only and never stores the raw token', async () => {
    const server = await prisma.server.create({ data: { alias: 'enroll-me', archivedAt: null } });
    const member = await actor();
    const owner = await actor({ ownerFlag: true });
    expect((await request(app).post(`/api/v1/servers/${server.id}/enrollment`).set(auth(member)).send({})).status).toBe(403);
    const res = await request(app).post(`/api/v1/servers/${server.id}/enrollment`).set(auth(owner)).send({});
    expect(res.status).toBe(201);
    const stored = prisma.agentEnrollment.rows.find((r) => r.serverId === server.id);
    expect(stored.tokenHash).toBe(sha(res.body.data.token));
    expect(JSON.stringify(stored)).not.toContain(res.body.data.token);
  });

  it('a non-owner gets 404 (not 403) for a server outside their scope', async () => {
    const server = await prisma.server.create({ data: { alias: 'hidden-srv', archivedAt: null } });
    const member = await actor();
    const owner = await actor({ ownerFlag: true });
    const res = await request(app).get(`/api/v1/servers/${server.id}`).set(auth(member));
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('SERVER_NOT_FOUND');
    expect((await request(app).get(`/api/v1/servers/${server.id}`).set(auth(owner))).status).toBe(200);
  });
});

describe('teams scoping', () => {
  it('members see only their teams; Owner sees all; non-owner cannot create or manage', async () => {
    const owner = await actor({ ownerFlag: true });
    const a = await actor();
    const b = await actor();
    const teamA = await prisma.team.create({ data: { name: 'Team A', slug: 'team-a', archivedAt: null } });
    const teamB = await prisma.team.create({ data: { name: 'Team B', slug: 'team-b', archivedAt: null } });
    await prisma.teamMember.create({ data: { teamId: teamA.id, userId: a.user.id, teamRole: 'developer' } });
    await prisma.teamMember.create({ data: { teamId: teamB.id, userId: b.user.id, teamRole: 'developer' } });

    const mine = await request(app).get('/api/v1/teams').set(auth(a));
    expect(mine.body.data.map((t) => t.slug)).toEqual(['team-a']);
    const all = await request(app).get('/api/v1/teams').set(auth(owner));
    expect(all.body.data.map((t) => t.slug).sort()).toEqual(['team-a', 'team-b']);

    expect((await request(app).post('/api/v1/teams').set(auth(a)).send({ name: 'New Team', slug: 'new-team' })).status).toBe(403);
    // plain member (not lead) cannot add members, and cannot touch another team either
    const addOwn = await request(app).post(`/api/v1/teams/${teamA.id}/members`).set(auth(a)).send({ userId: b.user.id, teamRole: 'developer' });
    expect(addOwn.status).toBe(403);
    const addOther = await request(app).post(`/api/v1/teams/${teamB.id}/members`).set(auth(a)).send({ userId: a.user.id, teamRole: 'developer' });
    expect(addOther.status).toBe(403);
    const created = await request(app).post('/api/v1/teams').set(auth(owner)).send({ name: 'New Team', slug: 'new-team' });
    expect(created.status).toBe(201);
    expect((await request(app).post('/api/v1/teams').set(auth(owner)).send({ name: 'New Team', slug: 'new-team' })).status).toBe(409);
  });
});

describe('notifications user scoping', () => {
  it('user A cannot read or mark user B notifications', async () => {
    const a = await actor();
    const b = await actor();
    const na = await prisma.notification.create({ data: { userId: a.user.id, kind: 'x', title: 'for A', readAt: null } });
    const nb = await prisma.notification.create({ data: { userId: b.user.id, kind: 'x', title: 'for B', readAt: null } });

    const list = await request(app).get('/api/v1/notifications').set(auth(a));
    expect(list.status).toBe(200);
    expect(list.body.data.items.map((n) => n.title)).toEqual(['for A']);
    expect(list.body.data.unreadCount).toBe(1);
    expect(JSON.stringify(list.body)).not.toContain('for B');

    const cross = await request(app).post(`/api/v1/notifications/${nb.id}/read`).set(auth(a)).send({});
    expect(cross.status).toBe(404);
    expect(cross.body.error.code).toBe('NOTIFICATION_NOT_FOUND');
    expect(prisma.notification.rows.find((n) => n.id === nb.id).readAt).toBeNull();

    const own = await request(app).post(`/api/v1/notifications/${na.id}/read`).set(auth(a)).send({});
    expect(own.status).toBe(200);
    // read-all only touches the caller's rows
    await request(app).post('/api/v1/notifications/read-all').set(auth(a)).send({});
    expect(prisma.notification.rows.find((n) => n.id === nb.id).readAt).toBeNull();
  });
});

describe('audit read', () => {
  it('is denied for a non-owner without grant, allowed with an exact grant, allowed for Owner', async () => {
    const owner = await actor({ ownerFlag: true });
    const member = await actor();
    await prisma.auditEvent.create({ data: { action: 'x.y', resourceType: 'server', result: 'success', occurredAt: new Date(), actorId: owner.user.id } });

    const denied = await request(app).get('/api/v1/audit/events').set(auth(member));
    expect(denied.status).toBe(403);
    expect(denied.body.error.code).toBe('FORBIDDEN');

    const allowedOwner = await request(app).get('/api/v1/audit/events').set(auth(owner));
    expect(allowedOwner.status).toBe(200);
    expect(allowedOwner.body.data.length).toBeGreaterThan(0);
    expect(JSON.stringify(allowedOwner.body)).not.toMatch(/passwordHash/);

    await prisma.resourceGrant.create({
      data: { userId: member.user.id, permissionCode: 'audit.logs.read', resourceType: 'audit', resourceId: 'all', revokedAt: null, expiresAt: null, environmentId: null },
    });
    expect((await request(app).get('/api/v1/audit/events').set(auth(member))).status).toBe(200);
  });
});

describe('approval separation of duties (platform routes)', () => {
  const seedApproval = (requesterId, over = {}) =>
    prisma.approvalRequest.create({
      data: { status: 'pending', requesterId, resourceType: 'project', resourceId: randomUUID(), createdAt: new Date(), ...over },
    });

  it('a non-Owner requester cannot approve their own request; an Owner can approve their own (selfApproved) and others', async () => {
    const owner1 = await actor({ ownerFlag: true });
    const owner2 = await actor({ ownerFlag: true });
    const member = await actor();
    await prisma.resourceGrant.create({
      data: { userId: member.user.id, permissionCode: 'platform.approval.decide', resourceType: 'platform', resourceId: 'platform', revokedAt: null, expiresAt: null, environmentId: null },
    });
    const own = await seedApproval(member.user.id);
    const denied = await request(app).post(`/api/v1/platform/approvals/${own.id}/decision`).set(auth(member)).send({ decision: 'approve' });
    expect(denied.status).toBe(403);
    expect(denied.body.error.code).toBe('SELF_APPROVAL_DENIED');
    expect(prisma.approvalRequest.rows.find((r) => r.id === own.id).status).toBe('pending');

    const req = await seedApproval(owner1.user.id);
    const self = await request(app).post(`/api/v1/platform/approvals/${req.id}/decision`).set(auth(owner1)).send({ decision: 'approve' });
    expect(self.status).toBe(200);
    expect(self.body.data).toMatchObject({ status: 'approved', approverId: owner1.user.id });
    const replayed = await request(app).post(`/api/v1/platform/approvals/${req.id}/decision`).set(auth(owner1)).send({ decision: 'approve' });
    expect(replayed.status).toBe(409);

    const req2 = await seedApproval(owner1.user.id);
    const ok = await request(app).post(`/api/v1/platform/approvals/${req2.id}/decision`).set(auth(owner2)).send({ decision: 'approve', note: 'ok' });
    expect(ok.status).toBe(200);
    expect(ok.body.data).toMatchObject({ status: 'approved', approverId: owner2.user.id });
    const again = await request(app).post(`/api/v1/platform/approvals/${req2.id}/decision`).set(auth(owner2)).send({ decision: 'approve' });
    expect(again.status).toBe(409);
  });

  it('a non-owner without the approval permission gets 403; unknown id is 404; bad decision is 400', async () => {
    const requester = await actor();
    const member = await actor();
    const owner = await actor({ ownerFlag: true });
    const req = await seedApproval(requester.user.id);
    const denied = await request(app).post(`/api/v1/platform/approvals/${req.id}/decision`).set(auth(member)).send({ decision: 'approve' });
    expect(denied.status).toBe(403);
    expect(denied.body.error.code).toBe('FORBIDDEN');
    expect((await request(app).post(`/api/v1/platform/approvals/${randomUUID()}/decision`).set(auth(owner)).send({ decision: 'approve' })).status).toBe(404);
    expect((await request(app).post(`/api/v1/platform/approvals/${req.id}/decision`).set(auth(owner)).send({ decision: 'maybe' })).status).toBe(400);
    expect((await request(app).get('/api/v1/platform/approvals').set(auth(member))).status).toBe(403);
  });
});

describe('project scoping', () => {
  it('non-owner gets 404 (never 403) for out-of-scope project ids; members and Owner get 200', async () => {
    const server = await prisma.server.create({ data: { alias: 'proj-host', archivedAt: null } });
    const project = await prisma.project.create({ data: { name: 'Shop', slug: 'shop', serverId: server.id, archivedAt: null } });
    const outsider = await actor();
    const member = await actor();
    const owner = await actor({ ownerFlag: true });
    await prisma.projectMember.create({ data: { projectId: project.id, userId: member.user.id } });

    for (const path of [`/api/v1/projects/${project.id}`, `/api/v1/projects/${project.id}/overview`]) {
      const res = await request(app).get(path).set(auth(outsider));
      expect(res.status).toBe(404);
      expect(res.body.error.code).toBe('PROJECT_NOT_FOUND');
    }
    expect((await request(app).get(`/api/v1/projects/${randomUUID()}`).set(auth(outsider))).status).toBe(404);
    expect((await request(app).get(`/api/v1/projects/${project.id}`).set(auth(member))).status).toBe(200);
    expect((await request(app).get(`/api/v1/projects/${project.id}`).set(auth(owner))).status).toBe(200);
  });
});
