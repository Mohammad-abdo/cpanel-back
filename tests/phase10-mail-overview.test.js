import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import request from 'supertest';

vi.mock('../src/config/prisma.js', async () => {
  const { createFakePrisma } = await import('./http/fake-prisma.js');
  return { prisma: createFakePrisma() };
});

import { prisma } from '../src/config/prisma.js';
import { createApp } from '../src/app.js';
import { bearer, seedSession, seedUser } from './http/fake-prisma.js';

const app = createApp();
const API = '/api/v1';
const actor = async (over = {}) => {
  const user = await seedUser(prisma, over);
  const { token } = await seedSession(prisma, user);
  return { user, token };
};

async function seedWorld() {
  const server = await prisma.server.create({ data: { alias: `srv-${randomUUID().slice(0, 6)}`, status: 'online', archivedAt: null } });
  const domain = await prisma.domain.create({ data: { name: `ov-${randomUUID().slice(0, 5)}.test`, serverId: server.id, projectId: null, archivedAt: null } });
  await prisma.serverMailService.create({ data: { serverId: server.id, status: 'enabled', provisioned: true, mailHostname: 'mail.example.test', lastHealthAt: new Date(), lastHealthJson: { health: { ok: true, checks: [{ id: 'tls', pass: true }] } } } });
  await prisma.domainMailConfig.create({ data: { domainId: domain.id, enabled: true, quotaDefaultMb: 2048, dkimSelector: 'nt1', dnsState: 'pending', dkimPublicKey: 'PUBKEY' } });
  await prisma.mailboxAccount.create({ data: { domainId: domain.id, localPart: 'alice', quotaMb: 1024, status: 'active', passwordHash: 'scrypt$secret-hash', passwordSetAt: new Date() } });
  await prisma.mailboxAccount.create({ data: { domainId: domain.id, localPart: 'bob', quotaMb: 512, status: 'suspended', passwordHash: 'scrypt$secret-hash-2' } });
  await prisma.auditEvent.create({ data: { actorType: 'user', action: 'mail.server.enable', resourceType: 'server', resourceId: server.id, result: 'success', correlationId: randomUUID(), occurredAt: new Date() } });
  return { server, domain };
}
const noLeak = (res) => {
  const text = JSON.stringify(res.body);
  expect(text).not.toMatch(/passwordHash/i);
  expect(text).not.toMatch(/scrypt/i);
  expect(text).not.toContain('PUBKEY');
};

describe('mail overview endpoints', () => {
  it.each(['/mail/overview', '/mail/audit', '/mail/health-summary', '/mailboxes'])('GET %s is 401 without a session', async (p) => {
    expect((await request(app).get(`${API}${p}`)).status).toBe(401);
  });

  it('owner overview aggregates KPIs without leaking hashes or keys', async () => {
    const { server, domain } = await seedWorld();
    const owner = await actor({ ownerFlag: true });
    const res = await request(app).get(`${API}/mail/overview`).set(bearer(owner.token));
    expect(res.status).toBe(200);
    const k = res.body.data.kpis;
    expect(k.serversWithMail).toBeGreaterThanOrEqual(1);
    expect(k.provisionedStacks).toBeGreaterThanOrEqual(1);
    expect(k.mailboxes).toBeGreaterThanOrEqual(2);
    expect(k.suspended).toBeGreaterThanOrEqual(1);
    expect(k.dnsPending).toBeGreaterThanOrEqual(1);
    const srv = res.body.data.servers.find((s) => s.serverId === server.id);
    expect(srv.readiness.map((r) => r.id)).toEqual(['preflight', 'provision', 'firewall', 'health', 'dns', 'mailbox']);
    expect(res.body.data.domains.find((d) => d.domainId === domain.id).dkimPublicKeyPresent).toBe(true);
    noLeak(res);
  });

  it('a user with no grants sees an empty, scoped overview', async () => {
    await seedWorld();
    const user = await actor();
    const res = await request(app).get(`${API}/mail/overview`).set(bearer(user.token));
    expect(res.status).toBe(200);
    expect(res.body.data.servers).toEqual([]);
    expect(res.body.data.kpis.mailboxes).toBe(0);
    const audit = await request(app).get(`${API}/mail/audit`).set(bearer(user.token));
    expect(audit.body.data.items).toEqual([]);
    const health = await request(app).get(`${API}/mail/health-summary`).set(bearer(user.token));
    expect(health.body.data.items).toEqual([]);
  });

  it('audit lists recent mail events for the owner and rejects bad query', async () => {
    const { server } = await seedWorld();
    const owner = await actor({ ownerFlag: true });
    const res = await request(app).get(`${API}/mail/audit?limit=5`).set(bearer(owner.token));
    expect(res.status).toBe(200);
    expect(res.body.data.items.some((e) => e.action === 'mail.server.enable' && e.resourceId === server.id)).toBe(true);
    expect((await request(app).get(`${API}/mail/audit?limit=9999`).set(bearer(owner.token))).status).toBe(400);
  });

  it('health summary uses stored data only', async () => {
    const { server } = await seedWorld();
    const owner = await actor({ ownerFlag: true });
    const res = await request(app).get(`${API}/mail/health-summary`).set(bearer(owner.token));
    expect(res.status).toBe(200);
    const item = res.body.data.items.find((i) => i.serverId === server.id);
    expect(item.probe).toBe('STORED');
    expect(item.queue.source).toBe('NOT_COLLECTED');
  });
});

describe('cross-server mailbox list', () => {
  it('owner lists with filters and pagination, no hashes', async () => {
    const { server, domain } = await seedWorld();
    const owner = await actor({ ownerFlag: true });
    const all = await request(app).get(`${API}/mailboxes?serverId=${server.id}`).set(bearer(owner.token));
    expect(all.status).toBe(200);
    expect(all.body.data.total).toBe(2);
    expect(all.body.data.items[0].domainName).toBe(domain.name);
    noLeak(all);
    const susp = await request(app).get(`${API}/mailboxes?status=suspended&serverId=${server.id}`).set(bearer(owner.token));
    expect(susp.body.data.items.map((m) => m.localPart)).toEqual(['bob']);
    const search = await request(app).get(`${API}/mailboxes?q=ALI&serverId=${server.id}`).set(bearer(owner.token));
    expect(search.body.data.items.map((m) => m.localPart)).toEqual(['alice']);
    const page = await request(app).get(`${API}/mailboxes?limit=1&offset=1&serverId=${server.id}`).set(bearer(owner.token));
    expect(page.body.data.items).toHaveLength(1);
    expect(page.body.data.total).toBe(2);
  });

  it('an out-of-scope user sees no mailboxes across servers', async () => {
    await seedWorld();
    const user = await actor();
    const res = await request(app).get(`${API}/mailboxes`).set(bearer(user.token));
    expect(res.status).toBe(200);
    expect(res.body.data.items).toEqual([]);
    expect(res.body.data.total).toBe(0);
  });
});
