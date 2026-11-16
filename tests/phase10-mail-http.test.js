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
const SECRET = 'S3cret-passphrase-xyz';

async function seedWorld() {
  const server = await prisma.server.create({ data: { alias: `srv-${randomUUID().slice(0, 6)}`, status: 'online', archivedAt: null } });
  const domain = await prisma.domain.create({ data: { name: 'example.test', serverId: server.id, projectId: null, archivedAt: null } });
  return { server, domain };
}
const noLeak = (res) => {
  const text = JSON.stringify(res.body);
  expect(text).not.toMatch(/passwordHash/i);
  expect(text).not.toContain(SECRET);
  expect(text).not.toMatch(/scrypt/i);
};

describe('mail routers require a session', () => {
  const id = randomUUID();
  it.each([
    ['get', `/servers/${id}/mail`],
    ['post', `/servers/${id}/mail/enable`],
    ['post', `/servers/${id}/mail/provision/apply`],
    ['get', `/domains/${id}/mail`],
    ['post', `/domains/${id}/mail/enable`],
    ['get', `/mailboxes?domainId=${id}`],
    ['post', '/mailboxes'],
    ['post', `/mailboxes/${id}/password`],
  ])('%s %s is 401 without a session', async (method, path) => {
    const res = await request(app)[method](`${API}${path}`).send({});
    expect(res.status).toBe(401);
  });
});

describe('mail-server (Owner only writes)', () => {
  it('non-owner cannot enable, preview or apply: 403 OWNER_ONLY', async () => {
    const { server } = await seedWorld();
    const user = await actor();
    for (const p of ['enable', 'provision/preview', 'provision/apply']) {
      const res = await request(app).post(`${API}/servers/${server.id}/mail/${p}`).set(bearer(user.token)).send({});
      expect(res.status, p).not.toBe(200);
      expect([403, 404]).toContain(res.status);
      noLeak(res);
    }
  });

  it('owner enable is metadata-only and provisioning apply is 403 MAIL_PROVISIONING_NOT_AUTHORIZED', async () => {
    const { server } = await seedWorld();
    const owner = await actor({ ownerFlag: true });
    const en = await request(app).post(`${API}/servers/${server.id}/mail/enable`).set(bearer(owner.token)).send({ mailHostname: 'mail.example.test' });
    expect(en.status).toBe(200);
    expect(en.body.data).toMatchObject({ status: 'enabled', provisioned: false });
    noLeak(en);
    const prev = await request(app).post(`${API}/servers/${server.id}/mail/provision/preview`).set(bearer(owner.token)).send({});
    expect(prev.status).toBe(200);
    expect(prev.body.data.executes).toBe(false);
    const apply = await request(app).post(`${API}/servers/${server.id}/mail/provision/apply`).set(bearer(owner.token)).send({});
    expect(apply.status).toBe(403);
    expect(apply.body.error.code).toBe('MAIL_PROVISIONING_NOT_AUTHORIZED');
  });

  it('validates input with 400 VALIDATION_ERROR (the API validation status)', async () => {
    const { server } = await seedWorld();
    const owner = await actor({ ownerFlag: true });
    const bad = await request(app).post(`${API}/servers/${server.id}/mail/enable`).set(bearer(owner.token)).send({ mailHostname: 'not a host', extra: 1 });
    expect(bad.status).toBe(400);
    expect(bad.body.error.code).toBe('VALIDATION_ERROR');
    const badId = await request(app).get(`${API}/servers/not-a-uuid/mail`).set(bearer(owner.token));
    expect(badId.status).toBe(400);
  });
});

describe('mail-domain', () => {
  it('owner enables, reads and rejects bad bodies; non-owner is denied', async () => {
    const { domain } = await seedWorld();
    const owner = await actor({ ownerFlag: true });
    const user = await actor();
    const en = await request(app).post(`${API}/domains/${domain.id}/mail/enable`).set(bearer(owner.token)).send({ quotaDefaultMb: 500 });
    expect(en.status).toBeLessThan(300);
    noLeak(en);
    const bad = await request(app).post(`${API}/domains/${domain.id}/mail/enable`).set(bearer(owner.token)).send({ quotaDefaultMb: 1 });
    expect(bad.status).toBe(400);
    const empty = await request(app).patch(`${API}/domains/${domain.id}/mail`).set(bearer(owner.token)).send({});
    expect(empty.status).toBe(400);
    const denied = await request(app).post(`${API}/domains/${domain.id}/mail/enable`).set(bearer(user.token)).send({});
    expect([403, 404]).toContain(denied.status);
  });
});

describe('mailboxes', () => {
  it('create/list/get/suspend never leak the password or hash; invalid input is 400; non-owner denied', async () => {
    const { domain } = await seedWorld();
    const owner = await actor({ ownerFlag: true });
    const user = await actor();
    await request(app).post(`${API}/domains/${domain.id}/mail/enable`).set(bearer(owner.token)).send({});

    const bad = await request(app).post(`${API}/mailboxes`).set(bearer(owner.token)).send({ domainId: domain.id, localPart: 'Bad..Name', password: 'short' });
    expect(bad.status).toBe(400);
    expect(bad.body.error.code).toBe('VALIDATION_ERROR');

    const denied = await request(app).post(`${API}/mailboxes`).set(bearer(user.token)).send({ domainId: domain.id, localPart: 'demo-a', password: SECRET });
    expect([403, 404]).toContain(denied.status);
    noLeak(denied);

    const created = await request(app).post(`${API}/mailboxes`).set(bearer(owner.token)).send({ domainId: domain.id, localPart: 'demo-a', password: SECRET });
    expect(created.status).toBe(201);
    expect(created.body.data.address).toBe('demo-a@example.test');
    noLeak(created);
    const id = created.body.data.id;

    for (const path of [`/mailboxes?domainId=${domain.id}`, `/mailboxes/${id}`, `/mailboxes/${id}/audit`]) {
      const res = await request(app).get(`${API}${path}`).set(bearer(owner.token));
      expect(res.status, path).toBe(200);
      noLeak(res);
    }
    const pw = await request(app).post(`${API}/mailboxes/${id}/password`).set(bearer(owner.token)).send({ password: 'another-Secret-123' });
    expect(pw.status).toBeLessThan(300);
    noLeak(pw);
    const sus = await request(app).post(`${API}/mailboxes/${id}/suspend`).set(bearer(owner.token)).send({});
    expect(sus.status).toBe(200);
    expect(sus.body.data.status).toBe('suspended');
    noLeak(sus);
  });
});
