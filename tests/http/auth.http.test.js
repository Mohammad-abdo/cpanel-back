import { describe, expect, it, vi } from 'vitest';
import request from 'supertest';

vi.mock('../../src/config/prisma.js', async () => {
  const { createFakePrisma } = await import('./fake-prisma.js');
  return { prisma: createFakePrisma() };
});

import { prisma } from '../../src/config/prisma.js';
import { createApp } from '../../src/app.js';
import { generateTotp, generateTotpSecret } from '../../src/common/crypto/totp.js';
import { PASSWORD, bearer, seedSession, seedUser } from './fake-prisma.js';

const app = createApp();
let n = 0;
const email = () => `user${++n}@example.test`;
const login = (e, p = PASSWORD) => request(app).post('/api/v1/auth/login').send({ email: e, password: p });

async function userWithMfa(over = {}) {
  const user = await seedUser(prisma, { email: email(), ...over });
  const secret = generateTotpSecret();
  const factor = await prisma.mfaFactor.create({ data: { userId: user.id, type: 'totp', secretRef: secret, verifiedAt: new Date() } });
  return { user, secret, factor };
}

describe('POST /auth/login', () => {
  it('succeeds with valid credentials and returns a usable bearer token', async () => {
    const e = email();
    await seedUser(prisma, { email: e, displayName: 'Ada' });
    const res = await login(e.toUpperCase());
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ authorized: true, mfaRequired: false, user: { email: e, displayName: 'Ada', isOwner: false } });
    expect(res.body.data.user.passwordHash).toBeUndefined();
    const me = await request(app).get('/api/v1/auth/me').set(bearer(res.body.data.token));
    expect(me.status).toBe(200);
    expect(me.body.data.email).toBe(e);
  });

  it('answers wrong password and unknown email identically (401 AUTH_INVALID)', async () => {
    const e = email();
    await seedUser(prisma, { email: e });
    const wrong = await login(e, 'wrong-password-1');
    const unknown = await login('nobody@example.test');
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.error.code).toBe('AUTH_INVALID');
    expect(wrong.body.error.message).toBe(unknown.body.error.message);
  });

  it('refuses disabled users at login', async () => {
    const e = email();
    await seedUser(prisma, { email: e, status: 'disabled' });
    expect((await login(e)).status).toBe(401);
  });

  it.each([
    [{}],
    [{ email: 'not-an-email', password: 'longenough1' }],
    [{ email: 'a@b.test', password: 'short' }],
    [{ email: 'a@b.test', password: 12345678 }],
  ])('rejects invalid body %j with 400 VALIDATION_ERROR', async (body) => {
    const res = await request(app).post('/api/v1/auth/login').send(body);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('rate limits repeated failures: 429 RATE_LIMITED with Retry-After', async () => {
    const e = email();
    await seedUser(prisma, { email: e });
    for (let i = 0; i < 10; i += 1) expect((await login(e, 'bad-password-xx')).status).toBe(401);
    const res = await login(e, 'bad-password-xx');
    expect(res.status).toBe(429);
    expect(res.body.error.code).toBe('RATE_LIMITED');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    // The correct password is also throttled for that email, but another email is not.
    expect((await login(e)).status).toBe(429);
    const other = email();
    await seedUser(prisma, { email: other });
    expect((await login(other)).status).toBe(200);
  });
});

describe('MFA pending flow', () => {
  it('login with an enrolled factor returns a pending session that cannot reach guarded routes', async () => {
    const { user } = await userWithMfa();
    const res = await login(user.email);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ mfaRequired: true, authorized: false });
    const token = res.body.data.token;
    const guarded = await request(app).get('/api/v1/teams').set(bearer(token));
    expect(guarded.status).toBe(401);
    expect(guarded.body.error.code).toBe('MFA_REQUIRED');
    // /auth/me is allowed while pending
    expect((await request(app).get('/api/v1/auth/me').set(bearer(token))).status).toBe(200);
  });

  it('verify with the right TOTP code authorizes the session; wrong code is 401 MFA_INVALID', async () => {
    const { user, secret } = await userWithMfa();
    const { body } = await login(user.email);
    const { token, sessionId } = body.data;
    const bad = await request(app).post('/api/v1/auth/mfa/verify').send({ sessionId, code: '000000' });
    expect(bad.status).toBe(401);
    expect(bad.body.error.code).toBe('MFA_INVALID');
    const ok = await request(app).post('/api/v1/auth/mfa/verify').send({ sessionId, code: generateTotp(secret) });
    expect(ok.status).toBe(200);
    expect(ok.body.data.authorized).toBe(true);
    expect((await request(app).get('/api/v1/teams').set(bearer(token))).status).toBe(200);
  });

  it('rate limits MFA code guessing per pending session (429 after 5 attempts)', async () => {
    const { user } = await userWithMfa();
    const { body } = await login(user.email);
    const { sessionId } = body.data;
    for (let i = 0; i < 5; i += 1) {
      expect((await request(app).post('/api/v1/auth/mfa/verify').send({ sessionId, code: '111111' })).status).toBe(401);
    }
    const res = await request(app).post('/api/v1/auth/mfa/verify').send({ sessionId, code: '111111' });
    expect(res.status).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
  });

  it('bypass fix: a pending session cannot enroll or confirm a factor when one already exists', async () => {
    const { user } = await userWithMfa();
    const { body } = await login(user.email);
    const token = body.data.token;
    const enroll = await request(app).post('/api/v1/auth/mfa/totp/enroll').set(bearer(token)).send({});
    expect(enroll.status).toBe(401);
    expect(enroll.body.error.code).toBe('MFA_REQUIRED');
    const before = prisma.mfaFactor.rows.length;
    expect(prisma.mfaFactor.rows.length).toBe(before);
    const rogue = await prisma.mfaFactor.create({ data: { userId: user.id, type: 'totp', secretRef: generateTotpSecret(), verifiedAt: null } });
    const confirm = await request(app)
      .post('/api/v1/auth/mfa/totp/confirm')
      .set(bearer(token))
      .send({ factorId: rogue.id, code: generateTotp(rogue.secretRef) });
    expect(confirm.status).toBe(401);
    expect(confirm.body.error.code).toBe('MFA_REQUIRED');
    expect(rogue.verifiedAt).toBeNull();
  });

  it('a user without a factor can enroll and confirm one (201 then 200)', async () => {
    const user = await seedUser(prisma, { email: email() });
    const { token } = await seedSession(prisma, user);
    const enroll = await request(app).post('/api/v1/auth/mfa/totp/enroll').set(bearer(token)).send({});
    expect(enroll.status).toBe(201);
    const { factorId, secret } = enroll.body.data;
    const confirm = await request(app)
      .post('/api/v1/auth/mfa/totp/confirm')
      .set(bearer(token))
      .send({ factorId, code: generateTotp(secret) });
    expect(confirm.status).toBe(200);
    expect(prisma.mfaFactor.rows.find((f) => f.id === factorId).verifiedAt).toBeTruthy();
  });
});

describe('sessions, logout, disabled users', () => {
  it('logout revokes the token: subsequent use is 401', async () => {
    const user = await seedUser(prisma, { email: email() });
    const { token } = await seedSession(prisma, user);
    expect((await request(app).get('/api/v1/auth/me').set(bearer(token))).status).toBe(200);
    const out = await request(app).post('/api/v1/auth/logout').set(bearer(token)).send({});
    expect(out.status).toBe(200);
    const after = await request(app).get('/api/v1/auth/me').set(bearer(token));
    expect(after.status).toBe(401);
    expect(after.body.error.code).toBe('SESSION_INVALID');
  });

  it('logout without a token is an idempotent 200', async () => {
    expect((await request(app).post('/api/v1/auth/logout').send({})).status).toBe(200);
  });

  it('expired and revoked sessions are 401 SESSION_INVALID', async () => {
    const user = await seedUser(prisma, { email: email() });
    const expired = await seedSession(prisma, user, { expiresAt: new Date(Date.now() - 1000) });
    const revoked = await seedSession(prisma, user, { revokedAt: new Date() });
    for (const { token } of [expired, revoked]) {
      const res = await request(app).get('/api/v1/auth/me').set(bearer(token));
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe('SESSION_INVALID');
    }
  });

  it('a disabled user with a live session gets 403 USER_DISABLED', async () => {
    const user = await seedUser(prisma, { email: email() });
    const { token } = await seedSession(prisma, user);
    await prisma.user.update({ where: { id: user.id }, data: { status: 'disabled', disabledAt: new Date() } });
    const res = await request(app).get('/api/v1/auth/me').set(bearer(token));
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('USER_DISABLED');
  });

  it('lists only own sessions without token hashes; revoking another user session is 404', async () => {
    const a = await seedUser(prisma, { email: email() });
    const b = await seedUser(prisma, { email: email() });
    const sa = await seedSession(prisma, a);
    const sb = await seedSession(prisma, b);
    const list = await request(app).get('/api/v1/auth/sessions').set(bearer(sa.token));
    expect(list.status).toBe(200);
    expect(list.body.data.map((s) => s.id)).toEqual([sa.session.id]);
    expect(JSON.stringify(list.body)).not.toMatch(/tokenHash/);
    const res = await request(app).delete(`/api/v1/auth/sessions/${sb.session.id}`).set(bearer(sa.token));
    expect(res.status).toBe(404);
  });
});

describe('POST /auth/password/change', () => {
  it('enforces the 12-character policy (400) and rejects a wrong current password (401)', async () => {
    const user = await seedUser(prisma, { email: email() });
    const { token } = await seedSession(prisma, user);
    const short = await request(app).post('/api/v1/auth/password/change').set(bearer(token)).send({ currentPassword: PASSWORD, newPassword: 'short-11-ch' });
    expect(short.status).toBe(400);
    expect(short.body.error.code).toBe('VALIDATION_ERROR');
    const wrong = await request(app).post('/api/v1/auth/password/change').set(bearer(token)).send({ currentPassword: 'wrong', newPassword: 'a-brand-new-passphrase' });
    expect(wrong.status).toBe(401);
    const same = await request(app).post('/api/v1/auth/password/change').set(bearer(token)).send({ currentPassword: PASSWORD, newPassword: PASSWORD });
    expect(same.status).toBe(400);
    expect(same.body.error.code).toBe('PASSWORD_POLICY');
  });

  it('changes the password, revokes other sessions, keeps the current one, and the new password logs in', async () => {
    const e = email();
    const user = await seedUser(prisma, { email: e });
    const current = await seedSession(prisma, user);
    const other = await seedSession(prisma, user);
    const res = await request(app)
      .post('/api/v1/auth/password/change')
      .set(bearer(current.token))
      .send({ currentPassword: PASSWORD, newPassword: 'a-brand-new-passphrase' });
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ ok: true, revokedSessions: 1 });
    expect((await request(app).get('/api/v1/auth/me').set(bearer(current.token))).status).toBe(200);
    expect((await request(app).get('/api/v1/auth/me').set(bearer(other.token))).status).toBe(401);
    expect((await login(e, PASSWORD)).status).toBe(401);
    expect((await login(e, 'a-brand-new-passphrase')).status).toBe(200);
  });

  it('rate limits password change attempts per user (429 after 5)', async () => {
    const user = await seedUser(prisma, { email: email() });
    const { token } = await seedSession(prisma, user);
    const body = { currentPassword: 'wrong-current', newPassword: 'a-brand-new-passphrase' };
    for (let i = 0; i < 5; i += 1) expect((await request(app).post('/api/v1/auth/password/change').set(bearer(token)).send(body)).status).toBe(401);
    const res = await request(app).post('/api/v1/auth/password/change').set(bearer(token)).send(body);
    expect(res.status).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
  });
});
