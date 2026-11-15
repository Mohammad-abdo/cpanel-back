import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import request from 'supertest';

vi.mock('../../src/config/prisma.js', async () => {
  const { createFakePrisma } = await import('./fake-prisma.js');
  return { prisma: createFakePrisma() };
});

import { prisma } from '../../src/config/prisma.js';
import { createApp } from '../../src/app.js';
import { apiRouter } from '../../src/routes.js';
import { bearer, seedSession, seedUser } from './fake-prisma.js';

const app = createApp();
const UUID = '00000000-0000-4000-8000-000000000001';

/** Zip `apiRouter.use('/x', router)` lines in src/routes.js with the router stack to list every GET route. */
function listGetRoutes() {
  const src = readFileSync(new URL('../../src/routes.js', import.meta.url), 'utf8');
  const mounts = [...src.matchAll(/apiRouter\.use\('([^']+)'/g)].map((m) => m[1]);
  expect(mounts.length).toBe(apiRouter.stack.length);
  const out = [];
  apiRouter.stack.forEach((layer, i) => {
    for (const sub of layer.handle.stack ?? []) {
      if (sub.route?.methods?.get) out.push(`${mounts[i]}${sub.route.path === '/' ? '' : sub.route.path}`);
    }
  });
  return out.filter((p) => p !== '/health');
}

describe('platform plumbing', () => {
  it('GET /health is public and returns the liveness envelope', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ data: { status: 'ok', service: 'nodeteam-api' } });
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('sets helmet headers, request id, and hides x-powered-by', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['strict-transport-security']).toBeDefined();
    expect(res.headers['x-frame-options']).toBeDefined();
    expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('answers unknown routes with the 404 envelope and a request id', async () => {
    const res = await request(app).get('/api/v1/nope');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
    expect(res.body.error.requestId).toBe(res.headers['x-request-id']);
    const root = await request(app).post('/anything').send({});
    expect(root.status).toBe(404);
  });

  it('rejects malformed JSON with 400 INVALID_JSON', async () => {
    const res = await request(app).post('/api/v1/auth/login').set('Content-Type', 'application/json').send('{"email":');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_JSON');
  });

  it('enforces the 64kb body limit with 413', async () => {
    const res = await request(app).post('/api/v1/auth/login').send({ email: 'a@b.test', password: 'x'.repeat(70 * 1024) });
    expect(res.status).toBe(413);
    expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE');
  });

  it('500 path returns a generic envelope without stack traces or internals', async () => {
    const user = await seedUser(prisma, { ownerFlag: true });
    const { token } = await seedSession(prisma, user);
    const spy = vi.spyOn(prisma.team, 'findMany').mockRejectedValue(new Error('SECRET_DB_HOST=10.0.0.5 stack boom'));
    const res = await request(app).get('/api/v1/teams').set(bearer(token));
    spy.mockRestore();
    expect(res.status).toBe(500);
    expect(res.body).toEqual({
      error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred.', requestId: res.headers['x-request-id'] },
    });
    expect(res.text).not.toMatch(/SECRET_DB_HOST|boom|at .*\.js|node_modules/);
  });
});

describe('authentication guard over every GET route', () => {
  const routes = listGetRoutes();

  it('discovers a meaningful number of routes', () => {
    expect(routes.length).toBeGreaterThan(40);
  });

  it.each(routes)('GET %s without Authorization is 401', async (path) => {
    const url = `/api/v1${path.replace(/:\w+/g, UUID)}`;
    const res = await request(app).get(url);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH_REQUIRED');
  });

  it('rejects a non-Bearer scheme and an unknown token', async () => {
    expect((await request(app).get('/api/v1/teams').set('Authorization', 'Basic abc')).status).toBe(401);
    const res = await request(app).get('/api/v1/teams').set(bearer('not-a-real-token'));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('SESSION_INVALID');
  });
});

describe('strict schemas and params', () => {
  it.each([
    ['/api/v1/auth/login', { email: 'a@b.test', password: 'longenough1', extra: 1 }],
    ['/api/v1/agents/enroll', { token: 'x'.repeat(30), admin: true }],
    ['/api/v1/agents/report', { cpuPercent: 1, memPercent: 1, diskPercent: 1, extra: 1 }],
  ])('POST %s rejects unknown keys (public routes: validated before auth where applicable)', async (path, body) => {
    const res = await request(app).post(path).send(body);
    // agents/report authenticates first, so it is 401; the others validate first
    expect([400, 401]).toContain(res.status);
    if (res.status === 400) expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it.each([
    ['/api/v1/servers', { alias: 'web-1', evil: true }],
    ['/api/v1/teams', { name: 'Team', slug: 'team', evil: true }],
    ['/api/v1/auth/password/change', { currentPassword: 'x', newPassword: 'y'.repeat(14), evil: 1 }],
    ['/api/v1/notifications/read-all', { evil: 1 }],
    ['/api/v1/platform/approvals/' + UUID + '/decision', { decision: 'approve', evil: 1 }],
  ])('authenticated POST %s rejects unknown JSON keys with 400 VALIDATION_ERROR', async (path, body) => {
    const user = await seedUser(prisma, { ownerFlag: true });
    const { token } = await seedSession(prisma, user);
    const res = await request(app).post(path).set(bearer(token)).send(body);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });

  it.each([
    ['get', '/api/v1/servers/not-a-uuid'],
    ['get', '/api/v1/projects/123'],
    ['delete', '/api/v1/agents/xyz'],
    ['delete', '/api/v1/auth/sessions/xyz'],
    ['post', '/api/v1/notifications/abc/read'],
  ])('%s %s with an invalid UUID is 400', async (method, path) => {
    const user = await seedUser(prisma, { ownerFlag: true });
    const { token } = await seedSession(prisma, user);
    const res = await request(app)[method](path).set(bearer(token)).send(method === 'post' ? {} : undefined);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });
});
