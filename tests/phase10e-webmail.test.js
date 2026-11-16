import { describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { createWebmailApp } from '../src/webmail-app.js';

describe('TASK-037 webmail gateway isolation', () => {
  it('serves webmail health and does not mount /api/v1', async () => {
    const app = createWebmailApp();
    const health = await request(app).get('/wm/v1/health');
    expect(health.status).toBe(200);
    expect(health.body.data.service).toBe('webmail');

    const ownerApi = await request(app).get('/api/v1/health');
    expect(ownerApi.status).toBe(404);
  });

  it('rejects mail routes without mailbox session', async () => {
    const app = createWebmailApp();
    const res = await request(app).get('/wm/v1/mail/folders');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toMatch(/WEBMAIL_SESSION/);
  });

  it('login validates body and rate-limits shape', async () => {
    const app = createWebmailApp();
    const bad = await request(app).post('/wm/v1/auth/login').send({ address: 'not-an-email', password: 'x' });
    expect(bad.status).toBe(400);
  });
});

describe('TASK-037 auth service session shape', () => {
  it('me() returns mailbox fields only (no RBAC)', async () => {
    const { createWebmailAuthService } = await import('../src/modules/webmail-auth/webmail-auth.service.js');
    const auth = createWebmailAuthService({
      prisma: {
        domain: { findFirst: vi.fn() },
        mailboxAccount: { findFirst: vi.fn() },
        mailboxSession: { create: vi.fn(), updateMany: vi.fn(), findUnique: vi.fn(), update: vi.fn() },
        serverMailService: { findUnique: vi.fn() },
        serverCredential: { findUnique: vi.fn() },
      },
    });
    const me = auth.me({ address: 'a@b.test', displayName: 'A', domain: 'b.test', mailboxId: 'x', host: 'h', password: 'secret' });
    expect(me).toEqual({ address: 'a@b.test', displayName: 'A', domain: 'b.test' });
    expect(me).not.toHaveProperty('password');
    expect(me).not.toHaveProperty('permissions');
  });
});
