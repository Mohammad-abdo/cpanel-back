import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';

describe('protected routes fail closed', () => {
  const app = createApp();

  it('rejects audit list without session', async () => {
    const res = await request(app).get('/api/v1/audit/events');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH_REQUIRED');
  });

  it('rejects operations enqueue without session', async () => {
    const res = await request(app).post('/api/v1/operations').send({});
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH_REQUIRED');
  });

  it('rejects rbac grants without session', async () => {
    const res = await request(app).get('/api/v1/rbac/grants');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('AUTH_REQUIRED');
  });
});
