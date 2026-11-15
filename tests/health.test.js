import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { parseEnv } from '../src/config/env.js';
import { errorHandler } from '../src/common/middleware/error-handler.js';
import express from 'express';
describe('API foundation', () => {
  it('serves liveness without claiming dependency readiness', async () => {
    const res = await request(createApp()).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ data: { status: 'ok', service: 'nodeteam-api' } });
    expect(res.headers['x-request-id']).toMatch(/^[a-f0-9-]{36}$/);
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['cache-control']).toBe('no-store');
  });
  it('rejects unknown query input through module validation', async () => {
    const res = await request(createApp()).get('/api/v1/health?secret=hidden');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
    expect(JSON.stringify(res.body)).not.toContain('hidden');
  });
  it('returns a consistent 404 with a matching request ID', async () => {
    const res = await request(createApp()).get('/api/v1/missing');
    expect(res.status).toBe(404);
    expect(res.body.error.requestId).toBe(res.headers['x-request-id']);
  });
  it('handles malformed JSON without exposing request contents', async () => {
    const res = await request(createApp()).post('/api/v1/health').set('Content-Type', 'application/json').send('{"token":"secret"');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_JSON');
    expect(JSON.stringify(res.body)).not.toContain('secret');
  });
  it('enforces request body limits', async () => {
    const res = await request(createApp()).post('/api/v1/health').send({ data: 'x'.repeat(70000) });
    expect(res.status).toBe(413);
  });
  it('sanitizes unexpected async service errors', async () => {
    const app = express();
    app.get('/', async () => { throw new Error('database-password'); });
    app.use(errorHandler);
    const res = await request(app).get('/');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
    expect(JSON.stringify(res.body)).not.toContain('database-password');
  });
  it('validates environment without exposing values', () => {
    expect(parseEnv({}).PORT).toBe(4000);
    expect(() => parseEnv({ PORT: '0' })).toThrow('PORT');
    expect(() => parseEnv({ NODE_ENV: 'private-value' })).toThrow('NODE_ENV');
    expect(() => parseEnv({ NODE_ENV: 'private-value' })).not.toThrow('private-value');
  });
});
