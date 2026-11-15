import { describe, expect, it, vi } from 'vitest';
import { classify, createCertificatesService } from '../src/modules/certificates/certificates.service.js';
import { DEV, ENV_PROD, ENV_STAGING, OWNER, PROJECT, U, approve, makeCtx } from './phase6-helpers.js';

const DOMAIN_ID = U(20);
const NOW = new Date('2026-06-01T00:00:00Z');
const days = (n) => new Date(NOW.getTime() + n * 86400000);

function setup({ domain, certs = [], grants = [] } = {}) {
  const store = new Map(certs.map((c) => [c.id, c]));
  const ctx = makeCtx({
    grants,
    now: () => NOW,
    prismaExtra: {
      domain: { findUnique: vi.fn(async () => domain ?? { id: DOMAIN_ID, name: 'app.example.com', projectId: PROJECT, status: 'active', archivedAt: null }) },
      projectEnvironment: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: PROJECT })) },
      sslCertificate: {
        findMany: vi.fn(async () => [...store.values()]),
        findUnique: vi.fn(async ({ where }) => store.get(where.id) ?? null),
        create: vi.fn(async ({ data }) => { const r = { id: U(40), ...data }; store.set(r.id, r); return r; }),
        update: vi.fn(async ({ where, data }) => { Object.assign(store.get(where.id), data); return store.get(where.id); }),
      },
    },
  });
  return { ...ctx, svc: createCertificatesService(ctx), store };
}
const body = { environmentId: ENV_PROD, challenge: 'http-01', wildcard: false, reason: 'go live', rollbackNote: 'serve over http' };

describe('certificates: classification', () => {
  it('classifies valid, expiring, expired', () => {
    expect(classify({ status: 'active', expiresAt: days(60) }, NOW)).toBe('valid');
    expect(classify({ status: 'active', expiresAt: days(10) }, NOW)).toBe('expiring');
    expect(classify({ status: 'active', expiresAt: days(-1) }, NOW)).toBe('expired');
    expect(classify({ status: 'failed' }, NOW)).toBe('failed');
  });
  it('scan flips stale active status to expired', async () => {
    const t = setup({ certs: [{ id: 'c1', status: 'active', expiresAt: days(-2) }, { id: 'c2', status: 'active', expiresAt: days(5) }, { id: 'c3', status: 'active', expiresAt: days(90) }] });
    const r = await t.svc.scanExpiry();
    expect(r).toEqual({ expired: ['c1'], expiring: ['c2'], valid: 1 });
    expect(t.store.get('c1').status).toBe('expired');
  });
});

describe('certificates: issue', () => {
  it('requires approval, then issues and records expiry', async () => {
    const t = setup();
    const first = await t.svc.issue(DOMAIN_ID, body, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.prisma.sslCertificate.create).not.toHaveBeenCalled();
    await approve(t, first.approval.id);
    const cert = await t.svc.issue(DOMAIN_ID, { ...body, approvalId: first.approval.id }, OWNER);
    expect(cert.status).toBe('active');
    expect(cert.state).toBe('valid');
    expect(cert.simulated).toBe(true);
  });
  it('denies a user without exact-scope ssl.issue grant', async () => {
    const t = setup({ grants: [{ userId: DEV.id, permissionKey: 'ssl.issue', resourceId: PROJECT, environmentId: ENV_STAGING }] });
    await expect(t.svc.issue(DOMAIN_ID, body, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('wildcard requires dns-01; unresolved DNS is refused', async () => {
    const t = setup();
    await expect(t.svc.issue(DOMAIN_ID, { ...body, wildcard: true }, OWNER)).rejects.toMatchObject({ code: 'WILDCARD_NEEDS_DNS01' });
    t.adapters.dns.resolve = vi.fn(async () => ({ resolves: false }));
    await expect(t.svc.issue(DOMAIN_ID, body, OWNER)).rejects.toMatchObject({ code: 'DNS_NOT_READY' });
  });
  it('marks the certificate failed when the CA rejects', async () => {
    const t = setup();
    const first = await t.svc.issue(DOMAIN_ID, body, OWNER);
    await approve(t, first.approval.id);
    t.adapters.acme.issue = vi.fn(async () => { throw new Error('rate limited'); });
    await expect(t.svc.issue(DOMAIN_ID, { ...body, approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'ACME_ISSUE_FAILED' });
    expect(t.store.get(U(40)).status).toBe('failed');
  });
  it('refuses archived domains', async () => {
    const t = setup({ domain: { id: DOMAIN_ID, name: 'x.example.com', projectId: PROJECT, status: 'active', archivedAt: NOW } });
    await expect(t.svc.issue(DOMAIN_ID, body, OWNER)).rejects.toMatchObject({ code: 'DOMAIN_NOT_FOUND' });
  });
});

describe('certificates: renewal', () => {
  const rb = { environmentId: ENV_PROD, force: false };
  it('does not renew early without force', async () => {
    const t = setup({ certs: [{ id: 'c1', domainId: DOMAIN_ID, status: 'active', expiresAt: days(80) }] });
    await expect(t.svc.renew('c1', rb, OWNER)).rejects.toMatchObject({ code: 'RENEWAL_NOT_DUE' });
  });
  it('renews inside the window and recovers an expired certificate', async () => {
    const t = setup({ certs: [{ id: 'c1', domainId: DOMAIN_ID, status: 'active', expiresAt: days(-3) }] });
    const r = await t.svc.renew('c1', rb, OWNER);
    expect(r.state).toBe('valid');
  });
  it('keeps expired state when renewal fails', async () => {
    const t = setup({ certs: [{ id: 'c1', domainId: DOMAIN_ID, status: 'active', expiresAt: days(-3) }] });
    t.adapters.acme.issue = vi.fn(async () => { throw new Error('down'); });
    await expect(t.svc.renew('c1', rb, OWNER)).rejects.toMatchObject({ code: 'ACME_RENEW_FAILED' });
    expect(t.store.get('c1').status).toBe('expired');
  });
  it('refuses unauthorized renewal', async () => {
    const t = setup({ certs: [{ id: 'c1', domainId: DOMAIN_ID, status: 'active', expiresAt: days(5) }] });
    await expect(t.svc.renew('c1', rb, DEV)).rejects.toMatchObject({ status: 403 });
  });
});
