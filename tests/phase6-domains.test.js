import { describe, expect, it, vi } from 'vitest';
import { createDomainsService, renderVhost, validateDnsRecord } from '../src/modules/domains/domains.service.js';
import { createDomainsController } from '../src/modules/domains/domains.controller.js';
import { createDomainBodySchema } from '../src/modules/domains/domains.validator.js';
import { APPROVER, DEV, ENV_PROD, ENV_STAGING, OWNER, PROJECT, U, approve, makeCtx } from './phase6-helpers.js';

const DOMAIN_ID = U(20);
function setup({ grants = [], domain } = {}) {
  const dom = domain ?? { id: DOMAIN_ID, name: 'app.example.com', projectId: PROJECT, dnsRecords: [], certificates: [] };
  const ctx = makeCtx({
    grants,
    prismaExtra: {
      projectEnvironment: {
        findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: [ENV_STAGING, ENV_PROD].includes(where.id) ? PROJECT : U(99) })),
      },
      domain: {
        findUnique: vi.fn(async ({ where }) => (where.name ? null : dom)),
        create: vi.fn(async ({ data }) => ({ id: DOMAIN_ID, ...data })),
        findMany: vi.fn(async () => []),
      },
      dnsRecord: { create: vi.fn(async ({ data }) => ({ id: U(30), ...data })), update: vi.fn(), delete: vi.fn() },
    },
  });
  const svc = createDomainsService(ctx);
  return { ...ctx, svc, dom };
}
const g = (userId, env) => ({ userId, permissionKey: 'domain.create', resourceId: PROJECT, environmentId: env });

describe('domains: create and authorization', () => {
  it('creates a domain for a granted user and audits it', async () => {
    const t = setup({ grants: [g(DEV.id, ENV_STAGING)] });
    const row = await t.svc.create({ name: 'a.example.com', projectId: PROJECT, environmentId: ENV_STAGING }, DEV);
    expect(row.name).toBe('a.example.com');
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'domain.create', result: 'success' }));
  });
  it('denies a staging grant against production', async () => {
    const t = setup({ grants: [g(DEV.id, ENV_STAGING)] });
    await expect(t.svc.create({ name: 'a.example.com', projectId: PROJECT, environmentId: ENV_PROD }, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('denies an unauthenticated actor and cross-project environment', async () => {
    const t = setup({ grants: [g(DEV.id, ENV_STAGING)] });
    await expect(t.svc.create({ name: 'a.example.com', projectId: U(98), environmentId: ENV_STAGING }, DEV)).rejects.toMatchObject({ code: 'ENVIRONMENT_PROJECT_MISMATCH' });
    await expect(t.svc.create({ name: 'a.example.com', projectId: PROJECT, environmentId: ENV_STAGING }, null)).rejects.toMatchObject({ status: 401 });
  });
  it('rejects duplicate domains', async () => {
    const t = setup();
    t.prisma.domain.findUnique.mockResolvedValue({ id: 'x' });
    await expect(t.svc.create({ name: 'a.example.com', projectId: PROJECT, environmentId: ENV_PROD }, OWNER)).rejects.toMatchObject({ code: 'DOMAIN_EXISTS' });
  });
  it('validator is strict and rejects bad hostnames', () => {
    expect(createDomainBodySchema.safeParse({ name: 'bad_host', projectId: PROJECT, environmentId: ENV_PROD }).success).toBe(false);
    expect(createDomainBodySchema.safeParse({ name: 'ok.example.com', projectId: PROJECT, environmentId: ENV_PROD, extra: 1 }).success).toBe(false);
  });
});

describe('domains: virtual host', () => {
  const input = { upstreamPort: 3000, webserver: 'nginx', environmentId: ENV_PROD };
  it('renders a deterministic preview diff with no side effect', async () => {
    const t = setup();
    const p = await t.svc.previewVhost(DOMAIN_ID, input, OWNER);
    expect(p.valid).toBe(true);
    expect(p.diff[0]).toBe('+ server {');
    expect(t.adapters.calls.some((c) => c.name === 'web.apply')).toBe(false);
    expect(renderVhost({ name: 'a.b.co', upstreamPort: 1, webserver: 'apache' })).toContain('ServerName a.b.co');
  });
  it('requires approval before applying, then applies once with a separate approver', async () => {
    const t = setup();
    const first = await t.svc.applyVhost(DOMAIN_ID, { ...input, reason: 'launch', rollbackNote: 'restore previous vhost' }, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.adapters.calls.some((c) => c.name === 'web.apply')).toBe(false);
    await approve(t, first.approval.id);
    const done = await t.svc.applyVhost(DOMAIN_ID, { ...input, approvalId: first.approval.id }, OWNER);
    expect(done.applied).toBe(true);
    await expect(t.svc.applyVhost(DOMAIN_ID, { ...input, approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });
  it('refuses to apply an unapproved approval id and missing reason', async () => {
    const t = setup();
    await expect(t.svc.applyVhost(DOMAIN_ID, input, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_FIELDS_REQUIRED' });
    const first = await t.svc.applyVhost(DOMAIN_ID, { ...input, reason: 'launch', rollbackNote: 'restore previous' }, OWNER);
    await expect(t.svc.applyVhost(DOMAIN_ID, { ...input, approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_APPROVED' });
  });
  it('blocks self approval', async () => {
    const t = setup();
    const first = await t.svc.applyVhost(DOMAIN_ID, { ...input, reason: 'launch', rollbackNote: 'restore previous' }, OWNER);
    await expect(t.platform.decide(first.approval.id, { decision: 'approve' }, OWNER)).rejects.toMatchObject({ code: 'SELF_APPROVAL_DENIED' });
    await expect(t.platform.decide(first.approval.id, { decision: 'approve' }, DEV)).rejects.toMatchObject({ status: 403 });
  });
  it('rejects invalid config before approval is even requested', async () => {
    const t = setup();
    t.adapters.webserver.validate = vi.fn(async () => ({ ok: false, errors: ['bad'] }));
    await expect(t.svc.applyVhost(DOMAIN_ID, { ...input, reason: 'x1234', rollbackNote: 'y1234' }, OWNER)).rejects.toMatchObject({ code: 'VHOST_INVALID' });
    expect(t.prisma.approvalRequest.create).not.toHaveBeenCalled();
  });
  it('rolls back when apply fails', async () => {
    const t = setup();
    const first = await t.svc.applyVhost(DOMAIN_ID, { ...input, reason: 'launch', rollbackNote: 'restore previous' }, OWNER);
    await approve(t, first.approval.id);
    t.adapters.webserver.apply = vi.fn(async () => { throw new Error('reload failed'); });
    await expect(t.svc.applyVhost(DOMAIN_ID, { ...input, approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'VHOST_APPLY_FAILED' });
    expect(t.adapters.calls.some((c) => c.name === 'web.rollback')).toBe(true);
  });
});

describe('domains: DNS', () => {
  const rec = { op: 'upsert', type: 'A', name: 'app.example.com', value: '203.0.113.10', ttl: 300, environmentId: ENV_PROD };
  it('validates records', () => {
    expect(() => validateDnsRecord('example.com', { type: 'A', name: 'x.example.com', value: 'nope' })).toThrow();
    expect(() => validateDnsRecord('example.com', { type: 'A', name: 'x.other.com', value: '1.2.3.4' })).toThrow(/outside/);
    expect(() => validateDnsRecord('example.com', { type: 'CNAME', name: '@', value: 'a.b.com' })).toThrow(/apex/);
  });
  it('needs approval, persists only after provider success', async () => {
    const t = setup();
    const first = await t.svc.changeDns(DOMAIN_ID, { ...rec, reason: 'cutover', rollbackNote: 'restore old A record' }, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.prisma.dnsRecord.create).not.toHaveBeenCalled();
    await approve(t, first.approval.id);
    const done = await t.svc.changeDns(DOMAIN_ID, { ...rec, approvalId: first.approval.id }, OWNER);
    expect(done.record.valueSummary).toBe('203.0.113.10');
  });
  it('stores nothing when the provider fails', async () => {
    const t = setup();
    const first = await t.svc.changeDns(DOMAIN_ID, { ...rec, reason: 'cutover', rollbackNote: 'restore old A record' }, OWNER);
    await approve(t, first.approval.id);
    t.adapters.dns.upsert = vi.fn(async () => { throw new Error('provider down'); });
    await expect(t.svc.changeDns(DOMAIN_ID, { ...rec, approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'DNS_PROVIDER_FAILED' });
    expect(t.prisma.dnsRecord.create).not.toHaveBeenCalled();
  });
  it('rejects an approval issued for another domain', async () => {
    const t = setup();
    const first = await t.svc.changeDns(DOMAIN_ID, { ...rec, reason: 'cutover', rollbackNote: 'restore old A record' }, OWNER);
    await approve(t, first.approval.id);
    t.prisma.domain.findUnique.mockResolvedValue({ id: U(21), name: 'app.example.com', projectId: PROJECT, dnsRecords: [], certificates: [] });
    await expect(t.svc.changeDns(U(21), { ...rec, approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
  });
  it('controller maps approval-required to 202', async () => {
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const c = createDomainsController({ changeDns: async () => ({ approvalRequired: true, approval: { id: 'a', impactJson: {} } }) });
    await c.changeDns({ validated: { params: { id: 'x' }, body: {} }, user: APPROVER }, res);
    expect(res.status).toHaveBeenCalledWith(202);
  });
});
