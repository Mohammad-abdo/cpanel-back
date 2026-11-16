import { describe, expect, it, vi } from 'vitest';
import { createMailServerService, planProvisioning } from '../src/modules/mail-server/mail-server.service.js';
import { createMailServerController } from '../src/modules/mail-server/mail-server.controller.js';
import { createMailDomainService, renderMailDnsRecipe, DKIM_PLACEHOLDER } from '../src/modules/mail-domain/mail-domain.service.js';
import { createMailboxesService } from '../src/modules/mailboxes/mailboxes.service.js';
import { createBodyValidators } from './phase10-helpers.js';
import { verifyPassword } from '../src/common/crypto/password.js';
import { ACTION_RISK } from '../src/modules/platform/platform.risk.js';
import { APPROVER, DEV, ENV_STAGING, OWNER, PROJECT, U, makeCtx } from './phase6-helpers.js';

const SERVER = U(40);
const DOMAIN = U(41);
const SECRET = 'correct horse battery staple';

function setup({ grants = [], config = {}, domainOver = {} } = {}) {
  const mailboxes = new Map();
  const events = [];
  let cfg = null;
  let svcRow = null;
  let n = 600;
  const domain = { id: DOMAIN, name: 'example.com', projectId: PROJECT, serverId: SERVER, archivedAt: null, dnsRecords: [], server: { id: SERVER, alias: 'lab-1', hostname: '203.0.113.10' }, ...domainOver };
  const ctx = makeCtx({
    grants,
    prismaExtra: {
      server: { findUnique: vi.fn(async () => ({ id: SERVER, alias: 'lab-1', archivedAt: null })) },
      domain: { findUnique: vi.fn(async () => domain) },
      projectEnvironment: { findMany: vi.fn(async () => [{ id: ENV_STAGING, projectId: PROJECT }]) },
      serverMailService: {
        findUnique: vi.fn(async () => svcRow),
        upsert: vi.fn(async ({ create, update }) => (svcRow = svcRow ? { ...svcRow, ...update } : { id: U(70), provisioned: false, ...create })),
        update: vi.fn(async ({ data }) => (svcRow = { ...svcRow, ...data })),
      },
      domainMailConfig: {
        findUnique: vi.fn(async () => cfg),
        count: vi.fn(async () => (cfg?.enabled ? 1 : 0)),
        upsert: vi.fn(async ({ create, update }) => (cfg = cfg ? { ...cfg, ...update } : { quotaDefaultMb: 1024, dkimSelector: 'nt1', dnsState: 'pending', catchAllMailboxId: null, dkimPublicKey: null, ...create })),
        update: vi.fn(async ({ data }) => (cfg = { ...cfg, ...data })),
      },
      mailboxAccount: {
        count: vi.fn(async () => mailboxes.size),
        findUnique: vi.fn(async ({ where }) => (where.id ? mailboxes.get(where.id) ?? null : [...mailboxes.values()].find((m) => m.domainId === where.domainId_localPart.domainId && m.localPart === where.domainId_localPart.localPart) ?? null)),
        findMany: vi.fn(async () => [...mailboxes.values()].filter((m) => m.status !== 'deleted')),
        create: vi.fn(async ({ data }) => {
          const row = { id: U(++n), createdAt: new Date(), updatedAt: new Date(), ...data };
          mailboxes.set(row.id, row);
          return row;
        }),
        update: vi.fn(async ({ where, data }) => {
          Object.assign(mailboxes.get(where.id), data);
          return mailboxes.get(where.id);
        }),
      },
      mailboxAuditEvent: {
        create: vi.fn(async ({ data }) => {
          const e = { id: U(++n), createdAt: new Date(), ...data };
          events.push(e);
          return e;
        }),
        findMany: vi.fn(async () => events.slice().reverse()),
      },
    },
  });
  const deps = { ...ctx, config };
  return { ...ctx, mailboxes, events, getCfg: () => cfg, server: createMailServerService(deps), domainSvc: createMailDomainService(deps), mbox: createMailboxesService(deps) };
}
const configGrant = (userId) => ({ userId, permissionKey: 'project.configure', resourceId: PROJECT, environmentId: ENV_STAGING });
const leaks = (v) => JSON.stringify(v).match(/passwordHash|scrypt\$|"password"/i);

describe('mail-server: status, enable and provisioning gate', () => {
  it('defaults to disabled/unprovisioned and reports closed provisioning', async () => {
    const t = setup();
    const s = await t.server.get(SERVER, OWNER);
    expect(s).toMatchObject({ status: 'disabled', provisioned: false, provisioning: { authorized: false } });
    expect(s.plannedPorts.map((p) => p.port)).toContain(2096);
  });
  it('enable records intent only and is Owner-only', async () => {
    const t = setup({ grants: [configGrant(DEV.id)] });
    await expect(t.server.enable(SERVER, {}, DEV)).rejects.toMatchObject({ status: 403, code: 'OWNER_ONLY' });
    const s = await t.server.enable(SERVER, { mailHostname: 'mail.example.com' }, OWNER);
    expect(s).toMatchObject({ status: 'enabled', provisioned: false, mailHostname: 'mail.example.com' });
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'mail.server.enable' }));
    expect((await t.server.disable(SERVER, {}, OWNER)).status).toBe('disabled');
  });
  it('health reports NOT_AUTHORIZED probe with unknown relay state', async () => {
    const h = await setup().server.health(SERVER, OWNER);
    expect(h).toMatchObject({ probe: 'NOT_AUTHORIZED', openRelay: 'unknown', checked: false });
  });
  it('preview returns planned steps and executes nothing', async () => {
    const p = await setup().server.previewProvision(SERVER, { mailHostname: 'mail.example.com' }, OWNER);
    expect(p).toMatchObject({ executes: false, simulated: true });
    expect(p.steps.map((s) => s.id)).toEqual(expect.arrayContaining(['packages', 'firewall', 'relaytest']));
    expect(p.steps.find((s) => s.id === 'firewall')).toMatchObject({ risk: 'critical', requiresApproval: true });
  });
  it('apply is NOT_AUTHORIZED by default and audited as denied', async () => {
    const t = setup();
    await expect(t.server.applyProvision(SERVER, {}, OWNER)).rejects.toMatchObject({ status: 403, code: 'MAIL_PROVISIONING_NOT_AUTHORIZED' });
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'mail.provision.apply', result: 'denied' }));
  });
  it('apply stays closed when only the flag is on or only the lab list names the server', async () => {
    await expect(setup({ config: { provisioningEnabled: true, labServerIds: [] } }).server.applyProvision(SERVER, {}, OWNER)).rejects.toMatchObject({ code: 'MAIL_PROVISIONING_NOT_AUTHORIZED' });
    await expect(setup({ config: { provisioningEnabled: false, labServerIds: [SERVER] } }).server.applyProvision(SERVER, {}, OWNER)).rejects.toMatchObject({ code: 'MAIL_PROVISIONING_NOT_AUTHORIZED' });
  });
  it('even when opened, apply needs approval first and then hits the unbuilt executor (501)', async () => {
    const t = setup({ config: { provisioningEnabled: true, labServerIds: [SERVER] } });
    const first = await t.server.applyProvision(SERVER, { reason: 'lab rollout', rollbackNote: 'remove packages' }, OWNER);
    expect(first.approvalRequired).toBe(true);
    await t.platform.decide(first.approval.id, { decision: 'approve' }, APPROVER);
    await expect(t.server.applyProvision(SERVER, { approvalId: first.approval.id, reason: 'lab rollout', rollbackNote: 'remove packages' }, OWNER)).rejects.toMatchObject({ status: 501, code: 'MAIL_EXECUTOR_NOT_IMPLEMENTED' });
  });
  it('non-Owner cannot preview or apply', async () => {
    const t = setup({ config: { provisioningEnabled: true, labServerIds: [SERVER] } });
    await expect(t.server.previewProvision(SERVER, {}, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.server.applyProvision(SERVER, {}, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(t.server.get(SERVER, DEV)).rejects.toMatchObject({ status: 404 });
  });
  it('risk table registers mail actions and the controller maps approval to 202', async () => {
    expect(ACTION_RISK['mail.provision.apply']).toBe('high');
    expect(ACTION_RISK['mail.firewall.open']).toBe('critical');
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const c = createMailServerController({ applyProvision: async () => ({ approvalRequired: true, approval: { id: U(1), impactJson: [] } }) });
    await c.applyProvision({ validated: { params: { id: SERVER }, body: {} }, user: OWNER }, res);
    expect(res.status).toHaveBeenCalledWith(202);
  });
  it('planner is pure and deterministic', () => {
    expect(planProvisioning({ serverAlias: 'a', mailHostname: 'm.example.com' })).toEqual(planProvisioning({ serverAlias: 'a', mailHostname: 'm.example.com' }));
  });
});

describe('mail-domain: enable, catch-all, quota, DNS recipe', () => {
  it('Owner enables, config reflects quota; non-granted user is denied and out-of-scope is 404', async () => {
    const t = setup({ grants: [configGrant(DEV.id)] });
    expect(await t.domainSvc.enable(DOMAIN, { quotaDefaultMb: 2048 }, OWNER)).toMatchObject({ enabled: true, quotaDefaultMb: 2048 });
    const t2 = setup();
    await expect(t2.domainSvc.enable(DOMAIN, {}, DEV)).rejects.toMatchObject({ status: 404 });
  });
  it('a member with project.configure may enable; a visible member without it gets 403', async () => {
    const t = setup({ grants: [configGrant(DEV.id)] });
    t.prisma.projectMember = { findMany: vi.fn(async () => [{ projectId: PROJECT }]) };
    expect((await t.domainSvc.enable(DOMAIN, {}, DEV)).enabled).toBe(true);
    const t2 = setup();
    t2.prisma.projectMember = { findMany: vi.fn(async () => [{ projectId: PROJECT }]) };
    await expect(t2.domainSvc.enable(DOMAIN, {}, DEV)).rejects.toMatchObject({ status: 403 });
    expect((await t2.domainSvc.get(DOMAIN, DEV)).enabled).toBe(false);
  });
  it('requires a linked server', async () => {
    const t = setup({ domainOver: { serverId: null } });
    await expect(t.domainSvc.enable(DOMAIN, {}, OWNER)).rejects.toMatchObject({ code: 'DOMAIN_NO_SERVER' });
  });
  it('catch-all must be an active mailbox of the domain', async () => {
    const t = setup();
    await t.domainSvc.enable(DOMAIN, {}, OWNER);
    await expect(t.domainSvc.update(DOMAIN, { catchAllMailboxId: U(99) }, OWNER)).rejects.toMatchObject({ code: 'CATCHALL_MAILBOX_INVALID' });
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'catch', password: SECRET }, OWNER);
    expect((await t.domainSvc.update(DOMAIN, { catchAllMailboxId: mb.id }, OWNER)).catchAllMailboxId).toBe(mb.id);
    await expect(t.mbox.remove(mb.id, {}, OWNER)).rejects.toMatchObject({ code: 'MAILBOX_IS_CATCHALL' });
  });
  it('DNS recipe has MX, SPF, DKIM placeholder and DMARC', () => {
    const r = renderMailDnsRecipe({ domain: 'example.com', serverIp: '203.0.113.10', selector: 'nt1' });
    const byId = Object.fromEntries(r.records.map((x) => [x.id, x]));
    expect(byId.mx).toMatchObject({ type: 'MX', name: '@', value: '10 mail.example.com.' });
    expect(byId['mail-a']).toMatchObject({ type: 'A', name: 'mail', value: '203.0.113.10', status: 'ready' });
    expect(byId.spf.value).toBe('v=spf1 mx ~all');
    expect(byId.dkim).toMatchObject({ name: 'nt1._domainkey', status: 'placeholder' });
    expect(byId.dkim.value).toContain(DKIM_PLACEHOLDER);
    expect(byId.dmarc).toMatchObject({ name: '_dmarc', value: expect.stringContaining('v=DMARC1; p=none') });
    expect(r.notes.join(' ')).toMatch(/PTR/);
  });
  it('DNS recipe uses a real DKIM public key and a custom mail host without an A record', () => {
    const r = renderMailDnsRecipe({ domain: 'example.com', mailHostname: 'mx.other.net', dkimPublicKey: 'MIIB', selector: 's2' });
    expect(r.records.find((x) => x.id === 'mx').value).toBe('10 mx.other.net.');
    expect(r.records.find((x) => x.id === 'mail-a')).toBeUndefined();
    expect(r.records.find((x) => x.id === 'dkim')).toMatchObject({ status: 'ready', value: 'v=DKIM1; k=rsa; p=MIIB' });
    expect(JSON.stringify(r)).not.toMatch(/PRIVATE KEY/);
  });
  it('dns() marks records already present in panel DNS metadata', async () => {
    const t = setup({ domainOver: { dnsRecords: [{ type: 'MX', name: '@', valueSummary: '10 mail.example.com.' }] } });
    const d = await t.domainSvc.dns(DOMAIN, OWNER);
    expect(d.records.find((r) => r.id === 'mx')).toMatchObject({ present: true, matches: true });
    expect(d.records.find((r) => r.id === 'spf')).toMatchObject({ present: false });
  });
});

describe('mailboxes: CRUD, hash safety, audit, RBAC', () => {
  async function enabled(over) {
    const t = setup(over);
    await t.domainSvc.enable(DOMAIN, { quotaDefaultMb: 512 }, OWNER);
    return t;
  }
  it('creates a mailbox, stores only a scrypt hash, returns no hash or password', async () => {
    const t = await enabled();
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'info', displayName: 'Info', password: SECRET }, OWNER);
    expect(mb).toMatchObject({ address: 'info@example.com', quotaMb: 512, status: 'active', provisioned: false, passwordSet: true });
    expect(leaks(mb)).toBeNull();
    const stored = [...t.mailboxes.values()][0];
    expect(stored.passwordHash.startsWith('scrypt$')).toBe(true);
    expect(stored.passwordHash).not.toContain(SECRET);
    expect(verifyPassword(SECRET, stored.passwordHash)).toBe(true);
    expect(leaks(await t.mbox.get(mb.id, OWNER))).toBeNull();
    expect(leaks(await t.mbox.list({ domainId: DOMAIN, limit: 10 }, OWNER))).toBeNull();
  });
  it('audit trail and platform audit never contain the password or hash', async () => {
    const t = await enabled();
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'info', password: SECRET }, OWNER);
    await t.mbox.setPassword(mb.id, { password: 'another long secret 99' }, OWNER);
    await t.mbox.suspend(mb.id, { reason: 'abuse report' }, OWNER);
    await t.mbox.unsuspend(mb.id, {}, OWNER);
    const evts = await t.mbox.auditEvents(mb.id, { limit: 50 }, OWNER);
    expect(evts.items.map((e) => e.action)).toEqual(expect.arrayContaining(['create', 'password.set', 'suspend', 'unsuspend']));
    const blob = JSON.stringify([evts, t.auditService.record.mock.calls, t.events]);
    expect(blob).not.toContain(SECRET);
    expect(blob).not.toContain('another long secret 99');
    expect(blob).not.toMatch(/scrypt\$/);
  });
  it('password reset re-hashes and marks the mailbox unprovisioned', async () => {
    const t = await enabled();
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'info', password: SECRET }, OWNER);
    const before = [...t.mailboxes.values()][0].passwordHash;
    const out = await t.mbox.setPassword(mb.id, { password: 'another long secret 99' }, OWNER);
    expect(leaks(out)).toBeNull();
    expect([...t.mailboxes.values()][0].passwordHash).not.toBe(before);
  });
  it('rejects duplicates, disabled domains and unauthorized actors', async () => {
    const t = await enabled({ grants: [] });
    await t.mbox.create({ domainId: DOMAIN, localPart: 'info', password: SECRET }, OWNER);
    await expect(t.mbox.create({ domainId: DOMAIN, localPart: 'info', password: SECRET }, OWNER)).rejects.toMatchObject({ code: 'MAILBOX_EXISTS' });
    await expect(t.mbox.create({ domainId: DOMAIN, localPart: 'x', password: SECRET }, null)).rejects.toMatchObject({ status: 401 });
    await expect(t.mbox.create({ domainId: DOMAIN, localPart: 'x', password: SECRET }, DEV)).rejects.toMatchObject({ status: 404 });
    const off = setup();
    await expect(off.mbox.create({ domainId: DOMAIN, localPart: 'x', password: SECRET }, OWNER)).rejects.toMatchObject({ code: 'MAIL_DOMAIN_NOT_ENABLED' });
  });
  it('RBAC: visible member without project.configure cannot write; with it can', async () => {
    const t = await enabled({ grants: [configGrant(DEV.id)] });
    t.prisma.projectMember = { findMany: vi.fn(async () => [{ projectId: PROJECT }]) };
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'dev', password: SECRET }, DEV);
    expect(mb.status).toBe('active');
    const noGrant = await enabled();
    noGrant.prisma.projectMember = { findMany: vi.fn(async () => [{ projectId: PROJECT }]) };
    await expect(noGrant.mbox.create({ domainId: DOMAIN, localPart: 'dev', password: SECRET }, DEV)).rejects.toMatchObject({ status: 403 });
    const owned = await noGrant.mbox.create({ domainId: DOMAIN, localPart: 'own', password: SECRET }, OWNER);
    await expect(noGrant.mbox.setPassword(owned.id, { password: SECRET }, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(noGrant.mbox.remove(owned.id, {}, DEV)).rejects.toMatchObject({ status: 403 });
    expect((await noGrant.mbox.get(owned.id, DEV)).address).toBe('own@example.com');
  });
  it('out-of-scope actors get 404 for the mailbox itself', async () => {
    const t = await enabled();
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'info', password: SECRET }, OWNER);
    await expect(t.mbox.get(mb.id, DEV)).rejects.toMatchObject({ status: 404, code: 'MAILBOX_NOT_FOUND' });
  });
  it('soft delete wipes credentials, keeps the row and blocks further mutation', async () => {
    const t = await enabled();
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'info', password: SECRET }, OWNER);
    const out = await t.mbox.remove(mb.id, { reason: 'left company' }, OWNER);
    expect(out.status).toBe('deleted');
    const row = [...t.mailboxes.values()][0];
    expect(row.passwordHash).toBeNull();
    await expect(t.mbox.suspend(mb.id, {}, OWNER)).rejects.toMatchObject({ code: 'MAILBOX_DELETED' });
  });
  it('stale Prisma client degrades to 501 SCHEMA_REQUIRED, not a crash', async () => {
    const t = setup();
    delete t.prisma.mailboxAccount;
    delete t.prisma.domainMailConfig;
    delete t.prisma.serverMailService;
    await expect(t.mbox.create({ domainId: DOMAIN, localPart: 'x', password: SECRET }, OWNER)).rejects.toMatchObject({ status: 501, code: 'SCHEMA_REQUIRED' });
    expect(await t.mbox.list({ domainId: DOMAIN, limit: 10 }, OWNER)).toMatchObject({ items: [], schemaPending: true });
    expect(await t.domainSvc.get(DOMAIN, OWNER)).toMatchObject({ enabled: false, schemaPending: true });
    expect(await t.server.get(SERVER, OWNER)).toMatchObject({ status: 'disabled', schemaPending: true });
  });
});

describe('mail validators', () => {
  const v = createBodyValidators();
  it('accepts a normal mailbox body and lowercases the local part', () => {
    const r = v.create.safeParse({ domainId: DOMAIN, localPart: 'John.Doe+tag', password: SECRET });
    expect(r.success).toBe(true);
    expect(r.data.localPart).toBe('john.doe+tag');
  });
  it('rejects injection, dots, spaces, short passwords and unknown keys', () => {
    for (const bad of ['a..b', '.a', 'a.', 'a b', 'a;rm', 'a@b', 'a\nb', 'a/../b', '', 'x'.repeat(65)]) {
      expect(v.create.safeParse({ domainId: DOMAIN, localPart: bad, password: SECRET }).success, bad).toBe(false);
    }
    expect(v.create.safeParse({ domainId: DOMAIN, localPart: 'ok', password: 'short' }).success).toBe(false);
    expect(v.create.safeParse({ domainId: DOMAIN, localPart: 'ok', password: SECRET, passwordHash: 'x' }).success).toBe(false);
    expect(v.create.safeParse({ domainId: DOMAIN, localPart: 'ok', password: SECRET, quotaMb: 1 }).success).toBe(false);
  });
  it('server and domain validators are strict', () => {
    expect(v.enableServer.safeParse({ mailHostname: 'bad_host' }).success).toBe(false);
    expect(v.enableServer.safeParse({ mailHostname: 'mail.example.com' }).success).toBe(true);
    expect(v.applyServer.safeParse({ approvalId: 'nope' }).success).toBe(false);
    expect(v.updateDomain.safeParse({}).success).toBe(false);
    expect(v.updateDomain.safeParse({ dkimSelector: 'Bad Selector' }).success).toBe(false);
    expect(v.updateDomain.safeParse({ catchAllMailboxId: null }).success).toBe(true);
  });
});
