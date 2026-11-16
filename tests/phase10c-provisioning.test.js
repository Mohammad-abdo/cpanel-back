import { describe, expect, it, vi } from 'vitest';
import { createMailServerService } from '../src/modules/mail-server/mail-server.service.js';
import { createMailDomainService } from '../src/modules/mail-domain/mail-domain.service.js';
import { createMailboxesService } from '../src/modules/mailboxes/mailboxes.service.js';
import { createMailRemote } from '../src/common/mail-remote.js';
import * as S from '../src/common/mail-provision.scripts.js';
import { APPROVER, ENV_STAGING, OWNER, PROJECT, U, makeCtx } from './phase6-helpers.js';

const SERVER = U(40);
const DOMAIN = U(41);
const SECRET = 'Zx9!correct-horse-battery';
const GOOD_PRE = 'os_id=ubuntu\nos_version=24.04\nis_root=yes\nport_25=free\nport_465=free\nport_587=free\nport_993=free\nexisting_mta=none\nufw=active\ndisk_free_mb=20000\n';
const GOOD_HEALTH = 'svc_postfix=active\nsvc_dovecot=active\nsvc_opendkim=active\nsvc_rspamd=active\nport_25=up\nport_465=up\nport_587=up\nport_993=up\ntls=existing\nopen_relay=closed\npostfix_version=3.8\n';

/** Fake SSH executor: records every script run; `reply(script, opts)` decides the result. No network, no real server. */
function fakeSsh(reply) {
  const calls = [];
  return {
    calls,
    runRemote: vi.fn(async (_id, fn) =>
      fn({
        run: async (script, opts = {}) => {
          calls.push({ script, ...opts });
          return reply(script, opts);
        },
      }),
    ),
  };
}
const ok = (stdout = '') => ({ code: 0, stdout, stderr: '' });
const defaultReply = (script) => {
  if (script === S.preflightScript()) return ok(GOOD_PRE);
  if (script === S.healthScript()) return ok(GOOD_HEALTH);
  if (script === S.firewallScript()) return ok('NT_RESULT ufw=active changed=yes\n');
  if (script === S.firewallStatusScript()) return ok('ufw=active\nrule_25=absent\n');
  if (script === S.domainAddScript()) return ok('NT_RESULT dkim_public=MIIBIjANPUBLICKEY\n');
  if (script === S.mailboxSetScript()) return ok('NT_RESULT hash_scheme=ARGON2ID\n');
  return ok('');
};

function setup({ ssh, config = {}, provisioned = false } = {}) {
  let svcRow = provisioned ? { id: U(70), serverId: SERVER, provisioned: true, status: 'enabled', mailHostname: 'mail.example.com' } : null;
  let cfg = null;
  const mailboxes = new Map();
  let n = 800;
  const domain = { id: DOMAIN, name: 'example.com', projectId: PROJECT, serverId: SERVER, archivedAt: null, dnsRecords: [], server: { id: SERVER, alias: 'lab-1', hostname: '203.0.113.10' } };
  const ctx = makeCtx({
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
        count: vi.fn(async () => 0),
        upsert: vi.fn(async ({ create, update }) => (cfg = cfg ? { ...cfg, ...update } : { quotaDefaultMb: 1024, dkimSelector: 'nt1', dnsState: 'pending', dkimPublicKey: null, ...create })),
        update: vi.fn(async ({ data }) => (cfg = { ...cfg, ...data })),
      },
      mailboxAccount: {
        count: vi.fn(async () => 0),
        findUnique: vi.fn(async ({ where }) => (where.id ? mailboxes.get(where.id) ?? null : null)),
        create: vi.fn(async ({ data }) => {
          const row = { id: U(++n), createdAt: new Date(), updatedAt: new Date(), ...data };
          mailboxes.set(row.id, row);
          return row;
        }),
        update: vi.fn(async ({ where, data }) => Object.assign(mailboxes.get(where.id), data)),
      },
      mailboxAuditEvent: { create: vi.fn(async ({ data }) => data) },
    },
  });
  const remote = createMailRemote({ prisma: ctx.prisma, ssh, config });
  const deps = { ...ctx, config, ssh, remote };
  return { ...ctx, getRow: () => svcRow, mailboxes, server: createMailServerService(deps), domainSvc: createMailDomainService(deps), mbox: createMailboxesService(deps) };
}

async function applyApproved(t, input) {
  const base = { mailHostname: 'mail.example.com', confirmAlias: 'lab-1', reason: 'owner rollout', rollbackNote: 'see rollback notes', ...input };
  const first = await t.server.applyProvision(SERVER, base, OWNER);
  expect(first.approvalRequired).toBe(true);
  await t.platform.decide(first.approval.id, { decision: 'approve' }, APPROVER);
  return t.server.applyProvision(SERVER, { ...base, approvalId: first.approval.id }, OWNER);
}

describe('script generators', () => {
  it('contain no secret, no interpolated values, and never enable or reset ufw', () => {
    const all = [...S.PROVISION_STEP_ORDER.map(S.stepScript), S.preflightScript(), S.domainAddScript(), S.mailboxSetScript(), S.mailboxRemoveScript(), S.firewallScript(), S.healthScript()].join('\n');
    expect(all).not.toMatch(/ufw (enable|reset|disable|default|delete|deny|--force)/);
    expect(all).not.toMatch(/ufw allow [0-9]/); // ports only ever arrive as args
    expect(all).not.toMatch(/example\.com|nt1|password=/i);
    expect(S.stepScript('postfix')).toContain('smtpd_relay_restrictions = permit_sasl_authenticated, reject_unauth_destination');
    expect(S.stepScript('postfix')).toContain('smtpd_tls_security_level=encrypt');
    expect(S.stepScript('postfix')).not.toMatch(/permit_mynetworks/);
    expect(S.mailboxSetScript()).toContain('ARGON2ID');
    expect(S.mailboxSetScript()).toContain('SHA512-CRYPT');
    expect(S.domainAddScript()).not.toMatch(/cat .*\.private/);
    expect(() => S.stepScript('firewall')).toThrow();
    expect(S.PROVISION_STEP_ORDER).not.toContain('firewall');
  });
  it('rejects unsafe args and evaluates prerequisites and health', () => {
    expect(() => S.assertSafeArgs(['a; rm -rf /'])).toThrow();
    expect(S.evaluatePrerequisites(S.parseKeyValues(GOOD_PRE)).ok).toBe(true);
    expect(S.evaluatePrerequisites(S.parseKeyValues('os_id=debian\nos_version=12\nis_root=no')).blockers.length).toBeGreaterThan(1);
    expect(S.evaluateHealth(S.parseKeyValues(GOOD_HEALTH)).ok).toBe(true);
    expect(S.evaluateHealth(S.parseKeyValues(GOOD_HEALTH.replace('closed', 'open'))).checks.find((c) => c.id === 'open_relay').pass).toBe(false);
    const selfSigned = S.evaluateHealth(S.parseKeyValues(GOOD_HEALTH.replace('tls=existing', 'tls=selfsigned-placeholder')));
    expect(selfSigned.ok).toBe(true);
    expect(selfSigned.checks.find((c) => c.id === 'tls')).toMatchObject({ pass: true, warn: true });
    expect(S.normalizeStoredHealth({ ok: false, tls: 'selfsigned-placeholder', checks: [{ id: 'tls', pass: false, detail: 'self-signed placeholder: replace with a real certificate' }] }).ok).toBe(true);
  });
});

describe('provision apply: approval flow', () => {
  it('202 first, mismatched alias refused, replay with approval runs steps in order and marks provisioned', async () => {
    const ssh = fakeSsh(defaultReply);
    const t = setup({ ssh });
    await expect(t.server.applyProvision(SERVER, { mailHostname: 'mail.example.com', confirmAlias: 'wrong' }, OWNER)).rejects.toMatchObject({ code: 'CONFIRM_ALIAS_MISMATCH' });
    expect(ssh.calls).toHaveLength(0);
    const res = await applyApproved(t, {});
    expect(res).toMatchObject({ ok: true, failedStep: null });
    expect(res.steps.map((s) => s.id)).toEqual(['preflight', ...S.PROVISION_STEP_ORDER, 'health']);
    expect(t.getRow()).toMatchObject({ provisioned: true, status: 'enabled' });
    expect(t.getRow().lastHealthJson.provision.steps.length).toBeGreaterThan(5);
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'mail.provision.apply', result: 'success' }));
  });
  it('non-Owner self-approval is denied; the replay is bound to the server/host', async () => {
    const ssh = fakeSsh(defaultReply);
    const t = setup({ ssh });
    const base = { mailHostname: 'mail.example.com', confirmAlias: 'lab-1', reason: 'owner rollout' };
    const first = await t.server.applyProvision(SERVER, base, OWNER);
    const own = await t.platform.request({ action: 'dns.change', resourceType: 'domain', resourceId: DOMAIN, reason: 'because', impact: ['x'], rollbackPlan: 'undo' }, APPROVER);
    await expect(t.platform.decide(own.id, { decision: 'approve' }, APPROVER)).rejects.toMatchObject({ code: 'SELF_APPROVAL_DENIED' });
    await t.platform.decide(first.approval.id, { decision: 'approve' }, APPROVER);
    await expect(t.server.applyProvision(SERVER, { ...base, mailHostname: 'other.example.com', approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    expect(ssh.calls).toHaveLength(0);
  });
  it('Owner self-approval succeeds, is audited selfApproved, single-use and bound to the host', async () => {
    const ssh = fakeSsh(defaultReply);
    const t = setup({ ssh });
    const base = { mailHostname: 'mail.example.com', confirmAlias: 'lab-1', reason: 'owner rollout' };
    const first = await t.server.applyProvision(SERVER, base, OWNER);
    const decided = await t.platform.decide(first.approval.id, { decision: 'approve' }, OWNER);
    expect(decided).toMatchObject({ status: 'approved', approverId: OWNER.id });
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'approval.approve', metadata: expect.objectContaining({ selfApproved: true }) }));
    await expect(t.server.applyProvision(SERVER, { ...base, mailHostname: 'other.example.com', approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    const res = await t.server.applyProvision(SERVER, { ...base, approvalId: first.approval.id }, OWNER);
    expect(res).toMatchObject({ ok: true });
    const callsAfter = ssh.calls.length;
    // Single-use: the second replay never re-executes; provisioning maps APPROVAL_CONSUMED on a provisioned server to alreadyDone.
    expect(await t.server.applyProvision(SERVER, { ...base, approvalId: first.approval.id }, OWNER)).toMatchObject({ alreadyDone: true });
    expect(ssh.calls.length).toBe(callsAfter);
    expect(t.getRow().status).toBe('enabled');
  });
  it('stops on the first failing step and reports which one', async () => {
    const ssh = fakeSsh((script) => (script === S.stepScript('dovecot') ? { code: 1, stdout: '', stderr: 'doveconf: Fatal' } : defaultReply(script)));
    const t = setup({ ssh });
    const res = await applyApproved(t, {});
    expect(res).toMatchObject({ ok: false, failedStep: 'dovecot' });
    expect(res.steps.map((s) => s.id)).toEqual(['preflight', 'packages', 'postfix', 'dovecot']);
    expect(res.rollbackNotes.length).toBeGreaterThan(0);
    expect(ssh.calls.some((c) => c.script === S.stepScript('opendkim'))).toBe(false);
    expect(t.getRow()).toMatchObject({ provisioned: false, status: 'error' });
  });
  it('preflight blockers stop before any change', async () => {
    const ssh = fakeSsh((script) => (script === S.preflightScript() ? ok('os_id=debian\nos_version=12\nis_root=yes\nexisting_mta=none') : defaultReply(script)));
    const res = await applyApproved(setup({ ssh }), {});
    expect(res).toMatchObject({ ok: false, failedStep: 'preflight' });
    expect(ssh.calls).toHaveLength(1);
  });
  it('kill switch blocks apply, preview probing, firewall and health probe', async () => {
    const ssh = fakeSsh(defaultReply);
    const t = setup({ ssh, config: { provisioningDisabled: true }, provisioned: true });
    await expect(t.server.applyProvision(SERVER, { mailHostname: 'mail.example.com', confirmAlias: 'lab-1' }, OWNER)).rejects.toMatchObject({ code: 'MAIL_PROVISIONING_DISABLED' });
    await expect(t.server.probeHealth(SERVER, OWNER)).rejects.toMatchObject({ code: 'MAIL_PROVISIONING_DISABLED' });
    await expect(t.server.applyFirewall(SERVER, { confirmAlias: 'lab-1' }, OWNER)).rejects.toMatchObject({ code: 'MAIL_PROVISIONING_DISABLED' });
    const pv = await t.server.previewProvision(SERVER, {}, OWNER);
    expect(pv.prerequisites.available).toBe(false);
    expect(ssh.calls).toHaveLength(0);
  });
  it('501 only when no executor is wired (after approval)', async () => {
    const t = setup({ ssh: null });
    await expect(applyApproved(t, {})).rejects.toMatchObject({ status: 501, code: 'MAIL_EXECUTOR_NOT_IMPLEMENTED' });
  });
  it('preview probes read-only and returns detected prerequisites', async () => {
    const ssh = fakeSsh(defaultReply);
    const p = await setup({ ssh }).server.previewProvision(SERVER, { mailHostname: 'mail.example.com' }, OWNER);
    expect(p.prerequisites).toMatchObject({ available: true, ok: true });
    expect(ssh.calls.map((c) => c.script)).toEqual([S.preflightScript()]);
  });
});

describe('firewall: separate CRITICAL action', () => {
  it('requires provisioning, typed alias, approval; passes only the mail ports as args', async () => {
    const ssh = fakeSsh(defaultReply);
    const t = setup({ ssh, provisioned: true });
    const base = { confirmAlias: 'lab-1', reason: 'open mail ports' };
    await expect(t.server.applyFirewall(SERVER, { ...base, confirmAlias: 'x' }, OWNER)).rejects.toMatchObject({ code: 'CONFIRM_ALIAS_MISMATCH' });
    const first = await t.server.applyFirewall(SERVER, base, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(ssh.calls).toHaveLength(0);
    await t.platform.decide(first.approval.id, { decision: 'approve' }, APPROVER);
    const res = await t.server.applyFirewall(SERVER, { ...base, approvalId: first.approval.id }, OWNER);
    expect(res).toMatchObject({ applied: true, ports: [25, 465, 587, 993], changed: true });
    expect(ssh.calls).toHaveLength(1);
    expect(ssh.calls[0].args).toEqual(['25', '465', '587', '993']);
    expect(ssh.calls[0].script).not.toMatch(/ufw (enable|reset|delete|default)/);
  });
  it('webmail port only when requested; unprovisioned server refused; inactive ufw reports without change', async () => {
    const t0 = setup({ ssh: fakeSsh(defaultReply) });
    await expect(t0.server.applyFirewall(SERVER, { confirmAlias: 'lab-1' }, OWNER)).rejects.toMatchObject({ code: 'MAIL_NOT_PROVISIONED' });
    const ssh = fakeSsh((s) => (s === S.firewallScript() ? ok('NT_RESULT ufw=inactive changed=no\n') : defaultReply(s)));
    const t = setup({ ssh, provisioned: true });
    const base = { confirmAlias: 'lab-1', reason: 'open mail ports', webmail: true };
    const first = await t.server.applyFirewall(SERVER, base, OWNER);
    await t.platform.decide(first.approval.id, { decision: 'approve' }, APPROVER);
    const res = await t.server.applyFirewall(SERVER, { ...base, approvalId: first.approval.id }, OWNER);
    expect(ssh.calls[0].args).toEqual(['25', '465', '587', '993', '2096']);
    expect(res).toMatchObject({ applied: false, changed: false, ufw: 'inactive' });
    expect(res.note).toMatch(/never enables/);
  });
});

describe('health probe and open relay', () => {
  it('open relay result fails the probe; closed passes; result is stored', async () => {
    const closed = setup({ ssh: fakeSsh(defaultReply), provisioned: true });
    expect((await closed.server.probeHealth(SERVER, OWNER)).ok).toBe(true);
    expect((await closed.server.health(SERVER, OWNER)).probe).toBe('STORED');
    const open = setup({ ssh: fakeSsh((s) => (s === S.healthScript() ? ok(GOOD_HEALTH.replace('open_relay=closed', 'open_relay=open')) : defaultReply(s))), provisioned: true });
    const h = await open.server.probeHealth(SERVER, OWNER);
    expect(h.ok).toBe(false);
    expect(h.checks.find((c) => c.id === 'open_relay')).toMatchObject({ pass: false, detail: 'open' });
  });
});

describe('domain and mailbox push', () => {
  it('metadata-only when not provisioned; pushes domain and stores only the DKIM public key when provisioned', async () => {
    const ssh0 = fakeSsh(defaultReply);
    const t0 = setup({ ssh: ssh0 });
    expect((await t0.domainSvc.enable(DOMAIN, {}, OWNER)).remote).toEqual({ pushed: false, reason: 'not_provisioned' });
    expect(ssh0.calls).toHaveLength(0);
    const ssh = fakeSsh(defaultReply);
    const t = setup({ ssh, provisioned: true });
    const d = await t.domainSvc.enable(DOMAIN, {}, OWNER);
    expect(d.remote.pushed).toBe(true);
    expect(d.dkimPublicKeyPresent).toBe(true);
    expect(ssh.calls[0].args).toEqual(['example.com', 'nt1']);
    expect((await t.domainSvc.dns(DOMAIN, OWNER)).records.find((r) => r.id === 'dkim').value).toContain('MIIBIjANPUBLICKEY');
  });
  it('mailbox password goes over stdin only; never in args, audit, events or responses', async () => {
    const ssh = fakeSsh(defaultReply);
    const t = setup({ ssh, provisioned: true });
    await t.domainSvc.enable(DOMAIN, {}, OWNER);
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'info', password: SECRET }, OWNER);
    expect(mb).toMatchObject({ provisioned: true, remote: { pushed: true } });
    const call = ssh.calls.find((c) => c.script === S.mailboxSetScript());
    expect(call.stdin).toBe(`${SECRET}\n`);
    expect(JSON.stringify(call.args)).not.toContain(SECRET);
    expect(call.script).not.toContain(SECRET);
    const dump = JSON.stringify([mb, t.auditService.record.mock.calls]);
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toMatch(/scrypt\$|passwordHash/);
    const reset = await t.mbox.setPassword(mb.id, { password: `${SECRET}2` }, OWNER);
    expect(JSON.stringify(reset)).not.toContain(SECRET);
  });
  it('a failing push keeps the panel mailbox (unprovisioned) and reports the reason', async () => {
    const ssh = fakeSsh((s) => (s === S.mailboxSetScript() ? { code: 3, stdout: '', stderr: 'boom' } : defaultReply(s)));
    const t = setup({ ssh, provisioned: true });
    await t.domainSvc.enable(DOMAIN, {}, OWNER);
    const mb = await t.mbox.create({ domainId: DOMAIN, localPart: 'info', password: SECRET }, OWNER);
    expect(mb).toMatchObject({ provisioned: false, remote: { pushed: false, reason: 'MAIL_REMOTE_FAILED' } });
  });
});

describe('mailbox scripts match addresses literally (no regex)', () => {
  it('uses awk exact field match, never grep on the address', async () => {
    const m = await import('../src/common/mail-provision.scripts.js');
    for (const s of [m.mailboxSetScript(), m.mailboxRemoveScript(), m.domainAddScript()]) {
      expect(s).not.toMatch(/grep -v "\^\$addr/);
      expect(s).not.toMatch(/grep -q "\^/);
    }
    expect(m.mailboxRemoveScript()).toContain("awk -F: -v a=\"$addr\" '$1 != a'");
  });
});
