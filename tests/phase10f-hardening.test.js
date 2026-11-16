import { describe, expect, it } from 'vitest';
import * as S from '../src/common/mail-provision.scripts.js';
import { createMailAccess } from '../src/common/mail-support.js';
import { PERMISSION_LIST, PERMISSION_RISK, PERMISSIONS } from '../src/common/permission-catalog.js';
import { PERMISSIONS as PKG_PERMISSIONS, PERMISSION_RISK as PKG_RISK } from '../../../packages/permission-catalog/src/index.js';
import { checkMailboxPassword, createMailboxBodySchema, setMailboxPasswordBodySchema } from '../src/modules/mailboxes/mailboxes.validator.js';

const hard = () => S.stepScript('hardening');

describe('Phase 10F hardening step', () => {
  it('is ordered after tls and before services; firewall is still not a step', () => {
    const o = S.PROVISION_STEP_ORDER;
    expect(o.indexOf('hardening')).toBeGreaterThan(o.indexOf('tls'));
    expect(o.indexOf('hardening')).toBeLessThan(o.indexOf('services'));
    expect(o.indexOf('packages')).toBe(0);
    expect(S.PROVISION_STEPS.map((s) => s.id)).toEqual(o);
  });
  it('configures fail2ban jails, rspamd baseline, postfix rate limits and dovecot auth delay', () => {
    const h = hard();
    for (const j of ['[postfix]', '[postfix-sasl]', '[dovecot]']) expect(h).toContain(j);
    expect(h).toContain('/etc/fail2ban/jail.d/nt-mail.local');
    expect(h).toContain('smtpd_client_message_rate_limit');
    expect(h).toContain('anvil_rate_time_unit');
    expect(h).toContain('smtpd_client_auth_rate_limit');
    expect(h).toContain('auth_failure_delay');
    expect(h).toContain('/etc/rspamd/local.d/actions.conf');
    expect(h).toContain('127.0.0.1:11334');
    expect(S.stepScript('packages')).toContain('fail2ban');
  });
  it('is idempotent: managed files are rewritten whole with a marker and postconf -e is used', () => {
    const h = hard();
    expect((h.match(/NT-HARDENING-v1/g) ?? []).length).toBeGreaterThanOrEqual(5);
    expect(h).not.toMatch(/>>\s*\/etc/);
    expect(h).toMatch(/postconf -e/);
    expect(hard()).toBe(S.stepScript('hardening'));
  });
  it('validates before it finishes (stop-on-failure) and carries no secrets or dynamic values', () => {
    const h = hard();
    expect(h.split('\n')[1]).toBe('set -euo pipefail');
    const checks = ['postfix check', 'doveconf -n', 'fail2ban-client -t', 'NT_RESULT hardening=applied'].map((m) => h.indexOf(m));
    expect(checks.every((i) => i > 0)).toBe(true);
    expect(h.indexOf('NT_RESULT hardening=applied')).toBe(Math.max(...checks));
    expect(h).not.toMatch(/\$1|\$2|password\s*=|secret|example\.com|permit_mynetworks/i);
    expect(h).not.toMatch(/ufw /);
  });
  it('services step restarts and verifies fail2ban', () => {
    const sv = S.stepScript('services');
    expect(sv).toContain('postfix fail2ban; do');
    expect(sv).toContain('exit 1');
  });
});

describe('Phase 10F health probe additions', () => {
  const base = 'svc_postfix=active\nsvc_dovecot=active\nsvc_opendkim=active\nsvc_rspamd=active\nport_25=up\nport_465=up\nport_587=up\nport_993=up\ntls=existing\nopen_relay=closed\n';
  it('probe script reports fail2ban, cert days and queue size', () => {
    const h = S.healthScript();
    expect(h).toContain('fail2ban');
    expect(h).toContain('tls_days_left=');
    expect(h).toContain('queue_size=');
    expect(h).toContain('mailq');
  });
  it('legacy probe output (no new keys) remains valid', () => {
    const r = S.evaluateHealth(S.parseKeyValues(base));
    expect(r.ok).toBe(true);
    expect(r.checks.find((c) => c.id === 'service.fail2ban')).toBeUndefined();
    expect(r.checks.find((c) => c.id === 'maildir.backup')).toMatchObject({ pass: true, warn: true });
  });
  it('evaluates fail2ban, jails, cert expiry and queue', () => {
    const good = S.evaluateHealth(S.parseKeyValues(`${base}svc_fail2ban=active\nf2b_jails=dovecot+postfix+postfix-sasl\ntls_days_left=60\nqueue_size=3\n`));
    expect(good.ok).toBe(true);
    expect(good.checks.find((c) => c.id === 'queue.size')).toMatchObject({ pass: true, queueSize: 3 });
    expect(good.checks.find((c) => c.id === 'maildir.backup')).toMatchObject({ pass: true, warn: true, detail: expect.stringMatching(/not configured/i) });
    expect(S.evaluateHealth(S.parseKeyValues(`${base}svc_fail2ban=inactive\n`)).ok).toBe(false);
    expect(S.evaluateHealth(S.parseKeyValues(`${base}svc_fail2ban=active\nf2b_jails=dovecot\n`)).checks.find((c) => c.id === 'fail2ban.jails').pass).toBe(false);
    const soon = S.evaluateHealth(S.parseKeyValues(`${base}tls_days_left=5\n`)).checks.find((c) => c.id === 'tls.expiry');
    expect(soon).toMatchObject({ pass: true, warn: true });
    expect(S.evaluateHealth(S.parseKeyValues(`${base}tls_days_left=-2\n`)).ok).toBe(false);
    expect(S.evaluateHealth(S.parseKeyValues(`${base}queue_size=900\n`)).ok).toBe(false);
    expect(S.evaluateHealth(S.parseKeyValues(`${base}queue_size=unknown\n`)).ok).toBe(true);
  });
  it('normalizeStoredHealth injects maildir.backup warning when missing', () => {
    const stored = S.normalizeStoredHealth({ ok: true, tls: 'existing', checks: [{ id: 'open_relay', pass: true, detail: 'closed' }] });
    expect(stored.checks.find((c) => c.id === 'maildir.backup')).toMatchObject({ pass: true, warn: true });
    expect(stored.ok).toBe(true);
  });
});

describe('mail.manage permission', () => {
  it('is in both catalogs with a risk tier', () => {
    expect(PERMISSIONS.MAIL_MANAGE).toBe('mail.manage');
    expect(PERMISSION_LIST).toContain('mail.manage');
    expect(PERMISSION_RISK['mail.manage']).toBe('high');
    expect(PKG_PERMISSIONS.MAIL_MANAGE).toBe('mail.manage');
    expect(PKG_RISK['mail.manage']).toBe('high');
  });
  const domain = { id: 'd1', projectId: 'p1', serverId: 's1' };
  const mk = (can) => createMailAccess({ prisma: { projectEnvironment: { findMany: async () => [{ id: 'e1' }] } }, rbac: { can: async (_a, c) => can(c) } });
  it('Owner passes; holder of mail.manage passes; unrelated member is denied', async () => {
    await expect(mk(() => false).requireWrite({ id: 'o', isOwner: true }, domain)).resolves.toBeUndefined();
    const seen = [];
    await expect(mk((c) => (seen.push(c.permissionKey), c.permissionKey === 'mail.manage' && c.resourceType === 'project')).requireWrite({ id: 'u' }, domain)).resolves.toBeUndefined();
    expect(seen[0]).toBe('mail.manage');
    await expect(mk(() => false).requireWrite({ id: 'u' }, domain)).rejects.toMatchObject({ status: 403 });
    await expect(mk(() => true).requireWrite(null, domain)).rejects.toMatchObject({ status: 401 });
  });
  it('legacy project.configure holders keep working', async () => {
    await expect(mk((c) => c.permissionKey === 'project.configure').requireWrite({ id: 'u' }, domain)).resolves.toBeUndefined();
  });
});

describe('mailbox password policy', () => {
  it.each([
    ['short1!', 'at least 12'],
    ['password1234', 'common'],
    ['abcdefghijkl', 'sequential'],
    ['x1234567890Zq', 'sequential'],
    ['aaaaaaaaaaaaaa', 'sequential'],
    ['zyxwvutsrqpo', 'sequential'],
  ])('rejects %s', (pw, frag) => {
    const msg = checkMailboxPassword(pw);
    expect(msg).toBeTruthy();
    if (pw !== 'password1234') expect(msg).toContain(frag);
    expect(setMailboxPasswordBodySchema.safeParse({ password: pw }).success).toBe(false);
  });
  it('rejects a password equal to or containing the local part', () => {
    expect(checkMailboxPassword('info.mailbox.1', 'info.mailbox.1')).toMatch(/mailbox name/);
    const r = createMailboxBodySchema.safeParse({ domainId: '3fa85f64-5717-4562-b3fc-2c963f66afa6', localPart: 'sales-team', password: 'My-sales-team-Pw9' });
    expect(r.success).toBe(false);
  });
  it('accepts a strong password', () => {
    expect(checkMailboxPassword('Zx9!correct-horse-battery', 'info')).toBeNull();
    expect(setMailboxPasswordBodySchema.safeParse({ password: 'another long secret 99' }).success).toBe(true);
  });
});
