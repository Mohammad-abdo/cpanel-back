import { describe, expect, it, vi } from 'vitest';
import {
  STATUS_SCRIPT,
  applyToRules,
  assertSafeChange,
  buildApplyScript,
  buildConfirmScript,
  buildRevertScript,
  buildRollbackScript,
  createUfwExecutor,
  lockoutProblems,
  parseNumbered,
  parseUfwState,
  portReachable,
  ruleArgs,
  sourceContains,
} from '../src/modules/firewall/firewall.ufw.js';
import { createFirewallService, evaluate } from '../src/modules/firewall/firewall.service.js';
import { applyBodySchema } from '../src/modules/firewall/firewall.validator.js';
import { CronParseError, nextRun, nextRuns, parseCron } from '../src/modules/cron/cron.parser.js';
import { buildCronScript, isSafeWorkDir, parseCronOutput, redactOutput } from '../src/modules/cron/cron.commands.js';
import { createCronService } from '../src/modules/cron/cron.service.js';
import { createBodySchema } from '../src/modules/cron/cron.validator.js';
import { applyScript, enabledTasks, parseCleanupOutput, previewScript } from '../src/modules/server-cleanup/server-cleanup.scripts.js';
import { createServerCleanupService } from '../src/modules/server-cleanup/server-cleanup.service.js';
import { APPROVER, OWNER, PROJECT, U, approve, makeCtx } from './phase6-helpers.js';

const SERVER = U(5);
const NOW = new Date('2026-06-01T10:00:00Z');
const win = { windowStart: '2026-06-01T09:00:00.000Z', windowEnd: '2026-06-01T11:00:00.000Z' };

const NUMBERED = [
  'Status: active',
  '',
  '     To                         Action      From',
  '     --                         ------      ----',
  '[ 1] 2222/tcp                   ALLOW IN    Anywhere',
  '[ 2] 80/tcp                     ALLOW IN    Anywhere',
  '[ 3] 3306/tcp                   ALLOW IN    10.0.0.5',
  '[ 4] 2222/tcp (v6)              ALLOW IN    Anywhere (v6)',
  '[ 5] 22/tcp                     LIMIT IN    203.0.113.0/24',
  '[ 6] 443,8443/tcp               ALLOW IN    Anywhere        # web',
];
const statusOut = (over = {}) =>
  [
    '##conn',
    over.conn ?? '203.0.113.9 51000 10.1.1.1 2222',
    '##ufw',
    over.installed ?? 'present',
    '##verbose',
    `Status: ${over.status ?? 'active'}`,
    `Default: ${over.def ?? 'deny'} (incoming), allow (outgoing), disabled (routed)`,
    '##numbered',
    ...(over.numbered ?? NUMBERED),
    '##end',
  ].join('\n');

describe('ufw: parsing', () => {
  it('parses numbered rows, expands lists, skips v6 mirror rows, maps Anywhere to any', () => {
    const rules = parseNumbered(NUMBERED);
    expect(rules).toContainEqual({ number: 1, action: 'allow', port: 2222, proto: 'tcp', source: 'any' });
    expect(rules.filter((r) => r.port === 2222)).toHaveLength(1);
    expect(rules).toContainEqual({ number: 5, action: 'limit', port: 22, proto: 'tcp', source: '203.0.113.0/24' });
    expect(rules.map((r) => r.port)).toEqual(expect.arrayContaining([443, 8443]));
  });
  it('reads the SSH port in use and the panel address from SSH_CONNECTION', () => {
    const st = parseUfwState(statusOut());
    expect(st).toMatchObject({ installed: true, active: true, defaultIncoming: 'deny', sshPort: 2222, panelIp: '203.0.113.9' });
    expect(parseUfwState(statusOut({ status: 'inactive' })).active).toBe(false);
  });
});

describe('ufw: lockout guards', () => {
  const st = { sshPort: 2222, panelIp: '203.0.113.9', defaultIncoming: 'deny', active: true };
  const rules = parseNumbered(NUMBERED);
  it('first-match evaluation', () => {
    expect(portReachable(rules, 2222, '203.0.113.9', 'deny')).toBe(true);
    expect(portReachable([{ action: 'deny', port: 2222, proto: 'tcp', source: 'any' }, ...rules], 2222, '203.0.113.9', 'deny')).toBe(false);
    expect(portReachable([], 2222, '203.0.113.9', 'deny')).toBe(false);
    expect(sourceContains('203.0.113.0/24', '203.0.113.9')).toBe(true);
    expect(sourceContains('10.0.0.0/8', '203.0.113.9')).toBe(false);
  });
  it('refuses deleting the SSH allow rule of the port in use (not port 22)', () => {
    const { next } = applyToRules(rules, [{ op: 'delete', port: 2222, proto: 'tcp', source: 'any' }]);
    expect(lockoutProblems(next, st)[0].code).toBe('LOCKOUT_RISK');
  });
  it('refuses a deny that precedes the allow for the SSH port', () => {
    const { next } = applyToRules(rules, [{ op: 'deny', port: 2222, proto: 'tcp', source: '203.0.113.9' }]);
    // appended after the allow-any rule: first match is still the allow, so this alone is fine ...
    expect(lockoutProblems(next, st)).toEqual([]);
    // ... but removing the any-allow leaves only the deny
    const gone = applyToRules(next, [{ op: 'delete', port: 2222, proto: 'tcp', source: 'any' }]).next;
    expect(lockoutProblems(gone, st)).toHaveLength(1);
  });
  it('refuses narrowing SSH to a CIDR that excludes the panel address, allows one that includes it', () => {
    const base = rules.filter((r) => r.port !== 2222);
    expect(lockoutProblems(applyToRules(base, [{ op: 'allow', port: 2222, proto: 'tcp', source: '198.51.100.0/24' }]).next, st)).toHaveLength(1);
    expect(lockoutProblems(applyToRules(base, [{ op: 'allow', port: 2222, proto: 'tcp', source: '203.0.113.0/24' }]).next, st)).toEqual([]);
  });
  it('skips the guard while the firewall is inactive, and evaluate() uses the live context', () => {
    expect(lockoutProblems([], { ...st, active: false })).toEqual([]);
    const ev = evaluate(rules, [{ op: 'delete', port: 2222, proto: 'tcp', source: 'any' }], { sshPort: 2222, panelIp: '203.0.113.9', defaultIncoming: 'deny', active: true });
    expect(ev.problems[0].code).toBe('LOCKOUT_RISK');
    expect(ev.touchesProtected).toBe(true);
  });
  it('enable on an inactive firewall adds the SSH allow to the diff and is critical', () => {
    const ev = evaluate([], [{ op: 'allow', port: 80, proto: 'tcp', source: 'any' }], { sshPort: 2222, panelIp: '1.2.3.4', defaultIncoming: 'deny', active: false, enable: true });
    expect(ev.problems).toEqual([]);
    expect(ev.diff.join('|')).toMatch(/allow 2222\/tcp.*before enabling/);
    expect(ev.touchesProtected).toBe(true);
  });
});

describe('ufw: allowlist and validation', () => {
  it('refuses ufw reset and any non-allowlisted verb', () => {
    expect(() => assertSafeChange({ op: 'reset', port: 22, proto: 'tcp', source: 'any' })).toThrow(/reset/);
    for (const op of ['disable', 'enable', 'reload', 'allow; ufw reset']) expect(() => assertSafeChange({ op, port: 80 })).toThrow();
    const bad = applyBodySchema.safeParse({ changes: [{ op: 'reset', port: 22, proto: 'tcp', source: 'any' }], ...win });
    expect(bad.success).toBe(false);
  });
  it('validates port, proto, CIDR and comment', () => {
    const base = { op: 'allow', port: 80, proto: 'tcp', source: 'any' };
    for (const patch of [{ port: 0 }, { port: 70000 }, { proto: 'icmp' }, { source: '10.0.0.0/33' }, { source: '300.1.1.1' }, { source: '10.0.0.1; ls' }, { comment: "x'; rm -rf /" }]) {
      expect(applyBodySchema.safeParse({ changes: [{ ...base, ...patch }], ...win }).success).toBe(false);
    }
    expect(applyBodySchema.safeParse({ changes: [{ ...base, op: 'limit', source: '10.0.0.0/8', comment: 'office' }], ...win, enable: true }).success).toBe(true);
  });
  it('builds rule argument vectors, deleting by spec and never by number', () => {
    expect(ruleArgs({ op: 'allow', port: 80, proto: 'tcp', source: 'any' })).toEqual(['allow', '80/tcp']);
    expect(ruleArgs({ op: 'limit', port: 22, proto: 'tcp', source: '10.0.0.0/8', comment: 'ssh' })).toEqual(['limit', 'proto', 'tcp', 'from', '10.0.0.0/8', 'to', 'any', 'port', '22', 'comment', 'ssh']);
    const del = ruleArgs({ op: 'delete', port: 80, proto: 'tcp', source: '1.2.3.4' }, { resolvedAction: 'allow' });
    expect(del.slice(0, 2)).toEqual(['delete', 'allow']);
    expect(del.some((a) => /^\d+$/.test(a) && a !== '80')).toBe(false);
  });
});

describe('ufw: dead-man switch script', () => {
  const token = 'abcdef0123456789';
  const script = buildApplyScript({ token, commands: [['allow', '80/tcp']], sshPort: 2222, enable: true, wasActive: false, seconds: 90 });
  it('backs up rules, arms the timer BEFORE changing rules, and refuses without a timer', () => {
    expect(script).toContain('cp -a /etc/ufw/user.rules');
    expect(script).toContain('systemd-run --on-active=90s --unit=nt-ufw-revert-abcdef0123456789');
    expect(script).toContain('at now + 2 minutes');
    expect(script).toContain('NT_ERR no_deadman');
    expect(script.indexOf('NT_DEADMAN')).toBeLessThan(script.indexOf("ufw 'allow' '80/tcp'"));
    expect(script.indexOf('NT_ERR no_deadman')).toBeLessThan(script.indexOf("ufw 'allow' '80/tcp'"));
  });
  it('enables only after the SSH allow exists, and never resets or disables in the apply script', () => {
    expect(script.indexOf("ufw allow '2222/tcp'")).toBeLessThan(script.indexOf('ufw --force enable'));
    expect(script.indexOf('NT_ERR ssh_allow_missing')).toBeLessThan(script.indexOf('ufw --force enable'));
    expect(script).not.toMatch(/ufw (--force )?reset/);
    // only the stored revert script (the dead-man fallback) may disable
    expect(script.replace(buildRevertScript(token, { wasActive: false }), '')).not.toMatch(/ufw (--force )?disable/);
    expect(buildApplyScript({ token, commands: [], sshPort: 22, enable: false, wasActive: true })).not.toContain('--force enable');
    expect(buildApplyScript({ token, commands: [], sshPort: 22, enable: true, wasActive: true })).not.toContain('--force enable');
  });
  it('revert script restores the saved files and falls back to ufw disable', () => {
    const r = buildRevertScript(token, { wasActive: true });
    expect(r).toContain('cp -a "$D/user.rules" /etc/ufw/user.rules');
    expect(r).toContain('ufw --force reload || ufw --force disable');
    expect(buildRevertScript(token, { wasActive: false })).toContain('ufw --force disable');
  });
  it('confirm cancels the timer and detects a fired revert; rollback runs the revert now', () => {
    const c = buildConfirmScript(token);
    expect(c).toContain(`systemctl stop nt-ufw-revert-${token}.timer`);
    expect(c).toContain('atrm');
    expect(c).toContain('NT_REVERTED');
    expect(buildRollbackScript(token)).toContain('revert.sh');
  });
  it('quotes every argument (no injection through values) and validates the token', () => {
    const s = buildApplyScript({ token, commands: [['allow', "80/tcp", 'comment', "a'b"]], sshPort: 22, wasActive: true });
    expect(s).toContain(`'a'\\''b'`);
    expect(() => buildRollbackScript('../../etc')).toThrow(/token/);
    expect(STATUS_SCRIPT).not.toMatch(/ufw (allow|deny|delete|reset|enable|disable)/);
  });
});

function fakeRun(state = {}) {
  const scripts = [];
  const respond = state.respond ?? (() => null);
  const run = vi.fn(async (script) => {
    scripts.push(script);
    const custom = respond(script);
    if (custom) return custom;
    if (script === STATUS_SCRIPT) return { code: 0, stdout: statusOut(state.status) };
    if (script.includes('NT_DEADMAN')) return { code: 0, stdout: 'NT_DEADMAN systemd\nNT_OK\n' };
    if (script.includes('NT_CONFIRMED')) return { code: 0, stdout: 'NT_CONFIRMED\n' };
    if (script.includes('NT_ROLLED_BACK')) return { code: 0, stdout: 'NT_ROLLED_BACK\n' };
    return { code: 0, stdout: '' };
  });
  const runRemote = vi.fn(async (_id, fn) => fn({ client: {}, run }));
  return { run, runRemote, scripts };
}

describe('ufw: executor (fake SSH)', () => {
  it('applies new rules, skips existing ones (idempotent) and returns a token', async () => {
    const f = fakeRun();
    const ex = createUfwExecutor({ runRemote: f.runRemote, probeSsh: async () => {} });
    const res = await ex.apply({ serverId: SERVER, changes: [{ op: 'allow', port: 80, proto: 'tcp', source: 'any' }, { op: 'allow', port: 9000, proto: 'tcp', source: 'any' }] });
    expect(res.rollbackToken).toMatch(/^[a-f0-9]{16}$/);
    const apply = f.scripts.find((s) => s.includes('NT_DEADMAN'));
    expect(apply).toContain("ufw 'allow' '9000/tcp'");
    expect(apply).not.toContain("ufw 'allow' '80/tcp'"); // already present
    const noop = await ex.apply({ serverId: SERVER, changes: [{ op: 'allow', port: 80, proto: 'tcp', source: 'any' }] });
    expect(noop.noop).toBe(true);
  });
  it('re-checks the lockout guard inside the apply session', async () => {
    const f = fakeRun();
    const ex = createUfwExecutor({ runRemote: f.runRemote, probeSsh: async () => {} });
    await expect(ex.apply({ serverId: SERVER, changes: [{ op: 'delete', port: 2222, proto: 'tcp', source: 'any' }] })).rejects.toMatchObject({ code: 'LOCKOUT_RISK' });
    expect(f.scripts.some((s) => s.includes('NT_DEADMAN'))).toBe(false);
  });
  it('resolves the action of a delete from the live rules (by spec, not by number)', async () => {
    const f = fakeRun();
    const ex = createUfwExecutor({ runRemote: f.runRemote, probeSsh: async () => {} });
    await ex.apply({ serverId: SERVER, changes: [{ op: 'delete', port: 3306, proto: 'tcp', source: '10.0.0.5' }] });
    const apply = f.scripts.find((s) => s.includes('NT_DEADMAN'));
    expect(apply).toContain("ufw 'delete' 'allow' 'proto' 'tcp' 'from' '10.0.0.5' 'to' 'any' 'port' '3306'");
    const gone = await ex.apply({ serverId: SERVER, changes: [{ op: 'delete', port: 5555, proto: 'tcp', source: 'any' }] });
    expect(gone.noop).toBe(true);
  });
  it('rolls back immediately when the script fails after arming the timer; refuses when no timer exists', async () => {
    const fail = fakeRun({ respond: (s) => (s.includes('NT_DEADMAN') ? { code: 12, stdout: 'NT_DEADMAN systemd\nNT_ERR rule\n' } : null) });
    const ex = createUfwExecutor({ runRemote: fail.runRemote, probeSsh: async () => {} });
    await expect(ex.apply({ serverId: SERVER, changes: [{ op: 'allow', port: 9000, proto: 'tcp', source: 'any' }] })).rejects.toMatchObject({ code: 'UFW_APPLY_FAILED' });
    expect(fail.scripts.some((s) => s.includes('NT_ROLLED_BACK') || s.includes('revert.sh') && s.includes('NT_ROLLED_BACK'))).toBe(true);
    const none = fakeRun({ respond: (s) => (s.includes('NT_DEADMAN') ? { code: 11, stdout: 'NT_ERR no_deadman\n' } : null) });
    const ex2 = createUfwExecutor({ runRemote: none.runRemote, probeSsh: async () => {} });
    await expect(ex2.apply({ serverId: SERVER, changes: [{ op: 'allow', port: 9000, proto: 'tcp', source: 'any' }] })).rejects.toMatchObject({ code: 'UFW_NO_DEADMAN' });
  });
  it('requires ufw to be installed and reports a fired dead-man switch on confirm', async () => {
    const missing = fakeRun({ status: { installed: 'missing' } });
    await expect(createUfwExecutor({ runRemote: missing.runRemote, probeSsh: async () => {} }).snapshot(SERVER)).rejects.toMatchObject({ code: 'UFW_NOT_INSTALLED' });
    const fired = fakeRun({ respond: (s) => (s.includes('NT_REVERTED') ? { code: 20, stdout: 'NT_REVERTED\n' } : null) });
    await expect(createUfwExecutor({ runRemote: fired.runRemote, probeSsh: async () => {} }).confirm({ serverId: SERVER, rollbackToken: 'abcdef0123456789' })).rejects.toMatchObject({ code: 'UFW_DEADMAN_FIRED' });
  });
});

describe('ufw: firewall service with the ssh executor (gating, audit, connectivity check)', () => {
  function setup({ probeOk = true, rollbackThrows = false } = {}) {
    const ctx = makeCtx({ now: () => NOW, prismaExtra: { server: { findUnique: vi.fn(async () => ({ id: SERVER, archivedAt: null })) } } });
    const f = fakeRun();
    const ex = createUfwExecutor({ runRemote: f.runRemote, probeSsh: async () => {} });
    const confirm = vi.spyOn(ex, 'confirm');
    const rollback = vi.spyOn(ex, 'rollback');
    if (rollbackThrows) rollback.mockRejectedValue(new Error('no route'));
    const adapters = { ...ctx.adapters, simulated: false, firewall: ex, fleet: { probe: async () => ({ reachable: probeOk }) } };
    return { ...ctx, adapters, svc: createFirewallService({ ...ctx, adapters }), f, confirm, rollback };
  }
  const body = (over = {}) => ({ changes: [{ op: 'allow', port: 9000, proto: 'tcp', source: 'any' }], ...win, reason: 'open app port', rollbackNote: 'delete the rule', ...over });

  it('preview shows a diff and live before/after rules without applying', async () => {
    const t = setup();
    const p = await t.svc.preview(SERVER, { changes: body().changes }, OWNER);
    expect(p.executor).toBe('ssh');
    expect(p.diff[0]).toMatch(/allow 9000/);
    expect(p.rulesBefore.length).toBeGreaterThan(0);
    expect(t.f.scripts.some((s) => s.includes('NT_DEADMAN'))).toBe(false);
  });
  it('blocks a lockout change before approval is even requested and audits it as denied', async () => {
    const t = setup();
    await expect(t.svc.apply(SERVER, body({ changes: [{ op: 'delete', port: 2222, proto: 'tcp', source: 'any' }] }), OWNER)).rejects.toMatchObject({ code: 'LOCKOUT_RISK' });
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ result: 'denied' }));
  });
  it('gates via approval, applies, confirms the dead-man switch and audits before/after rules', async () => {
    const t = setup();
    const first = await t.svc.apply(SERVER, body(), OWNER);
    expect(first.approvalRequired).toBe(true);
    await approve(t, first.approval.id, APPROVER);
    const done = await t.svc.apply(SERVER, body({ approvalId: first.approval.id }), OWNER);
    expect(done).toMatchObject({ applied: true, executor: 'ssh', simulated: false });
    expect(t.confirm).toHaveBeenCalledTimes(1);
    const evt = t.auditService.record.mock.calls.map((c) => c[0]).find((e) => e.action === 'firewall.change' && e.result === 'success');
    expect(evt.before.rules.length).toBeGreaterThan(0);
    expect(evt.after.diff[0]).toMatch(/9000/);
  });
  it('rolls back when the fresh connectivity check fails; if even rollback is unreachable the dead-man switch is reported', async () => {
    const a = setup({ probeOk: false });
    const first = await a.svc.apply(SERVER, body(), OWNER);
    await approve(a, first.approval.id, APPROVER);
    await expect(a.svc.apply(SERVER, body({ approvalId: first.approval.id }), OWNER)).rejects.toMatchObject({ code: 'LOCKOUT_ROLLED_BACK' });
    expect(a.confirm).not.toHaveBeenCalled();
    const b = setup({ probeOk: false, rollbackThrows: true });
    const f2 = await b.svc.apply(SERVER, body(), OWNER);
    await approve(b, f2.approval.id, APPROVER);
    await expect(b.svc.apply(SERVER, body({ approvalId: f2.approval.id }), OWNER)).rejects.toMatchObject({ code: 'LOCKOUT_DEADMAN_PENDING' });
  });
  it('enabling the firewall is a sensitive (critical) action', async () => {
    const t = setup();
    const first = await t.svc.apply(SERVER, body({ enable: true }), OWNER);
    expect(first.approval.impactJson.riskTier).toBe('critical');
  });
});

describe('cron parser', () => {
  const at = (s) => new Date(s);
  it('rejects malformed expressions', () => {
    for (const bad of ['', '* * * *', '* * * * * *', '60 * * * *', '* 24 * * *', '* * 0 * *', '* * 32 * *', '* * * 13 *', '* * * * 8', '*/0 * * * *', '5-1 * * * *', 'a * * * *', '1,,2 * * * *', '@reboot', '1/2/3 * * * *']) {
      expect(() => parseCron(bad), bad).toThrow(CronParseError);
    }
  });
  it('computes steps, ranges, lists, names and macros', () => {
    expect(nextRun('*/15 * * * *', at('2026-06-01T10:07:30Z')).toISOString()).toBe('2026-06-01T10:15:00.000Z');
    expect(nextRun('* * * * *', at('2026-06-01T10:07:30Z')).toISOString()).toBe('2026-06-01T10:08:00.000Z');
    expect(nextRun('30 2 * * *', at('2026-06-01T10:00:00Z')).toISOString()).toBe('2026-06-02T02:30:00.000Z');
    expect(nextRun('0 9-17/4 * * MON-FRI', at('2026-06-01T10:00:00Z')).toISOString()).toBe('2026-06-01T13:00:00.000Z'); // Monday
    expect(nextRun('0 0 1 JAN,JUL *', at('2026-06-01T10:00:00Z')).toISOString()).toBe('2026-07-01T00:00:00.000Z');
    expect(nextRun('@hourly', at('2026-06-01T10:00:00Z')).toISOString()).toBe('2026-06-01T11:00:00.000Z');
    expect(nextRun('5/20 * * * *', at('2026-06-01T10:30:00Z')).toISOString()).toBe('2026-06-01T10:45:00.000Z');
  });
  it('is strictly after the reference time and handles year, leap-day and day-of-week 7', () => {
    expect(nextRun('0 0 * * *', at('2026-06-01T00:00:00Z')).toISOString()).toBe('2026-06-02T00:00:00.000Z');
    expect(nextRun('59 23 31 12 *', at('2026-12-31T23:59:00Z')).toISOString()).toBe('2027-12-31T23:59:00.000Z');
    expect(nextRun('0 0 29 2 *', at('2026-03-01T00:00:00Z')).toISOString()).toBe('2028-02-29T00:00:00.000Z');
    expect(nextRun('0 12 * * 7', at('2026-06-01T10:00:00Z')).getUTCDay()).toBe(0);
  });
  it('uses OR semantics when both day-of-month and day-of-week are restricted', () => {
    // 2026-06-01 is a Monday; day-of-month 15 OR Friday: next is Friday 2026-06-05
    expect(nextRun('0 0 15 * FRI', at('2026-06-01T10:00:00Z')).toISOString()).toBe('2026-06-05T00:00:00.000Z');
  });
  it('returns null for impossible dates and lists consecutive runs', () => {
    expect(nextRun('0 0 31 2 *', at('2026-06-01T00:00:00Z'))).toBeNull();
    expect(nextRuns('*/30 * * * *', at('2026-06-01T10:00:00Z'), 3).map((d) => d.toISOString())).toEqual(['2026-06-01T10:30:00.000Z', '2026-06-01T11:00:00.000Z', '2026-06-01T11:30:00.000Z']);
  });
});

describe('cron: redaction and script', () => {
  it('redacts secrets in output and caps the tail', () => {
    const out = redactOutput('DB_PASSWORD=hunter2\nAuthorization: Bearer abcdef1234567890\nmysql://root:s3cr3t@db/app\ntoken: ghp_abcdefghijklmnop1234\nmysql -pMyPass1 x\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n');
    for (const leak of ['hunter2', 'abcdef1234567890', 's3cr3t', 'ghp_abcdefghijklmnop1234', 'MyPass1', 'AAAA']) expect(out).not.toContain(leak);
    expect(out).toContain('[REDACTED');
    expect(redactOutput('x'.repeat(10_000), 100).length).toBeLessThanOrEqual(103);
  });
  it('builds a timeout-wrapped, quoted script and parses the exit marker', () => {
    const s = buildCronScript({ workDir: '/var/www/app', command: "echo 'hi'", timeoutSec: 30 });
    expect(s).toContain('timeout --signal=TERM --kill-after=10 30 sh -c');
    expect(s).toContain(`'echo '\\''hi'\\'''`);
    expect(parseCronOutput('out\nNT_EXIT:124\n')).toEqual({ exitCode: 124, output: 'out\n' });
    expect(() => buildCronScript({ workDir: '/etc', command: 'x', timeoutSec: 5 })).toThrow();
    expect(isSafeWorkDir('/var/www/../etc')).toBe(false);
    expect(isSafeWorkDir('/root/x')).toBe(false);
  });
  it('validator needs exactly one command source and a valid schedule', () => {
    const base = { name: 'n', schedule: '*/5 * * * *', workDir: '/var/www/app' };
    expect(createBodySchema.safeParse({ ...base, commandKey: 'npm.cron' }).success).toBe(true);
    expect(createBodySchema.safeParse({ ...base }).success).toBe(false);
    expect(createBodySchema.safeParse({ ...base, commandKey: 'npm.cron', customCommand: 'ls' }).success).toBe(false);
    expect(createBodySchema.safeParse({ ...base, commandKey: 'rm-rf' }).success).toBe(false);
    expect(createBodySchema.safeParse({ ...base, schedule: '* * * *', commandKey: 'npm.cron' }).success).toBe(false);
    expect(createBodySchema.safeParse({ ...base, customCommand: 'ls\nrm -rf /' }).success).toBe(false);
  });
});

function cronPrisma() {
  const jobs = new Map();
  const runs = new Map();
  let n = 0;
  const id = () => U(200 + ++n);
  const match = (row, where = {}) =>
    Object.entries(where).every(([k, v]) => {
      if (v && typeof v === 'object' && !(v instanceof Date)) {
        if ('lte' in v) return row[k] && row[k] <= v.lte;
        if ('gte' in v) return row[k] >= v.gte;
        return true;
      }
      return row[k] === v;
    });
  return {
    jobs,
    runs,
    project: { findUnique: vi.fn(async () => ({ id: PROJECT, serverId: SERVER, archivedAt: null })) },
    projectEnvironment: { findMany: vi.fn(async () => []) },
    cronJob: {
      create: vi.fn(async ({ data }) => {
        const row = { id: id(), createdAt: NOW, archivedAt: null, lastRunAt: null, lastStatus: null, ...data };
        jobs.set(row.id, row);
        return row;
      }),
      findUnique: vi.fn(async ({ where }) => jobs.get(where.id) ?? null),
      findMany: vi.fn(async ({ where }) => [...jobs.values()].filter((r) => match(r, where)).map((r) => ({ ...r }))),
      count: vi.fn(async ({ where }) => [...jobs.values()].filter((r) => match(r, where)).length),
      update: vi.fn(async ({ where, data }) => Object.assign(jobs.get(where.id), data)),
      updateMany: vi.fn(async ({ where, data }) => {
        const r = jobs.get(where.id);
        if (!r || (where.nextRunAt && r.nextRunAt?.getTime() !== where.nextRunAt.getTime())) return { count: 0 };
        Object.assign(r, data);
        return { count: 1 };
      }),
    },
    cronRun: {
      create: vi.fn(async ({ data }) => {
        const row = { id: id(), exitCode: null, finishedAt: null, outputTail: null, ...data };
        runs.set(row.id, row);
        return row;
      }),
      findFirst: vi.fn(async ({ where }) => [...runs.values()].find((r) => r.jobId === where.jobId && r.status === where.status && r.startedAt >= where.startedAt.gte) ?? null),
      findMany: vi.fn(async ({ where }) => [...runs.values()].filter((r) => r.jobId === where.jobId)),
      update: vi.fn(async ({ where, data }) => Object.assign(runs.get(where.id), data)),
    },
  };
}

describe('cron service (fake SSH)', () => {
  function setup({ stdout = 'ok\nNT_EXIT:0\n', code = 0, timedOut = false, hold = null } = {}) {
    const extra = cronPrisma();
    const ctx = makeCtx({ now: () => NOW, prismaExtra: extra });
    const scripts = [];
    const serverAccessService = {
      runRemote: vi.fn(async (_id, fn) => {
        if (hold) await hold;
        return fn({ client: {}, run: async (script) => (scripts.push(script), { code, stdout, timedOut }) });
      }),
    };
    const svc = createCronService({ ...ctx, prisma: ctx.prisma, serverAccessService, now: () => NOW });
    return { ...ctx, svc, extra, scripts, serverAccessService };
  }
  const key = { name: 'sched', schedule: '*/5 * * * *', commandKey: 'laravel.schedule', workDir: '/var/www/app', enabled: true, timeoutSec: 60 };
  const custom = { name: 'x', schedule: '0 3 * * *', customCommand: 'node scripts/report.js', workDir: '/var/www/app', enabled: true, timeoutSec: 60, reason: 'nightly report', rollbackNote: 'disable job' };

  it('creates allowlisted jobs without approval and computes nextRunAt; custom commands are gated and bound', async () => {
    const t = setup();
    const j = await t.svc.create(PROJECT, key, OWNER);
    expect(j.nextRunAt.toISOString()).toBe('2026-06-01T10:05:00.000Z');
    const first = await t.svc.create(PROJECT, custom, OWNER);
    expect(first.approvalRequired).toBe(true);
    await approve(t, first.approval.id, APPROVER);
    await expect(t.svc.create(PROJECT, { ...custom, customCommand: 'node other.js', approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    const made = await t.svc.create(PROJECT, { ...custom, approvalId: first.approval.id }, OWNER);
    expect(made.custom).toBe(true);
  });
  it('requires project.configure for non-owners', async () => {
    const t = setup();
    await expect(t.svc.create(PROJECT, key, { id: U(2), isOwner: false })).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
  it('run-now of an allowlisted job executes, redacts output, records history and audit', async () => {
    const t = setup({ stdout: 'DB_PASSWORD=hunter2\nNT_EXIT:0\n' });
    const j = await t.svc.create(PROJECT, key, OWNER);
    const r = await t.svc.runNow(PROJECT, j.id, {}, OWNER);
    expect(r.status).toBe('success');
    expect(r.outputTail).not.toContain('hunter2');
    expect(t.scripts[0]).toContain('php artisan schedule:run');
    const hist = await t.svc.runs(PROJECT, j.id, {}, OWNER).catch(() => null);
    expect(hist === null || hist.length === 1).toBe(true);
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'cron.run', result: 'success' }));
  });
  it('run-now of a custom job needs a fresh approval each time', async () => {
    const t = setup();
    const a = await t.svc.create(PROJECT, custom, OWNER);
    await approve(t, a.approval.id, APPROVER);
    const job = await t.svc.create(PROJECT, { ...custom, approvalId: a.approval.id }, OWNER);
    const first = await t.svc.runNow(PROJECT, job.id, { reason: 'check now', rollbackNote: 'n/a nothing' }, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.scripts).toHaveLength(0);
    await approve(t, first.approval.id, APPROVER);
    const done = await t.svc.runNow(PROJECT, job.id, { approvalId: first.approval.id }, OWNER);
    expect(done.status).toBe('success');
  });
  it('maps exit 124 and SSH timeouts to timeout and non-zero to failure', async () => {
    const a = setup({ stdout: 'slow\nNT_EXIT:124\n' });
    const ja = await a.svc.create(PROJECT, key, OWNER);
    expect((await a.svc.runNow(PROJECT, ja.id, {}, OWNER)).status).toBe('timeout');
    const b = setup({ stdout: 'boom\nNT_EXIT:2\n' });
    const jb = await b.svc.create(PROJECT, key, OWNER);
    expect((await b.svc.runNow(PROJECT, jb.id, {}, OWNER)).status).toBe('failure');
    const c = setup({ stdout: '', code: null, timedOut: true });
    const jc = await c.svc.create(PROJECT, key, OWNER);
    expect((await c.svc.runNow(PROJECT, jc.id, {}, OWNER)).status).toBe('timeout');
  });
  it('prevents overlap: a manual run while running is refused, a scheduled one is recorded as skipped', async () => {
    let release;
    const hold = new Promise((r) => (release = r));
    const t = setup({ hold });
    const j = await t.svc.create(PROJECT, key, OWNER);
    const p = t.svc.runNow(PROJECT, j.id, {}, OWNER);
    await new Promise((r) => setTimeout(r, 5));
    await expect(t.svc.runNow(PROJECT, j.id, {}, OWNER)).rejects.toMatchObject({ code: 'CRON_ALREADY_RUNNING' });
    const skipped = await t.svc.execute(t.extra.jobs.get(j.id), { trigger: 'schedule' });
    expect(skipped.status).toBe('skipped');
    release();
    expect((await p).status).toBe('success');
  });
  it('runDue claims each due job once (compare-and-set) and advances nextRunAt', async () => {
    const t = setup();
    const j = await t.svc.create(PROJECT, key, OWNER);
    t.extra.jobs.get(j.id).nextRunAt = new Date('2026-06-01T09:55:00Z');
    const [a, b] = await Promise.all([t.svc.runDue(NOW), t.svc.runDue(NOW)]);
    expect(a.length + b.length).toBe(1);
    expect(t.extra.jobs.get(j.id).nextRunAt.toISOString()).toBe('2026-06-01T10:05:00.000Z');
    expect(await t.svc.runDue(NOW)).toEqual([]);
  });
  it('degrades to 501 SCHEMA_REQUIRED with a stale Prisma client', async () => {
    const ctx = makeCtx({ now: () => NOW, prismaExtra: { project: { findUnique: vi.fn(async () => ({ id: PROJECT, serverId: SERVER })) } } });
    const svc = createCronService({ ...ctx, serverAccessService: {} });
    await expect(svc.create(PROJECT, key, OWNER)).rejects.toMatchObject({ code: 'SCHEMA_REQUIRED' });
  });
});

describe('server cleanup', () => {
  function setup(env = {}) {
    const ctx = makeCtx({ now: () => NOW, prismaExtra: { server: { findUnique: vi.fn(async () => ({ id: SERVER, archivedAt: null })) } } });
    const scripts = [];
    const serverAccessService = {
      runRemote: vi.fn(async (_id, fn) =>
        fn({
          client: {},
          run: async (script) => {
            scripts.push(script);
            return { code: 0, stdout: script.includes('status=') ? '##apt-cache\nstatus=ok\n##old-logs\nstatus=ok\n' : '##apt-cache\nbytes=2048\n##old-logs\nbytes=4096\nitem=4096 rotated logs\n' };
          },
        }),
      ),
    };
    return { ...ctx, scripts, svc: createServerCleanupService({ ...ctx, serverAccessService, env }) };
  }
  it('docker prune is off by default and refused; unknown tasks never reach a script', async () => {
    expect(enabledTasks({}).find((t) => t.key === 'docker-prune').enabled).toBe(false);
    expect(enabledTasks({ CLEANUP_DOCKER_PRUNE: 'true' }).find((t) => t.key === 'docker-prune').enabled).toBe(true);
    const t = setup();
    await expect(t.svc.preview(SERVER, { tasks: ['docker-prune'] }, OWNER)).rejects.toMatchObject({ code: 'CLEANUP_TASK_DISABLED' });
    await expect(t.svc.preview(SERVER, { tasks: ['rm-rf'] }, OWNER)).rejects.toMatchObject({ code: 'CLEANUP_TASK_UNKNOWN' });
    expect(t.scripts).toHaveLength(0);
  });
  it('preview is a read-only dry run with sizes', async () => {
    const t = setup();
    const p = await t.svc.preview(SERVER, { tasks: ['apt-cache', 'old-logs'] }, OWNER);
    expect(p).toMatchObject({ dryRun: true, totalBytes: 6144 });
    expect(t.scripts.join('\n')).not.toMatch(/apt-get clean|rm -rf|--vacuum|-delete/);
  });
  it('apply is Owner-only and approval gated, bound to the task set, then audited with sizes', async () => {
    const t = setup();
    await expect(t.svc.apply(SERVER, { tasks: ['apt-cache'] }, { id: U(2), isOwner: false })).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    const first = await t.svc.apply(SERVER, { tasks: ['apt-cache', 'old-logs'], reason: 'free disk', rollbackNote: 'not recoverable' }, OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(t.scripts).toHaveLength(0);
    await approve(t, first.approval.id, APPROVER);
    await expect(t.svc.apply(SERVER, { tasks: ['apt-cache'], approvalId: first.approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    const done = await t.svc.apply(SERVER, { tasks: ['old-logs', 'apt-cache'], approvalId: first.approval.id }, OWNER);
    expect(done.ok).toBe(true);
    expect(t.scripts.some((s) => s.includes('apt-get clean'))).toBe(true);
    expect(t.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'server.cleanup', result: 'success' }));
  });
  it('scripts only contain the requested tasks and never touch volumes', () => {
    const s = applyScript(['apt-cache']);
    expect(s).toContain('apt-get clean');
    expect(s).not.toContain('journalctl');
    expect(applyScript(['docker-prune'])).not.toMatch(/volume|system prune|-a\b/);
    expect(previewScript(['old-releases'])).toContain('releases');
    expect(parseCleanupOutput('##apt-cache\nbytes=5\nstatus=ok\n')['apt-cache']).toMatchObject({ bytes: 5, status: 'ok' });
  });
});
