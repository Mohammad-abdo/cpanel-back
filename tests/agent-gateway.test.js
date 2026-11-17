import { describe, expect, it, vi } from 'vitest';
import * as apiProto from '../src/modules/agent-gateway/agent-gateway.protocol.js';
import * as agentProto from '../../../agents/exec-agent/src/protocol.js';
import { resolveInJail } from '../../../agents/exec-agent/src/jail.js';
import { planCommand } from '../../../agents/exec-agent/src/commands.js';
import { createCommandHandler } from '../../../agents/exec-agent/src/agent.js';
import { verifyUpdateManifest } from '../../../agents/exec-agent/src/update.js';
import { createAgentGatewayService } from '../src/modules/agent-gateway/agent-gateway.service.js';
import { createAgentsService } from '../src/modules/agents/agents.service.js';
import { createHub, attachAgentGateway } from '../src/modules/agent-gateway/agent-gateway.hub.js';
import { parseRecoverOutput } from '../src/modules/agent-gateway/agent-gateway.recover.js';
import { sendCommandBodySchema, COMMAND_ARGS } from '../src/modules/agent-gateway/agent-gateway.validator.js';
import { createQueueDriver, createBullmqDriver, parseQueueConfig } from '../../worker/src/queue-driver.js';

const SECRET = 'x'.repeat(40);
const AID = '11111111-1111-4111-8111-111111111111';
const SID = '22222222-2222-4222-8222-222222222222';
const keys = () => apiProto.deriveAgentKeys(SECRET, AID, 1);
const env = (over = {}) => apiProto.signEnvelope({ signKey: keys().signKey, agentId: AID, commandId: 'c1', type: 'stats', args: {}, ...over });

describe('envelope signing and verification', () => {
  const opts = (o = {}) => ({ signKey: keys().signKey, agentId: AID, replay: new agentProto.ReplayCache(), ...o });

  it('API-signed envelopes verify in the agent copy (interop)', () => {
    expect(agentProto.verifyEnvelope(env(), opts()).type).toBe('stats');
  });
  it('rejects tampered args, type, agent and signature', () => {
    const e = env({ type: 'file.list', args: { path: '/var/www' } });
    expect(() => agentProto.verifyEnvelope({ ...e, args: { path: '/etc' } }, opts())).toThrow(/signature|hash/i);
    expect(() => agentProto.verifyEnvelope({ ...e, type: 'stats' }, opts())).toThrow();
    expect(() => agentProto.verifyEnvelope({ ...e, sig: 'AAAA' }, opts())).toThrow(/signature/i);
    expect(() => agentProto.verifyEnvelope(e, opts({ agentId: 'other' }))).toThrow(/another agent/i);
  });
  it('rejects a signature made with another agent key (stolen socket token cannot sign)', () => {
    const forged = apiProto.signEnvelope({ signKey: Buffer.alloc(32, 7), agentId: AID, commandId: 'c1', type: 'stats' });
    expect(() => agentProto.verifyEnvelope(forged, opts())).toThrow(/signature/i);
  });
  it('rejects expired and over-long envelopes', () => {
    const old = env({ now: Date.now() - 120_000, ttlMs: 60_000 });
    expect(() => agentProto.verifyEnvelope(old, opts())).toThrow(/expired/i);
    expect(() => apiProto.signEnvelope({ signKey: keys().signKey, agentId: AID, commandId: 'c', type: 'stats', ttlMs: 3_600_000 })).toThrow();
  });
  it('rejects replay of the same envelope', () => {
    const o = opts();
    const e = env();
    agentProto.verifyEnvelope(e, o);
    expect(() => agentProto.verifyEnvelope(e, o)).toThrow(/replay/i);
  });
  it('signed results verify only with the matching key', () => {
    const r = agentProto.signResult({ signKey: keys().signKey, agentId: AID, commandId: 'c1', result: { ok: true } });
    expect(apiProto.verifyResult(r, { signKey: keys().signKey, agentId: AID })).toBe(true);
    expect(apiProto.verifyResult({ ...r, result: { ok: false } }, { signKey: keys().signKey, agentId: AID })).toBe(false);
  });
});

describe('secret field encryption', () => {
  it('round trips and is bound to the command and field', () => {
    const k = keys().encKey;
    const f = apiProto.encryptField(k, 'p@ss word', 'c1:passwordEnc');
    expect(JSON.stringify(f)).not.toContain('p@ss');
    expect(agentProto.decryptField(k, f, 'c1:passwordEnc')).toBe('p@ss word');
    expect(() => agentProto.decryptField(k, f, 'c2:passwordEnc')).toThrow();
    expect(() => agentProto.decryptField(Buffer.alloc(32, 1), f, 'c1:passwordEnc')).toThrow();
  });
});

describe('path jail', () => {
  const roots = ['/var/www', '/var/backups/nodeteam'];
  const fsImpl = { realpathSync: (p) => (p.includes('escape') ? '/etc/passwd' : p) };
  it('allows paths inside the roots', () => {
    expect(resolveInJail('/var/www/app/index.js', roots, { fsImpl })).toBe('/var/www/app/index.js');
  });
  it.each(['/var/www/../../etc/passwd', '/var/wwwx/app', '/etc/passwd', 'relative/path', '/var/www/a\\..\\b', '/var/www/\0x', '/'])('rejects %j', (p) => {
    expect(() => resolveInJail(p, roots, { fsImpl })).toThrow();
  });
  it('rejects a symlink that resolves outside the jail', () => {
    expect(() => resolveInJail('/var/www/escape', roots, { fsImpl })).toThrow(/outside/);
  });
  it('fails closed with no roots and refuses a filesystem-root jail', () => {
    expect(() => resolveInJail('/var/www', [], { fsImpl })).toThrow();
    expect(() => resolveInJail('/var/www', ['/'], { fsImpl })).toThrow();
  });
});

describe('typed command allowlist', () => {
  const ctx = { config: { jailRoots: ['/var/www'], serviceAllowlist: ['nginx.service'], cronJobs: { nightly: ['/usr/local/bin/n.sh'] } } };
  const plan = (t, a) => planCommand(t, a, { ...ctx, config: { ...ctx.config } });
  it('rejects unknown command types (including inherited names)', () => {
    for (const t of ['bash', 'exec', 'shell', 'constructor', '__proto__', 'toString']) expect(() => plan(t, {})).toThrow(/Unknown command/);
  });
  it('rejects shell metacharacters and extra args', () => {
    for (const name of ['app; rm -rf /', 'a|b', '$(id)', 'a b', '`x`', 'a&&b', "a'b", 'a\nb']) {
      expect(() => plan('pm2.control', { action: 'restart', name })).toThrow();
    }
    expect(() => plan('stats', { extra: 1 })).toThrow(/Unknown argument/);
    expect(() => plan('deploy.step', { step: 'git_checkout', dir: '/var/www/app', ref: 'main;id' })).toThrow();
    expect(() => plan('deploy.step', { step: 'npm_script', dir: '/var/www/app', script: 'build && id' })).toThrow();
    expect(() => plan('ufw', { action: 'allow', port: 22, from: '1.2.3.4; reboot' })).toThrow();
  });
  it('builds argv without a shell and keeps elevated work on the sudo path', () => {
    const p = plan('ufw', { action: 'allow', port: 8080, proto: 'tcp' }).plan;
    expect(p).toMatchObject({ file: 'ufw', argv: ['allow', '8080/tcp'], elevated: true });
    expect(plan('pm2.control', { action: 'restart', name: 'api' }).plan).toMatchObject({ file: 'pm2', argv: ['restart', 'api'] });
  });
  it('enforces the service allowlist and cron job definitions', () => {
    expect(plan('service.restart', { unit: 'nginx.service' }).plan.elevated).toBe(true);
    expect(() => plan('service.restart', { unit: 'sshd.service' })).toThrow(/allowlist/);
    expect(() => plan('cron.run', { job: 'unknown' })).toThrow(/not defined/);
    expect(plan('cron.run', { job: 'nightly' }).plan.file).toBe('/usr/local/bin/n.sh');
  });
  it('confines deploy dir and denies secret files for file.read', () => {
    expect(() => plan('deploy.step', { step: 'npm_ci', dir: '/etc' })).toThrow();
    expect(() => plan('file.list', { path: '/var/www/../etc' })).toThrow();
  });
  it('API validator mirrors the allowlist', () => {
    expect(sendCommandBodySchema.safeParse({ type: 'bash', args: {} }).success).toBe(false);
    expect(COMMAND_ARGS['pm2.control'].safeParse({ action: 'restart', name: 'a;b' }).success).toBe(false);
    expect(COMMAND_ARGS['pm2.control'].safeParse({ action: 'restart', name: 'api', extra: 1 }).success).toBe(false);
  });
});

describe('agent command handler', () => {
  const credentials = { agentId: AID, ...keys() };
  const mk = (extra = {}) => createCommandHandler({ credentials, config: { jailRoots: ['/var/www'], serviceAllowlist: [], cronJobs: {}, terminalAllowed: false }, execImpl: vi.fn().mockResolvedValue({ ok: true, exitCode: 0, data: { fine: true } }), ...extra });
  it('executes verified commands and returns a signed result', async () => {
    const h = mk();
    const res = await h(env());
    expect(res.result.ok).toBe(true);
    expect(apiProto.verifyResult(res, { signKey: keys().signKey, agentId: AID })).toBe(true);
  });
  it('refuses replays, bad signatures and unknown types without executing', async () => {
    const execImpl = vi.fn().mockResolvedValue({ ok: true });
    const h = mk({ execImpl });
    const e = env();
    await h(e);
    expect((await h(e)).result.error).toBe('ENVELOPE_REPLAY');
    expect((await h({ ...env({ commandId: 'c2' }), sig: 'bad' })).result.error).toBe('ENVELOPE_BAD_SIGNATURE');
    expect((await h(env({ commandId: 'c3', type: 'bash', args: { cmd: 'id' } }))).result.error).toBe('COMMAND_UNKNOWN');
    expect(execImpl).toHaveBeenCalledTimes(1);
  });
  it('keeps the terminal off unless the host allows it locally', async () => {
    const execImpl = vi.fn();
    const res = await mk({ execImpl })(env({ type: 'agent.terminal', args: { enabled: true } }));
    expect(res.result.error).toBe('TERMINAL_DISABLED');
    expect(execImpl).not.toHaveBeenCalled();
  });
});

describe('signed self-update', () => {
  it('rejects unsigned, unpinned host and malformed manifests', () => {
    const base = { version: '9.9.9', url: 'https://releases.invalid/a.tgz', sha256: 'a'.repeat(64), size: 10, sig: 'AAAA' };
    expect(() => verifyUpdateManifest(base)).toThrow(/signature/i);
    expect(() => verifyUpdateManifest({ ...base, url: 'https://evil.example/a.tgz' })).toThrow(/pinned/i);
    expect(() => verifyUpdateManifest({ ...base, url: 'http://releases.invalid/a.tgz' })).toThrow(/pinned/i);
    expect(() => verifyUpdateManifest({ version: 'x' })).toThrow(/Malformed/);
  });
});

// ---------- control plane service (fake prisma / hub) ----------
function fakeDb() {
  const agent = { id: 'a1', serverId: SID, agentPublicId: AID, certFingerprint: 'h', keyGeneration: 1, revokedAt: null };
  const commands = new Map();
  const prisma = {
    serverAgent: { findFirst: vi.fn().mockResolvedValue(agent), update: vi.fn(async ({ data }) => Object.assign(agent, data)) },
    agentCommand: {
      create: vi.fn(async ({ data }) => (commands.set(data.id, { ...data }), data)),
      findUnique: vi.fn(async ({ where }) => commands.get(where.id) ?? null),
      updateMany: vi.fn(async ({ where, data }) => {
        const c = commands.get(where.id);
        if (!c || (where.status && c.status !== where.status)) return { count: 0 };
        Object.assign(c, data);
        return { count: 1 };
      }),
      findMany: vi.fn(async () => [...commands.values()]),
    },
  };
  return { prisma, agent, commands };
}
const owner = { id: 'u1', isOwner: true };

describe('agent gateway service', () => {
  const setup = (over = {}) => {
    const db = fakeDb();
    const sent = [];
    const hub = { available: true, isConnected: () => true, send: vi.fn(async (_id, e) => sent.push(e)) };
    const auditService = { record: vi.fn() };
    const platform = over.platform ?? { gate: vi.fn().mockResolvedValue({ proceed: true }) };
    const svc = createAgentGatewayService({ prisma: db.prisma, auditService, platform, hub, env: { AGENT_CONTROL_SECRET: SECRET }, ...over.deps });
    return { ...db, sent, hub, auditService, platform, svc };
  };

  it('is Owner only and needs the control secret', async () => {
    const s = setup();
    await expect(s.svc.sendCommand(SID, { type: 'stats', args: {} }, { id: 'u2', isOwner: false })).rejects.toMatchObject({ status: 403 });
    const noSecret = createAgentGatewayService({ prisma: s.prisma, hub: s.hub, platform: s.platform, env: {} });
    await expect(noSecret.sendCommand(SID, { type: 'stats', args: {} }, owner)).rejects.toMatchObject({ code: 'CONFIG_REQUIRED' });
  });

  it('signs a verifiable envelope, stores it and audits the send', async () => {
    const s = setup();
    const out = await s.svc.sendCommand(SID, { type: 'pm2.control', args: { action: 'restart', name: 'api' } }, owner);
    expect(out.status).toBe('sent');
    expect(s.platform.gate).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent.pm2.control', resourceId: SID }), owner);
    expect(agentProto.verifyEnvelope(s.sent[0], { signKey: keys().signKey, agentId: AID, replay: new agentProto.ReplayCache() }).type).toBe('pm2.control');
    expect(s.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent.command.send' }));
  });

  it('returns the pending approval and sends nothing when the gate blocks', async () => {
    const s = setup({ platform: { gate: vi.fn().mockResolvedValue({ proceed: false, approval: { id: 'ap1' } }) } });
    const out = await s.svc.sendCommand(SID, { type: 'ufw', args: { action: 'allow', port: 80 } }, owner);
    expect(out).toMatchObject({ approvalRequired: true });
    expect(s.sent).toHaveLength(0);
  });

  it('rejects invalid args and offline agents', async () => {
    const s = setup();
    await expect(s.svc.sendCommand(SID, { type: 'pm2.control', args: { action: 'restart', name: 'a;b' } }, owner)).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
    s.hub.isConnected = () => false;
    await expect(s.svc.sendCommand(SID, { type: 'stats', args: {} }, owner)).rejects.toMatchObject({ code: 'AGENT_OFFLINE' });
  });

  it('never puts the database password in clear on the socket or in storage', async () => {
    const s = setup();
    await s.svc.sendCommand(SID, { type: 'backup.dump', args: { kind: 'mysql', database: 'app', user: 'dump', password: 'Sup3r-Secret', outPath: '/var/backups/nodeteam/a.sql' } }, owner);
    expect(JSON.stringify(s.sent[0])).not.toContain('Sup3r-Secret');
    const field = s.sent[0].args.passwordEnc;
    expect(agentProto.decryptField(keys().encKey, field, `${s.sent[0].commandId}:passwordEnc`)).toBe('Sup3r-Secret');
    expect(JSON.stringify([...s.commands.values()])).not.toContain('Sup3r-Secret');
  });

  it('records a verified result once and audits it; rejects forged results', async () => {
    const s = setup();
    const { commandId } = await s.svc.sendCommand(SID, { type: 'stats', args: {} }, owner);
    const forged = agentProto.signResult({ signKey: Buffer.alloc(32, 9), agentId: AID, commandId, result: { ok: true } });
    expect(await s.svc.recordResult(AID, forged)).toEqual({ recorded: false });
    const good = agentProto.signResult({ signKey: keys().signKey, agentId: AID, commandId, result: { ok: true, exitCode: 0 } });
    expect(await s.svc.recordResult(AID, good)).toMatchObject({ recorded: true, ok: true });
    expect(await s.svc.recordResult(AID, good)).toEqual({ recorded: false });
    expect(s.commands.get(commandId).status).toBe('succeeded');
    expect(s.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent.command.result', result: 'success' }));
  });

  it('rotation: new key travels encrypted, DB switches only after a result signed with the new key', async () => {
    const s = setup();
    const { commandId } = await s.svc.rotateCredential(SID, {}, owner);
    const e = s.sent[0];
    expect(e.type).toBe('agent.rotate');
    const newKey = agentProto.decryptField(keys().encKey, e.args.agentKeyEnc, `${commandId}:agentKeyEnc`);
    expect(s.agent.certFingerprint).toBe('h'); // not switched yet
    const oldSigned = agentProto.signResult({ signKey: keys().signKey, agentId: AID, commandId, result: { ok: true } });
    expect((await s.svc.recordResult(AID, oldSigned)).recorded).toBe(false);
    const next = apiProto.deriveAgentKeys(SECRET, AID, 2);
    expect(agentProto.decryptField(keys().encKey, e.args.signKeyEnc, `${commandId}:signKeyEnc`)).toBe(next.signKey.toString('base64url'));
    const ok = agentProto.signResult({ signKey: next.signKey, agentId: AID, commandId, result: { ok: true } });
    expect((await s.svc.recordResult(AID, ok)).recorded).toBe(true);
    expect(s.agent.keyGeneration).toBe(2);
    expect(s.agent.certFingerprint).not.toBe('h');
    expect(newKey.length).toBeGreaterThan(20);
  });

  it('terminal: enabling is approval-gated, disabling is not', async () => {
    const s = setup({ platform: { gate: vi.fn().mockResolvedValue({ proceed: false, approval: { id: 'ap' } }) } });
    expect(await s.svc.setTerminal(SID, { enabled: true }, owner)).toMatchObject({ approvalRequired: true });
    const off = await s.svc.setTerminal(SID, { enabled: false }, owner);
    expect(off.status).toBe('sent');
    expect(s.sent[0].type).toBe('agent.terminal');
  });

  it('recover: no-op when connected; gates when offline; runs SSH script via serverAccess', async () => {
    expect(parseRecoverOutput('noise\n{"ok":true,"method":"systemd","steps":[]}\n')).toMatchObject({ ok: true, method: 'systemd' });
    const connected = setup();
    expect(await connected.svc.recoverAgent(SID, {}, owner)).toMatchObject({ ok: true, alreadyConnected: true });

    const blocked = setup({
      platform: { gate: vi.fn().mockResolvedValue({ proceed: false, approval: { id: 'ap-r' } }) },
      deps: { hub: { available: true, isConnected: () => false, send: vi.fn() } },
    });
    expect(await blocked.svc.recoverAgent(SID, {}, owner)).toMatchObject({ approvalRequired: true });

    const run = vi.fn(async () => ({
      stdout: '{"ok":true,"method":"systemd","unit":"nodeteam-agent","steps":[{"step":"systemd-start","ok":true,"detail":"started"}]}\n',
      timedOut: false,
    }));
    const offline = setup({
      deps: {
        hub: { available: true, isConnected: () => false, send: vi.fn() },
        serverAccessService: { runRemote: vi.fn(async (_id, fn) => fn({ run })) },
        connectWaitMs: 0,
      },
    });
    const out = await offline.svc.recoverAgent(SID, { reason: 'bring agent back' }, owner);
    expect(out).toMatchObject({ ok: true, method: 'systemd', connected: false });
    expect(run).toHaveBeenCalled();
    expect(offline.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'agent.recover', result: 'success' }));
  });
});

describe('enrollment issues per-agent command keys', () => {
  it('returns derived keys only when the control secret is configured', async () => {
    const mkPrisma = () => {
      const t = { agentEnrollment: { updateMany: vi.fn().mockResolvedValue({ count: 1 }) }, serverAgent: { deleteMany: vi.fn(), create: vi.fn() }, server: { update: vi.fn() } };
      return { agentEnrollment: { findUnique: vi.fn().mockResolvedValue({ id: 'e', serverId: SID, usedAt: null, expiresAt: new Date(Date.now() + 9000) }) }, serverAgent: { findFirst: vi.fn().mockResolvedValue(null) }, $transaction: (fn) => fn(t) };
    };
    const withKeys = await createAgentsService({ prisma: mkPrisma(), controlSecret: SECRET }).enroll({ token: 'x'.repeat(30) });
    const derived = apiProto.deriveAgentKeys(SECRET, withKeys.agentId, 1);
    expect(withKeys.signKeyB64).toBe(derived.signKey.toString('base64url'));
    const without = await createAgentsService({ prisma: mkPrisma(), controlSecret: undefined }).enroll({ token: 'x'.repeat(30) });
    expect(without.signKeyB64).toBeUndefined();
  });
});

// ---------- hub with a fake Socket.IO ----------
function fakeIo() {
  const handlers = {};
  const mkNs = () => {
    const ns = { mw: null, onConn: null, rooms: [], use: (f) => (ns.mw = f), on: (e, f) => e === 'connection' && (ns.onConn = f), to: (r) => ({ emit: (e, p) => ns.rooms.push([r, e, p]) }) };
    return ns;
  };
  return { of: (n) => (handlers[n] ??= mkNs()), handlers };
}
const fakeSocket = (auth, extra = {}) => {
  const ev = {};
  return { handshake: { auth }, data: {}, joined: [], on: (e, f) => (ev[e] = f), emitEvent: (e, ...a) => ev[e]?.(...a), join: async function (r) { this.joined.push(r); }, leave: vi.fn(), disconnect: vi.fn(), timeout: () => ({ emit: (_e, env, cb) => cb(null, { commandId: env.commandId }) }), ...extra };
};

describe('socket hub', () => {
  const build = (over = {}) => {
    const io = fakeIo();
    const gateway = { markConnected: vi.fn().mockResolvedValue(), recordResult: vi.fn().mockResolvedValue({}) };
    const agentsService = { authenticate: vi.fn(async (h) => { if (!h.includes('goodkey')) throw new Error('no'); return { agentPublicId: AID, serverId: SID, id: 'a1' }; }) };
    const scope = { canSeeServer: vi.fn(async (_a, id) => id === SID), canSeeProject: vi.fn(async () => false) };
    const hub = createHub({ io, agentsService, gateway, scope, authenticateSession: async (t) => { if (t !== 'tok') throw new Error('x'); return { id: 'u9', isOwner: false }; }, getDeploymentProjectId: async () => 'p1', log: () => {}, ...over });
    return { io, gateway, hub, scope };
  };
  it('authenticates agents by credential and routes results; rejects bad keys', async () => {
    const { io, hub, gateway } = build();
    const ns = io.handlers['/agents'];
    const bad = vi.fn();
    await ns.mw(fakeSocket({ agentId: AID, key: 'bad' }), bad);
    expect(bad.mock.calls[0][0]).toBeInstanceOf(Error);
    const sock = fakeSocket({ agentId: AID, key: 'goodkey', version: '0.1.0' });
    await ns.mw(sock, vi.fn());
    ns.onConn(sock);
    expect(hub.isConnected(AID)).toBe(true);
    await hub.send(AID, { commandId: 'c1' });
    expect(gateway.recordResult).toHaveBeenCalledWith(AID, { commandId: 'c1' });
    sock.emitEvent('disconnect');
    expect(hub.isConnected(AID)).toBe(false);
    await expect(hub.send(AID, {})).rejects.toMatchObject({ code: 'AGENT_OFFLINE' });
  });
  it('/rt requires a session and scope-checks room subscriptions', async () => {
    const { io } = build();
    const ns = io.handlers['/rt'];
    const rejected = vi.fn();
    await ns.mw(fakeSocket({}), rejected);
    expect(rejected.mock.calls[0][0]).toBeInstanceOf(Error);
    const sock = fakeSocket({ token: 'tok' });
    await ns.mw(sock, vi.fn());
    ns.onConn(sock);
    const ack = (room) => new Promise((r) => sock.emitEvent('subscribe', { room }, r));
    expect(await ack(`server:${SID}`)).toEqual({ ok: true });
    expect((await ack('server:33333333-3333-4333-8333-333333333333')).ok).toBe(false);
    expect((await ack('deployment:44444444-4444-4444-8444-444444444444')).ok).toBe(false);
    expect((await ack('anything')).error).toBe('BAD_ROOM');
    expect(sock.joined).toEqual([`server:${SID}`]);
  });
  it('relays pm2:log and scopes pm2:logs:subscribe', async () => {
    const { io, hub } = build();
    const agentNs = io.handlers['/agents'];
    const agentSock = fakeSocket({ agentId: AID, key: 'goodkey', version: '0.1.0' });
    const emitted = [];
    agentSock.emit = (e, p) => emitted.push([e, p]);
    await agentNs.mw(agentSock, vi.fn());
    agentNs.onConn(agentSock);
    expect(hub.isConnected(AID)).toBe(true);

    const rt = io.handlers['/rt'];
    const browser = fakeSocket({ token: 'tok' });
    await rt.mw(browser, vi.fn());
    rt.onConn(browser);
    const sub = (p) => new Promise((r) => browser.emitEvent('pm2:logs:subscribe', p, r));
    expect(await sub({ serverId: SID, appName: 'web' })).toMatchObject({ ok: true, live: true });
    expect(emitted.some(([e, p]) => e === 'pm2:logs:start' && p.appName === 'web')).toBe(true);
    expect((await sub({ serverId: '33333333-3333-4333-8333-333333333333', appName: 'web' })).ok).toBe(false);
    expect((await sub({ serverId: SID, appName: '../etc' })).error).toBe('BAD_ROOM');

    agentSock.emitEvent('pm2:log', { appName: 'web', stream: 'stdout', line: 'hello' });
    expect(rt.rooms.some(([room, ev, p]) => room === `pm2:${SID}:web` && ev === 'pm2.log' && p.line === 'hello')).toBe(true);

    browser.emitEvent('pm2:logs:unsubscribe', { serverId: SID, appName: 'web' });
    expect(emitted.some(([e, p]) => e === 'pm2:logs:stop' && p.appName === 'web')).toBe(true);
  });
  it('degrades gracefully when socket.io is absent', async () => {
    const hub = await attachAgentGateway({}, {}, { importer: async () => { throw new Error('not found'); }, log: () => {} });
    expect(hub.available).toBe(false);
    expect(hub.isConnected(AID)).toBe(false);
  });
});

// ---------- queue adapter (fake bullmq, no Redis) ----------
describe('queue driver', () => {
  const jobs = [{ name: 'a.job', intervalMs: 60_000, run: vi.fn().mockResolvedValue({ n: 1 }) }, { name: 'b.job', intervalMs: 5000, run: vi.fn().mockRejectedValue(new Error('boom')) }];
  const fakeBullmq = () => {
    const state = { schedulers: [], added: [], workers: [], closed: [] };
    class Queue { constructor(n, o) { state.queue = { n, o }; } async upsertJobScheduler(...a) { state.schedulers.push(a); } add(...a) { state.added.push(a); return Promise.resolve({}); } async close() { state.closed.push('q'); } }
    class Worker { constructor(n, fn, o) { this.fn = fn; this.o = o; this.h = {}; state.workers.push(this); } on(e, f) { this.h[e] = f; } async close() { state.closed.push('w'); } }
    return { state, bullmq: { Queue, Worker } };
  };
  it('defaults to interval and needs no Redis', async () => {
    expect(parseQueueConfig({}).driver).toBe('interval');
    const d = await createQueueDriver({ jobs, env: {}, schedulerFactory: () => ({ start() {}, stop() {}, status: () => ({}) }), bullmqImporter: () => { throw new Error('must not import'); } });
    expect(d.name).toBe('interval');
    expect(() => parseQueueConfig({ QUEUE_DRIVER: 'kafka' })).toThrow();
    await expect(createQueueDriver({ jobs, env: { QUEUE_DRIVER: 'bullmq' } })).rejects.toThrow(/REDIS_URL/);
  });
  it('registers repeatable jobs with retry/backoff and concurrency, runs them, audits only exhausted failures', async () => {
    const { state, bullmq } = fakeBullmq();
    const onFailure = vi.fn().mockResolvedValue();
    const d = await createQueueDriver({ jobs, env: { QUEUE_DRIVER: 'bullmq', REDIS_URL: 'redis://x', NT_QUEUE_CONCURRENCY: '4', NT_QUEUE_ATTEMPTS: '5' }, bullmqImporter: async () => bullmq, connectionFactory: async () => ({ quit: vi.fn() }), onFailure });
    await d.start();
    expect(state.schedulers.map((s) => [s[0], s[1].every])).toEqual([['a.job', 60_000], ['b.job', 5000]]);
    expect(state.schedulers[0][2].opts).toMatchObject({ attempts: 5, backoff: { type: 'exponential' } });
    const w = state.workers[0];
    expect(w.o.concurrency).toBe(4);
    expect(await w.fn({ name: 'a.job', data: {} })).toEqual({ n: 1 });
    await expect(w.fn({ name: 'b.job', data: {} })).rejects.toThrow('boom');
    expect(d.status()['b.job'].failures).toBe(1);
    w.h.failed({ name: 'b.job', attemptsMade: 2, opts: { attempts: 5 } }, new Error('boom'));
    expect(onFailure).not.toHaveBeenCalled();
    w.h.failed({ name: 'b.job', attemptsMade: 5, opts: { attempts: 5 } }, new Error('boom'));
    expect(onFailure).toHaveBeenCalledTimes(1);
    await d.enqueueDelayed('a.job', {}, 30_000);
    expect(state.added[0][2]).toMatchObject({ delay: 30_000, attempts: 5 });
    expect(() => d.enqueueDelayed('nope')).toThrow();
    await d.stop();
    expect(state.closed).toEqual(['w', 'q']);
  });
  it('createBullmqDriver ignores unknown job names safely', async () => {
    const { state, bullmq } = fakeBullmq();
    const d = createBullmqDriver({ jobs, queueConfig: parseQueueConfig({ QUEUE_DRIVER: 'bullmq' }), bullmq, connection: {} });
    await d.start();
    expect(await state.workers[0].fn({ name: 'ghost', data: {} })).toMatchObject({ skipped: true });
  });
});
