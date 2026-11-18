import { describe, expect, it } from 'vitest';
import { createProjectProvisioningService } from '../src/modules/project-provisioning/project-provisioning.service.js';
import { createProvisioningRunRepository } from '../src/modules/project-provisioning/project-provisioning.repository.js';
import {
  APPDIR_SCRIPT, BUILD_SCRIPT, CERTBOT_APACHE_SCRIPT, CLONE_SCRIPT, DECOMMISSION_SCRIPT, ENV_SCRIPT, PM2_SCRIPT, PREFLIGHT_SCRIPT, VHOST_SCRIPT,
  evaluatePreflight, renderApacheVhost, renderEcosystem, renderEnvFile,
} from '../src/modules/project-provisioning/project-provisioning.scripts.js';
import { planSchema, secretsSchema } from '../src/modules/project-provisioning/project-provisioning.validator.js';
import { execScriptStdin } from '../src/modules/server-access/ssh.connector.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';
import { ACTION_RISK, requiresApproval } from '../src/modules/platform/platform.risk.js';
import { createFakeSsh } from './server-access-fake-ssh.js';
import { APPROVER, KEY, OWNER, U, approve, makeCtx } from './phase6-helpers.js';

const SERVER = U(5);
const SERVER_IP = '203.0.113.10';
const TOKEN = 'ghp_SuperSecretTokenValue1234567890';
const ENV_SECRET = 'db-password-xyz-9876';

const basePlan = (over = {}) => ({
  serverId: SERVER,
  name: 'Shop',
  slug: 'shop',
  repoUrl: 'https://github.com/acme/shop.git',
  branch: 'main',
  framework: 'node',
  domains: ['shop.example.com', 'www.shop.example.com'],
  ssl: true,
  dnsMode: 'manual',
  envVars: [{ key: 'DATABASE_URL', value: `mysql://u:${ENV_SECRET}@127.0.0.1/db`, isSecret: true }],
  ...over,
});
const parse = (over) => planSchema.parse(basePlan(over));

describe('provisioning validators', () => {
  it.each([
    'a.com;rm -rf /', 'a.com\nServerName evil.com', 'a.com`id`', '$(id).example.com', 'a.com && curl x', 'a b.com', 'a.com/../x', '-a.com', 'a..com', 'localhost',
  ])('rejects domain %j', (d) => {
    expect(planSchema.safeParse(basePlan({ domains: [d] })).success).toBe(false);
  });
  it('normalizes case and rejects bad repo, branch, port, slug and env values', () => {
    expect(parse({ domains: ['Shop.Example.COM'] }).domains[0]).toBe('shop.example.com');
    for (const bad of [{ repoUrl: 'ext::sh -c id' }, { repoUrl: 'file:///etc' }, { repoUrl: 'https://user:pw@github.com/a/b.git' }, { branch: '--upload-pack=x' }, { branch: 'a..b' }, { port: 80 }, { slug: 'Bad_Slug' }, { slug: 'x'.repeat(40) }, { startFile: '../../etc/passwd' }, { installCommand: 'rm -rf /' }, { buildCommand: 'curl evil | sh' }, { envVars: [{ key: 'A', value: 'x\nEVIL=1' }] }, { envVars: [{ key: 'A B', value: 'x' }] }]) {
      expect(planSchema.safeParse(basePlan(bad)).success, JSON.stringify(bad)).toBe(false);
    }
  });
  it('accepts only one git secret and validates its shape', () => {
    expect(secretsSchema.safeParse({ gitToken: TOKEN }).success).toBe(true);
    expect(secretsSchema.safeParse({ gitToken: 'x y' }).success).toBe(false);
    expect(secretsSchema.safeParse({ gitToken: TOKEN, deployKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n' }).success).toBe(false);
  });
  it('registers the new risk entries as High', () => {
    for (const a of ['project.provision', 'project.decommission', 'apache.vhost.apply', 'certbot.issue']) {
      expect(ACTION_RISK[a]).toBe('high');
      expect(requiresApproval(a)).toBe(true);
    }
  });
});

describe('vhost / ecosystem / env generators', () => {
  it('renders a proxy vhost with websocket upgrade, headers and aliases', () => {
    const t = renderApacheVhost({ domains: ['shop.example.com', 'www.shop.example.com'], port: 21001 });
    expect(t).toContain('ServerName shop.example.com');
    expect(t).toContain('ServerAlias www.shop.example.com');
    expect(t).toContain('ProxyPass / http://127.0.0.1:21001/');
    expect(t).toContain('ws://127.0.0.1:21001/$1');
    expect(t).toContain('X-Content-Type-Options');
    expect(t).not.toContain('Strict-Transport-Security');
  });
  it('renders static (FallbackResource) and tls variants', () => {
    const s = renderApacheVhost({ domains: ['a.example.com'], docRoot: '/var/www/site/app/dist' });
    expect(s).toContain('FallbackResource /index.html');
    expect(s).toContain('DocumentRoot /var/www/site/app/dist');
    const tls = renderApacheVhost({ domains: ['a.example.com'], port: 21002, tls: true });
    expect(tls).toContain('<VirtualHost *:443>');
    expect(tls).toContain('/etc/letsencrypt/live/a.example.com/fullchain.pem');
    expect(tls).toContain('Strict-Transport-Security');
  });
  it('refuses injection in domains, ports and doc roots at render time too', () => {
    for (const d of ['a.com;rm -rf /', 'a.com\nRewriteRule x', 'a.com`id`', 'a.com\r\n<Directory />']) {
      expect(() => renderApacheVhost({ domains: [d], port: 21001 })).toThrow();
    }
    expect(() => renderApacheVhost({ domains: ['a.com'], port: '21001; x' })).toThrow();
    expect(() => renderApacheVhost({ domains: ['a.com'], docRoot: '/etc/../passwd' })).toThrow();
    expect(() => renderApacheVhost({ domains: ['a.com'], docRoot: '/var/www/x\nEvil' })).toThrow();
  });
  it('ecosystem holds no secrets and the env file escapes values', () => {
    const eco = renderEcosystem({ name: 'nt-shop', appDir: '/var/www/shop', port: 21001 });
    expect(eco).toContain('"nt-shop"');
    expect(eco).toContain('app/.env');
    expect(eco).not.toContain(ENV_SECRET);
    expect(() => renderEcosystem({ name: 'nt-shop"; evil', appDir: '/var/www/shop', port: 21001 })).toThrow();
    const env = renderEnvFile([{ key: 'A', value: 'he said "hi" $(id) `x`' }]);
    expect(env).toBe('A="he said \\"hi\\" $(id) `x`"\n');
    expect(() => renderEnvFile([{ key: 'A', value: 'x\nB=1' }])).toThrow();
  });
  it('vhost script runs configtest before reload and reverts on failure; secrets stay out of script text', () => {
    expect(VHOST_SCRIPT.indexOf('configtest')).toBeGreaterThan(-1);
    expect(VHOST_SCRIPT.indexOf('configtest')).toBeLessThan(VHOST_SCRIPT.indexOf('systemctl reload'));
    expect(VHOST_SCRIPT).toContain('NT_REVERTED=1');
    for (const s of [PREFLIGHT_SCRIPT, APPDIR_SCRIPT, CLONE_SCRIPT, ENV_SCRIPT, BUILD_SCRIPT, PM2_SCRIPT, VHOST_SCRIPT, CERTBOT_APACHE_SCRIPT, DECOMMISSION_SCRIPT]) {
      expect(s).not.toContain(TOKEN);
      expect(s).not.toMatch(/\$\{?(DOMAIN|URL)\}?[^"A-Za-z]*;\s*rm/);
    }
    expect(CLONE_SCRIPT).toContain('cat > "$TMP/secret"');
    expect(CERTBOT_APACHE_SCRIPT).toContain('--non-interactive --agree-tos');
  });
  it('evaluates preflight output', () => {
    const good = { SUDO: 'ok', APACHE: 'apache2', LAYOUT: 'debian', MODS_MISSING: '', CERTBOT: 'certbot 2', CERTBOT_APACHE: 'yes', NODE: 'v20', PM2: '5', GIT: 'git', PORT: '21000', DISK_MB: '9000' };
    expect(evaluatePreflight(good).ok).toBe(true);
    const bad = evaluatePreflight({ ...good, APACHE: 'httpd', MODS_MISSING: 'proxy_wstunnel_module', PM2: '', PORT: '0' });
    expect(bad.ok).toBe(false);
    expect(bad.blockers.length).toBeGreaterThanOrEqual(3);
  });
});

// ------------------------------------------------------------------------------------------------ service with fake prisma + fake SSH
const SCRIPTS = new Map([
  [PREFLIGHT_SCRIPT, 'preflight'], [APPDIR_SCRIPT, 'app_dir'], [CLONE_SCRIPT, 'clone'], [ENV_SCRIPT, 'env'], [BUILD_SCRIPT, 'build'], [PM2_SCRIPT, 'pm2'],
  [VHOST_SCRIPT, 'vhost'], [CERTBOT_APACHE_SCRIPT, 'ssl'], [DECOMMISSION_SCRIPT, 'decommission'],
]);
const shq = (cmd) => {
  const tail = cmd.slice(cmd.indexOf('nt-script') + 'nt-script'.length);
  return [...tail.matchAll(/'((?:[^']|'\\'')*)'/g)].map((m) => m[1].replace(/'\\''/g, "'"));
};
const GOOD_KV = 'NT_OS=Debian\nNT_APACHE=apache2\nNT_LAYOUT=debian\nNT_MODS_MISSING=\nNT_CERTBOT=certbot 2.1\nNT_CERTBOT_APACHE=yes\nNT_NODE=v20\nNT_PM2=5.3\nNT_GIT=git version 2.4\nNT_SUDO=ok\nNT_PORT=21003\nNT_DISK_MB=8000\n';
const PKG = Buffer.from(JSON.stringify({ scripts: { start: 'node server.js', build: 'echo build' }, dependencies: { express: '4' } })).toString('base64');

function table(unique = []) {
  const rows = new Map();
  let n = 0;
  const match = (row, where = {}) => Object.entries(where).every(([k, v]) => (v && typeof v === 'object' && 'not' in v ? row[k] !== v.not : row[k] === v));
  return {
    rows,
    findUnique: async ({ where }) => [...rows.values()].find((r) => Object.entries(where).every(([k, v]) => r[k] === v)) ?? null,
    findFirst: async ({ where }) => [...rows.values()].find((r) => match(r, where)) ?? null,
    findMany: async ({ where } = {}) => [...rows.values()].filter((r) => match(r, where)),
    create: async ({ data }) => { const row = { id: U(200 + ++n + rows.size), createdAt: new Date(), ...data }; rows.set(row.id, row); return row; },
    update: async ({ where, data }) => { const row = [...rows.values()].find((r) => Object.entries(where).every(([k, v]) => r[k] === v)); Object.assign(row, data); return row; },
  };
}

function setup({ executor = 'ssh', respond = () => null, env = {}, resolveIps = [], fetchStatus = 200 } = {}) {
  const ctx = makeCtx();
  const t = { server: table(), serverCredential: table(), project: table(), projectEnvironment: table(), projectEnvVar: table(), projectRuntime: table(), projectRepository: table(), domain: table(), sslCertificate: table(), deployment: table() };
  Object.assign(ctx.prisma, t);
  t.server.rows.set(SERVER, { id: SERVER, alias: 'prod-vps', archivedAt: null });
  t.serverCredential.rows.set('c1', { id: 'c1', serverId: SERVER, host: SERVER_IP, port: 22, username: 'root', secretEnc: encrypt('pw', KEY) });
  const calls = [];
  // The shared fake invokes respond twice per bash -c exec; answer once per exec.
  let execId = 0;
  let lastId = -1;
  let lastResp = null;
  const fake = createFakeSsh({
    respond: (input) => {
      if (lastId === execId) return lastResp;
      lastId = execId;
      lastResp = answer(input);
      return lastResp;
    },
  });
  function answer({ command }) {
    {
      const b64 = /printf %s '([A-Za-z0-9+/=]+)'/.exec(command)?.[1];
      const script = b64 ? Buffer.from(b64, 'base64').toString('utf8') : '';
      const step = SCRIPTS.get(script) ?? 'unknown';
      const entry = { step, args: shq(command), command };
      calls.push(entry);
      const custom = respond({ step, args: entry.args, calls });
      if (custom) return custom;
      return {
        preflight: { stdout: GOOD_KV },
        app_dir: { stdout: 'NT_APPDIR=/var/www/shop\n' },
        clone: { stdout: `NT_SHA=${'a'.repeat(40)}\nNT_PKG_B64=${PKG}\n` },
        env: { stdout: 'NT_ENV_VARS=1\n' },
        build: { stdout: 'NT_INSTALL=npm install\nNT_BUILD=-\n' },
        pm2: { stdout: 'NT_LISTENING=21003\n' },
        vhost: { stdout: 'NT_CONF=/etc/apache2/sites-available/nt-shop.example.com.conf\nNT_RELOADED=1\n' },
        ssl: { stdout: 'NT_EXPIRES=Feb  1 00:00:00 2027 GMT\n' },
        decommission: { stdout: 'NT_VHOST_DISABLED=1\nNT_PM2_DELETED=1\n' },
      }[step] ?? { code: 1, stderr: 'unknown script' };
    }
  }
  const stdins = [];
  const serverAccessService = {
    async runRemote(serverId, fn) {
      const { client } = await fake.connector.connect({});
      try {
        return await fn({ client, run: (script, opts = {}) => { execId += 1; stdins.push({ step: SCRIPTS.get(script), stdin: opts.stdin ?? '' }); return execScriptStdin(client, script, opts); } });
      } finally {
        client.end();
      }
    },
  };
  let ips = resolveIps;
  const fetched = [];
  const svc = createProjectProvisioningService({
    prisma: ctx.prisma, auditService: ctx.auditService, platform: ctx.platform, rbac: ctx.rbac, serverAccessService,
    env: { PROVISION_EXECUTOR: executor, ACME_EMAIL: 'ops@example.com', ...env }, credentialKey: () => KEY, background: false,
    resolveName: async () => ips, sleep: async () => {}, now: () => new Date('2026-11-18T00:00:00Z'),
    fetchImpl: async (url) => { fetched.push(url); return { status: fetchStatus }; },
  });
  return { ctx, t, svc, calls, stdins, fetched, fake, setIps: (v) => { ips = v; } };
}

const confirm = { serverAlias: 'prod-vps', domain: 'shop.example.com' };
const body = (over = {}) => ({ plan: parse(), confirm, ...over });

async function runToCompletion(s, { secrets } = {}) {
  let r = await s.svc.createRun(body({ secrets }), OWNER);
  expect(r.approvalRequired).toBe(true);
  r = await s.svc.createRun(body({ secrets, approvalId: await approve(s.ctx, r.approval.id) }), OWNER);
  return r;
}

describe('project provisioning service (fake SSH)', () => {
  it('gates the run, pauses for vhost / DNS / certbot approvals and finishes with real rows', async () => {
    const s = setup();
    let r = await runToCompletion(s, { secrets: { gitToken: TOKEN } });
    expect(r.status).toBe('awaiting_approval');
    expect(r.pendingApproval.action).toBe('apache.vhost.apply');
    expect(r.steps.filter((x) => x.status === 'success').map((x) => x.id)).toEqual(['preflight', 'app_dir', 'clone', 'env', 'build', 'pm2']);

    // vhost approved -> DNS (manual, not resolving) waits
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    expect(r.status).toBe('waiting_dns');
    expect(r.steps.find((x) => x.id === 'dns').log).toContain(`A shop.example.com -> ${SERVER_IP}`);
    expect(s.calls.filter((c) => c.step === 'vhost')).toHaveLength(1);

    // DNS now resolves -> certbot approval requested
    s.setIps([SERVER_IP]);
    r = await s.svc.resume(r.id, {}, OWNER);
    expect(r.status).toBe('awaiting_approval');
    expect(r.pendingApproval.action).toBe('certbot.issue');
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    expect(r.status).toBe('succeeded');
    expect(r.result.url).toBe('https://shop.example.com/');
    expect(s.fetched[0]).toBe('https://shop.example.com/');

    const certArgs = s.calls.find((c) => c.step === 'ssl').args;
    expect(certArgs.slice(0, 5)).toEqual(['shop.example.com', 'ops@example.com', '1', '0', '0']);
    expect(certArgs.slice(5)).toEqual(['shop.example.com', 'www.shop.example.com']);

    const project = [...s.t.project.rows.values()][0];
    expect(project.status).toBe('active');
    expect([...s.t.domain.rows.values()].map((d) => d.name).sort()).toEqual(['shop.example.com', 'www.shop.example.com']);
    expect([...s.t.sslCertificate.rows.values()][0].expiresAt.toISOString()).toBe('2027-02-01T00:00:00.000Z');
    expect([...s.t.deployment.rows.values()][0].commitSha).toBe('a'.repeat(40));
    expect([...s.t.projectRepository.rows.values()][0].remoteUrl).toBe('https://github.com/acme/shop.git');
    expect(s.t.projectRuntime.rows.size).toBe(1);
  });

  it('keeps secrets out of arguments, scripts, run rows, logs and audit; sends them on stdin only', async () => {
    const s = setup();
    let r = await runToCompletion(s, { secrets: { gitToken: TOKEN } });
    for (const c of s.calls) {
      expect(c.command).not.toContain(TOKEN);
      expect(c.command).not.toContain(ENV_SECRET);
    }
    expect(s.stdins.find((x) => x.step === 'clone').stdin).toBe(TOKEN);
    expect(s.stdins.find((x) => x.step === 'env').stdin).toContain(ENV_SECRET);
    expect(s.stdins.find((x) => x.step === 'pm2').stdin).not.toContain(ENV_SECRET);
    expect(s.calls.find((c) => c.step === 'clone').args).toEqual(['/var/www/shop', 'https://github.com/acme/shop.git', 'main', '-', 'token']);
    const dump = JSON.stringify([r, s.ctx.auditService.record.mock.calls, [...s.ctx.prisma.rows.values()]]);
    expect(dump).not.toContain(TOKEN);
    expect(dump).not.toContain(ENV_SECRET);
    r = await s.svc.getRun(r.id, OWNER);
    expect(JSON.stringify(r)).not.toContain(ENV_SECRET);
  });

  it('redacts a leaked secret from a failing step log', async () => {
    const s = setup({ respond: ({ step }) => (step === 'clone' ? { code: 70, stderr: `fatal: auth failed ${TOKEN}` } : null) });
    const r = await runToCompletion(s, { secrets: { gitToken: TOKEN } });
    expect(r.status).toBe('failed');
    expect(JSON.stringify(r)).not.toContain(TOKEN);
  });

  it('requires typed confirmation, honors the kill switch and the Owner rule', async () => {
    const s = setup();
    await expect(s.svc.createRun(body({ confirm: { serverAlias: 'wrong', domain: 'shop.example.com' } }), OWNER)).rejects.toMatchObject({ code: 'CONFIRMATION_MISMATCH' });
    await expect(s.svc.createRun(body({ confirm: { serverAlias: 'prod-vps', domain: 'other.example.com' } }), OWNER)).rejects.toMatchObject({ code: 'CONFIRMATION_MISMATCH' });
    await expect(s.svc.createRun(body(), { id: U(2), isOwner: false })).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    const off = setup({ env: { PROJECT_PROVISIONING_DISABLED: '1' } });
    await expect(off.svc.createRun(body(), OWNER)).rejects.toMatchObject({ code: 'PROVISIONING_DISABLED' });
    expect(off.calls).toHaveLength(0);
  });

  it('does not execute anything before approval and binds the approval to the plan', async () => {
    const s = setup();
    const first = await s.svc.createRun(body(), OWNER);
    expect(first.approvalRequired).toBe(true);
    expect(s.calls).toHaveLength(0);
    expect(s.t.project.rows.size).toBe(0);
    const id = await approve(s.ctx, first.approval.id);
    await expect(s.svc.createRun({ plan: parse({ branch: 'other' }), confirm, approvalId: id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
  });

  it('stops on the first failure with a rollback note, then resumes without repeating finished steps', async () => {
    let failBuild = true;
    const s = setup({ respond: ({ step }) => (step === 'build' && failBuild ? { code: 71, stderr: 'build failed' } : null) });
    let r = await runToCompletion(s);
    expect(r.status).toBe('failed');
    expect(r.steps.find((x) => x.id === 'build').status).toBe('failed');
    expect(r.steps.find((x) => x.id === 'pm2').status).toBe('pending');
    expect(r.rollbackNote).toMatch(/Stopped at/);
    expect(r.rollbackNote).toMatch(/Resume/);
    expect(s.calls.map((c) => c.step)).toEqual(['preflight', 'app_dir', 'clone', 'env', 'build']);
    failBuild = false;
    r = await s.svc.resume(r.id, {}, OWNER);
    expect(r.status).toBe('awaiting_approval');
    const steps = s.calls.map((c) => c.step);
    expect(steps.filter((x) => x === 'clone')).toHaveLength(1);
    expect(steps.filter((x) => x === 'preflight')).toHaveLength(1);
    expect(steps.filter((x) => x === 'build')).toHaveLength(2);
    expect(steps).toContain('pm2');
  });

  it('reverts automatically when apachectl configtest fails and reloads nothing', async () => {
    let bad = true;
    const s = setup({ respond: ({ step }) => (step === 'vhost' && bad ? { code: 71, stdout: 'NT_REVERTED=1\n', stderr: 'AH00526: Syntax error' } : null) });
    let r = await runToCompletion(s);
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    expect(r.status).toBe('failed');
    const vhost = r.steps.find((x) => x.id === 'vhost');
    expect(vhost.status).toBe('failed');
    expect(vhost.error).toMatch(/restored/);
    expect(vhost.errorCode).toBe('VHOST_REVERTED');
    expect(r.rollbackNote).toMatch(/configtest/i);
    expect(r.steps.find((x) => x.id === 'ssl').status).toBe('pending');
    // approval is released: retry needs no new request
    bad = false;
    const before = s.ctx.prisma.rows.size;
    r = await s.svc.resume(r.id, {}, OWNER);
    expect(s.ctx.prisma.rows.size).toBe(before);
    expect(['waiting_dns', 'awaiting_approval']).toContain(r.status);
    expect(r.steps.find((x) => x.id === 'vhost').status).toBe('success');
  });

  it('fails preflight with every missing prerequisite and changes nothing', async () => {
    const s = setup({ respond: ({ step }) => (step === 'preflight' ? { stdout: GOOD_KV.replace('NT_PM2=5.3', 'NT_PM2=').replace('NT_MODS_MISSING=', 'NT_MODS_MISSING=proxy_wstunnel_module') } : null) });
    const r = await runToCompletion(s);
    expect(r.status).toBe('failed');
    expect(r.steps[0].error).toMatch(/pm2/);
    expect(r.steps[0].error).toMatch(/proxy_wstunnel_module/);
    expect(s.calls.map((c) => c.step)).toEqual(['preflight']);
  });

  it('falls back to an in-memory run store with a stale Prisma client and still gates first', async () => {
    const s = setup();
    const repo = createProvisioningRunRepository({ prisma: {}, now: () => new Date() });
    expect(repo.durable).toBe(false);
    const first = await s.svc.createRun(body(), OWNER);
    expect(first.approvalRequired).toBe(true);
  });

  it('preview returns steps and exact generated text with no changes', async () => {
    const s = setup();
    const p = await s.svc.preview({ plan: parse() }, OWNER);
    expect(p.steps.map((x) => x.id)).toEqual(['preflight', 'app_dir', 'clone', 'env', 'build', 'pm2', 'vhost', 'dns', 'ssl', 'health', 'register']);
    expect(p.apacheVhost).toContain('ServerName shop.example.com');
    expect(p.ecosystem).toContain('nt-shop');
    expect(p.envKeys).toEqual(['DATABASE_URL']);
    expect(JSON.stringify(p)).not.toContain(ENV_SECRET);
    expect(p.confirmationRequired).toEqual({ serverAlias: 'prod-vps', domain: 'shop.example.com' });
    expect(p.dns.effectiveMode).toBe('manual');
    expect(s.calls).toHaveLength(0);
    expect(s.t.project.rows.size).toBe(0);
  });

  it('static sites skip pm2 and use a document root vhost', async () => {
    const s = setup();
    const p = await s.svc.preview({ plan: parse({ framework: 'static', outputDir: 'dist', ssl: false }) }, OWNER);
    expect(p.steps.map((x) => x.id)).not.toContain('pm2');
    expect(p.steps.map((x) => x.id)).not.toContain('ssl');
    expect(p.apacheVhost).toContain('FallbackResource');
  });

  it('simulated executor never opens an SSH connection, DNS lookup or HTTP request', async () => {
    const s = setup({ executor: 'simulated' });
    let r = await runToCompletion(s);
    expect(r.simulated).toBe(true);
    for (let i = 0; i < 4 && r.status === 'awaiting_approval'; i += 1) r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    expect(r.status).toBe('succeeded');
    expect(s.fake.connector.connect).not.toHaveBeenCalled();
    expect(s.fetched).toHaveLength(0);
    expect([...s.t.project.rows.values()][0].status).toBe('simulated');
    expect(s.t.deployment.rows.size).toBe(0);
    expect([...s.t.domain.rows.values()][0].metaJson.simulated).toBe(true);
  });

  it('decommission previews first, needs typed confirmation and approval, keeps files and data', async () => {
    const s = setup();
    let r = await runToCompletion(s);
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    s.setIps([SERVER_IP]);
    r = await s.svc.resume(r.id, {}, OWNER);
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    expect(r.status).toBe('succeeded');
    const projectId = r.projectId;
    const calls = s.calls.length;
    const pre = await s.svc.decommission(projectId, { preview: true }, OWNER);
    expect(pre.changesNothing).toBe(true);
    expect(pre.kept.join(' ')).toMatch(/Databases/);
    expect(s.calls.length).toBe(calls);
    await expect(s.svc.decommission(projectId, { preview: false, confirm: { serverAlias: 'x', domain: 'shop.example.com' } }, OWNER)).rejects.toMatchObject({ code: 'CONFIRMATION_MISMATCH' });
    const gated = await s.svc.decommission(projectId, { preview: false, confirm }, OWNER);
    expect(gated.approvalRequired).toBe(true);
    const done = await s.svc.decommission(projectId, { preview: false, confirm, approvalId: await approve(s.ctx, gated.approval.id) }, OWNER);
    expect(done.status).toBe('decommissioned');
    const dec = s.calls.find((c) => c.step === 'decommission');
    expect(dec.args).toEqual(['nt-shop.example.com.conf', 'nt-shop']);
    expect(s.t.project.rows.get(projectId).status).toBe('decommissioned');
    expect([...s.t.domain.rows.values()].every((d) => d.status === 'disabled')).toBe(true);
    expect(s.t.projectEnvVar.rows.size).toBe(1);
  });

  it('vhost update previews the text and re-applies through its own approval', async () => {
    const s = setup();
    let r = await runToCompletion(s);
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    s.setIps([SERVER_IP]);
    r = await s.svc.resume(r.id, {}, OWNER);
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    const pre = await s.svc.updateVhost(r.projectId, { preview: true }, OWNER);
    expect(pre.apacheVhost).toContain('<VirtualHost *:443>');
    const run = await s.svc.updateVhost(r.projectId, { preview: false }, OWNER);
    expect(run.status).toBe('awaiting_approval');
    expect(run.pendingApproval.action).toBe('apache.vhost.apply');
  });

  it('server state reads vhost, pm2 and certificate expiry from the server', async () => {
    const jlist = JSON.stringify([{ name: 'nt-shop', pid: 55, pm2_env: { status: 'online', restart_time: 1, pm_uptime: 1 }, monit: { memory: 1000, cpu: 1 } }]);
    const s = setup({
      respond: ({ step, calls }) => {
        void step;
        const cmd = calls[calls.length - 1].command;
        if (calls[calls.length - 1].step === 'unknown' && /nt-script/.test(cmd)) {
          return { stdout: `NT_VHOST_FILE=present\nNT_VHOST_ENABLED=yes\nNT_VHOST_B64=${Buffer.from('<VirtualHost *:80>\n</VirtualHost>').toString('base64')}\nNT_PM2_B64=${Buffer.from(jlist).toString('base64')}\nNT_EXPIRES=Feb  1 00:00:00 2027 GMT\n` };
        }
        return null;
      },
    });
    let r = await runToCompletion(s);
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    s.setIps([SERVER_IP]);
    r = await s.svc.resume(r.id, {}, OWNER);
    r = await s.svc.resume(r.id, { approvalId: await approve(s.ctx, r.pendingApproval.approvalId) }, OWNER);
    const st = await s.svc.serverState(r.projectId, OWNER);
    expect(st.simulated).toBe(false);
    expect(st.vhost).toMatchObject({ present: true, enabled: true });
    expect(st.pm2).toMatchObject({ status: 'online', pid: 55 });
    expect(st.certificate.daysLeft).toBeGreaterThan(60);
  });
});
