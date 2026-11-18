/**
 * TASK-053: "Add project to server" orchestration (Apache + certbot + PM2).
 *
 * Steps (each recorded with status and a redacted log tail, idempotent, resumable, stop on first failure):
 *   preflight, app_dir, clone, env, build, pm2, vhost, dns, ssl, health, register
 * Safety: one run per server at a time (plus the per-server SSH lock inside serverAccessService.runRemote); the whole run is gated by
 * platform.gate `project.provision` (typed confirmation of server alias + domain), and the vhost / DNS / certbot steps pause for their own
 * approvals (`apache.vhost.apply`, `dns.change`, `certbot.issue`). No value is ever interpolated into a shell string: fixed scripts get
 * positional args; the git secret and the .env travel on stdin only. Kill switch: PROJECT_PROVISIONING_DISABLED.
 * PROVISION_EXECUTOR=simulated (default) never contacts a server, DNS or the ACME CA; =ssh runs the scripts for real (NOT_RUN in this repo).
 */
import { createHash } from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import { AppError } from '../../common/errors/app-error.js';
import { isSystemActor } from '../../common/system-actor.js';
import { sanitizeRemoteUrl } from '../projects/projects.service.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { redactText } from '../logs/logs.redaction.js';
import { parseOpensslDate } from '../certificates/certbot.script.js';
import { detectFramework } from '../deployments/deployments.commands.js';
import { createProvisioningRunRepository } from './project-provisioning.repository.js';
import {
  APPDIR_SCRIPT, BUILD_SCRIPT, CERTBOT_APACHE_SCRIPT, CLONE_SCRIPT, DECOMMISSION_SCRIPT, ENV_SCRIPT, INSPECT_SCRIPT, PM2_SCRIPT, PREFLIGHT_SCRIPT, VHOST_SCRIPT,
  appDirFor, evaluatePreflight, parseKv, pm2NameFor, renderApacheVhost, renderEcosystem, renderEnvFile, vhostConfName,
} from './project-provisioning.scripts.js';
import { validateAppRoot, validateHostname } from './project-provisioning.validator.js';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

export const STEP_DEFS = Object.freeze({
  preflight: { title: 'Preflight checks (read-only)', gate: null },
  app_dir: { title: 'Create application directory', gate: 'project.provision' },
  clone: { title: 'Clone repository and check out branch / commit', gate: 'project.provision' },
  env: { title: 'Write environment file (0600)', gate: 'project.provision' },
  build: { title: 'Install dependencies and build', gate: 'project.provision' },
  pm2: { title: 'Start with PM2 and save the process list', gate: 'project.provision' },
  vhost: { title: 'Apply Apache virtual host (configtest before reload)', gate: 'apache.vhost.apply' },
  dns: { title: 'DNS records', gate: null },
  ssl: { title: 'Issue TLS certificate with certbot --apache', gate: 'certbot.issue' },
  health: { title: 'Health check over the public URL', gate: null },
  register: { title: 'Register project, domain, certificate and deployment', gate: null },
  decommission: { title: 'Disable Apache vhost and delete the PM2 process (files and databases are kept)', gate: 'project.decommission' },
});
export const STEP_SETS = Object.freeze({
  provision: ['preflight', 'app_dir', 'clone', 'env', 'build', 'pm2', 'vhost', 'dns', 'ssl', 'health', 'register'],
  redeploy: ['clone', 'env', 'build', 'pm2', 'health', 'register'],
  vhost: ['vhost', 'health'],
  decommission: ['decommission'],
});
const ROLLBACK = {
  preflight: () => 'Nothing was changed.',
  app_dir: (r) => `Remove the empty directory ${r.appDir} if you abandon this project.`,
  clone: (r) => `Delete ${r.appDir}/app if you abandon this project (nothing else was changed).`,
  env: (r) => `Delete ${r.appDir}/app/.env if you abandon this project.`,
  build: (r) => `Build output lives inside ${r.appDir}/app only; delete it or fix the build command and resume.`,
  pm2: (r) => `Run: pm2 delete ${r.pm2Name} && pm2 save (the process is not exposed publicly until the vhost step).`,
  vhost: (r) => `If configtest failed the previous file was restored automatically. To undo a applied vhost: a2dissite ${r.confName} && apachectl configtest && systemctl reload apache2.`,
  dns: () => 'Remove the DNS records listed in this step from your DNS provider.',
  ssl: (r) => `certbot delete --cert-name ${r.primary} (certbot rolls back its own Apache edit on failure).`,
  health: () => 'No server change. Fix the application or DNS and resume.',
  register: () => 'No server change. Rows can be corrected from the project page.',
  decommission: (r) => `Re-enable with: a2ensite ${r.confName} && systemctl reload apache2; pm2 start ${r.appDir}/ecosystem.config.cjs && pm2 save.`,
};

class StepFailure extends Error {
  constructor(message, { log = '', code = 'STEP_FAILED' } = {}) {
    super(message);
    this.log = log;
    this.code = code;
  }
}

const DAY = 86400000;
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const p2 = (n) => String(n).padStart(2, '0');
/** openssl -enddate format: "Jan  1 00:00:00 2027 GMT". */
const opensslDate = (d) => `${MON[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} ${d.getUTCFullYear()} GMT`;
const ipOf =(host) => (net.isIP(String(host ?? '')) ? String(host) : null);

export function createProjectProvisioningService({
  prisma,
  auditService = null,
  platform = null,
  rbac = null,
  serverAccessService = null,
  rootDomains = null,
  repository = null,
  env = process.env,
  now = () => new Date(),
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
  fetchImpl = (...a) => fetch(...a),
  resolveName = async (name) => {
    const out = [];
    for (const fn of [dns.resolve4, dns.resolve6]) {
      try {
        out.push(...(await fn(name)));
      } catch {
        /* no record of this family */
      }
    }
    return out;
  },
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  /** false = the run is awaited inside the call (tests). */
  background = true,
}) {
  const runs = repository ?? createProvisioningRunRepository({ prisma, now });
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'project', ...event }) : null);
  const active = new Set();

  // ------------------------------------------------------------------------------------------------ config and guards
  const executorMode = () => (String(env.PROVISION_EXECUTOR ?? 'simulated').toLowerCase() === 'ssh' ? 'ssh' : 'simulated');
  const disabled = () => ['1', 'true', 'yes'].includes(String(env.PROJECT_PROVISIONING_DISABLED ?? '').toLowerCase());
  const portRange = () => {
    const start = Number(env.PROVISION_PORT_START) || 21000;
    const end = Number(env.PROVISION_PORT_END) || 21999;
    return start >= 1024 && end <= 65535 && start <= end ? { start, end } : { start: 21000, end: 21999 };
  };
  const appRoot = () => validateAppRoot(env.PROVISION_APP_ROOT || '/var/www');
  const effectiveDnsMode = (plan) => (plan.dnsMode === 'cloudflare' && String(env.DNS_PROVIDER ?? '').toLowerCase() === 'cloudflare' ? 'cloudflare' : 'manual');

  function requireEnabled() {
    if (disabled()) throw new AppError(503, 'PROVISIONING_DISABLED', 'Project provisioning is switched off (PROJECT_PROVISIONING_DISABLED)');
  }
  function requireOwner(actor) {
    if (isSystemActor(actor)) return;
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can add a new project to a server');
  }
  /** Owner, or project.configure on any environment of an existing project. */
  async function requireProjectWrite(actor, projectId) {
    if (isSystemActor(actor) || actor?.isOwner) return;
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (projectId && rbac?.can) {
      const envs = (await prisma.projectEnvironment?.findMany?.({ where: { projectId } })) ?? [];
      for (const e of envs) {
        if (await rbac.can(actor, { permissionKey: 'project.configure', resourceType: 'project', resourceId: projectId, environmentId: e.id })) return;
      }
    }
    throw new AppError(403, 'FORBIDDEN', 'You need project.configure on this project');
  }
  async function loadServer(serverId) {
    const s = await prisma.server.findUnique({ where: { id: serverId } });
    if (!s || s.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
    return s;
  }
  async function loadRun(id) {
    const r = await runs.find(id);
    if (!r) throw new AppError(404, 'RUN_NOT_FOUND', 'Provisioning run not found');
    return r;
  }
  function checkConfirm(confirm, server, primary) {
    if (!confirm || confirm.serverAlias !== server.alias || confirm.domain !== primary) {
      throw new AppError(422, 'CONFIRMATION_MISMATCH', 'Type the exact server alias and primary domain to confirm');
    }
  }

  // ------------------------------------------------------------------------------------------------ plan resolution
  const canonical = (plan) => ({ ...plan, envVars: undefined, envKeys: (plan.envVars ?? []).map((e) => e.key).sort() });
  const storedPlan = (plan) => JSON.parse(JSON.stringify(canonical(plan)));

  function resolve(plan, ctx = {}) {
    const primary = validateHostname(plan.domains[0]);
    const eff = ctx.effective ?? {};
    const framework = plan.framework !== 'auto' ? plan.framework : eff.framework ?? 'node';
    const isStatic = framework === 'static' || (framework === 'vite' && !plan.startFile && eff.static !== false);
    const outputDir = plan.outputDir ?? eff.outputDir ?? (framework === 'vite' ? 'dist' : '.');
    const dir = appDirFor(appRoot(), plan.slug);
    return {
      primary,
      appDir: dir,
      pm2Name: pm2NameFor(plan.slug),
      confName: vhostConfName(primary),
      framework,
      static: isStatic,
      outputDir,
      docRoot: isStatic ? `${dir}/app${outputDir === '.' ? '' : `/${outputDir}`}` : null,
      port: ctx.port ?? plan.port ?? null,
      installCommand: plan.installCommand ?? eff.install ?? (isStatic && !plan.buildCommand && !eff.build ? '-' : 'npm install'),
      buildCommand: plan.buildCommand ?? eff.build ?? '-',
      startMode: plan.startFile ? 'file' : 'npm-start',
      tls: ctx.tls === true,
    };
  }
  const stepIds = (mode, r) => STEP_SETS[mode].filter((id) => !(id === 'pm2' && r.static));

  // ------------------------------------------------------------------------------------------------ preview (no changes)
  function preview(plan) {
    const r = resolve(plan, { port: plan.port ?? undefined });
    const port = r.port ?? Math.min(portRange().start, 65535);
    const dnsMode = effectiveDnsMode(plan);
    const steps = stepIds('provision', r)
      .filter((id) => !(id === 'ssl' && !plan.ssl))
      .map((id) => ({ id, title: STEP_DEFS[id].title, gate: id === 'dns' ? (dnsMode === 'cloudflare' ? 'dns.change' : null) : STEP_DEFS[id].gate, rollback: ROLLBACK[id](r) }));
    return {
      executor: executorMode(),
      simulated: executorMode() !== 'ssh',
      disabled: disabled(),
      resolved: { appDir: r.appDir, pm2Name: r.pm2Name, confName: r.confName, framework: r.framework, static: r.static, port: r.static ? null : port, portNote: r.port ? null : 'Chosen at preflight from the free ports in the configured range', frameworkNote: plan.framework === 'auto' ? 'Auto-detected from package.json after clone; this preview assumes a Node server' : null, install: r.installCommand, build: r.buildCommand },
      steps,
      dns: { requestedMode: plan.dnsMode, effectiveMode: dnsMode, note: dnsMode !== plan.dnsMode ? 'DNS_PROVIDER is not cloudflare: create the records manually' : null, records: plan.domains.map((name) => ({ type: 'A', name, content: '<server IP>', ttl: 300 })) },
      apacheVhost: renderApacheVhost({ domains: plan.domains, port: r.static ? null : port, docRoot: r.docRoot }),
      apacheVhostTls: plan.ssl ? renderApacheVhost({ domains: plan.domains, port: r.static ? null : port, docRoot: r.docRoot, tls: true }) : null,
      ecosystem: r.static ? null : renderEcosystem({ name: r.pm2Name, appDir: r.appDir, port, mode: r.startMode, startFile: plan.startFile ?? null }),
      envKeys: plan.envVars.map((e) => e.key),
      certbot: plan.ssl ? { command: `certbot --apache --non-interactive --agree-tos --email <ACME_EMAIL> --cert-name ${r.primary} --keep-until-expiring --redirect ${plan.domains.map((d) => `-d ${d}`).join(' ')}`, emailConfigured: Boolean(env.ACME_EMAIL) } : null,
      gates: ['project.provision', 'apache.vhost.apply', ...(dnsMode === 'cloudflare' ? ['dns.change'] : []), ...(plan.ssl ? ['certbot.issue'] : [])],
    };
  }

  // ------------------------------------------------------------------------------------------------ remote execution
  const simulatedStdout = (script, { args = [] }, ctx) => {
    if (script === PREFLIGHT_SCRIPT) {
      const port = Number(args[2]) || Number(args[0]);
      return `NT_OS=Simulated\nNT_APACHE=apache2\nNT_LAYOUT=debian\nNT_MODS_MISSING=\nNT_CERTBOT=certbot (simulated)\nNT_CERTBOT_APACHE=yes\nNT_NODE=v20.0.0\nNT_PM2=5.0.0\nNT_GIT=git version 2\nNT_SUDO=ok\nNT_PORT=${port}\nNT_DISK_MB=50000\n`;
    }
    if (script === CLONE_SCRIPT) {
      const pkg = Buffer.from(JSON.stringify({ scripts: { build: 'build', start: 'start' }, dependencies: ctx.framework === 'next' ? { next: '14' } : {} })).toString('base64');
      return `NT_SHA=${(args[3] !== '-' ? args[3] : '0'.repeat(40)).padEnd(40, '0')}\nNT_PKG_B64=${pkg}\n`;
    }
    if (script === ENV_SCRIPT) return `NT_ENV_VARS=${ctx.envCount}\n`;
    if (script === PM2_SCRIPT) return `NT_LISTENING=${args[2]}\nNT_PM2_NAME=${args[1]}\n`;
    if (script === VHOST_SCRIPT) return `NT_CONF=/etc/apache2/sites-available/${args[0]}\nNT_RELOADED=1\n`;
    if (script === CERTBOT_APACHE_SCRIPT) return `NT_EXPIRES=${opensslDate(new Date(now().getTime() + 90 * DAY))}\n`;
    if (script === DECOMMISSION_SCRIPT) return 'NT_VHOST_DISABLED=1\nNT_PM2_DELETED=1\n';
    return '';
  };

  function makeRemote(serverId, ctx) {
    const mode = executorMode();
    return async (script, { args = [], stdin = '', timeoutMs = 60_000 } = {}) => {
      if (mode !== 'ssh') return { code: 0, stdout: simulatedStdout(script, { args }, ctx), stderr: '', simulated: true };
      if (!serverAccessService?.runRemote) throw new AppError(500, 'SSH_UNAVAILABLE', 'Server access is not wired');
      return serverAccessService.runRemote(serverId, ({ run }) => run(script, { args, stdin, timeoutMs }));
    };
  }

  const cleanLog = (text, secrets = []) => {
    let out = String(text ?? '');
    for (const s of secrets) if (s && String(s).length >= 4) out = out.split(String(s)).join('[REDACTED]');
    out = out.replace(/^(NT_PKG_B64)=.*$/gm, '$1=[omitted]').replace(/^(NT_VHOST_B64|NT_PM2_B64)=.*$/gm, '$1=[omitted]');
    out = redactText(out);
    const lines = out.split('\n').filter((l) => l.trim());
    return lines.slice(-40).join('\n').slice(-4000);
  };

  async function exec(remote, script, opts, secrets) {
    let res;
    try {
      res = await remote(script, opts);
    } catch (error) {
      throw new StepFailure(error instanceof AppError ? error.message : 'Could not run the step over SSH', { log: cleanLog(String(error?.message ?? error), secrets), code: error?.code ?? 'SSH_FAILED' });
    }
    const log = cleanLog(`${res.stdout ?? ''}\n${res.code === 0 ? '' : res.stderr ?? ''}`, secrets);
    if (res.timedOut) throw new StepFailure('The step timed out', { log, code: 'STEP_TIMEOUT' });
    if (res.code !== 0) {
      const reverted = /NT_REVERTED=1/.test(res.stdout ?? '');
      throw new StepFailure(reverted ? 'Apache configtest failed; the previous configuration was restored and Apache was not reloaded' : `The step failed (exit ${res.code})`, { log, code: reverted ? 'VHOST_REVERTED' : 'STEP_FAILED' });
    }
    return { kv: parseKv(res.stdout), log, simulated: Boolean(res.simulated) };
  }

  async function serverAddress(serverId) {
    const cred = await prisma.serverCredential.findUnique({ where: { serverId } });
    const host = cred?.host ?? null;
    if (!host) return { host: null, ip: null };
    return { host, ip: ipOf(host) ?? (await resolveName(host).catch(() => []))[0] ?? null };
  }

  // ------------------------------------------------------------------------------------------------ step implementations
  function envRows(run) {
    return prisma.projectEnvVar.findMany({ where: { environmentId: run.contextJson?.environmentId } });
  }
  async function loadEnv(run) {
    const rows = run.contextJson?.environmentId ? await envRows(run) : [];
    return rows.map((row) => ({ key: row.key, value: decrypt(Buffer.from(row.valueEnc), credentialKey()).toString('utf8') }));
  }

  const impls = {
    async preflight({ run, plan, r, remote, secrets, simulated }) {
      const { start, end } = portRange();
      const { kv, log } = await exec(remote, PREFLIGHT_SCRIPT, { args: [String(start), String(end), String(plan.port ?? 0), appRoot()], timeoutMs: 60_000 }, secrets);
      const verdict = evaluatePreflight(kv);
      const extra = [];
      if (!simulated) {
        const addr = await serverAddress(run.serverId);
        for (const name of plan.domains) {
          const ips = await resolveName(name).catch(() => []);
          extra.push(addr.ip && ips.includes(addr.ip) ? `DNS ok: ${name} -> ${addr.ip}` : `DNS pending: ${name} does not resolve to ${addr.ip ?? 'the server IP'} yet (${ips.join(', ') || 'no record'})`);
        }
      }
      const summary = [log, ...verdict.warnings.map((w) => `warning: ${w}`), ...extra].join('\n');
      if (!verdict.ok) throw new StepFailure(`Preflight failed: ${verdict.blockers.join('; ')}`, { log: summary, code: 'PREFLIGHT_FAILED' });
      return { log: summary, ctxPatch: { port: Number(kv.PORT) } };
    },
    async app_dir({ r, remote, secrets }) {
      return exec(remote, APPDIR_SCRIPT, { args: [r.appDir] }, secrets);
    },
    async clone({ plan, r, remote, secrets, rawSecrets }) {
      const auth = rawSecrets.gitToken ? 'token' : rawSecrets.deployKey ? 'key' : 'none';
      const stdin = rawSecrets.gitToken ?? rawSecrets.deployKey ?? '';
      if (auth === 'token' && !/^https:\/\//.test(plan.repoUrl)) throw new StepFailure('A token needs an https:// repository URL', { code: 'AUTH_URL_MISMATCH' });
      if (auth === 'key' && /^https:\/\//.test(plan.repoUrl)) throw new StepFailure('A deploy key needs an ssh:// or git@ repository URL', { code: 'AUTH_URL_MISMATCH' });
      const out = await exec(remote, CLONE_SCRIPT, { args: [r.appDir, plan.repoUrl, plan.branch, plan.commitSha ?? '-', auth], stdin, timeoutMs: 300_000 }, secrets);
      let eff = {};
      try {
        const pkg = JSON.parse(Buffer.from(out.kv.PKG_B64 ?? '', 'base64').toString('utf8'));
        const d = detectFramework(pkg);
        eff = { framework: d.framework === 'next' ? 'next' : d.framework === 'vite' || d.framework === 'cra' ? (d.static ? 'vite' : 'node') : d.framework === 'static' ? 'static' : 'node', static: d.static, outputDir: d.framework === 'cra' ? 'build' : d.outputDir, install: d.install === 'npm ci' ? 'npm install' : d.install, build: d.build };
      } catch {
        eff = {};
      }
      return { log: out.log, ctxPatch: { commitSha: out.kv.SHA ?? null, effective: plan.framework === 'auto' ? eff : {} } };
    },
    async env({ run, remote, secrets, r }) {
      const vars = await loadEnv(run);
      if (!vars.length) return { skipped: true, log: 'No environment variables configured; nothing written.' };
      secrets.push(...vars.map((v) => v.value));
      const out = await exec(remote, ENV_SCRIPT, { args: [r.appDir], stdin: renderEnvFile(vars) }, secrets);
      return { log: `${out.log}\nvariables: ${vars.map((v) => v.key).join(', ')}` };
    },
    async build({ r, remote, secrets }) {
      if (r.installCommand === '-' && r.buildCommand === '-') return { skipped: true, log: 'No install or build command.' };
      return exec(remote, BUILD_SCRIPT, { args: [r.appDir, r.installCommand, r.buildCommand], timeoutMs: 1_200_000 }, secrets);
    },
    async pm2({ plan, r, remote, secrets }) {
      const text = renderEcosystem({ name: r.pm2Name, appDir: r.appDir, port: r.port, mode: r.startMode, startFile: plan.startFile ?? null });
      return exec(remote, PM2_SCRIPT, { args: [r.appDir, r.pm2Name, String(r.port)], stdin: text, timeoutMs: 120_000 }, secrets);
    },
    async vhost({ plan, r, remote, secrets, run }) {
      const text = renderApacheVhost({ domains: plan.domains, port: r.static ? null : r.port, docRoot: r.docRoot, tls: r.tls });
      const out = await exec(remote, VHOST_SCRIPT, { args: [r.confName], stdin: text, timeoutMs: 60_000 }, secrets);
      void run;
      return { log: `${out.log}\nvhost lines: ${text.split('\n').length}` };
    },
    async dns({ plan, run, simulated }) {
      const mode = effectiveDnsMode(plan);
      if (simulated) return { skipped: true, log: `[simulated] DNS ${mode} mode: no provider or resolver contacted. Create A records for ${plan.domains.join(', ')} pointing at the server.` };
      const addr = await serverAddress(run.serverId);
      if (!addr.ip) throw new StepFailure('The server address is unknown, so the DNS target cannot be computed', { code: 'SERVER_IP_UNKNOWN' });
      const type = net.isIPv6(addr.ip) ? 'AAAA' : 'A';
      const lines = [];
      if (mode === 'cloudflare') {
        if (!rootDomains?.system) throw new StepFailure('Root domain service is not wired', { code: 'DNS_UNAVAILABLE' });
        for (const name of plan.domains) {
          const root = await rootDomains.system.findFor(name);
          if (!root) throw new StepFailure(`No connected Cloudflare zone covers ${name}. Connect the root domain or use manual DNS.`, { code: 'DNS_ZONE_NOT_FOUND' });
          await rootDomains.system.apply(root, 'upsert', { type, name, content: addr.ip, ttl: 300, proxied: false });
          lines.push(`created/updated ${type} ${name} -> ${addr.ip}`);
        }
      }
      const pending = [];
      for (let attempt = 0; attempt < (mode === 'cloudflare' ? 3 : 1); attempt += 1) {
        pending.length = 0;
        for (const name of plan.domains) if (!(await resolveName(name).catch(() => [])).includes(addr.ip)) pending.push(name);
        if (!pending.length) break;
        if (attempt < 2 && mode === 'cloudflare') await sleep(2000);
      }
      if (pending.length) {
        const records = pending.map((n) => `${type} ${n} -> ${addr.ip} (TTL 300)`).join('\n');
        const log = [...lines, `Waiting for DNS. Create these records${mode === 'manual' ? ' at your DNS provider' : ''}, then press Resume:`, records].join('\n');
        if (plan.ssl) return { waiting: true, log };
        return { log: `${log}\n(SSL is off: continuing without waiting)` };
      }
      return { log: [...lines, `DNS ok: ${plan.domains.join(', ')} -> ${addr.ip}`].join('\n') };
    },
    async ssl({ plan, r, remote, secrets, run }) {
      const email = String(env.ACME_EMAIL ?? '');
      if (!/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/.test(email)) throw new StepFailure('ACME_EMAIL is not configured; set it before issuing certificates', { code: 'ACME_EMAIL_REQUIRED' });
      const out = await exec(remote, CERTBOT_APACHE_SCRIPT, { args: [r.primary, email, '1', plan.sslStaging ? '1' : '0', plan.renewalDryRun ? '1' : '0', ...plan.domains], timeoutMs: 300_000 }, secrets);
      const expires = parseOpensslDate(`NT_EXPIRES=${out.kv.EXPIRES ?? ''}`);
      void run;
      return { log: out.log, ctxPatch: { tls: true, certExpiresAt: expires ? expires.toISOString() : null, renewalDryRun: out.kv.RENEW_DRYRUN ?? null } };
    },
    async health({ plan, r, simulated, ctx }) {
      if (simulated) return { skipped: true, log: '[simulated] Health check skipped (no network contact in simulated mode).' };
      const scheme = plan.ssl && (ctx.tls || r.tls) ? 'https' : 'http';
      const url = `${scheme}://${r.primary}/`;
      let last = 'no response';
      for (let i = 0; i < 4; i += 1) {
        try {
          const res = await fetchImpl(url, { redirect: 'manual', signal: AbortSignal.timeout(10_000), headers: { 'user-agent': 'NodeTeam-health/1' } });
          last = `HTTP ${res.status}`;
          if (res.status < 500) return { log: `GET ${url} -> ${last}`, ctxPatch: { healthStatus: res.status } };
        } catch (error) {
          last = String(error?.cause?.code ?? error?.name ?? 'request failed');
        }
        if (i < 3) await sleep(3000);
      }
      throw new StepFailure(`Health check failed: ${url} -> ${last}`, { log: `GET ${url} -> ${last}`, code: 'HEALTH_FAILED' });
    },
    async register({ run, plan, r, ctx, simulated }) {
      return register({ run, plan, r, ctx, simulated });
    },
    async decommission({ run, r, remote, secrets, simulated }) {
      const out = await exec(remote, DECOMMISSION_SCRIPT, { args: [r.confName, r.pm2Name], timeoutMs: 90_000 }, secrets);
      if (run.projectId) {
        await prisma.project.update({ where: { id: run.projectId }, data: { status: 'decommissioned' } });
        for (const d of await prisma.domain.findMany({ where: { projectId: run.projectId } })) await prisma.domain.update({ where: { id: d.id }, data: { status: 'disabled' } });
      }
      return { log: `${out.log}\nFiles, repository checkout, certificates and databases were kept.${simulated ? '\n[simulated]' : ''}` };
    },
  };

  async function register({ run, plan, r, ctx, simulated }) {
    const projectId = run.projectId;
    const [primary, ...aliases] = plan.domains;
    const meta = { webserver: 'apache', confPath: `/etc/apache2/sites-available/${r.confName}`, upstreamPort: r.static ? null : r.port, provisioned: true, provisionRunId: run.id, ...(simulated ? { simulated: true } : {}) };
    for (const [i, name] of plan.domains.entries()) {
      const existing = await prisma.domain.findUnique({ where: { name } });
      const data = { projectId, serverId: run.serverId, status: 'active', archivedAt: null, metaJson: i === 0 ? meta : { ...meta, aliasOf: primary } };
      if (existing) await prisma.domain.update({ where: { id: existing.id }, data });
      else await prisma.domain.create({ data: { name, ...data } });
    }
    void aliases;
    if (run.mode === 'provision' && plan.ssl && ctx.tls) {
      const dom = await prisma.domain.findUnique({ where: { name: primary } });
      if (dom) await prisma.sslCertificate.create({ data: { domainId: dom.id, provider: simulated ? 'simulated-certbot' : 'letsencrypt-certbot', challenge: 'http-01', status: simulated ? 'simulated' : 'active', expiresAt: ctx.certExpiresAt ? new Date(ctx.certExpiresAt) : null } });
    }
    const runtimeMeta = { provisioning: { appDir: r.appDir, pm2Name: r.pm2Name, port: r.static ? null : r.port, confName: r.confName, framework: r.framework, static: r.static, outputDir: r.outputDir, runId: run.id, simulated } };
    const existingRuntime = await prisma.projectRuntime.findFirst({ where: { projectId } });
    const runtimeData = { runtime: 'node', processManager: r.static ? 'apache' : 'pm2', metaJson: { ...(existingRuntime?.metaJson ?? {}), ...runtimeMeta } };
    if (existingRuntime) await prisma.projectRuntime.update({ where: { projectId }, data: runtimeData });
    else await prisma.projectRuntime.create({ data: { projectId, ...runtimeData } });
    const repoData = { remoteUrl: sanitizeRemoteUrl(plan.repoUrl), defaultBranch: plan.branch, lastCommitSha: ctx.commitSha ?? plan.commitSha ?? null };
    if (await prisma.projectRepository.findFirst({ where: { projectId } })) await prisma.projectRepository.update({ where: { projectId }, data: repoData });
    else await prisma.projectRepository.create({ data: { projectId, ...repoData } });
    let deploymentId = null;
    if (!simulated && ctx.environmentId) {
      const dep = await prisma.deployment.create({ data: { projectId, environmentId: ctx.environmentId, status: 'Success', commitSha: ctx.commitSha ?? null, initiatedById: run.createdById ?? null, correlationId: run.id } });
      deploymentId = dep.id;
    }
    await prisma.project.update({ where: { id: projectId }, data: { status: simulated ? 'simulated' : 'active' } });
    return { log: `Registered project, ${plan.domains.length} domain(s)${plan.ssl && ctx.tls ? ', certificate' : ''}${deploymentId ? ', deployment' : ' (no deployment row in simulated mode)'}.`, ctxPatch: { deploymentId } };
  }

  // ------------------------------------------------------------------------------------------------ the engine
  const view = (run) => {
    const ctx = run.contextJson ?? {};
    const plan = run.planJson ?? {};
    const r = resolve(plan, ctx);
    const scheme = ctx.tls ? 'https' : 'http';
    return {
      id: run.id,
      mode: run.mode,
      status: run.status,
      executor: run.executor,
      simulated: run.executor !== 'ssh',
      durable: runs.durable ?? true,
      serverId: run.serverId,
      projectId: run.projectId ?? null,
      slug: run.slug,
      domains: plan.domains ?? [],
      steps: run.stepsJson ?? [],
      rollbackNote: run.rollbackNote ?? null,
      pendingApproval: ctx.pendingApproval ?? null,
      waiting: ctx.waiting ?? null,
      port: ctx.port ?? null,
      commitSha: ctx.commitSha ?? null,
      certExpiresAt: ctx.certExpiresAt ?? null,
      result: run.status === 'succeeded' ? { url: `${scheme}://${r.primary}/`, projectPath: `/projects/${run.projectId}`, simulated: run.executor !== 'ssh' } : null,
      createdAt: run.createdAt,
      updatedAt: run.updatedAt,
    };
  };

  async function save(run, patch) {
    Object.assign(run, patch);
    await runs.update(run.id, patch);
  }
  const patchStep = (run, id, patch) => run.stepsJson.map((s) => (s.id === id ? { ...s, ...patch } : s));

  async function gateStep(run, def, input, actor, r, plan) {
    const ctx = run.contextJson;
    const approvalId = input.approvalId ?? ctx.lastApproval?.[def.gate];
    const impactByGate = {
      'apache.vhost.apply': [`Write /etc/apache2/sites-available/${r.confName} on the managed server`, 'a2ensite, apachectl configtest, then reload Apache (automatic revert if configtest fails)', `Serves ${plan.domains.join(', ')}`],
      'certbot.issue': [`Run certbot --apache for ${plan.domains.join(', ')}`, 'Contacts the ACME certificate authority and edits the Apache vhost', 'Needs DNS to already point at this server'],
      'dns.change': [`Create or update A records for ${plan.domains.join(', ')} through the DNS provider`],
      'project.decommission': [`Disable ${r.confName} and delete PM2 process ${r.pm2Name}`, 'Files, repository checkout, certificates and databases are kept'],
    };
    const gate = await platform.gate(
      {
        action: def.gate,
        binding: sha256(JSON.stringify([def.gate, run.id, plan.domains, r.port, r.appDir])),
        resourceType: 'provisioning_run',
        resourceId: run.id,
        approvalId,
        reason: input.reason ?? `${def.title} for ${run.slug}`,
        impact: impactByGate[def.gate] ?? [def.title],
        rollbackPlan: run.rollbackNote ?? 'See the rollback note on each step',
        context: { runId: run.id, projectId: run.projectId },
      },
      actor,
    );
    return gate;
  }

  async function advance(runId, actor, input = {}, rawSecrets = {}) {
    let run = await loadRun(runId);
    const plan = run.planJson;
    const simulated = run.executor !== 'ssh';
    const secrets = [rawSecrets.gitToken, rawSecrets.deployKey, ...(rawSecrets.deployKey ? rawSecrets.deployKey.split('\n') : [])].filter(Boolean);
    try {
      for (const stepId of stepIds(run.mode, resolve(plan, run.contextJson ?? {}))) {
        run = await loadRun(runId);
        const ctx = run.contextJson ?? {};
        let step = run.stepsJson.find((s) => s.id === stepId);
        if (!step || ['success', 'skipped'].includes(step.status)) continue;
        if (stepId === 'ssl' && !plan.ssl) {
          await save(run, { stepsJson: patchStep(run, 'ssl', { status: 'skipped', log: 'SSL is off for this project.' }) });
          continue;
        }
        const r = resolve(plan, ctx);
        const def = STEP_DEFS[stepId];
        const gateAction = stepId === 'dns' ? (effectiveDnsMode(plan) === 'cloudflare' && !simulated ? 'dns.change' : null) : def.gate;
        let approvalIdUsed = null;
        if (gateAction && gateAction !== 'project.provision' && gateAction !== 'project.decommission') {
          const g = await gateStep(run, { ...def, gate: gateAction }, input, actor, r, plan);
          if (!g.proceed) {
            await save(run, {
              status: 'awaiting_approval',
              stepsJson: patchStep(run, stepId, { status: 'awaiting_approval', log: `Waiting for approval of ${gateAction}` }),
              contextJson: { ...ctx, pendingApproval: { action: gateAction, approvalId: g.approval.id, stepId } },
            });
            return;
          }
          approvalIdUsed = g.approval?.id ?? null;
          input = { ...input, approvalId: undefined };
        }
        await save(run, { status: 'running', stepsJson: patchStep(run, stepId, { status: 'running', startedAt: now().toISOString(), finishedAt: null, log: '' }), contextJson: { ...ctx, pendingApproval: null, waiting: null } });
        const remote = makeRemote(run.serverId, { framework: r.framework, envCount: (plan.envKeys ?? []).length });
        let out;
        try {
          out = await impls[stepId]({ run, plan, r, ctx, remote, secrets, rawSecrets, simulated });
        } catch (error) {
          const failure = error instanceof StepFailure ? error : new StepFailure(error instanceof AppError ? error.message : 'Unexpected error', { code: error?.code ?? 'STEP_FAILED' });
          if (approvalIdUsed && platform?.releaseFailedExecution) await platform.releaseFailedExecution(approvalIdUsed, actor).catch(() => {});
          const fresh = await loadRun(runId);
          await save(fresh, {
            status: 'failed',
            stepsJson: patchStep(fresh, stepId, { status: 'failed', finishedAt: now().toISOString(), log: cleanLog(failure.log || failure.message, secrets), error: cleanLog(failure.message, secrets), errorCode: failure.code, rollback: ROLLBACK[stepId](r) }),
            rollbackNote: `Stopped at "${def.title}": ${cleanLog(failure.message, secrets)}. ${ROLLBACK[stepId](r)} Fix the cause and press Resume; completed steps are skipped.`,
            contextJson: { ...(fresh.contextJson ?? {}), lastApproval: approvalIdUsed ? { ...(fresh.contextJson?.lastApproval ?? {}), [gateAction]: approvalIdUsed } : fresh.contextJson?.lastApproval },
          });
          await audit({ actorId: actor?.id ?? null, action: 'project.provision.step', resourceId: run.projectId ?? run.id, result: 'failure', metadata: { runId: run.id, step: stepId, code: failure.code } });
          return;
        }
        const fresh = await loadRun(runId);
        const nextCtx = { ...(fresh.contextJson ?? {}), ...(out.ctxPatch ?? {}) };
        if (out.waiting) {
          await save(fresh, { status: 'waiting_dns', stepsJson: patchStep(fresh, stepId, { status: 'waiting', finishedAt: now().toISOString(), log: cleanLog(out.log, secrets) }), contextJson: { ...nextCtx, waiting: { step: stepId } } });
          return;
        }
        await save(fresh, { stepsJson: patchStep(fresh, stepId, { status: out.skipped ? 'skipped' : 'success', finishedAt: now().toISOString(), log: cleanLog(out.log, secrets), rollback: ROLLBACK[stepId](r) }), contextJson: nextCtx });
      }
      run = await loadRun(runId);
      await save(run, { status: run.mode === 'decommission' ? 'decommissioned' : 'succeeded', rollbackNote: run.rollbackNote });
      await audit({ actorId: actor?.id ?? null, action: `project.${run.mode}`, resourceId: run.projectId ?? run.id, result: 'success', after: { runId: run.id, slug: run.slug, domains: plan.domains, executor: run.executor } });
    } catch (error) {
      const fresh = await loadRun(runId).catch(() => null);
      if (fresh) await save(fresh, { status: 'failed', rollbackNote: `Unexpected error (${error?.code ?? 'ERROR'}). Review the steps and press Resume.` });
    } finally {
      active.delete(run?.serverId);
    }
  }

  function start(runId, actor, input, rawSecrets, serverId) {
    active.add(serverId);
    const p = advance(runId, actor, input, rawSecrets);
    if (!background) return p;
    p.catch(() => {});
    return null;
  }

  function newSteps(ids, r, plan) {
    return ids.map((id) => ({ id, title: STEP_DEFS[id].title, gate: id === 'dns' ? (effectiveDnsMode(plan) === 'cloudflare' ? 'dns.change' : null) : STEP_DEFS[id].gate, status: 'pending', startedAt: null, finishedAt: null, log: '', rollback: ROLLBACK[id](r) }));
  }

  function assertFree(serverId) {
    if (active.has(serverId)) throw new AppError(409, 'PROVISIONING_BUSY', 'Another provisioning run is active on this server');
  }

  async function createRunRecord({ mode, plan, server, actor, projectId = null, context = {}, rollbackNote }) {
    const r = resolve(plan, context);
    return runs.create({
      serverId: server.id,
      projectId,
      mode,
      status: 'running',
      executor: executorMode(),
      slug: plan.slug,
      primaryDomain: r.primary,
      planJson: plan,
      stepsJson: newSteps(stepIds(mode, r).filter((id) => !(id === 'ssl' && !plan.ssl)), r, plan),
      contextJson: context,
      rollbackNote: rollbackNote ?? null,
      createdById: actor?.id ?? null,
    });
  }

  const defaultRollback = 'Each step lists its own rollback. Nothing outside the app directory, one Apache vhost file, one PM2 process and (optionally) one certificate is touched; databases are never touched.';

  // ------------------------------------------------------------------------------------------------ public API
  return {
    STEP_DEFS,
    config(actor) {
      requireOwnerOrAny(actor);
      return { executor: executorMode(), disabled: disabled(), portRange: portRange(), appRoot: appRoot(), acmeEmailConfigured: Boolean(env.ACME_EMAIL), dnsProvider: String(env.DNS_PROVIDER ?? 'simulated').toLowerCase(), durableRuns: runs.durable ?? true };
    },

    /** Dry run: planned steps and the exact generated vhost / ecosystem text. Changes nothing. */
    async preview(input, actor) {
      requireOwner(actor);
      const server = await loadServer(input.plan.serverId);
      const out = preview(input.plan);
      return { ...out, server: { id: server.id, alias: server.alias }, confirmationRequired: { serverAlias: server.alias, domain: input.plan.domains[0] } };
    },

    async createRun(input, actor) {
      requireEnabled();
      requireOwner(actor);
      const plan = input.plan;
      const server = await loadServer(plan.serverId);
      checkConfirm(input.confirm, server, plan.domains[0]);
      assertFree(server.id);
      if (executorMode() === 'ssh' && !serverAccessService?.runRemote) throw new AppError(500, 'SSH_UNAVAILABLE', 'Server access is not wired');
      const existing = await prisma.project.findFirst({ where: { serverId: server.id, slug: plan.slug } });
      if (existing && !['provisioning'].includes(existing.status)) throw new AppError(409, 'PROJECT_EXISTS', 'A project with this slug already exists on this server');
      for (const name of plan.domains) {
        const d = await prisma.domain.findUnique({ where: { name } });
        if (d && d.projectId && d.projectId !== existing?.id) throw new AppError(409, 'DOMAIN_IN_USE', `${name} already belongs to another project`);
      }
      const gate = await platform.gate(
        {
          action: 'project.provision',
          binding: sha256(JSON.stringify(canonical(plan))),
          resourceType: 'server',
          resourceId: server.id,
          approvalId: input.approvalId,
          reason: input.reason ?? `Provision ${plan.slug} (${plan.domains[0]}) on ${server.alias}`,
          impact: [`Create ${appDirFor(appRoot(), plan.slug)}, clone ${plan.repoUrl}@${plan.branch}`, `Start PM2 process ${pm2NameFor(plan.slug)}`, `Apache vhost + certbot for ${plan.domains.join(', ')} (separately approved)`, `Executor: ${executorMode()}`],
          rollbackPlan: input.rollbackNote ?? defaultRollback,
          context: { slug: plan.slug },
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };

      const project = existing ?? (await prisma.project.create({ data: { serverId: server.id, name: plan.name, slug: plan.slug, type: plan.framework === 'next' ? 'nextjs' : plan.framework === 'vite' ? 'react' : plan.framework === 'static' ? 'static' : 'node', status: 'provisioning' } }));
      let environment = await prisma.projectEnvironment.findFirst({ where: { projectId: project.id, code: 'production' } });
      if (!environment) environment = await prisma.projectEnvironment.create({ data: { projectId: project.id, code: 'production', displayName: 'Production' } });
      for (const v of plan.envVars) {
        const data = { valueEnc: encrypt(v.value, credentialKey()), isSecret: v.isSecret, updatedById: actor.id ?? null };
        const row = await prisma.projectEnvVar.findFirst({ where: { environmentId: environment.id, key: v.key } });
        if (row) await prisma.projectEnvVar.update({ where: { id: row.id }, data });
        else await prisma.projectEnvVar.create({ data: { environmentId: environment.id, key: v.key, ...data } });
      }
      const stored = storedPlan(plan);
      const run = await createRunRecord({ mode: 'provision', plan: stored, server, actor, projectId: project.id, context: { environmentId: environment.id, passed: { 'project.provision': true } }, rollbackNote: input.rollbackNote ?? defaultRollback });
      await audit({ actorId: actor.id ?? null, action: 'project.provision.start', resourceId: project.id, result: 'success', after: { runId: run.id, slug: plan.slug, domains: plan.domains, executor: executorMode(), envKeys: stored.envKeys } });
      const done = start(run.id, actor, {}, input.secrets ?? {}, server.id);
      if (done) await done;
      return view(await loadRun(run.id));
    },

    async getRun(id, actor) {
      const run = await loadRun(id);
      await requireProjectWrite(actor, run.projectId);
      return view(run);
    },

    async listRuns(q, actor) {
      if (q.projectId) await requireProjectWrite(actor, q.projectId);
      else requireOwner(actor);
      return (await runs.list(q)).map(view);
    },

    /** Continue after a failure, an approval or DNS propagation. Completed steps are skipped. */
    async resume(id, input, actor) {
      requireEnabled();
      let run = await loadRun(id);
      await requireProjectWrite(actor, run.projectId);
      if (!['failed', 'awaiting_approval', 'waiting_dns'].includes(run.status)) throw new AppError(409, 'RUN_NOT_RESUMABLE', 'This run is not waiting for anything');
      assertFree(run.serverId);
      const stepsJson = run.stepsJson.map((s) => (['failed', 'waiting', 'awaiting_approval'].includes(s.status) ? { ...s, status: 'pending' } : s));
      await save(run, { status: 'running', stepsJson, contextJson: { ...(run.contextJson ?? {}), pendingApproval: null } });
      const done = start(run.id, actor, { approvalId: input.approvalId, reason: input.reason }, input.secrets ?? {}, run.serverId);
      if (done) await done;
      run = await loadRun(id);
      return view(run);
    },

    /** Pending approval handoff for the UI (same 202 shape the other gated actions use). */
    pendingApprovalOf(runView) {
      return runView?.status === 'awaiting_approval' ? runView.pendingApproval : null;
    },

    async redeploy(projectId, input, actor) {
      requireEnabled();
      await requireProjectWrite(actor, projectId);
      const { run: last, plan, server } = await latestProvision(projectId);
      checkConfirm(input.confirm, server, plan.domains[0]);
      assertFree(server.id);
      const gate = await platform.gate({ action: 'project.provision', binding: sha256(JSON.stringify(['redeploy', canonical(plan)])), resourceType: 'project', resourceId: projectId, approvalId: input.approvalId, reason: input.reason ?? `Redeploy ${plan.slug}`, impact: [`Fetch ${plan.branch}, rebuild and reload PM2 process ${pm2NameFor(plan.slug)}`], rollbackPlan: input.rollbackNote ?? defaultRollback, context: { mode: 'redeploy' } }, actor);
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      const run = await createRunRecord({ mode: 'redeploy', plan, server, actor, projectId, context: { ...(last.contextJson ?? {}), pendingApproval: null, waiting: null, deploymentId: null }, rollbackNote: input.rollbackNote ?? defaultRollback });
      const done = start(run.id, actor, {}, input.secrets ?? {}, server.id);
      if (done) await done;
      return view(await loadRun(run.id));
    },

    /** Regenerate and re-apply the Apache vhost for an existing project (preview: text only). */
    async updateVhost(projectId, input, actor) {
      requireEnabled();
      await requireProjectWrite(actor, projectId);
      const { run: last, plan, server } = await latestProvision(projectId);
      const r = resolve(plan, last.contextJson ?? {});
      const text = renderApacheVhost({ domains: plan.domains, port: r.static ? null : r.port, docRoot: r.docRoot, tls: r.tls });
      if (input.preview) return { confName: r.confName, apacheVhost: text, gate: 'apache.vhost.apply', changesNothing: true };
      assertFree(server.id);
      const run = await createRunRecord({ mode: 'vhost', plan, server, actor, projectId, context: { ...(last.contextJson ?? {}), pendingApproval: null, waiting: null }, rollbackNote: defaultRollback });
      const done = start(run.id, actor, { approvalId: input.approvalId, reason: input.reason }, {}, server.id);
      if (done) await done;
      return view(await loadRun(run.id));
    },

    async decommission(projectId, input, actor) {
      requireEnabled();
      await requireProjectWrite(actor, projectId);
      const { run: last, plan, server } = await latestProvision(projectId);
      const r = resolve(plan, last.contextJson ?? {});
      const planned = {
        steps: [`a2dissite ${r.confName}; apachectl configtest; reload Apache`, `pm2 delete ${r.pm2Name}; pm2 save`],
        kept: [`${r.appDir} (files and repository checkout)`, 'Databases and database users', `Certificate for ${r.primary}`, 'Domain, project and deployment history rows (marked decommissioned/disabled)'],
        rollback: ROLLBACK.decommission(r),
        executor: executorMode(),
        gate: 'project.decommission',
        confirmationRequired: { serverAlias: server.alias, domain: r.primary },
      };
      if (input.preview) return { ...planned, changesNothing: true };
      checkConfirm(input.confirm, server, r.primary);
      assertFree(server.id);
      const gate = await platform.gate({ action: 'project.decommission', binding: sha256(JSON.stringify(['decommission', projectId, r.confName, r.pm2Name])), resourceType: 'project', resourceId: projectId, approvalId: input.approvalId, reason: input.reason ?? `Decommission ${plan.slug}`, impact: [...planned.steps, `Kept: ${planned.kept.join('; ')}`], rollbackPlan: input.rollbackNote ?? planned.rollback, context: { mode: 'decommission' } }, actor);
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      const run = await createRunRecord({ mode: 'decommission', plan, server, actor, projectId, context: { ...(last.contextJson ?? {}), pendingApproval: null, waiting: null }, rollbackNote: planned.rollback });
      const done = start(run.id, actor, {}, {}, server.id);
      if (done) await done;
      return view(await loadRun(run.id));
    },

    /** What is actually on the server for this project: vhost file, PM2 process, certificate expiry. */
    async serverState(projectId, actor) {
      await requireProjectWrite(actor, projectId);
      const { run: last, plan, server } = await latestProvision(projectId);
      const r = resolve(plan, last.contextJson ?? {});
      const base = { projectId, serverId: server.id, domains: plan.domains, appDir: r.appDir, confName: r.confName, pm2Name: r.pm2Name, port: r.static ? null : r.port, runId: last.id };
      if (executorMode() !== 'ssh') {
        const dom = await prisma.domain.findUnique({ where: { name: r.primary } });
        const cert = dom ? (await prisma.sslCertificate.findMany({ where: { domainId: dom.id } }))[0] : null;
        return { ...base, simulated: true, collectedAt: now().toISOString(), vhost: { present: null, enabled: null, text: null }, pm2: null, certificate: cert ? { expiresAt: cert.expiresAt, daysLeft: cert.expiresAt ? Math.floor((new Date(cert.expiresAt) - now()) / DAY) : null } : null, note: 'Executor is simulated: showing recorded values, not the live server.' };
      }
      const remote = makeRemote(server.id, {});
      const out = await exec(remote, INSPECT_SCRIPT, { args: [r.confName, r.pm2Name, r.primary], timeoutMs: 45_000 }, []);
      const text = Buffer.from(out.kv.VHOST_B64 ?? '', 'base64').toString('utf8');
      let proc = null;
      try {
        const list = JSON.parse(Buffer.from(out.kv.PM2_B64 ?? '', 'base64').toString('utf8') || '[]');
        const p = list.find((x) => x.name === r.pm2Name);
        if (p) proc = { status: p.pm2_env?.status ?? 'unknown', pid: p.pid ?? null, restarts: p.pm2_env?.restart_time ?? 0, memoryBytes: p.monit?.memory ?? null, cpu: p.monit?.cpu ?? null, uptimeMs: p.pm2_env?.pm_uptime ? now().getTime() - p.pm2_env.pm_uptime : null };
      } catch {
        proc = null;
      }
      const expires = out.kv.EXPIRES ? parseOpensslDate(`NT_EXPIRES=${out.kv.EXPIRES}`) : null;
      return { ...base, simulated: false, collectedAt: now().toISOString(), vhost: { present: out.kv.VHOST_FILE === 'present', enabled: out.kv.VHOST_ENABLED === 'yes', text: text ? redactText(text) : null }, pm2: proc, certificate: expires ? { expiresAt: expires.toISOString(), daysLeft: Math.floor((expires - now()) / DAY) } : null };
    },
  };

  function requireOwnerOrAny(actor) {
    if (!actor?.id && !isSystemActor(actor)) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
  }

  async function latestProvision(projectId) {
    const project = await prisma.project.findUnique({ where: { id: projectId } });
    if (!project) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
    const list = await runs.list({ projectId, limit: 50 });
    const last = list.find((r) => r.mode === 'provision' && ['succeeded', 'failed', 'awaiting_approval', 'waiting_dns', 'running'].includes(r.status)) ?? null;
    if (!last) throw new AppError(404, 'NOT_PROVISIONED', 'This project was not provisioned by NodeTeam, so there is no recorded plan');
    return { run: last, plan: last.planJson, server: await loadServer(project.serverId) };
  }
}
