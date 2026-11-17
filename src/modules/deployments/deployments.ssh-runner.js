/**
 * TASK-043: real deploy runner over SSH, behind the same adapter interface as createSimulatedRunner()
 * ({ prepare, build, deploy, rollback } plus optional finalize/syntheticChecks).
 *
 * Select with DEPLOY_EXECUTOR=ssh (default: simulated). Tests drive it with the fake SSH connector;
 * running it against a real server is NOT_RUN and needs explicit Owner authorization.
 *
 * Layout on the server: <base>/releases/<deploymentId>, <base>/current -> release, <base>/previous.
 * All remote work uses fixed scripts (deployments.commands.js) fed through execScriptStdin; user-controlled
 * values travel only as quoted positional arguments, and the env file only through stdin.
 */
import { AppError } from '../../common/errors/app-error.js';
import { decrypt } from '../platform/platform.crypto.js';
import { redactText } from '../logs/logs.redaction.js';
import { createSshConnector, execScriptStdin } from '../server-access/ssh.connector.js';
import { PM2_ENV_SETUP } from '../server-access/pm2-live.scan.js';
import {
  ENV_SCRIPT,
  FETCH_SCRIPT,
  HEALTH_SCRIPT,
  PM2_SCRIPT,
  PRUNE_SCRIPT,
  ROLLBACK_SCRIPT,
  RUN_SCRIPT,
  SWITCH_SCRIPT,
  TEARDOWN_SCRIPT,
  PREVIEW_BASE_PATH,
  buildEnvFile,
  detectFramework,
  resolveCommand,
  resolveDeployConfig,
  validateRef,
  validateRepoUrl,
  validateSha,
} from './deployments.commands.js';
import { createSimulatedHealthChecker, createSimulatedRunner } from './deployments.executor.js';
import { realtime } from '../agent-gateway/agent-gateway.realtime.js';

const UUID = /^[0-9a-f-]{36}$/i;
const MAX_LOG_LINES = 200;

/** Default sink: one LogEntry per output line in the existing log store, secrets scrubbed before storage. */
export function createPrismaLogSink({ prisma, now = () => new Date() }) {
  return async function sink({ deployment, serverId = null, phase, severity = 'info', lines, secrets = [] }) {
    const clean = (lines ?? [])
      .map((l) => {
        let out = String(l);
        for (const s of secrets) out = out.split(s).join('[REDACTED]');
        return redactText(out).slice(0, 2000);
      })
      .filter((l) => l.trim().length > 0)
      .slice(-MAX_LOG_LINES);
    if (clean.length === 0) return;
    const at = now();
    try {
      await prisma.logEntry.createMany({
        data: clean.map((message) => ({
          projectId: deployment.projectId,
          serverId,
          environmentId: deployment.environmentId,
          source: 'deploy',
          kind: 'deployment',
          severity,
          message,
          deploymentId: deployment.id,
          fieldsJson: { phase },
          occurredAt: at,
        })),
      });
    } catch {
      /* log storage must never fail a deployment */
    }
    // Best-effort push to Socket.IO /rt room deployment:<id> (consumers keep polling as fallback).
    if (UUID.test(deployment?.id)) {
      realtime.publish(`deployment:${deployment.id}`, 'deployment.log', {
        deploymentId: deployment.id,
        phase,
        severity,
        lines: clean,
        at: at.toISOString?.() ?? String(at),
      });
    }
  };
}

export function createSshRunner({
  prisma,
  connector,
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
  logSink = createPrismaLogSink({ prisma }),
  timeouts = {},
}) {
  const t = { fetch: 180_000, env: 30_000, install: 900_000, build: 900_000, switch: 30_000, pm2: 90_000, prune: 60_000, ...timeouts };
  /** deploymentId -> { sha, detected } carried from prepare to build/deploy within the process. */
  const carry = new Map();

  async function loadContext(deployment) {
    if (!UUID.test(String(deployment.id))) throw new AppError(422, 'DEPLOYMENT_ID_INVALID', 'Deployment id is not safe');
    const project = await prisma.project.findUnique({ where: { id: deployment.projectId } });
    const environment = await prisma.projectEnvironment.findUnique({ where: { id: deployment.environmentId } });
    if (!project || !environment) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project or environment missing');
    const runtime = await prisma.projectRuntime.findUnique({ where: { projectId: project.id } });
    const repo = await prisma.projectRepository.findUnique({ where: { projectId: project.id } });
    const config = resolveDeployConfig({ project, environment, runtimeMeta: runtime?.metaJson ?? null });
    return { project, environment, repo, config, serverId: project.serverId };
  }

  async function withClient(serverId, fn) {
    const cred = await prisma.serverCredential.findUnique({ where: { serverId } });
    if (!cred) throw new AppError(409, 'SSH_CREDENTIAL_NOT_FOUND', 'This server has no SSH login saved');
    const password = decrypt(Buffer.from(cred.secretEnc), credentialKey()).toString('utf8');
    const conn = await connector.connect({
      host: cred.host,
      port: cred.port,
      username: cred.username,
      password,
      expectedHostKey: cred.hostKeySha256 ?? null,
    });
    try {
      return await fn(conn.client);
    } finally {
      conn.client.end();
    }
  }

  /** Runs one fixed script, stores its output in the log store, returns a step record. */
  async function runStep({ client, ctx, deployment, phase, name, script, args, stdin = '', timeoutMs, secrets = [] }) {
    const started = Date.now();
    let res;
    try {
      res = await execScriptStdin(client, script, { args, stdin, timeoutMs });
    } catch (error) {
      res = { code: null, stdout: '', stderr: String(error?.message ?? error) };
    }
    const ok = res.code === 0 && !res.timedOut;
    const lines = `${res.stdout ?? ''}\n${ok ? '' : res.stderr ?? ''}`.split('\n');
    await logSink({
      deployment,
      serverId: ctx.serverId,
      phase,
      severity: ok ? 'info' : 'error',
      lines: [`$ ${name}`, ...lines, ok ? `exit 0` : `exit ${res.code ?? 'timeout'}`],
      secrets,
    });
    return { name, ok, code: res.code, timedOut: Boolean(res.timedOut), ms: Date.now() - started, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
  }

  const summarize = (steps) => steps.map(({ name, ok, code, timedOut, ms }) => ({ name, ok, code, timedOut, ms }));
  const failure = (steps, extra = {}) => {
    const bad = steps.find((s) => !s.ok);
    return { ok: false, detail: { commands: summarize(steps), failed: bad?.name ?? null, exitCode: bad?.code ?? null, ...extra } };
  };

  const pm2Mode = (ctx, detected) => {
    if (ctx.config.static || detected?.static) return 'none';
    return ctx.config.startFile ? 'node-file' : 'npm-start';
  };

  return {
    name: 'ssh',

    async prepare({ deployment, job }) {
      const ctx = await loadContext(deployment);
      const url = validateRepoUrl(ctx.repo?.remoteUrl);
      const sha = deployment.commitSha ? validateSha(deployment.commitSha) : '';
      const branch = validateRef(job?.payloadJson?.branch ?? ctx.repo?.defaultBranch ?? 'main');
      return withClient(ctx.serverId, async (client) => {
        const step = await runStep({
          client,
          ctx,
          deployment,
          phase: 'Preparing',
          name: 'git fetch + checkout pinned commit',
          script: FETCH_SCRIPT,
          args: [ctx.config.basePath, deployment.id, url, sha, branch],
          timeoutMs: t.fetch,
        });
        if (!step.ok) return failure([step]);
        const full = /NT_SHA=([0-9a-f]{7,40})/.exec(step.stdout)?.[1] ?? null;
        const pkgText = /NT_PKG_BEGIN\n([\s\S]*?)\nNT_PKG_END/.exec(step.stdout)?.[1];
        let pkg = null;
        try {
          pkg = pkgText ? JSON.parse(pkgText) : null;
        } catch {
          pkg = null;
        }
        const detected = ctx.config.autoDetect ? detectFramework(pkg) : null;
        carry.set(deployment.id, { sha: full, detected });
        if (full && full !== deployment.commitSha) {
          deployment.commitSha = full;
          await prisma.deployment.update({ where: { id: deployment.id }, data: { commitSha: full } });
        }
        return { ok: true, detail: { commit: full, release: deployment.id, framework: detected?.framework ?? ctx.config.framework ?? null, commands: summarize([step]) } };
      });
    },

    async build({ deployment }) {
      const ctx = await loadContext(deployment);
      const info = carry.get(deployment.id) ?? {};
      const detected = info.detected ?? null;
      const installCmd = ctx.config.installCommand ?? detected?.install ?? 'npm ci';
      const buildCmd = ctx.config.buildCommand ?? detected?.build ?? null;
      const install = installCmd ? resolveCommand(installCmd, ctx.config.approvedCustomCommands) : null;
      const build = buildCmd ? resolveCommand(buildCmd, ctx.config.approvedCustomCommands) : null;
      const vars = await prisma.projectEnvVar.findMany({ where: { environmentId: deployment.environmentId } });
      const key = credentialKey();
      const decoded = vars.map((v) => ({ key: v.key, value: decrypt(Buffer.from(v.valueEnc), key).toString('utf8') }));
      const secrets = decoded.map((v) => v.value).filter((v) => v.length >= 6);
      return withClient(ctx.serverId, async (client) => {
        const steps = [];
        const base = { client, ctx, deployment, phase: 'Building', secrets };
        if (decoded.length > 0) {
          const envStep = await runStep({ ...base, name: 'write env file', script: ENV_SCRIPT, args: [ctx.config.basePath, deployment.id], stdin: buildEnvFile(decoded), timeoutMs: t.env });
          steps.push(envStep);
          if (!envStep.ok) return failure(steps, { envVars: decoded.length });
        }
        for (const [label, argv, ms] of [
          ['install', install, t.install],
          ['build', build, t.build],
        ]) {
          if (!argv) continue;
          const s = await runStep({ ...base, name: argv.join(' '), script: RUN_SCRIPT, args: [ctx.config.basePath, deployment.id, ...argv], timeoutMs: ms });
          steps.push({ ...s, label });
          if (!s.ok) return failure(steps);
        }
        return { ok: true, detail: { commands: summarize(steps), envVars: decoded.length, installed: Boolean(install), built: Boolean(build) } };
      });
    },

    async deploy({ deployment }) {
      const ctx = await loadContext(deployment);
      const detected = carry.get(deployment.id)?.detected ?? null;
      const mode = pm2Mode(ctx, detected);
      return withClient(ctx.serverId, async (client) => {
        const base = { client, ctx, deployment, phase: 'Deploying' };
        const sw = await runStep({ ...base, name: 'switch current symlink', script: SWITCH_SCRIPT, args: [ctx.config.basePath, deployment.id], timeoutMs: t.switch });
        if (!sw.ok) return failure([sw], { switched: false });
        const pm = await runStep({
          ...base,
          name: mode === 'none' ? 'static site (no process)' : 'pm2 reload/start',
          script: PM2_SCRIPT(PM2_ENV_SETUP),
          args: [ctx.config.basePath, ctx.config.pm2App, mode, ctx.config.startFile ?? ''],
          timeoutMs: t.pm2,
        });
        if (!pm.ok) return failure([sw, pm], { switched: true });
        return { ok: true, detail: { commands: summarize([sw, pm]), mode, pm2App: mode === 'none' ? null : ctx.config.pm2App, serveDir: mode === 'none' ? `${ctx.config.basePath}/current/${ctx.config.outputDir ?? detected?.outputDir ?? '.'}` : null } };
      });
    },

    async rollback({ deployment, targetDeployment }) {
      const ctx = await loadContext(deployment);
      if (!UUID.test(String(targetDeployment.id))) throw new AppError(422, 'DEPLOYMENT_ID_INVALID', 'Rollback target id is not safe');
      const sha = targetDeployment.commitSha ? validateSha(targetDeployment.commitSha) : '';
      const mode = ctx.config.static ? 'none' : ctx.config.startFile ? 'node-file' : 'npm-start';
      return withClient(ctx.serverId, async (client) => {
        const base = { client, ctx, deployment, phase: 'Rollback' };
        const rb = await runStep({ ...base, name: 'repoint current to previous release', script: ROLLBACK_SCRIPT, args: [ctx.config.basePath, targetDeployment.id, sha], timeoutMs: t.switch });
        if (!rb.ok) return failure([rb]);
        const pm = await runStep({ ...base, name: mode === 'none' ? 'static site (no process)' : 'pm2 reload', script: PM2_SCRIPT(PM2_ENV_SETUP), args: [ctx.config.basePath, ctx.config.pm2App, mode, ctx.config.startFile ?? ''], timeoutMs: t.pm2 });
        if (!pm.ok) return failure([rb, pm]);
        return { ok: true, detail: { commands: summarize([rb, pm]), restoredCommit: sha || null } };
      });
    },

    /** TASK-045: stop a preview's process and delete its directory. Only `pr-<n>` environments with a preview base path are accepted. */
    async teardown({ projectId, environmentId, serverId }) {
      const project = await prisma.project.findUnique({ where: { id: projectId } });
      const environment = await prisma.projectEnvironment.findUnique({ where: { id: environmentId } });
      if (!project || !environment || environment.projectId !== project.id) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project or environment missing');
      const config = resolveDeployConfig({ project, environment, runtimeMeta: null });
      if (!PREVIEW_BASE_PATH.test(config.basePath)) throw new AppError(422, 'TEARDOWN_PATH_REFUSED', 'Teardown only applies to preview environments');
      return withClient(serverId ?? project.serverId, async (client) => {
        const res = await execScriptStdin(client, TEARDOWN_SCRIPT(PM2_ENV_SETUP), { args: [config.basePath, config.pm2App], timeoutMs: t.prune });
        return { ok: res.code === 0 && !res.timedOut, detail: { basePath: config.basePath, pm2App: config.pm2App, exitCode: res.code } };
      });
    },

    /** After success: keep the newest N releases (never the current or previous target). Failure is logged, not fatal. */
    async finalize({ deployment }) {
      try {
        const ctx = await loadContext(deployment);
        carry.delete(deployment.id);
        return await withClient(ctx.serverId, async (client) => {
          const s = await runStep({ client, ctx, deployment, phase: 'Cleanup', name: `prune releases (keep ${ctx.config.keepReleases})`, script: PRUNE_SCRIPT, args: [ctx.config.basePath, String(ctx.config.keepReleases)], timeoutMs: t.prune });
          return { ok: s.ok, detail: { commands: summarize([s]) } };
        });
      } catch (error) {
        return { ok: false, detail: { error: String(error?.message ?? error).slice(0, 200) } };
      }
    },

    /** Health probe the SSH executor always adds: pm2 online (non-static) and the configured localhost URL. */
    async syntheticChecks(deployment) {
      const ctx = await loadContext(deployment);
      const detected = carry.get(deployment.id)?.detected ?? null;
      const isStatic = ctx.config.static || detected?.static;
      if (isStatic && !ctx.config.healthUrl) return [];
      return [{ id: null, kind: 'ssh-deploy', app: isStatic ? '' : ctx.config.pm2App, url: ctx.config.healthUrl ?? '', timeoutSec: ctx.config.healthTimeoutSec }];
    },
  };
}

/** Health checker for the ssh executor. Row-based kinds it cannot probe fall back to the simulated checker (flagged). */
export function createSshHealthChecker({ prisma, connector, credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY, fallback = createSimulatedHealthChecker() }) {
  return {
    name: 'ssh',
    async check({ check, deployment }) {
      if (check.kind !== 'ssh-deploy') return fallback.check({ check, deployment });
      const project = await prisma.project.findUnique({ where: { id: deployment.projectId } });
      const environment = await prisma.projectEnvironment.findUnique({ where: { id: deployment.environmentId } });
      const runtime = await prisma.projectRuntime.findUnique({ where: { projectId: project.id } });
      const config = resolveDeployConfig({ project, environment, runtimeMeta: runtime?.metaJson ?? null });
      const cred = await prisma.serverCredential.findUnique({ where: { serverId: project.serverId } });
      if (!cred) return { ok: false, detail: { reason: 'no ssh credential' } };
      const password = decrypt(Buffer.from(cred.secretEnc), credentialKey()).toString('utf8');
      const conn = await connector.connect({ host: cred.host, port: cred.port, username: cred.username, password, expectedHostKey: cred.hostKeySha256 ?? null });
      try {
        const res = await execScriptStdin(conn.client, HEALTH_SCRIPT(PM2_ENV_SETUP), {
          args: [config.basePath, check.app ?? '', check.url ?? '', String(check.timeoutSec ?? 30)],
          timeoutMs: (check.timeoutSec ?? 30) * 1000 + 15_000,
        });
        return { ok: res.code === 0 && !res.timedOut, detail: { probe: 'ssh', url: check.url || null, app: check.app || null, exitCode: res.code } };
      } finally {
        conn.client.end();
      }
    },
  };
}

/**
 * Chooses the runner/health checker from DEPLOY_EXECUTOR (simulated | ssh). Unknown values fall back to
 * simulated. `ssh` needs a connector (createSshConnector() in the API process).
 */
export function resolveDeploymentAdapters({ prisma, connector = null, env = process.env, logSink } = {}) {
  const mode = String(env.DEPLOY_EXECUTOR ?? 'simulated').toLowerCase();
  if (mode !== 'ssh') return { runner: createSimulatedRunner(), healthChecker: createSimulatedHealthChecker(), mode: 'simulated' };
  const conn = connector ?? createSshConnector({ timeoutMs: 30_000 });
  return {
    runner: createSshRunner({ prisma, connector: conn, ...(logSink ? { logSink } : {}) }),
    healthChecker: createSshHealthChecker({ prisma, connector: conn }),
    mode: 'ssh',
  };
}
