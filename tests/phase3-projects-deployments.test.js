import { describe, expect, it, vi } from 'vitest';
import { createOperationsService } from '../src/modules/operations/operations.service.js';
import { createProjectsService, sanitizeRemoteUrl } from '../src/modules/projects/projects.service.js';
import { createDeploymentsService } from '../src/modules/deployments/deployments.service.js';
import {
  createDeploymentExecutor,
  createSimulatedHealthChecker,
  createSimulatedRunner,
} from '../src/modules/deployments/deployments.executor.js';
import { configureBodySchema } from '../src/modules/projects/projects.validator.js';
import { fakePrisma, U } from './phase3-helpers.js';

const OWNER = { id: U(1), isOwner: true };
const DEV = { id: U(2), isOwner: false };
const REVIEWER = { id: U(3), isOwner: false };
const SERVER = U(5);
const P1 = U(10);
const P2 = U(11);
const STG = U(20);
const PROD = U(21);
const grant = (userId, key, environmentId) => ({
  id: `${userId}-${key}-${environmentId}`,
  userId,
  permissionCode: key,
  resourceType: 'project',
  resourceId: P1,
  environmentId,
  revokedAt: null,
  expiresAt: null,
});

function setup({ runner, healthChecker, grants = [], health = [], backups = null, backupPolicies = [] } = {}) {
  const prisma = fakePrisma({
    server: [{ id: SERVER, alias: 's1', archivedAt: null }],
    project: [
      { id: P1, serverId: SERVER, name: 'Api', slug: 'api', type: 'node', status: 'active', archivedAt: null },
      { id: P2, serverId: SERVER, name: 'Web', slug: 'web', type: 'node', status: 'active', archivedAt: null },
    ],
    projectEnvironment: [
      { id: STG, projectId: P1, code: 'staging' },
      { id: PROD, projectId: P1, code: 'production' },
    ],
    projectRuntime: [
      { id: 'r1', projectId: P1, processManager: 'pm2' },
      { id: 'r2', projectId: P2, processManager: 'pm2' },
    ],
    resourceGrant: grants,
    healthCheck: health,
    backupPolicy: backupPolicies,
  });
  const base = prisma.operationJob.findFirst;
  prisma.operationJob.findFirst = async (args) => {
    const job = await base(args);
    if (!job) return null;
    return {
      ...job,
      executions: prisma.operationExecution.rows.filter((e) => e.operationJobId === job.id),
      approvals: prisma.approvalRequest.rows.filter((a) => a.operationJobId === job.id),
    };
  };
  const auditService = { record: vi.fn().mockResolvedValue({}) };
  const executor = createDeploymentExecutor({
    prisma,
    runner: runner ?? createSimulatedRunner(),
    healthChecker: healthChecker ?? createSimulatedHealthChecker(),
    healthTimeoutMs: 20,
    backups,
  });
  const operations = createOperationsService({ prisma, auditService, executor });
  const projects = createProjectsService({ prisma, auditService, operationsService: operations });
  const deployments = createDeploymentsService({ prisma, auditService, operationsService: operations });
  return { prisma, auditService, operations, projects, deployments };
}

const stepNames = (prisma) => prisma.deploymentStep.rows.map((s) => s.name);
const failing = (name) => ({ ...createSimulatedRunner(), [name]: async () => ({ ok: false, detail: { error: `${name} failed` } }) });

describe('TASK-018 project discovery and configuration', () => {
  it('discovery is read-only: creates discovered projects, never touches existing, no operations or deployments', async () => {
    const { projects, prisma } = setup();
    const result = await projects.discover(
      {
        serverId: SERVER,
        candidates: [
          { name: 'Api', slug: 'api', type: 'node' },
          { name: 'Shop', type: 'laravel', processManager: 'php-fpm', path: '/var/www/shop', remoteUrl: 'https://user:tok3n@git.example/org/shop.git' },
        ],
      },
      OWNER,
    );
    expect(result.skipped).toEqual([{ name: 'Api', slug: 'api', reason: 'already-known' }]);
    expect(result.created).toHaveLength(1);
    expect(result.created[0].status).toBe('discovered');
    expect(prisma.operationJob.rows).toHaveLength(0);
    expect(prisma.deployment.rows).toHaveLength(0);
    expect(prisma.projectRepository.rows[0].remoteUrl).not.toContain('tok3n');
    expect(prisma.projectRuntime.rows.find((r) => r.metaJson?.readOnlyDiscovery).metaJson.discoveredPath).toBe('/var/www/shop');
  });

  it('only the Owner can discover, create, configure and archive', async () => {
    const { projects } = setup();
    await expect(projects.discover({ serverId: SERVER, candidates: [{ name: 'x', type: 'node' }] }, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(projects.configure(P1, { type: 'node' }, DEV)).rejects.toMatchObject({ status: 403 });
    await expect(projects.archive(P1, { reason: 'cleanup' }, DEV)).rejects.toMatchObject({ status: 403 });
  });

  it('creates a Node project with environments and rejects duplicate slug', async () => {
    const { projects, prisma } = setup();
    const input = {
      serverId: SERVER, name: 'New', slug: 'new', type: 'node',
      environments: [{ code: 'staging', displayName: 'Staging' }],
      repository: { remoteUrl: 'git@github.com:org/new.git', defaultBranch: 'main' },
      runtime: { runtime: 'node20', processManager: 'pm2' },
    };
    await projects.create(input, OWNER);
    expect(prisma.projectEnvironment.rows.filter((e) => e.code === 'staging')).toHaveLength(2);
    await expect(projects.create(input, OWNER)).rejects.toMatchObject({ code: 'PROJECT_EXISTS' });
  });

  it('secret configuration accepts names only; values are rejected and meta is redacted', async () => {
    expect(configureBodySchema.safeParse({ secretRefs: ['DB_URL'], DB_URL: 'mysql://x' }).success).toBe(false);
    expect(configureBodySchema.safeParse({ secretRefs: ['db password=1'] }).success).toBe(false);
    const { projects, prisma } = setup();
    await projects.configure(P1, { secretRefs: ['DB_URL', 'DB_URL', 'API_KEY'] }, OWNER);
    const rt = prisma.projectRuntime.rows.find((r) => r.projectId === P1);
    expect(rt.metaJson.configuredEnvKeys).toEqual(['DB_URL', 'API_KEY']);
  });

  it('sanitizes credentials in git remotes', () => {
    expect(sanitizeRemoteUrl('https://u:p@host/org/r.git')).toBe('https://host/org/r.git');
    expect(sanitizeRemoteUrl('git@github.com:org/r.git')).toBe('git@github.com:org/r.git');
  });

  it('visibility: non-members do not list or read projects; members do', async () => {
    const { projects, prisma } = setup();
    prisma.projectMember.rows.push({ projectId: P1, userId: DEV.id, projectRole: 'dev' });
    expect((await projects.list({ limit: 10 }, DEV)).map((p) => p.id)).toEqual([P1]);
    expect(await projects.list({ limit: 10 }, REVIEWER)).toEqual([]);
    await expect(projects.getById(P2, DEV)).rejects.toMatchObject({ status: 404 });
  });

  it('lifecycle needs exact scope, goes through the queue, replays idempotently, and previews shared impact', async () => {
    const { projects, prisma } = setup({ grants: [grant(DEV.id, 'project.restart.execute', STG)] });
    const input = { environmentId: STG, idempotencyKey: 'restart-key-1' };
    const first = await projects.lifecycle(P1, 'restart', input, DEV);
    expect(first.operation.status).toBe('QUEUED');
    expect(first.sharedImpact.projects.map((p) => p.slug)).toEqual(['web']);
    const again = await projects.lifecycle(P1, 'restart', input, DEV);
    expect(again.replayed).toBe(true);
    expect(prisma.operationJob.rows).toHaveLength(1);
    await expect(projects.lifecycle(P1, 'restart', { ...input, environmentId: PROD, idempotencyKey: 'restart-key-2' }, DEV)).rejects.toMatchObject({ status: 403 });
    // stop is high risk -> approval required
    const stop = await projects.lifecycle(P1, 'stop', { environmentId: STG, idempotencyKey: 'stop-key-0001' }, OWNER);
    expect(stop.operation.status).toBe('PENDING_APPROVAL');
  });

  it('archive is blocked while a deployment is active', async () => {
    const { projects, prisma } = setup();
    prisma.deployment.rows.push({ id: 'd1', projectId: P1, environmentId: STG, status: 'Building' });
    await expect(projects.archive(P1, { reason: 'cleanup' }, OWNER)).rejects.toMatchObject({ code: 'DEPLOYMENT_IN_PROGRESS' });
  });
});

describe('TASK-018/019 deployments, health checks and rollback', () => {
  const deploy = async (ctx, env = STG, key = 'deploy-key-001', actor = OWNER) =>
    ctx.deployments.create({ projectId: P1, environmentId: env, idempotencyKey: key, commitSha: 'abc1234' }, actor);

  it('successful staging deployment records every step with timing', async () => {
    const ctx = setup();
    const { deployment } = await deploy(ctx);
    const out = await ctx.deployments.run(deployment.id, OWNER);
    expect(out.deployment.status).toBe('Success');
    expect(stepNames(ctx.prisma)).toEqual(['Preparing', 'Building', 'Deploying', 'Health Check']);
    expect(ctx.prisma.deploymentStep.rows.every((s) => s.startedAt && s.finishedAt)).toBe(true);
    expect(ctx.prisma.deploymentStep.rows.at(-1).status).toBe('SKIPPED'); // no health checks configured
  });

  it('pre-deploy backup runs when a policy exists and blocks deploy when it fails', async () => {
    const runBackup = vi.fn(async () => ({ run: { id: 'br1' }, simulated: true, liveDb: false }));
    const ctx = setup({
      backups: { runBackup },
      backupPolicies: [{ id: 'bp1', projectId: P1, environmentId: STG, archivedAt: null, createdAt: new Date() }],
    });
    const { deployment } = await deploy(ctx, STG, 'deploy-key-pre1');
    const out = await ctx.deployments.run(deployment.id, OWNER);
    expect(out.deployment.status).toBe('Success');
    expect(stepNames(ctx.prisma)[0]).toBe('Pre-deploy Backup');
    expect(runBackup).toHaveBeenCalledWith(
      'bp1',
      expect.objectContaining({ environmentId: STG, trigger: 'pre-deploy', kinds: ['db', 'config'] }),
      expect.objectContaining({ system: true }),
    );

    const failingBackup = vi.fn(async () => {
      throw Object.assign(new Error('disk full'), { code: 'BACKUP_FAILED' });
    });
    const bad = setup({
      backups: { runBackup: failingBackup },
      backupPolicies: [{ id: 'bp2', projectId: P1, environmentId: STG, archivedAt: null, createdAt: new Date() }],
    });
    const d2 = await deploy(bad, STG, 'deploy-key-pre2');
    const failed = await bad.deployments.run(d2.deployment.id, OWNER);
    expect(failed.deployment.status).toBe('Failed');
    expect(stepNames(bad.prisma)).toEqual(['Pre-deploy Backup']);
    expect(stepNames(bad.prisma)).not.toContain('Building');
  });

  it('pre-deploy backup is skipped when no policy exists for the environment', async () => {
    const runBackup = vi.fn();
    const ctx = setup({ backups: { runBackup }, backupPolicies: [] });
    const { deployment } = await deploy(ctx, STG, 'deploy-key-pre3');
    await ctx.deployments.run(deployment.id, OWNER);
    expect(stepNames(ctx.prisma)[0]).toBe('Pre-deploy Backup');
    expect(ctx.prisma.deploymentStep.rows[0].status).toBe('SKIPPED');
    expect(runBackup).not.toHaveBeenCalled();
  });

  it('build failure ends Failed without rollback', async () => {
    const ctx = setup({ runner: failing('build') });
    const { deployment } = await deploy(ctx);
    const out = await ctx.deployments.run(deployment.id, OWNER);
    expect(out.deployment.status).toBe('Failed');
    expect(stepNames(ctx.prisma)).toEqual(['Preparing', 'Building']);
    expect(out.operation.status).toBe('FAILED');
  });

  it('health failure cannot report Success; rolls back to the previous good release with shared impact', async () => {
    const health = [{ id: 'h1', projectId: P1, kind: 'http', status: 'unknown' }];
    const ctx = setup({ health, healthChecker: { check: async () => ({ ok: false, detail: { code: 502 } }) } });
    ctx.prisma.deployment.rows.push({ id: 'old', projectId: P1, environmentId: STG, status: 'Success', commitSha: 'aaa1111', createdAt: new Date(Date.now() - 100000) });
    const { deployment } = await deploy(ctx);
    const out = await ctx.deployments.run(deployment.id, OWNER);
    expect(out.deployment.status).toBe('Rolled Back');
    const hc = ctx.prisma.deploymentStep.rows.find((s) => s.name === 'Health Check');
    expect(hc.status).toBe('FAILED');
    expect(hc.detailJson.sharedImpact.projects.map((p) => p.slug)).toEqual(['web']);
    expect(ctx.prisma.healthCheck.rows[0].status).toBe('unhealthy');
    expect(out.operation.status).toBe('FAILED');
  });

  it('health failure with no previous release ends Failed', async () => {
    const health = [{ id: 'h1', projectId: P1, kind: 'http', status: 'unknown' }];
    const ctx = setup({ health, healthChecker: { check: async () => ({ ok: false }) } });
    const { deployment } = await deploy(ctx);
    expect((await ctx.deployments.run(deployment.id, OWNER)).deployment.status).toBe('Failed');
  });

  it('health check timeout is a failure', async () => {
    const health = [{ id: 'h1', projectId: P1, kind: 'http', status: 'unknown' }];
    const ctx = setup({ health, healthChecker: { check: () => new Promise(() => {}) } });
    const { deployment } = await deploy(ctx);
    const out = await ctx.deployments.run(deployment.id, OWNER);
    expect(out.deployment.status).toBe('Failed');
    expect(ctx.prisma.deploymentStep.rows.find((s) => s.name === 'Health Check').detailJson.results[0].reason).toBe('timeout');
  });

  it('healthy checks give a verified Success', async () => {
    const health = [{ id: 'h1', projectId: P1, kind: 'http', status: 'unknown' }];
    const ctx = setup({ health });
    const { deployment } = await deploy(ctx);
    const out = await ctx.deployments.run(deployment.id, OWNER);
    expect(out.deployment.status).toBe('Success');
    expect(ctx.prisma.healthCheck.rows[0].status).toBe('healthy');
  });

  it('production deployment needs a separate approver before it runs; denied without exact production scope', async () => {
    const ctx = setup({ grants: [grant(DEV.id, 'project.deploy.create', PROD), grant(REVIEWER.id, 'project.deploy.create', PROD), grant(U(4), 'project.deploy.create', STG)] });
    await expect(deploy(ctx, PROD, 'deploy-key-002', { id: U(4), isOwner: false })).rejects.toMatchObject({ status: 403 });
    const { deployment, operation } = await deploy(ctx, PROD, 'deploy-key-003', DEV);
    expect(operation.status).toBe('PENDING_APPROVAL');
    await expect(ctx.deployments.run(deployment.id, DEV)).rejects.toMatchObject({ code: 'APPROVAL_REQUIRED' });
    await expect(ctx.operations.decide(operation.id, 'approve', { reason: 'self approval' }, DEV)).rejects.toMatchObject({ code: 'SEPARATION_OF_DUTIES' });
    await ctx.operations.decide(operation.id, 'approve', { reason: 'reviewed' }, REVIEWER);
    const out = await ctx.deployments.run(deployment.id, DEV);
    expect(out.deployment.status).toBe('Success');
    expect(out.operation.approverId).toBe(REVIEWER.id);
  });

  it('duplicate create with same idempotency key returns the same deployment; wrong environment rejected', async () => {
    const ctx = setup();
    const a = await deploy(ctx);
    const b = await deploy(ctx);
    expect(b.replayed).toBe(true);
    expect(b.deployment.id).toBe(a.deployment.id);
    expect(ctx.prisma.deployment.rows).toHaveLength(1);
    await expect(deploy(ctx, U(99), 'deploy-key-009')).rejects.toMatchObject({ code: 'ENVIRONMENT_MISMATCH' });
  });

  it('retrying a finished successful deployment does not re-run the runner', async () => {
    const runner = createSimulatedRunner();
    runner.deploy = vi.fn(runner.deploy);
    const ctx = setup({ runner });
    const { deployment } = await deploy(ctx);
    await ctx.deployments.run(deployment.id, OWNER);
    await ctx.deployments.run(deployment.id, OWNER);
    expect(runner.deploy).toHaveBeenCalledTimes(1);
  });

  it('manual rollback is approval-gated, restores the target, and marks the source Rolled Back', async () => {
    const ctx = setup();
    const first = await deploy(ctx, STG, 'deploy-key-101');
    await ctx.deployments.run(first.deployment.id, OWNER);
    const second = await deploy(ctx, STG, 'deploy-key-102');
    await ctx.deployments.run(second.deployment.id, OWNER);
    const rb = await ctx.deployments.rollback(second.deployment.id, { idempotencyKey: 'rollback-key-1' }, OWNER);
    expect(rb.operation.status).toBe('PENDING_APPROVAL');
    await expect(ctx.deployments.run(rb.deployment.id, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_REQUIRED' });
    await ctx.operations.decide(rb.operation.id, 'approve', { reason: 'known good' }, REVIEWER).catch(() => null);
    // REVIEWER holds no grant: still pending; Owner cannot approve own request
    expect(ctx.prisma.operationJob.rows.find((j) => j.id === rb.operation.id).status).toBe('PENDING_APPROVAL');
    ctx.prisma.resourceGrant.rows.push(grant(REVIEWER.id, 'project.deploy.create', STG));
    await ctx.operations.decide(rb.operation.id, 'approve', { reason: 'known good' }, REVIEWER);
    const out = await ctx.deployments.run(rb.deployment.id, REVIEWER);
    expect(out.deployment.status).toBe('Success');
    expect(ctx.prisma.deployment.rows.find((d) => d.id === second.deployment.id).status).toBe('Rolled Back');
  });

  it('rollback rejects a target from another environment or without a successful predecessor', async () => {
    const ctx = setup();
    const only = await deploy(ctx);
    await ctx.deployments.run(only.deployment.id, OWNER);
    await expect(ctx.deployments.rollback(only.deployment.id, { idempotencyKey: 'rollback-key-2' }, OWNER)).rejects.toMatchObject({ code: 'ROLLBACK_TARGET_INVALID' });
    ctx.prisma.deployment.rows.push({ id: 'prod-ok', projectId: P1, environmentId: PROD, status: 'Success', createdAt: new Date(0) });
    await expect(ctx.deployments.rollback(only.deployment.id, { idempotencyKey: 'rollback-key-3', targetDeploymentId: 'prod-ok' }, OWNER)).rejects.toMatchObject({ code: 'ROLLBACK_TARGET_INVALID' });
  });

  it('step detail is redacted and carries initiator context', async () => {
    const ctx = setup({ runner: { ...createSimulatedRunner(), build: async () => ({ ok: true, detail: { apiToken: 'leak-me', log: 'ok' } }) } });
    const { deployment } = await deploy(ctx);
    await ctx.deployments.run(deployment.id, OWNER);
    const build = ctx.prisma.deploymentStep.rows.find((s) => s.name === 'Building');
    expect(JSON.stringify(build.detailJson)).not.toContain('leak-me');
    expect(build.detailJson.initiatorId).toBe(OWNER.id);
  });

  it('non-members cannot read deployments', async () => {
    const ctx = setup();
    const { deployment } = await deploy(ctx);
    await expect(ctx.deployments.getById(deployment.id, DEV)).rejects.toMatchObject({ status: 404 });
    expect((await ctx.deployments.getById(deployment.id, OWNER)).steps).toEqual([]);
  });
});
