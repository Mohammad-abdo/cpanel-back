import { AppError } from '../../common/errors/app-error.js';
import { redact } from '../audit/audit.service.js';
import { createSimulatedExecutor } from '../operations/operations.executor.js';
import { computeSharedImpact } from '../projects/projects.service.js';

/**
 * Runner port: the real implementation lives in the server Agent (git pull, build, pm2 reload).
 * That path is NOT_RUN here; the default runner only simulates success.
 */
export function createSimulatedRunner() {
  const ok = (what) => async () => ({ ok: true, detail: { simulated: true, step: what } });
  return { name: 'simulated', prepare: ok('prepare'), build: ok('build'), deploy: ok('deploy'), rollback: ok('rollback') };
}

/** Health checker port. The simulated checker reports healthy and flags the result as simulated. */
export function createSimulatedHealthChecker() {
  return { name: 'simulated', async check() { return { ok: true, detail: { simulated: true } }; } };
}

const withTimeout = (promise, ms) => {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve) => {
      timer = setTimeout(() => resolve({ ok: false, detail: { reason: 'timeout', timeoutMs: ms } }), ms);
    }),
  ]).finally(() => clearTimeout(timer));
};

/**
 * Executes deployment.run / deployment.rollback operations as the state machine
 * Queued -> Preparing -> Building -> Deploying -> Health Check -> Success | Failed | Rolled Back.
 * Every step is recorded with timing, actor context and redacted detail.
 */
export function createDeploymentExecutor({
  prisma,
  runner = createSimulatedRunner(),
  healthChecker = createSimulatedHealthChecker(),
  now = () => new Date(),
  healthTimeoutMs = 30_000,
  fallback = createSimulatedExecutor(),
}) {
  async function setStatus(deployment, status) {
    deployment.status = status;
    await prisma.deployment.update({ where: { id: deployment.id }, data: { status } });
  }

  async function step(deployment, job, name, fn) {
    const row = await prisma.deploymentStep.create({
      data: {
        deploymentId: deployment.id,
        name,
        status: 'RUNNING',
        startedAt: now(),
        actorId: null,
        detailJson: { executor: 'system', initiatorId: job.initiatorId ?? null, approverId: job.approverId ?? null },
      },
    });
    let out;
    try {
      out = await fn();
    } catch (error) {
      out = { ok: false, detail: { error: String(error?.message ?? error).slice(0, 300) } };
    }
    await prisma.deploymentStep.update({
      where: { id: row.id },
      data: {
        status: out.skipped ? 'SKIPPED' : out.ok ? 'SUCCESS' : 'FAILED',
        finishedAt: now(),
        detailJson: redact({
          executor: 'system',
          initiatorId: job.initiatorId ?? null,
          approverId: job.approverId ?? null,
          ...(out.detail ?? {}),
        }),
      },
    });
    return out;
  }

  async function healthPhase(deployment, job) {
    await setStatus(deployment, 'Health Check');
    const checks = await prisma.healthCheck.findMany({ where: { projectId: deployment.projectId } });
    return step(deployment, job, 'Health Check', async () => {
      if (checks.length === 0) {
        return { ok: true, skipped: true, detail: { healthVerified: false, reason: 'no health checks configured' } };
      }
      const results = [];
      for (const check of checks) {
        const r = await withTimeout(
          Promise.resolve(healthChecker.check({ check, deployment })).catch((e) => ({
            ok: false,
            detail: { error: String(e?.message ?? e).slice(0, 200) },
          })),
          healthTimeoutMs,
        );
        results.push({ checkId: check.id, kind: check.kind, ok: Boolean(r.ok), ...(r.detail ?? {}) });
        await prisma.healthCheck.update({ where: { id: check.id }, data: { status: r.ok ? 'healthy' : 'unhealthy' } });
      }
      const ok = results.every((r) => r.ok);
      const detail = { healthVerified: true, results };
      if (!ok) detail.sharedImpact = await computeSharedImpact(prisma, deployment.projectId);
      return { ok, detail };
    });
  }

  async function previousSuccess(deployment) {
    const rows = await prisma.deployment.findMany({
      where: { projectId: deployment.projectId, environmentId: deployment.environmentId, status: 'Success' },
      orderBy: { createdAt: 'desc' },
    });
    return rows.find((r) => r.id !== deployment.id && r.createdAt <= deployment.createdAt) ?? null;
  }

  async function autoRollback(deployment, job) {
    const prev = await previousSuccess(deployment);
    if (!prev) {
      await step(deployment, job, 'Rollback', async () => ({
        ok: true,
        skipped: true,
        detail: { reason: 'no previous successful deployment' },
      }));
      await setStatus(deployment, 'Failed');
      return;
    }
    const r = await step(deployment, job, 'Rollback', () =>
      runner.rollback({ deployment, targetDeployment: prev, job }),
    );
    await setStatus(deployment, r.ok ? 'Rolled Back' : 'Failed');
  }

  async function runDeployment(deployment, job) {
    const phases = [
      ['Preparing', () => runner.prepare({ deployment, job })],
      ['Building', () => runner.build({ deployment, job })],
      ['Deploying', () => runner.deploy({ deployment, job })],
    ];
    for (const [name, fn] of phases) {
      await setStatus(deployment, name);
      const r = await step(deployment, job, name, fn);
      if (!r.ok) {
        // Only a failure during/after changing the live release warrants rollback.
        if (name === 'Deploying') await autoRollback(deployment, job);
        else await setStatus(deployment, 'Failed');
        return { result: 'FAILED', detail: { failedStep: name, status: deployment.status } };
      }
    }
    const health = await healthPhase(deployment, job);
    if (!health.ok) {
      await autoRollback(deployment, job);
      return { result: 'FAILED', detail: { failedStep: 'Health Check', status: deployment.status } };
    }
    await setStatus(deployment, 'Success');
    return { result: 'OK', detail: { status: 'Success', healthVerified: health.detail?.healthVerified ?? false } };
  }

  async function runRollback(deployment, job) {
    const payload = job.payloadJson ?? {};
    const target = await prisma.deployment.findUnique({ where: { id: payload.targetDeploymentId } });
    if (!target || target.projectId !== deployment.projectId || target.environmentId !== deployment.environmentId) {
      await setStatus(deployment, 'Failed');
      return { result: 'FAILED', detail: { error: 'rollback target invalid' } };
    }
    await setStatus(deployment, 'Deploying');
    const r = await step(deployment, job, 'Rollback', () => runner.rollback({ deployment, targetDeployment: target, job }));
    if (!r.ok) {
      await setStatus(deployment, 'Failed');
      return { result: 'FAILED', detail: { failedStep: 'Rollback' } };
    }
    const health = await healthPhase(deployment, job);
    if (!health.ok) {
      await setStatus(deployment, 'Failed');
      return { result: 'FAILED', detail: { failedStep: 'Health Check' } };
    }
    await setStatus(deployment, 'Success');
    if (payload.fromDeploymentId) {
      await prisma.deployment.update({ where: { id: payload.fromDeploymentId }, data: { status: 'Rolled Back' } });
    }
    return { result: 'OK', detail: { status: 'Success', restoredCommit: target.commitSha ?? null } };
  }

  return {
    name: 'deployment',
    async execute(job, ctx) {
      if (!job.action.startsWith('deployment.')) return fallback.execute(job, ctx);
      const deployment = await prisma.deployment.findFirst({ where: { correlationId: job.correlationId } });
      if (!deployment) throw new AppError(404, 'DEPLOYMENT_NOT_FOUND', 'Deployment record missing for operation');
      if (deployment.status === 'Success' && job.action === 'deployment.run') {
        return { result: 'OK', detail: { skipped: 'already finished', status: deployment.status } };
      }
      return job.action === 'deployment.rollback' ? runRollback(deployment, job) : runDeployment(deployment, job);
    },
  };
}
