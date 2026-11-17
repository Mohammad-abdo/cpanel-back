/**
 * TASK-043: stuck-deployment sweeper. A deployment still in an active state long after its last update
 * (executor crashed, API restarted mid-run) is marked Failed, its open steps are closed, and an audit row is written.
 * It never touches a server; release directories are left in place for the Owner to inspect.
 */
export const ACTIVE_STATUSES = ['Queued', 'Preparing', 'Building', 'Deploying', 'Health Check'];

export function createDeploymentSweeper({ prisma, auditService = null, now = () => new Date(), thresholdMs = Number(process.env.NT_DEPLOY_STUCK_MS) || 30 * 60_000 }) {
  return {
    async sweepStuck({ olderThanMs = thresholdMs, limit = 100 } = {}) {
      const cutoff = new Date(now().getTime() - olderThanMs);
      const rows = await prisma.deployment.findMany({
        where: { status: { in: ACTIVE_STATUSES }, updatedAt: { lt: cutoff } },
        take: limit,
      });
      let failed = 0;
      for (const d of rows) {
        // Compare-and-set: only fail it if nobody moved it since we read it.
        const claim = await prisma.deployment.updateMany({ where: { id: d.id, status: d.status, updatedAt: d.updatedAt }, data: { status: 'Failed' } });
        if (claim.count === 0) continue;
        failed += 1;
        await prisma.deploymentStep.updateMany({
          where: { deploymentId: d.id, status: 'RUNNING' },
          data: { status: 'FAILED', finishedAt: now() },
        });
        await prisma.deploymentStep.create({
          data: {
            deploymentId: d.id,
            name: 'Sweeper',
            status: 'FAILED',
            startedAt: now(),
            finishedAt: now(),
            detailJson: { reason: 'stuck', previousStatus: d.status, thresholdMs: olderThanMs },
          },
        });
        if (auditService?.record) {
          await auditService.record({
            actorId: null,
            action: 'deployment.sweep.failed',
            resourceType: 'project',
            resourceId: d.projectId,
            environmentId: d.environmentId,
            result: 'success',
            correlationId: d.correlationId ?? undefined,
            after: { deploymentId: d.id, previousStatus: d.status, thresholdMs: olderThanMs },
          });
        }
      }
      return { checked: rows.length, failed };
    },
  };
}
