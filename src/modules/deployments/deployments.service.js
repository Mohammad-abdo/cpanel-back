import { AppError } from '../../common/errors/app-error.js';
import { createProjectAccess } from '../projects/projects.access.js';
import { deterministicUuid } from '../projects/projects.service.js';

const ACTIVE = ['Queued', 'Preparing', 'Building', 'Deploying', 'Health Check'];

export function createDeploymentsService({ prisma, now = () => new Date(), auditService = null, operationsService = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const access = createProjectAccess({ prisma, now });

  function envelopeFor({ actor, projectId, environmentId, type, key, payload, riskLevel }) {
    const seed = `${actor.id}:${projectId}:${type}:${key}`;
    return {
      operationId: deterministicUuid(seed, 'op'),
      correlationId: deterministicUuid(seed, 'corr'),
      idempotencyKey: `deploy:${deterministicUuid(seed, 'idem')}`,
      type,
      resourceType: 'project',
      resourceId: projectId,
      environmentId,
      riskLevel,
      expiresAt: new Date(now().getTime() + 60 * 60 * 1000).toISOString(),
      payload,
    };
  }

  async function loadDeployment(id) {
    const row = await prisma.deployment.findUnique({ where: { id } });
    if (!row) throw new AppError(404, 'DEPLOYMENT_NOT_FOUND', 'Deployment not found');
    return row;
  }

  async function jobFor(deployment) {
    return prisma.operationJob.findFirst({ where: { correlationId: deployment.correlationId } });
  }

  async function withSteps(deployment) {
    const steps = await prisma.deploymentStep.findMany({
      where: { deploymentId: deployment.id },
      orderBy: { createdAt: 'asc' },
    });
    return { ...deployment, steps };
  }

  async function requireOps() {
    if (!operationsService) throw new AppError(500, 'OPERATIONS_UNAVAILABLE', 'Operation queue unavailable');
  }

  return {
    async list({ projectId, limit }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const visible = await access.visibleProjectIds(actor);
      if (projectId && visible && !visible.includes(projectId)) {
        throw new AppError(404, 'NOT_FOUND', 'Not found');
      }
      const rows = await prisma.deployment.findMany({
        where: {
          ...(projectId ? { projectId } : {}),
          ...(visible && !projectId ? { projectId: { in: visible } } : {}),
        },
        take: limit,
        orderBy: { createdAt: 'desc' },
      });
      return rows;
    },

    async getById(id, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const row = await loadDeployment(id);
      if (!(await access.canView(actor, row.projectId))) throw new AppError(404, 'DEPLOYMENT_NOT_FOUND', 'Deployment not found');
      const job = await jobFor(row);
      const approvals = job ? await prisma.approvalRequest.findMany({ where: { operationJobId: job.id } }) : [];
      return { ...(await withSteps(row)), approvals };
    },

    /** Creates the deployment record and its operation. High risk (production) waits for a separate approver. */
    async create(input, actor) {
      await requireOps();
      const project = await prisma.project.findUnique({ where: { id: input.projectId } });
      if (!project) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      if (project.archivedAt || project.status !== 'active') {
        throw new AppError(409, 'PROJECT_NOT_DEPLOYABLE', 'Project is not active');
      }
      const env = await prisma.projectEnvironment.findUnique({ where: { id: input.environmentId } });
      if (!env || env.projectId !== project.id) {
        throw new AppError(400, 'ENVIRONMENT_MISMATCH', 'Environment does not belong to the project');
      }
      const busy = await prisma.deployment.count({
        where: { projectId: project.id, environmentId: env.id, status: { in: ACTIVE } },
      });
      const envelope = envelopeFor({
        actor,
        projectId: project.id,
        environmentId: env.id,
        type: 'deployment.run',
        key: input.idempotencyKey,
        riskLevel: 'medium',
        payload: { commitSha: input.commitSha ?? null, branch: input.branch ?? null, rollbackPlan: input.rollbackPlan },
      });
      const { job, replayed } = await operationsService.enqueue(envelope, actor);
      const existing = await prisma.deployment.findFirst({ where: { correlationId: job.correlationId } });
      if (existing) return { deployment: existing, operation: job, replayed };
      if (busy > 0) throw new AppError(409, 'DEPLOYMENT_IN_PROGRESS', 'Another deployment is active for this environment');
      const deployment = await prisma.deployment.create({
        data: {
          projectId: project.id,
          environmentId: env.id,
          status: 'Queued',
          commitSha: input.commitSha ?? null,
          initiatedById: actor.id,
          correlationId: job.correlationId,
        },
      });
      await audit({
        actorId: actor.id,
        action: 'deployment.create',
        resourceType: 'project',
        resourceId: project.id,
        environmentId: env.id,
        result: 'success',
        correlationId: job.correlationId,
        after: { deploymentId: deployment.id, operationStatus: job.status },
      });
      return { deployment, operation: job, replayed };
    },

    /** Runs through the operation executor. Requires the operation to be approved when High/Critical. */
    async run(id, actor) {
      await requireOps();
      const deployment = await loadDeployment(id);
      const job = await jobFor(deployment);
      if (!job) throw new AppError(409, 'OPERATION_MISSING', 'Deployment has no operation');
      const result = await operationsService.execute(job.id, actor);
      return { operation: result, deployment: await withSteps(await loadDeployment(id)) };
    },

    /** Manual rollback to a previous successful deployment; always an approval-gated operation. */
    async rollback(id, input, actor) {
      await requireOps();
      const source = await loadDeployment(id);
      const target = input.targetDeploymentId
        ? await loadDeployment(input.targetDeploymentId)
        : (
            await prisma.deployment.findMany({
              where: { projectId: source.projectId, environmentId: source.environmentId, status: 'Success' },
              orderBy: { createdAt: 'desc' },
            })
          ).find((d) => d.id !== source.id && d.createdAt <= source.createdAt);
      if (
        !target ||
        target.id === source.id ||
        target.projectId !== source.projectId ||
        target.environmentId !== source.environmentId ||
        target.status !== 'Success'
      ) {
        throw new AppError(409, 'ROLLBACK_TARGET_INVALID', 'No valid successful deployment to roll back to');
      }
      const envelope = envelopeFor({
        actor,
        projectId: source.projectId,
        environmentId: source.environmentId,
        type: 'deployment.rollback',
        key: input.idempotencyKey,
        riskLevel: 'high',
        payload: {
          fromDeploymentId: source.id,
          targetDeploymentId: target.id,
          rollbackPlan: input.rollbackPlan ?? `Restore commit ${target.commitSha ?? 'unknown'}`,
        },
      });
      const { job, replayed } = await operationsService.enqueue(envelope, actor);
      const existing = await prisma.deployment.findFirst({ where: { correlationId: job.correlationId } });
      if (existing) return { deployment: existing, operation: job, replayed };
      const deployment = await prisma.deployment.create({
        data: {
          projectId: source.projectId,
          environmentId: source.environmentId,
          status: 'Queued',
          commitSha: target.commitSha ?? null,
          initiatedById: actor.id,
          correlationId: job.correlationId,
        },
      });
      await audit({
        actorId: actor.id,
        action: 'deployment.rollback.request',
        resourceType: 'project',
        resourceId: source.projectId,
        environmentId: source.environmentId,
        result: 'success',
        correlationId: job.correlationId,
        after: { fromDeploymentId: source.id, targetDeploymentId: target.id, deploymentId: deployment.id },
      });
      return { deployment, operation: job, replayed };
    },
  };
}
