import { PERMISSIONS } from '../../common/permission-catalog.js';
import { isOperationExpired } from '../../common/shared-contracts.js';
import { AppError } from '../../common/errors/app-error.js';
import { redact } from '../audit/audit.service.js';
import { createRbacService } from '../rbac/rbac.service.js';
import { createSimulatedExecutor } from './operations.executor.js';
import { notify, notifyOwners, notifyChannels } from '../notifications/notifications.service.js';

const RISK_ORDER = ['low', 'medium', 'high', 'critical'];
const TERMINAL = ['SUCCESS', 'FAILED', 'CANCELLED', 'DENIED', 'EXPIRED', 'TIMEOUT'];
const RETRYABLE = ['QUEUED', 'FAILED', 'TIMEOUT'];

/** Minimum risk per action; the server never trusts a lower client-declared level. */
const ACTION_MIN_RISK = {
  'deployment.run': 'medium',
  'deployment.rollback': 'high',
  'project.restart': 'medium',
  'project.start': 'medium',
  'project.stop': 'high',
  'project.discover': 'low',
};

export function permissionForAction(action) {
  if (action.startsWith('deployment.') || action.startsWith('project.deploy')) return PERMISSIONS.PROJECT_DEPLOY_CREATE;
  if (/^project\.(restart|start|stop)/.test(action)) return PERMISSIONS.PROJECT_RESTART_EXECUTE;
  if (action.startsWith('project.discover')) return PERMISSIONS.PROJECT_ENV_METADATA_READ;
  return null; // unknown actions are Owner-only
}

export function requiresApproval(riskTier) {
  return riskTier === 'high' || riskTier === 'critical';
}

function maxRisk(a, b) {
  return RISK_ORDER[Math.max(RISK_ORDER.indexOf(a), RISK_ORDER.indexOf(b ?? 'low'))];
}

export function createOperationsService({
  prisma,
  now = () => new Date(),
  auditService = null,
  rbac = null,
  executor = createSimulatedExecutor(),
  timeoutMs = 60_000,
}) {
  const access = rbac ?? createRbacService({ prisma, now });
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function canScope(actor, job, action = job.action) {
    if (actor?.isOwner) return true;
    const key = permissionForAction(action);
    if (!key) return false;
    return access.can(actor, {
      permissionKey: key,
      resourceType: job.resourceType,
      resourceId: job.resourceId,
      environmentId: job.environmentId ?? null,
    });
  }

  async function load(id) {
    const job = await prisma.operationJob.findFirst({
      where: { OR: [{ id }, { operationId: id }] },
      include: { executions: true, approvals: true },
    });
    if (!job) throw new AppError(404, 'OPERATION_NOT_FOUND', 'Operation not found');
    return job;
  }

  async function markExpired(job, actorId = null) {
    await prisma.operationJob.update({ where: { id: job.id }, data: { status: 'EXPIRED' } });
    await prisma.approvalRequest.updateMany({
      where: { operationJobId: job.id, status: 'PENDING' },
      data: { status: 'EXPIRED', decidedAt: now() },
    });
    await audit({
      actorId,
      action: 'operation.expire',
      resourceType: job.resourceType,
      resourceId: job.resourceId,
      environmentId: job.environmentId,
      result: 'expired',
      correlationId: job.correlationId,
      after: { operationId: job.operationId },
    });
  }

  const svc = {
    async enqueue(envelope, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      if (isOperationExpired(envelope.expiresAt, now())) {
        throw new AppError(409, 'OPERATION_EXPIRED', 'Operation expired before queue');
      }
      if (envelope.initiatorId && envelope.initiatorId !== actor.id) {
        throw new AppError(403, 'INITIATOR_MISMATCH', 'Initiator must be the authenticated user');
      }

      const existing = await prisma.operationJob.findUnique({ where: { idempotencyKey: envelope.idempotencyKey } });
      if (existing) {
        const same =
          existing.operationId === envelope.operationId &&
          existing.action === envelope.type &&
          existing.resourceId === envelope.resourceId &&
          (existing.environmentId ?? null) === (envelope.environmentId ?? null) &&
          existing.initiatorId === actor.id;
        if (!same) throw new AppError(409, 'IDEMPOTENCY_CONFLICT', 'Idempotency key already used by another operation');
        return { job: existing, replayed: true };
      }

      // Environment must exist and belong to the project named by the resource.
      let envCode = null;
      if (envelope.environmentId) {
        const env = await prisma.projectEnvironment.findUnique({ where: { id: envelope.environmentId } });
        if (!env || (envelope.resourceType === 'project' && env.projectId !== envelope.resourceId)) {
          throw new AppError(400, 'ENVIRONMENT_MISMATCH', 'Environment does not belong to the resource');
        }
        envCode = env.code;
      } else if (permissionForAction(envelope.type)?.startsWith('project.')) {
        throw new AppError(400, 'ENVIRONMENT_REQUIRED', 'Environment scope required for this operation');
      }

      const scope = {
        action: envelope.type,
        resourceType: envelope.resourceType,
        resourceId: envelope.resourceId,
        environmentId: envelope.environmentId ?? null,
      };
      if (!(await canScope(actor, scope))) {
        await audit({
          actorId: actor.id,
          action: 'operation.enqueue',
          resourceType: scope.resourceType,
          resourceId: scope.resourceId,
          environmentId: scope.environmentId,
          result: 'denied',
          correlationId: envelope.correlationId,
        });
        throw new AppError(403, 'FORBIDDEN', 'Insufficient permission for this resource and environment');
      }

      let risk = maxRisk(envelope.riskLevel, ACTION_MIN_RISK[envelope.type]);
      if (envCode === 'production') risk = maxRisk(risk, 'high');
      const needsApproval = requiresApproval(risk);
      const payload = envelope.payload ? redact(envelope.payload) : undefined;

      const job = await prisma.operationJob.create({
        data: {
          operationId: envelope.operationId,
          correlationId: envelope.correlationId,
          idempotencyKey: envelope.idempotencyKey,
          action: envelope.type,
          status: needsApproval ? 'PENDING_APPROVAL' : 'QUEUED',
          riskTier: risk,
          resourceType: envelope.resourceType,
          resourceId: envelope.resourceId,
          environmentId: envelope.environmentId ?? null,
          initiatorId: actor.id,
          approverId: null,
          payloadJson: payload,
          expiresAt: new Date(envelope.expiresAt),
        },
      });
      if (needsApproval) {
        await prisma.approvalRequest.create({
          data: {
            resourceType: envelope.resourceType,
            resourceId: envelope.resourceId,
            operationJobId: job.id,
            requesterId: actor.id,
            status: 'PENDING',
            impactJson: svc.buildImpact({ ...job, envCode }),
            rollbackPlan: typeof envelope.payload?.rollbackPlan === 'string' ? envelope.payload.rollbackPlan : null,
          },
        });
        await notifyOwners(
          {
            type: 'approval.requested',
            title: `Approval requested: ${job.action}`,
            resourceType: 'operation',
            resourceId: job.id,
          },
          { prisma, exceptUserId: actor.id },
        );
      }
      await audit({
        actorId: actor.id,
        action: 'operation.enqueue',
        resourceType: job.resourceType,
        resourceId: job.resourceId,
        environmentId: job.environmentId,
        result: 'success',
        correlationId: job.correlationId,
        after: { operationId: job.operationId, riskTier: risk, status: job.status },
      });
      return { job, replayed: false };
    },

    buildImpact(job) {
      return {
        action: job.action,
        resourceType: job.resourceType,
        resourceId: job.resourceId,
        environmentId: job.environmentId ?? null,
        environmentCode: job.envCode ?? null,
        riskTier: job.riskTier,
        requiresApproval: requiresApproval(job.riskTier),
        expiresAt: job.expiresAt ?? null,
        effects: [`Runs ${job.action} against ${job.resourceType} ${job.resourceId}`],
        executor: executor.name,
      };
    },

    async getById(id, actor) {
      const job = await load(id);
      if (actor) {
        const involved = actor.isOwner || job.initiatorId === actor.id || job.approverId === actor.id;
        if (!involved && !(await canScope(actor, job))) {
          throw new AppError(403, 'FORBIDDEN', 'Insufficient permission for this operation');
        }
      }
      return job;
    },

    async impactPreview(id, actor) {
      const job = await svc.getById(id, actor);
      let envCode = null;
      if (job.environmentId) {
        const env = await prisma.projectEnvironment.findUnique({ where: { id: job.environmentId } });
        envCode = env?.code ?? null;
      }
      const approval = job.approvals?.[0];
      return { ...svc.buildImpact({ ...job, envCode }), rollbackPlan: approval?.rollbackPlan ?? null, status: job.status };
    },

    async listApprovals({ status, limit }, actor) {
      const rows = await prisma.approvalRequest.findMany({
        where: { status },
        take: limit,
        orderBy: { createdAt: 'desc' },
        include: { operationJob: true },
      });
      if (actor?.isOwner) return rows;
      const visible = [];
      for (const row of rows) {
        if (row.requesterId === actor?.id) {
          visible.push(row);
          continue;
        }
        if (row.operationJob && (await canScope(actor, row.operationJob))) visible.push(row);
      }
      return visible;
    },

    async decide(id, decision, input, actor) {
      const job = await load(id);
      const pending = job.approvals.find((a) => a.status === 'PENDING');
      if (job.status !== 'PENDING_APPROVAL' || !pending) {
        throw new AppError(409, 'NOT_PENDING_APPROVAL', 'Operation is not awaiting approval');
      }
      if (job.initiatorId && job.initiatorId === actor.id) {
        await audit({
          actorId: actor.id,
          action: `operation.${decision}`,
          resourceType: job.resourceType,
          resourceId: job.resourceId,
          environmentId: job.environmentId,
          result: 'denied',
          correlationId: job.correlationId,
          after: { reason: 'initiator cannot approve own operation' },
        });
        throw new AppError(403, 'SEPARATION_OF_DUTIES', 'Initiator cannot decide their own operation');
      }
      if (!(await canScope(actor, job))) {
        throw new AppError(403, 'FORBIDDEN', 'Insufficient permission to decide this operation');
      }
      if (job.expiresAt && isOperationExpired(job.expiresAt, now())) {
        await markExpired(job, actor.id);
        throw new AppError(409, 'OPERATION_EXPIRED', 'Operation expired before decision');
      }
      const approved = decision === 'approve';
      await prisma.approvalRequest.update({
        where: { id: pending.id },
        data: {
          status: approved ? 'APPROVED' : 'DENIED',
          approverId: actor.id,
          reason: input.reason,
          rollbackPlan: input.rollbackPlan ?? pending.rollbackPlan ?? null,
          decidedAt: now(),
        },
      });
      const updated = await prisma.operationJob.update({
        where: { id: job.id },
        data: { status: approved ? 'QUEUED' : 'DENIED', approverId: actor.id },
      });
      if (pending.requesterId && pending.requesterId !== actor.id) {
        await notify(
          {
            userId: pending.requesterId,
            type: 'approval.decided',
            title: `Operation ${approved ? 'approved' : 'denied'}: ${job.action}`,
            resourceType: 'operation',
            resourceId: job.id,
          },
          { prisma },
        );
      }
      await audit({
        actorId: actor.id,
        action: `operation.${decision}`,
        resourceType: job.resourceType,
        resourceId: job.resourceId,
        environmentId: job.environmentId,
        result: approved ? 'success' : 'denied',
        correlationId: job.correlationId,
        after: { operationId: job.operationId, reason: input.reason },
      });
      return updated;
    },

    async cancel(id, actor) {
      const job = await load(id);
      if (TERMINAL.includes(job.status) || job.status === 'RUNNING') {
        throw new AppError(409, 'OPERATION_NOT_CANCELLABLE', 'Operation already finished or running');
      }
      const involved = actor?.isOwner || job.initiatorId === actor?.id;
      if (!involved && !(await canScope(actor, job))) {
        throw new AppError(403, 'FORBIDDEN', 'Insufficient permission to cancel this operation');
      }
      await prisma.approvalRequest.updateMany({
        where: { operationJobId: job.id, status: 'PENDING' },
        data: { status: 'DENIED', reason: 'operation cancelled', decidedAt: now() },
      });
      const updated = await prisma.operationJob.update({ where: { id: job.id }, data: { status: 'CANCELLED' } });
      await audit({
        actorId: actor?.id,
        action: 'operation.cancel',
        resourceType: job.resourceType,
        resourceId: job.resourceId,
        environmentId: job.environmentId,
        result: 'cancelled',
        correlationId: job.correlationId,
        after: { operationId: job.operationId },
      });
      return updated;
    },

    /** Runs through the injectable executor; a finished success is never re-executed. */
    async execute(id, actor) {
      const job = await load(id);
      if (job.status === 'SUCCESS') return job; // retry/replay: side effects not duplicated
      if (!(await canScope(actor, job))) {
        throw new AppError(403, 'FORBIDDEN', 'Insufficient permission to execute this operation');
      }
      if (job.expiresAt && isOperationExpired(job.expiresAt, now())) {
        await markExpired(job, actor?.id);
        throw new AppError(409, 'OPERATION_EXPIRED', 'Operation expired');
      }
      if (requiresApproval(job.riskTier) && (!job.approverId || job.approverId === job.initiatorId)) {
        throw new AppError(409, 'APPROVAL_REQUIRED', 'High and Critical operations need a separate approver');
      }
      if (!RETRYABLE.includes(job.status)) {
        throw new AppError(409, 'OPERATION_NOT_RUNNABLE', `Operation is ${job.status}`);
      }
      // Atomic claim so two concurrent callers cannot both run the side effect.
      const claim = await prisma.operationJob.updateMany({
        where: { id: job.id, status: { in: RETRYABLE } },
        data: { status: 'RUNNING' },
      });
      if (claim.count === 0) throw new AppError(409, 'OPERATION_NOT_RUNNABLE', 'Operation already claimed');

      const attemptId = `attempt-${(job.executions?.length ?? 0) + 1}`;
      const startedAt = now();
      let outcome;
      let timer;
      try {
        outcome = await Promise.race([
          executor.execute(job, { attemptId }),
          new Promise((resolve) => {
            timer = setTimeout(() => resolve({ result: 'TIMEOUT', detail: { timeoutMs } }), timeoutMs);
          }),
        ]);
      } catch (error) {
        outcome = { result: 'FAILED', detail: { error: String(error?.message ?? error).slice(0, 300) } };
      } finally {
        clearTimeout(timer);
      }
      const status = outcome.result === 'TIMEOUT' ? 'TIMEOUT' : outcome.result === 'FAILED' ? 'FAILED' : 'SUCCESS';
      await prisma.operationExecution.create({
        data: {
          operationJobId: job.id,
          attemptId,
          startedAt,
          finishedAt: now(),
          result: outcome.result,
          detailJson: redact(outcome.detail ?? {}),
        },
      });
      const updated = await prisma.operationJob.update({ where: { id: job.id }, data: { status } });
      if (status === 'FAILED' && /deploy/i.test(String(job.action))) {
        notifyChannels({ type: 'deployment.failed', severity: 'critical', title: `Deployment failed: ${job.action}`, resourceType: job.resourceType, resourceId: job.resourceId, dedupeKey: `deployment.failed:${job.id}` }, { prisma });
      }
      await audit({
        actorId: actor?.id,
        action: 'operation.execute',
        resourceType: job.resourceType,
        resourceId: job.resourceId,
        environmentId: job.environmentId,
        result: status.toLowerCase(),
        correlationId: job.correlationId,
        after: { operationId: job.operationId, attemptId, executor: executor.name },
      });
      return updated;
    },

    /** Sweeper: expire stale unfinished operations (call from a worker/cron). */
    async expireStale() {
      const stale = await prisma.operationJob.findMany({
        where: { status: { in: ['PENDING_APPROVAL', 'QUEUED'] }, expiresAt: { lte: now() } },
        take: 100,
      });
      for (const job of stale) await markExpired(job);
      return { expired: stale.length };
    },
  };
  return svc;
}
