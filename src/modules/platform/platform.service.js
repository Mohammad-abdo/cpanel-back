import { AppError } from '../../common/errors/app-error.js';
import { isSystemActor } from '../../common/system-actor.js';
import { redact } from '../audit/audit.service.js';
import { ACTION_RISK, PERM, requiresApproval } from './platform.risk.js';

export const APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;

/** Shared permission check. Exact scope: environment-scoped keys never pass without an environment. */
export async function assertCan(rbac, actor, check) {
  // Scheduled jobs act as the frozen SYSTEM_ACTOR (identity check: it cannot come from an HTTP session).
  if (isSystemActor(actor)) return;
  if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
  if (!rbac?.can) throw new AppError(500, 'RBAC_UNAVAILABLE', 'Authorization service unavailable');
  if (!(await rbac.can(actor, check))) {
    throw new AppError(403, 'FORBIDDEN', 'Insufficient permission for this resource and environment');
  }
}

export function createPlatformService({ prisma, now = () => new Date(), auditService = null, rbac = null, allowSelfApproval = false }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function request(input, actor) {
    const risk = ACTION_RISK[input.action];
    if (!risk) throw new AppError(400, 'UNKNOWN_ACTION', 'Unknown privileged action');
    if (!input.reason || !input.impact || !input.rollbackPlan) {
      throw new AppError(422, 'APPROVAL_FIELDS_REQUIRED', 'Reason, impact preview and rollback note are required');
    }
    const row = await prisma.approvalRequest.create({
      data: {
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        requesterId: actor.id,
        status: 'pending',
        reason: input.reason,
        impactJson: redact({ action: input.action, riskTier: risk, impact: input.impact, context: { ...(input.context ?? {}), binding: input.binding ?? null } }),
        rollbackPlan: input.rollbackPlan,
      },
    });
    await audit({ actorId: actor.id, action: 'approval.request', resourceType: input.resourceType, resourceId: input.resourceId, result: 'success', metadata: { approvalId: row.id, action: input.action, riskTier: risk } });
    return row;
  }

  return {
    request,

    /**
     * Gate for privileged actions. Low/medium proceed. High/critical return the pending request until
     * a separate approver approved it; an approved request is single-use and bound to action + resource.
     */
    async gate(input, actor) {
      if (!requiresApproval(input.action)) return { proceed: true, approval: null };
      if (!input.approvalId) {
        const approval = await request(input, actor);
        return { proceed: false, approval };
      }
      const row = await prisma.approvalRequest.findUnique({ where: { id: input.approvalId } });
      const meta = row?.impactJson ?? {};
      if (!row || row.resourceType !== input.resourceType || row.resourceId !== input.resourceId || meta.action !== input.action) {
        throw new AppError(409, 'APPROVAL_MISMATCH', 'Approval does not match this action and resource');
      }
      if ((meta.context?.binding ?? null) !== (input.binding ?? null)) {
        throw new AppError(409, 'APPROVAL_MISMATCH', 'Approval was issued for a different change');
      }
      if (row.status === 'consumed') throw new AppError(409, 'APPROVAL_CONSUMED', 'Approval was already used');
      if (row.status !== 'approved') throw new AppError(409, 'APPROVAL_NOT_APPROVED', 'Approval is not granted');
      if (now().getTime() - new Date(row.decidedAt ?? row.createdAt).getTime() > APPROVAL_TTL_MS) {
        throw new AppError(409, 'APPROVAL_EXPIRED', 'Approval has expired');
      }
      if (row.requesterId && row.requesterId !== actor.id) {
        throw new AppError(403, 'APPROVAL_REQUESTER_ONLY', 'Only the requester can execute an approved request');
      }
      // Atomic claim: two concurrent executions cannot both consume one approval.
      const claimed = await prisma.approvalRequest.updateMany({
        where: { id: row.id, status: 'approved' },
        data: { status: 'consumed' },
      });
      if (claimed.count !== 1) throw new AppError(409, 'APPROVAL_CONSUMED', 'Approval was already used');
      return { proceed: true, approval: row };
    },

    async decide(id, { decision, note }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      // Permission first: someone without approval rights must not learn whether a request exists or its state.
      await assertCan(rbac, actor, { permissionKey: PERM.APPROVAL_DECIDE, resourceType: 'platform', resourceId: 'platform', environmentId: null });
      const row = await prisma.approvalRequest.findUnique({ where: { id } });
      // Operation (deployment) approvals share this table but are decided through /operations/:id/approve.
      if (!row || row.operationJobId) throw new AppError(404, 'APPROVAL_NOT_FOUND', 'Approval request not found');
      if (row.status !== 'pending') throw new AppError(409, 'APPROVAL_NOT_PENDING', 'Approval request is not pending');
      if (now().getTime() - new Date(row.createdAt).getTime() > APPROVAL_TTL_MS) {
        throw new AppError(409, 'APPROVAL_EXPIRED', 'Approval request has expired');
      }
      if (!allowSelfApproval && row.requesterId === actor.id) {
        throw new AppError(403, 'SELF_APPROVAL_DENIED', 'Requester cannot approve their own request');
      }
      const updated = await prisma.approvalRequest.update({
        where: { id },
        data: { status: decision === 'approve' ? 'approved' : 'rejected', approverId: actor.id, decidedAt: now() },
      });
      await audit({ actorId: actor.id, action: `approval.${decision}`, resourceType: row.resourceType, resourceId: row.resourceId, result: 'success', metadata: { approvalId: id, note: note ?? null } });
      return updated;
    },

    async list({ status, limit }, actor) {
      await assertCan(rbac, actor, { permissionKey: PERM.APPROVAL_DECIDE, resourceType: "platform", resourceId: "platform", environmentId: null });
      // Platform approvals only: operation approvals (operationJobId set, status PENDING/APPROVED in upper case)
      // live in the same table, and MySQL's case-insensitive collation would otherwise match them too.
      return prisma.approvalRequest.findMany({ where: { operationJobId: null, ...(status ? { status } : {}) }, take: limit, orderBy: { createdAt: 'desc' } });
    },
  };
}
