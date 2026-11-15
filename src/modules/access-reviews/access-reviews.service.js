import { AppError } from '../../common/errors/app-error.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { notify } from '../notifications/notifications.service.js';

const HIGH_RISK = new Set(['ssl.issue', 'server.firewall.update', 'project.backup.restore', 'project.secret.rotate', 'project.database.manage', 'team.permission.assign']);
const PLATFORM = { resourceType: 'platform', resourceId: 'platform', environmentId: null };

/** Classify one active grant. A grant can raise several findings. */
export function classifyGrant(grant, user, at) {
  const kinds = [];
  if (grant.expiresAt && new Date(grant.expiresAt) <= at) kinds.push('stale_expired_not_revoked');
  if (user?.disabledAt || (user && user.status !== 'active')) kinds.push('disabled_user_active_grant');
  if (HIGH_RISK.has(grant.permissionCode) && !grant.expiresAt) kinds.push('high_risk_no_expiry');
  if (!grant.grantedById) kinds.push('no_grantor_on_record');
  return kinds;
}

export function createAccessReviewsService({ prisma, now = () => new Date(), auditService = null, rbac = null }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'access_review', ...event }) : null);

  async function load(id) {
    const r = await prisma.accessReview.findUnique({ where: { id } });
    if (!r) throw new AppError(404, 'REVIEW_NOT_FOUND', 'Access review not found');
    return r;
  }
  const requireReviewer = (r, actor) => {
    if (r.reviewerId !== actor.id && !actor.isOwner) throw new AppError(403, 'NOT_REVIEWER', 'Only the assigned reviewer can act on this review');
  };

  async function createReview(input, reviewerId, auditActorId) {
    const start = new Date(input.periodStart);
    const end = new Date(input.periodEnd);
    if (!(end > start)) throw new AppError(422, 'PERIOD_INVALID', 'Review period end must be after start');
    const grants = await prisma.resourceGrant.findMany({ where: { revokedAt: null, ...(input.subjectUserId ? { userId: input.subjectUserId } : {}) }, include: { user: true } });
    const items = grants
      // The reviewer's own grants are listed for transparency but cannot be decided by them.
      .map((g) => ({
        grantId: g.id,
        userId: g.userId,
        permissionCode: g.permissionCode,
        resourceType: g.resourceType,
        resourceId: g.resourceId,
        environmentId: g.environmentId ?? null,
        findings: classifyGrant(g, g.user, now()),
        ownGrant: g.userId === reviewerId,
        decision: null,
      }));
    const row = await prisma.accessReview.create({
      data: { reviewerId, subjectUserId: input.subjectUserId ?? null, periodStart: start, periodEnd: end, status: 'open', findingsJson: { items, generatedAt: now().toISOString() } },
    });
    await audit({ actorId: auditActorId, action: 'access_review.start', resourceId: row.id, result: 'success', after: { grants: items.length, flagged: items.filter((i) => i.findings.length).length } });
    return row;
  }

  return {
    async list({ status, limit }, actor) {
      await assertCan(rbac, actor, { permissionKey: PERM.ACCESS_REVIEW, ...PLATFORM });
      return prisma.accessReview.findMany({ where: status ? { status } : {}, take: limit, orderBy: { createdAt: 'desc' } });
    },

    async get(id, actor) {
      await assertCan(rbac, actor, { permissionKey: PERM.ACCESS_REVIEW, ...PLATFORM });
      return load(id);
    },

    /** Snapshot active grants with findings. A reviewer never reviews their own access. */
    async start(input, actor) {
      await assertCan(rbac, actor, { permissionKey: PERM.ACCESS_REVIEW, ...PLATFORM });
      if (input.subjectUserId && input.subjectUserId === actor.id) throw new AppError(403, 'SELF_REVIEW_DENIED', 'You cannot review your own access');
      return createReview(input, actor.id, actor.id);
    },

    /**
     * Scheduled review: when the newest review is older than `everyDays`, open one covering that
     * period, assign it to an active Owner and notify them. Nothing is decided automatically.
     */
    async startDue(at = now(), { everyDays = 90 } = {}) {
      const every = everyDays * 86400000;
      const last = await prisma.accessReview.findFirst({ orderBy: { createdAt: 'desc' } });
      if (last && at.getTime() - new Date(last.createdAt).getTime() < every) return { started: false, reason: 'not_due' };
      const owner = await prisma.user.findFirst({ where: { ownerFlag: true, status: 'active', disabledAt: null }, orderBy: { createdAt: 'asc' } });
      if (!owner) return { started: false, reason: 'no_active_owner' };
      const row = await createReview({ periodStart: new Date(at.getTime() - every).toISOString(), periodEnd: at.toISOString() }, owner.id, null);
      await notify({ userId: owner.id, type: 'access_review.scheduled', title: 'Scheduled access review is ready', resourceType: 'access_review', resourceId: row.id }, { prisma });
      return { started: true, reviewId: row.id };
    },


    async decide(id, { decisions }, actor) {
      const review = await load(id);
      await assertCan(rbac, actor, { permissionKey: PERM.ACCESS_REVIEW, ...PLATFORM });
      requireReviewer(review, actor);
      if (review.status !== 'open') throw new AppError(409, 'REVIEW_NOT_OPEN', 'Review is already completed');
      const items = review.findingsJson.items.map((i) => ({ ...i }));
      for (const d of decisions) {
        const item = items.find((i) => i.grantId === d.grantId);
        if (!item) throw new AppError(422, 'GRANT_NOT_IN_REVIEW', 'Grant is not part of this review');
        if (item.ownGrant) throw new AppError(403, 'SELF_REVIEW_DENIED', 'You cannot decide on your own grants');
        if (d.decision === 'revoke') await rbac.revoke(d.grantId, actor);
        item.decision = d.decision;
        item.note = d.note ?? null;
        item.decidedAt = now().toISOString();
      }
      const saved = await prisma.accessReview.update({ where: { id }, data: { findingsJson: { ...review.findingsJson, items } } });
      await audit({ actorId: actor.id, action: 'access_review.decide', resourceId: id, result: 'success', after: { decided: decisions.length, revoked: decisions.filter((d) => d.decision === 'revoke').length } });
      return saved;
    },

    async complete(id, actor) {
      const review = await load(id);
      await assertCan(rbac, actor, { permissionKey: PERM.ACCESS_REVIEW, ...PLATFORM });
      requireReviewer(review, actor);
      if (review.status !== 'open') throw new AppError(409, 'REVIEW_NOT_OPEN', 'Review is already completed');
      const pending = review.findingsJson.items.filter((i) => !i.decision && !i.ownGrant);
      if (pending.length) throw new AppError(409, 'REVIEW_INCOMPLETE', `${pending.length} grant(s) still need a decision`);
      const saved = await prisma.accessReview.update({ where: { id }, data: { status: 'completed' } });
      await audit({ actorId: actor.id, action: 'access_review.complete', resourceId: id, result: 'success' });
      return saved;
    },
  };
}
