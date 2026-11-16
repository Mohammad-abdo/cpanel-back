import { vi } from 'vitest';
import { createPlatformService } from '../src/modules/platform/platform.service.js';
import { createSimulatedAdapters } from '../src/modules/platform/platform.adapters.js';

export const U = (n) => `00000000-0000-4000-8000-0000000000${String(n).padStart(2, '0')}`;
export const OWNER = { id: U(1), isOwner: true, email: 'o@x.test' };
export const DEV = { id: U(2), isOwner: false, email: 'd@x.test' };
export const APPROVER = { id: U(3), isOwner: false, email: 'a@x.test' };
export const PROJECT = U(10);
export const ENV_STAGING = U(11);
export const ENV_PROD = U(12);
export const KEY = 'a'.repeat(64);

/** Exact-scope rbac stub that mirrors rbac.can: a grant for one environment never satisfies another. */
export function makeRbac(grants = []) {
  return {
    can: vi.fn(async (actor, c) => {
      if (actor?.isOwner) return true;
      if (!actor?.id) return false;
      return grants.some(
        (g) =>
          g.userId === actor.id &&
          g.permissionKey === c.permissionKey &&
          (g.resourceId ?? null) === (c.resourceId ?? null) &&
          (g.environmentId ?? null) === (c.environmentId ?? null),
      );
    }),
  };
}

export function makeApprovalPrisma(extra = {}) {
  const rows = new Map();
  let n = 100;
  return {
    rows,
    approvalRequest: {
      create: vi.fn(async ({ data }) => {
        const row = { id: U(++n), createdAt: new Date(), decidedAt: null, approverId: null, ...data };
        rows.set(row.id, row);
        return row;
      }),
      findUnique: vi.fn(async ({ where }) => rows.get(where.id) ?? null),
      update: vi.fn(async ({ where, data }) => {
        Object.assign(rows.get(where.id), data);
        return rows.get(where.id);
      }),
      // Atomic claim used by platform.gate: only rows still matching the status filter are updated.
      updateMany: vi.fn(async ({ where, data }) => {
        const row = rows.get(where.id);
        if (!row || (where.status && row.status !== where.status)) return { count: 0 };
        Object.assign(row, data);
        return { count: 1 };
      }),
      findMany: vi.fn(async () => [...rows.values()]),
    },
    auditEvent: { create: vi.fn(async () => ({})) },
    ...extra,
  };
}

export function makeCtx({ grants = [], prismaExtra = {}, now = () => new Date() } = {}) {
  const prisma = makeApprovalPrisma(prismaExtra);
  const rbac = makeRbac([
    { userId: APPROVER.id, permissionKey: 'platform.approval.decide', resourceId: 'platform', environmentId: null },
    ...grants,
  ]);
  const auditService = { record: vi.fn(async () => ({})) };
  const platform = createPlatformService({ prisma, now, auditService, rbac });
  const adapters = createSimulatedAdapters({ now });
  return { prisma, rbac, auditService, platform, adapters, now };
}

/** Request -> approve (by a different user) and return the approval id. */
export async function approve(ctx, approvalId, approver = APPROVER) {
  await ctx.platform.decide(approvalId, { decision: 'approve' }, approver);
  return approvalId;
}

export const BACKUP_POLICY = { id: U(90), projectId: PROJECT, environmentId: ENV_PROD, retentionDays: 30, rpoMinutes: 1440, rtoMinutes: 120, archivedAt: null };

export function backupPrisma({ runs = [], artifacts = [] } = {}, policy = BACKUP_POLICY) {
  const runStore = new Map(runs.map((r) => [r.id, { ...r }]));
  const artStore = new Map(artifacts.map((a) => [a.id, { ...a }]));
  let n = 500;
  return {
    runStore,
    artStore,
    projectEnvironment: { findUnique: vi.fn(async ({ where }) => ({ id: where.id, projectId: PROJECT })) },
    backupPolicy: { findMany: vi.fn(async () => [policy]), findUnique: vi.fn(async () => policy), create: vi.fn(async ({ data }) => ({ id: policy.id, ...data })) },
    backupRun: {
      create: vi.fn(async ({ data }) => { const r = { id: U(++n), ...data }; runStore.set(r.id, r); return r; }),
      update: vi.fn(async ({ where, data }) => { Object.assign(runStore.get(where.id), data); return runStore.get(where.id); }),
      findFirst: vi.fn(async ({ where }) => {
        const all = [...runStore.values()];
        if (where.status === undefined) return all.filter((r) => r.policyId === where.policyId).sort((a, b) => b.startedAt - a.startedAt)[0] ?? null;
        if (where.status?.in) return all.find((r) => where.status.in.includes(r.status)) ?? null;
        return all.filter((r) => r.status === where.status && r.verificationStatus === where.verificationStatus).sort((a, b) => b.finishedAt - a.finishedAt)[0] ?? null;
      }),
      findMany: vi.fn(async () => [...runStore.values()].filter((r) => r.status === 'retained').sort((a, b) => b.finishedAt - a.finishedAt)),
      findUnique: vi.fn(async ({ where }) => runStore.get(where.id) ?? null),
      count: vi.fn(async ({ where } = {}) =>
        [...runStore.values()].filter(
          (r) =>
            (!where?.policyId || r.policyId === where.policyId) &&
            (!where?.status || r.status === where.status) &&
            (!where?.verificationStatus || r.verificationStatus === where.verificationStatus),
        ).length,
      ),
    },
    backupArtifact: {
      create: vi.fn(async ({ data }) => { const a = { id: U(++n), ...data }; artStore.set(a.id, a); return a; }),
      findUnique: vi.fn(async ({ where }) => { const a = artStore.get(where.id); return a ? { ...a, backupRun: { ...runStore.get(a.backupRunId), policy } } : null; }),
      findMany: vi.fn(async ({ where }) => [...artStore.values()].filter((a) => a.backupRunId === where.backupRunId)),
      deleteMany: vi.fn(async ({ where }) => { for (const [k, a] of artStore) if (a.backupRunId === where.backupRunId) artStore.delete(k); }),
    },
  };
}

