import { describe, expect, it, vi } from 'vitest';
import { createOperationsService } from '../src/modules/operations/operations.service.js';
import { fakePrisma, U } from './phase3-helpers.js';

const OWNER = { id: U(1), isOwner: true };
const DEV = { id: U(2), isOwner: false };
const REVIEWER = { id: U(3), isOwner: false };
const PROJECT = U(10);
const ENV_STG = U(20);
const ENV_PROD = U(21);
const NOW = new Date('2026-01-01T00:00:00Z');
const FUTURE = '2026-01-02T00:00:00.000Z';

function setup({ grants = [], executor, timeoutMs, clock = () => NOW } = {}) {
  const prisma = fakePrisma({
    projectEnvironment: [
      { id: ENV_STG, projectId: PROJECT, code: 'staging' },
      { id: ENV_PROD, projectId: PROJECT, code: 'production' },
      { id: U(22), projectId: U(11), code: 'staging' },
    ],
    resourceGrant: grants,
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
  const svc = createOperationsService({ prisma, auditService, executor, timeoutMs, now: clock });
  return { prisma, svc, auditService };
}

const grant = (userId, key, environmentId, permissionCode) => ({
  id: `${userId}-${environmentId}-${key}`,
  userId,
  permissionCode: key,
  resourceType: 'project',
  resourceId: PROJECT,
  environmentId,
  revokedAt: null,
  expiresAt: null,
});

let seq = 100;
const envelope = (over = {}) => {
  seq += 1;
  return {
    operationId: U(seq),
    correlationId: U(seq + 1000),
    idempotencyKey: `idem-key-${seq}`,
    type: 'deployment.run',
    resourceType: 'project',
    resourceId: PROJECT,
    environmentId: ENV_STG,
    riskLevel: 'low',
    expiresAt: FUTURE,
    payload: { branch: 'main', apiToken: 'super-secret' },
    ...over,
  };
};

describe('operation queue', () => {
  it('queues a medium-risk staging operation, forces initiator, redacts payload', async () => {
    const { svc, prisma } = setup();
    const { job, replayed } = await svc.enqueue(envelope(), OWNER);
    expect(replayed).toBe(false);
    expect(job.status).toBe('QUEUED');
    expect(job.riskTier).toBe('medium');
    expect(job.initiatorId).toBe(OWNER.id);
    expect(JSON.stringify(prisma.operationJob.rows[0].payloadJson)).not.toContain('super-secret');
  });

  it('rejects non-owner without exact-scope grant and audits denial', async () => {
    const { svc, auditService } = setup();
    await expect(svc.enqueue(envelope(), DEV)).rejects.toMatchObject({ status: 403 });
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ result: 'denied' }));
  });

  it('staging grant does not satisfy production', async () => {
    const { svc } = setup({ grants: [grant(DEV.id, 'project.deploy.create', ENV_STG)] });
    await expect(svc.enqueue(envelope({ environmentId: ENV_PROD }), DEV)).rejects.toMatchObject({ status: 403 });
    const ok = await svc.enqueue(envelope(), DEV);
    expect(ok.job.status).toBe('QUEUED');
  });

  it('rejects an environment from another project', async () => {
    const { svc } = setup();
    await expect(svc.enqueue(envelope({ environmentId: U(22) }), OWNER)).rejects.toMatchObject({
      code: 'ENVIRONMENT_MISMATCH',
    });
  });

  it('rejects spoofed initiator and expired envelopes', async () => {
    const { svc } = setup();
    await expect(svc.enqueue(envelope({ initiatorId: U(9) }), OWNER)).rejects.toMatchObject({ code: 'INITIATOR_MISMATCH' });
    await expect(svc.enqueue(envelope({ expiresAt: '2025-12-31T00:00:00.000Z' }), OWNER)).rejects.toMatchObject({
      code: 'OPERATION_EXPIRED',
    });
  });

  it('replays a duplicate idempotency key without a second job; conflicts on different payload target', async () => {
    const { svc, prisma } = setup();
    const env = envelope();
    await svc.enqueue(env, OWNER);
    const again = await svc.enqueue(env, OWNER);
    expect(again.replayed).toBe(true);
    expect(prisma.operationJob.rows).toHaveLength(1);
    await expect(
      svc.enqueue({ ...env, operationId: U(999), resourceId: U(77) }, OWNER),
    ).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
  });
});

describe('approval workflow', () => {
  const highEnv = () => envelope({ type: 'deployment.rollback', environmentId: ENV_PROD, riskLevel: 'low' });
  const grants = [
    grant(DEV.id, 'project.deploy.create', ENV_PROD),
    grant(REVIEWER.id, 'project.deploy.create', ENV_PROD),
  ];

  it('production and rollback are escalated to high and wait for approval', async () => {
    const { svc, prisma } = setup({ grants });
    const { job } = await svc.enqueue(highEnv(), DEV);
    expect(job.riskTier).toBe('high');
    expect(job.status).toBe('PENDING_APPROVAL');
    expect(prisma.approvalRequest.rows[0].status).toBe('PENDING');
    await expect(svc.execute(job.id, DEV)).rejects.toMatchObject({ code: 'APPROVAL_REQUIRED' });
  });

  it('initiator cannot approve own operation (separation of duties)', async () => {
    const { svc } = setup({ grants });
    const { job } = await svc.enqueue(highEnv(), DEV);
    await expect(svc.decide(job.id, 'approve', { reason: 'self approve' }, DEV)).rejects.toMatchObject({
      code: 'SEPARATION_OF_DUTIES',
    });
  });

  it('ungranted user cannot approve; separate approver can, then executes with audit', async () => {
    const { svc, auditService } = setup({ grants });
    const { job } = await svc.enqueue(highEnv(), DEV);
    await expect(svc.decide(job.id, 'approve', { reason: 'no rights' }, { id: U(5), isOwner: false })).rejects.toMatchObject({
      status: 403,
    });
    const approved = await svc.decide(job.id, 'approve', { reason: 'looks safe' }, REVIEWER);
    expect(approved.status).toBe('QUEUED');
    expect(approved.approverId).toBe(REVIEWER.id);
    const done = await svc.execute(job.id, REVIEWER);
    expect(done.status).toBe('SUCCESS');
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'operation.execute' }));
  });

  it('denied operations never execute and are audited', async () => {
    const { svc, auditService } = setup({ grants });
    const { job } = await svc.enqueue(highEnv(), DEV);
    const denied = await svc.decide(job.id, 'deny', { reason: 'too risky' }, REVIEWER);
    expect(denied.status).toBe('DENIED');
    await expect(svc.execute(job.id, REVIEWER)).rejects.toMatchObject({ code: 'OPERATION_NOT_RUNNABLE' });
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'operation.deny' }));
  });

  it('expired approval is marked EXPIRED and audited', async () => {
    let t = NOW;
    const { svc, auditService, prisma } = setup({ grants, clock: () => t });
    const { job } = await svc.enqueue(highEnv(), DEV);
    t = new Date('2026-01-03T00:00:00Z');
    await expect(svc.decide(job.id, 'approve', { reason: 'late approval' }, REVIEWER)).rejects.toMatchObject({
      code: 'OPERATION_EXPIRED',
    });
    expect(prisma.operationJob.rows[0].status).toBe('EXPIRED');
    expect(prisma.approvalRequest.rows[0].status).toBe('EXPIRED');
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'operation.expire' }));
  });

  it('cancel is audited and finished operations cannot be cancelled', async () => {
    const { svc, auditService } = setup({ grants });
    const { job } = await svc.enqueue(highEnv(), DEV);
    const cancelled = await svc.cancel(job.id, DEV);
    expect(cancelled.status).toBe('CANCELLED');
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'operation.cancel' }));
    await expect(svc.cancel(job.id, DEV)).rejects.toMatchObject({ code: 'OPERATION_NOT_CANCELLABLE' });
  });
});

describe('execution', () => {
  it('does not re-run a successful operation (side effects not duplicated)', async () => {
    const executor = { name: 't', execute: vi.fn().mockResolvedValue({ result: 'OK', detail: {} }) };
    const { svc } = setup({ executor });
    const { job } = await svc.enqueue(envelope(), OWNER);
    await svc.execute(job.id, OWNER);
    await svc.execute(job.id, OWNER);
    expect(executor.execute).toHaveBeenCalledTimes(1);
  });

  it('records failure then allows retry with a new attempt id', async () => {
    const executor = {
      name: 't',
      execute: vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce({ result: 'OK', detail: {} }),
    };
    const { svc, prisma } = setup({ executor });
    const { job } = await svc.enqueue(envelope(), OWNER);
    expect((await svc.execute(job.id, OWNER)).status).toBe('FAILED');
    expect((await svc.execute(job.id, OWNER)).status).toBe('SUCCESS');
    expect(prisma.operationExecution.rows.map((e) => e.attemptId)).toEqual(['attempt-1', 'attempt-2']);
  });

  it('times out slow executors', async () => {
    const executor = { name: 't', execute: () => new Promise(() => {}) };
    const { svc, auditService } = setup({ executor, timeoutMs: 10 });
    const { job } = await svc.enqueue(envelope(), OWNER);
    expect((await svc.execute(job.id, OWNER)).status).toBe('TIMEOUT');
    expect(auditService.record).toHaveBeenCalledWith(expect.objectContaining({ result: 'timeout' }));
  });

  it('default executor is simulated and never real', async () => {
    const { svc, prisma } = setup();
    const { job } = await svc.enqueue(envelope(), OWNER);
    await svc.execute(job.id, OWNER);
    expect(prisma.operationExecution.rows[0].result).toBe('SIMULATED');
  });

  it('impact preview and expireStale work', async () => {
    let t = NOW;
    const { svc } = setup({ clock: () => t });
    const { job } = await svc.enqueue(envelope(), OWNER);
    const impact = await svc.impactPreview(job.id, OWNER);
    expect(impact.environmentCode).toBe('staging');
    t = new Date('2026-02-01T00:00:00Z');
    expect(await svc.expireStale()).toEqual({ expired: 1 });
  });
});
