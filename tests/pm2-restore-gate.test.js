import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createServerAccessService } from '../src/modules/server-access/server-access.service.js';
import { createDatabasesService } from '../src/modules/databases/databases.service.js';
import { pm2BodySchema } from '../src/modules/server-access/server-access.validator.js';
import { projectPm2BodySchema } from '../src/modules/projects/projects.validator.js';
import { instanceRestoreQuerySchema } from '../src/modules/databases/databases.validator.js';
import { ACTION_RISK, requiresApproval } from '../src/modules/platform/platform.risk.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';
import { createFakePrisma } from './http/fake-prisma.js';
import { createFakeSsh, liveResponder } from './server-access-fake-ssh.js';
import { APPROVER, OWNER, U, makeCtx } from './phase6-helpers.js';

const KEY = 'e'.repeat(64);
const WHY = { reason: 'Planned maintenance window', rollbackNote: 'Start the process again' };

describe('risk registry', () => {
  it('classifies live restore as critical and PM2 stop/restart/reload as high; start stays ungated', () => {
    expect(ACTION_RISK['db.restore.live']).toBe('critical');
    for (const a of ['stop', 'restart', 'reload', 'delete']) expect(ACTION_RISK[`pm2.${a}`]).toBe('high');
    expect(requiresApproval('db.restore.live')).toBe(true);
    expect(requiresApproval('pm2.start')).toBe(false);
  });
  it('validators accept optional approvalId/reason/rollbackNote and still reject unknown keys', () => {
    const id = randomUUID();
    expect(pm2BodySchema.safeParse({ name: 'a', action: 'restart', approvalId: id, ...WHY }).success).toBe(true);
    expect(projectPm2BodySchema.safeParse({ action: 'stop', approvalId: id, ...WHY }).success).toBe(true);
    expect(instanceRestoreQuerySchema.safeParse({ confirm: 'ALL', approvalId: id, ...WHY }).success).toBe(true);
    expect(pm2BodySchema.safeParse({ name: 'a', action: 'restart', approvalId: 'nope' }).success).toBe(false);
    expect(pm2BodySchema.safeParse({ name: 'a', action: 'restart', extra: 1 }).success).toBe(false);
  });
});

describe('PM2 gate', () => {
  async function setup() {
    const prisma = createFakePrisma();
    const server = await prisma.server.create({ data: { alias: 'web-1', status: 'online', archivedAt: null } });
    await prisma.serverCredential.create({
      data: { serverId: server.id, host: 'fake.invalid', port: 22, username: 't', authType: 'password', secretEnc: encrypt(Buffer.from('pw'), KEY), hostKeySha256: 'SHA256:x' },
    });
    const ssh = createFakeSsh({ respond: liveResponder() });
    const ctx = makeCtx();
    const svc = createServerAccessService({ prisma, connector: ssh.connector, auditService: { record: vi.fn(async () => ({})) }, credentialKey: () => KEY, platform: ctx.platform });
    return { ctx, svc, ssh, serverId: server.id };
  }

  it('returns approvalRequired without touching SSH, bound to action + server + process', async () => {
    const t = await setup();
    const res = await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'restart', ...WHY }, OWNER);
    expect(res.approvalRequired).toBe(true);
    expect(res.approval).toMatchObject({ resourceType: 'server', resourceId: t.serverId, status: 'pending' });
    expect(res.approval.impactJson).toMatchObject({ action: 'pm2.restart', riskTier: 'high' });
    expect(t.ssh.connector.connect).not.toHaveBeenCalled();
  });
  it('delete requires approval (fail-closed allowlist)', async () => {
    const t = await setup();
    const r = await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'delete', ...WHY }, OWNER);
    expect(r.approvalRequired).toBe(true);
  });
  it('422 when the reason or rollback note is missing', async () => {
    const t = await setup();
    await expect(t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'stop' }, OWNER)).rejects.toMatchObject({ status: 422, code: 'APPROVAL_FIELDS_REQUIRED' });
  });
  it('an approved request replays once; a second replay is APPROVAL_CONSUMED', async () => {
    const t = await setup();
    const { approval } = await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'reload', ...WHY }, OWNER);
    await t.ctx.platform.decide(approval.id, { decision: 'approve' }, APPROVER);
    const done = await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'reload', approvalId: approval.id }, OWNER);
    expect(done).toMatchObject({ ok: true, action: 'reload' });
    await expect(t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'reload', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });
  it('an approval for another process, action or server is APPROVAL_MISMATCH and runs nothing', async () => {
    const t = await setup();
    const { approval } = await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'restart', ...WHY }, OWNER);
    await t.ctx.platform.decide(approval.id, { decision: 'approve' }, APPROVER);
    const calls = t.ssh.connector.connect.mock.calls.length;
    await expect(t.svc.pm2Control(t.serverId, { name: 'worker', action: 'restart', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    await expect(t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'stop', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    await expect(t.svc.pm2Control(randomUUID(), { name: 'shop-api', action: 'restart', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    expect(t.ssh.connector.connect.mock.calls.length).toBe(calls);
  });
  it('replaying before approval is APPROVAL_NOT_APPROVED; a non-Owner requester cannot approve their own request', async () => {
    const t = await setup();
    const { approval } = await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'stop', ...WHY }, OWNER);
    await expect(t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'stop', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_APPROVED' });
    const own = await t.ctx.platform.request({ action: 'dns.change', resourceType: 'server', resourceId: t.serverId, reason: 'because', impact: ['x'], rollbackPlan: 'undo' }, APPROVER);
    await expect(t.ctx.platform.decide(own.id, { decision: 'approve' }, APPROVER)).rejects.toMatchObject({ code: 'SELF_APPROVAL_DENIED' });
  });
  it('Owner self-approval replays once, is audited selfApproved, bound to action/process, then APPROVAL_CONSUMED', async () => {
    const t = await setup();
    const { approval } = await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'stop', ...WHY }, OWNER);
    await t.ctx.platform.decide(approval.id, { decision: 'approve' }, OWNER);
    expect(t.ctx.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'approval.approve', metadata: expect.objectContaining({ selfApproved: true }) }));
    await expect(t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'restart', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    await expect(t.svc.pm2Control(t.serverId, { name: 'worker', action: 'stop', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    expect(await t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'stop', approvalId: approval.id }, OWNER)).toMatchObject({ ok: true, action: 'stop' });
    await expect(t.svc.pm2Control(t.serverId, { name: 'shop-api', action: 'stop', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });
  it('start, logs and describe are not gated', async () => {
    const t = await setup();
    expect(await t.svc.pm2Control(t.serverId, { name: 'worker', action: 'start' }, OWNER)).toMatchObject({ ok: true });
    expect(t.ctx.prisma.rows.size).toBe(0);
  });
  it('fails closed with 500 GATE_UNAVAILABLE when no approval service is wired', async () => {
    const t = await setup();
    const bare = createServerAccessService({ prisma: createFakePrisma(), connector: t.ssh.connector, credentialKey: () => KEY });
    await expect(bare.pm2Control(t.serverId, { name: 'x', action: 'restart' }, OWNER)).rejects.toMatchObject({ status: 500, code: 'GATE_UNAVAILABLE' });
  });
});

describe('live DB restore gate', () => {
  const INSTANCE = U(60);
  const DUMP = Buffer.from('-- dump\nCREATE TABLE t (id int);\n');
  function setup() {
    const ctx = makeCtx({
      prismaExtra: { databaseInstance: { findUnique: vi.fn(async () => ({ id: INSTANCE, name: 'main-mysql', engine: 'mysql', serverId: U(70) })) } },
    });
    const serverAccessService = { dbRestore: vi.fn(async () => ({ restored: true })) };
    const svc = createDatabasesService({ ...ctx, serverAccessService });
    return { ctx, svc, serverAccessService };
  }
  const input = (over = {}) => ({ db: 'shop_db', bytes: DUMP, confirm: 'shop_db', ...WHY, ...over });

  it('requires typed confirmation before any approval is requested', async () => {
    const t = setup();
    await expect(t.svc.liveRestore(INSTANCE, input({ confirm: 'nope' }), OWNER)).rejects.toMatchObject({ code: 'CONFIRM_MISMATCH' });
    expect(t.ctx.prisma.rows.size).toBe(0);
  });
  it('returns approvalRequired (critical) without restoring', async () => {
    const t = setup();
    const res = await t.svc.liveRestore(INSTANCE, input(), OWNER);
    expect(res.approvalRequired).toBe(true);
    expect(res.approval).toMatchObject({ resourceType: 'database_instance', resourceId: INSTANCE });
    expect(res.approval.impactJson).toMatchObject({ action: 'db.restore.live', riskTier: 'critical' });
    expect(t.serverAccessService.dbRestore).not.toHaveBeenCalled();
  });
  it('replay with the approvalId restores once, then APPROVAL_CONSUMED', async () => {
    const t = setup();
    const { approval } = await t.svc.liveRestore(INSTANCE, input(), OWNER);
    await t.ctx.platform.decide(approval.id, { decision: 'approve' }, APPROVER);
    const replay = { db: 'shop_db', bytes: DUMP, confirm: 'shop_db', approvalId: approval.id };
    expect(await t.svc.liveRestore(INSTANCE, replay, OWNER)).toEqual({ restored: true });
    expect(t.serverAccessService.dbRestore).toHaveBeenCalledTimes(1);
    await expect(t.svc.liveRestore(INSTANCE, replay, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });
  it('an approval cannot be reused for a different dump or target (APPROVAL_MISMATCH)', async () => {
    const t = setup();
    const { approval } = await t.svc.liveRestore(INSTANCE, input(), OWNER);
    await t.ctx.platform.decide(approval.id, { decision: 'approve' }, APPROVER);
    await expect(t.svc.liveRestore(INSTANCE, { db: 'shop_db', bytes: Buffer.from('-- other dump\nDROP TABLE t;'), confirm: 'shop_db', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    await expect(t.svc.liveRestore(INSTANCE, { db: 'other_db', bytes: DUMP, confirm: 'other_db', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    expect(t.serverAccessService.dbRestore).not.toHaveBeenCalled();
  });
  it('non-Owner self-approval is denied and an unapproved replay is refused', async () => {
    const t = setup();
    const { approval } = await t.svc.liveRestore(INSTANCE, input(), OWNER);
    const own = await t.ctx.platform.request({ action: 'dns.change', resourceType: 'database_instance', resourceId: INSTANCE, reason: 'because', impact: ['x'], rollbackPlan: 'undo' }, APPROVER);
    await expect(t.ctx.platform.decide(own.id, { decision: 'approve' }, APPROVER)).rejects.toMatchObject({ code: 'SELF_APPROVAL_DENIED' });
    await expect(t.svc.liveRestore(INSTANCE, { db: 'shop_db', bytes: DUMP, confirm: 'shop_db', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_APPROVED' });
  });
  it('Owner self-approval restores once, is audited selfApproved, bound to dump/target, then APPROVAL_CONSUMED', async () => {
    const t = setup();
    const { approval } = await t.svc.liveRestore(INSTANCE, input(), OWNER);
    await t.ctx.platform.decide(approval.id, { decision: 'approve' }, OWNER);
    expect(t.ctx.auditService.record).toHaveBeenCalledWith(expect.objectContaining({ action: 'approval.approve', metadata: expect.objectContaining({ selfApproved: true }) }));
    await expect(t.svc.liveRestore(INSTANCE, { db: 'other_db', bytes: DUMP, confirm: 'other_db', approvalId: approval.id }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_MISMATCH' });
    const replay = { db: 'shop_db', bytes: DUMP, confirm: 'shop_db', approvalId: approval.id };
    expect(await t.svc.liveRestore(INSTANCE, replay, OWNER)).toEqual({ restored: true });
    await expect(t.svc.liveRestore(INSTANCE, replay, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_CONSUMED' });
  });
  it('non-owners are refused before the gate', async () => {
    const t = setup();
    await expect(t.svc.liveRestore(INSTANCE, input(), { id: U(2), isOwner: false })).rejects.toMatchObject({ status: 403, code: 'OWNER_ONLY' });
  });
});
