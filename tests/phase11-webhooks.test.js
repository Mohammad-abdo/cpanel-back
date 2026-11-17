import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { createOperationsService } from '../src/modules/operations/operations.service.js';
import { createDeploymentsService } from '../src/modules/deployments/deployments.service.js';
import { createWebhooksService, normalizeRepoUrl } from '../src/modules/webhooks/webhooks.service.js';
import { githubSignature, verifyGithubSignature, hashHookToken } from '../src/modules/webhooks/webhooks.crypto.js';
import { createHookBodySchema, hookTokenParamsSchema, triggerHookBodySchema, updateSettingsBodySchema } from '../src/modules/webhooks/webhooks.validator.js';
import { hookLimiters } from '../src/modules/webhooks/webhooks.routes.js';
import { encrypt } from '../src/modules/platform/platform.crypto.js';
import { fakePrisma, U } from './phase3-helpers.js';

const KEY = randomBytes(32).toString('hex');
const OWNER = { id: U(1), isOwner: true };
const P1 = U(10);
const STG = U(20);
const PROD = U(21);
const SECRET = 'whsec_test_secret_value';
const SHA = 'c'.repeat(40);

beforeEach(() => vi.stubEnv('CREDENTIAL_ENCRYPTION_KEY', KEY));
afterEach(() => vi.unstubAllEnvs());

function setup({ platform = null } = {}) {
  const prisma = fakePrisma({
    user: [{ id: U(1), email: 'o@x.test', displayName: 'Owner', status: 'active', disabledAt: null, ownerFlag: true }],
    project: [{ id: P1, serverId: U(5), name: 'Api', slug: 'api', type: 'node', status: 'active', archivedAt: null }],
    projectEnvironment: [
      { id: STG, projectId: P1, code: 'staging' },
      { id: PROD, projectId: P1, code: 'production' },
    ],
    projectRepository: [{ id: 'r1', projectId: P1, remoteUrl: 'https://github.com/Acme/Api.git', defaultBranch: 'main' }],
    projectWebhook: [
      { id: 'w1', projectId: P1, enabled: true, secretEnc: encrypt(SECRET, KEY), branchMapJson: { main: 'production', develop: 'staging' }, prMapJson: { main: 'staging' }, actorUserId: U(1) },
    ],
  });
  const operations = createOperationsService({ prisma });
  const deployments = createDeploymentsService({ prisma, operationsService: operations });
  const auditService = { record: vi.fn() };
  const svc = createWebhooksService({ prisma, auditService, deploymentsService: deployments, platform });
  return { prisma, svc, auditService };
}

const repoPayload = { clone_url: 'https://github.com/acme/api.git', html_url: 'https://github.com/acme/api', full_name: 'acme/api' };
const push = (branch, after = SHA) => ({ ref: `refs/heads/${branch}`, after, deleted: false, repository: repoPayload });
const delivery = (payload, { event = 'push', id = 'deliv-0001', secret = SECRET, sig } = {}) => {
  const rawBody = Buffer.from(JSON.stringify(payload));
  return { rawBody, event, deliveryId: id, signature: sig ?? githubSignature(rawBody, secret) };
};

describe('GitHub signature', () => {
  it('verifies HMAC-SHA256 over the raw bytes and rejects anything else', () => {
    const body = Buffer.from('{"a":1}');
    const sig = githubSignature(body, SECRET);
    expect(sig).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(verifyGithubSignature(body, sig, SECRET)).toBe(true);
    expect(verifyGithubSignature(body, sig, 'other')).toBe(false);
    expect(verifyGithubSignature(Buffer.from('{"a": 1}'), sig, SECRET)).toBe(false);
    expect(verifyGithubSignature(body, sig.slice(0, -2), SECRET)).toBe(false);
    expect(verifyGithubSignature(body, undefined, SECRET)).toBe(false);
    expect(verifyGithubSignature(body, sig.replace('sha256=', 'sha1='), SECRET)).toBe(false);
    expect(normalizeRepoUrl('git@github.com:Acme/Api.git')).toBe('github.com/acme/api');
    expect(normalizeRepoUrl('https://github.com/acme/api/')).toBe('github.com/acme/api');
  });
});

describe('POST /webhooks/github service', () => {
  it('accepts a valid push, maps branch to environment, and creates an approval-gated request for production', async () => {
    const { svc, prisma } = setup();
    const res = await svc.handleGithub(delivery(push('main')));
    expect(res).toMatchObject({ accepted: true, approvalRequired: true, operationStatus: 'PENDING_APPROVAL' });
    const dep = prisma.deployment.rows[0];
    expect(dep).toMatchObject({ environmentId: PROD, status: 'Queued', commitSha: SHA });
    // Nothing ran: the operation still waits for a separate approver.
    expect(prisma.operationJob.rows[0].status).toBe('PENDING_APPROVAL');
    expect(prisma.approvalRequest.rows).toHaveLength(1);
  });

  it('non-production branch is queued without approval (still not executed)', async () => {
    const { svc, prisma } = setup();
    const res = await svc.handleGithub(delivery(push('develop'), { id: 'deliv-0002' }));
    expect(res).toMatchObject({ accepted: true, approvalRequired: false, operationStatus: 'QUEUED' });
    expect(prisma.deployment.rows[0].status).toBe('Queued');
  });

  it('rejects an invalid or missing signature with one generic 401 and creates nothing', async () => {
    const { svc, prisma } = setup();
    await expect(svc.handleGithub(delivery(push('main'), { secret: 'wrong' }))).rejects.toMatchObject({ status: 401, code: 'WEBHOOK_SIGNATURE_INVALID' });
    await expect(svc.handleGithub({ ...delivery(push('main')), signature: undefined })).rejects.toMatchObject({ status: 401 });
    const unknown = { ...push('main'), repository: { clone_url: 'https://github.com/other/repo.git' } };
    await expect(svc.handleGithub(delivery(unknown))).rejects.toMatchObject({ status: 401, code: 'WEBHOOK_SIGNATURE_INVALID' });
    expect(prisma.deployment.rows).toHaveLength(0);
    expect(prisma.webhookDelivery.rows).toHaveLength(0);
  });

  it('rejects a tampered body even with a previously valid signature', async () => {
    const { svc } = setup();
    const d = delivery(push('main'));
    const tampered = Buffer.from(JSON.stringify({ ...push('main'), after: 'd'.repeat(40) }));
    await expect(svc.handleGithub({ ...d, rawBody: tampered })).rejects.toMatchObject({ status: 401 });
  });

  it('replays of the same delivery id are acknowledged but do not create a second deployment', async () => {
    const { svc, prisma } = setup();
    const d = delivery(push('develop'), { id: 'deliv-0003' });
    expect((await svc.handleGithub(d)).accepted).toBe(true);
    expect(await svc.handleGithub(d)).toEqual({ accepted: false, replayed: true });
    expect(prisma.deployment.rows).toHaveLength(1);
    expect(prisma.webhookDelivery.rows).toHaveLength(1);
  });

  it('only push, pull_request and ping are allowed; unmapped branches, branch deletes and fork PRs are ignored', async () => {
    const { svc, prisma } = setup();
    expect(await svc.handleGithub(delivery({ zen: 'x', repository: repoPayload }, { event: 'ping', id: 'deliv-0004' }))).toEqual({ accepted: false, pong: true });
    expect(await svc.handleGithub(delivery({ repository: repoPayload }, { event: 'issues', id: 'deliv-0005' }))).toMatchObject({ accepted: false, ignored: 'event not allowed' });
    expect(await svc.handleGithub(delivery(push('feature/x'), { id: 'deliv-0006' }))).toMatchObject({ ignored: 'branch is not mapped to an environment' });
    expect(await svc.handleGithub(delivery({ ...push('develop'), deleted: true }, { id: 'deliv-0007' }))).toMatchObject({ ignored: 'not a branch update' });
    const pr = (headRepo) => ({ action: 'opened', repository: repoPayload, pull_request: { head: { ref: 'feat', sha: SHA, repo: { full_name: headRepo } }, base: { ref: 'main', repo: { full_name: 'acme/api' } } } });
    expect(await svc.handleGithub(delivery(pr('evil/api'), { event: 'pull_request', id: 'deliv-0008' }))).toMatchObject({ ignored: expect.stringContaining('fork') });
    const ok = await svc.handleGithub(delivery(pr('acme/api'), { event: 'pull_request', id: 'deliv-0009' }));
    expect(ok).toMatchObject({ accepted: true, operationStatus: 'QUEUED' });
    expect(prisma.deployment.rows).toHaveLength(1);
    expect(prisma.deployment.rows[0].environmentId).toBe(STG);
  });

  it('a disabled webhook behaves like an unknown repository', async () => {
    const { svc, prisma } = setup();
    prisma.projectWebhook.rows[0].enabled = false;
    await expect(svc.handleGithub(delivery(push('develop'), { id: 'deliv-0010' }))).rejects.toMatchObject({ status: 401 });
  });
});

describe('public deploy hooks', () => {
  it('stores only the SHA-256 of the token and never returns the hash', async () => {
    const { svc, prisma } = setup();
    const { token, hook } = await svc.createHook(P1, { environmentId: STG, label: 'ci' }, OWNER);
    expect(token).toMatch(/^ntdh_[A-Za-z0-9_-]{43}$/);
    const row = prisma.deployHook.rows[0];
    expect(row.tokenHash).toBe(createHash('sha256').update(token).digest('hex'));
    expect(JSON.stringify(row)).not.toContain(token);
    expect(JSON.stringify(hook)).not.toContain(row.tokenHash);
    expect(hook).not.toHaveProperty('tokenHash');
    const list = await svc.listHooks(P1, OWNER);
    expect(JSON.stringify(list)).not.toContain(row.tokenHash);
    expect(JSON.stringify(list)).not.toContain(token);
    expect(hookTokenParamsSchema.safeParse({ token }).success).toBe(true);
    expect(hookTokenParamsSchema.safeParse({ token: 'nope' }).success).toBe(false);
  });

  it('a valid hook creates a request scoped to its environment; production still needs approval', async () => {
    const { svc, prisma } = setup();
    const stg = await svc.createHook(P1, { environmentId: STG, label: 'stg' }, OWNER);
    const prod = await svc.createHook(P1, { environmentId: PROD, label: 'prod' }, OWNER);
    expect(await svc.triggerHook({ token: stg.token, body: { branch: 'develop' } })).toMatchObject({ accepted: true, operationStatus: 'QUEUED' });
    expect(await svc.triggerHook({ token: prod.token })).toMatchObject({ accepted: true, approvalRequired: true });
    expect(prisma.deployment.rows.map((d) => d.environmentId).sort()).toEqual([STG, PROD].sort());
    expect(prisma.deployHook.rows.find((h) => h.id === stg.hook.id).useCount).toBe(1);
  });

  it('rotate invalidates the old token; revoke blocks the hook; both are audited', async () => {
    const { svc, auditService } = setup();
    const { token, hook } = await svc.createHook(P1, { environmentId: STG, label: 'ci' }, OWNER);
    const rotated = await svc.rotateHook(P1, hook.id, OWNER);
    expect(rotated.token).not.toBe(token);
    await expect(svc.triggerHook({ token })).rejects.toMatchObject({ status: 401, code: 'HOOK_INVALID' });
    expect((await svc.triggerHook({ token: rotated.token })).accepted).toBe(true);
    const revoked = await svc.revokeHook(P1, hook.id, OWNER);
    expect(revoked.revokedAt).toBeTruthy();
    await expect(svc.triggerHook({ token: rotated.token })).rejects.toMatchObject({ code: 'HOOK_INVALID' });
    await expect(svc.rotateHook(P1, hook.id, OWNER)).rejects.toMatchObject({ code: 'HOOK_REVOKED' });
    const actions = auditService.record.mock.calls.map(([e]) => e.action);
    expect(actions).toEqual(expect.arrayContaining(['deploy_hook.create', 'deploy_hook.rotate', 'deploy_hook.revoke']));
  });

  it('only the Owner manages hooks and a hook from another project cannot be touched', async () => {
    const { svc } = setup();
    const member = { id: U(2), isOwner: false };
    await expect(svc.createHook(P1, { environmentId: STG, label: 'x' }, member)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    const { hook } = await svc.createHook(P1, { environmentId: STG, label: 'x' }, OWNER);
    await expect(svc.revokeHook(U(99), hook.id, OWNER)).rejects.toMatchObject({ code: 'HOOK_NOT_FOUND' });
    expect(triggerHookBodySchema.safeParse(undefined).success).toBe(true);
    expect(triggerHookBodySchema.safeParse({ commitSha: 'zz' }).success).toBe(false);
    expect(triggerHookBodySchema.safeParse({ extra: 1 }).success).toBe(false);
    expect(createHookBodySchema.safeParse({ environmentId: STG, label: '' }).success).toBe(false);
  });

  it('rate limits the public hook per token and per IP', () => {
    const req = { ip: '203.0.113.9', params: { token: 'ntdh_x' }, socket: {} };
    const outcomes = [];
    for (let i = 0; i < 8; i++) {
      let err = null;
      hookLimiters.forEach((limiter) => limiter(req, { set: () => {} }, (e) => { if (e) err = e; }));
      outcomes.push(err?.status ?? 200);
    }
    expect(outcomes.slice(0, 6).every((s) => s === 200)).toBe(true);
    expect(outcomes[6]).toBe(429);
    expect(hashHookToken('a')).toHaveLength(64);
  });
});

describe('deploy settings', () => {
  it('rotating returns the webhook secret once and stores it encrypted', async () => {
    const { svc, prisma } = setup();
    const out = await svc.updateSettings(P1, { webhook: { rotateSecret: true, branchMap: { main: 'production' } } }, OWNER);
    expect(out.webhookSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(out.settings)).not.toContain(out.webhookSecret);
    expect(out.settings.webhook.hasSecret).toBe(true);
    expect(Buffer.from(prisma.projectWebhook.rows[0].secretEnc).toString('utf8')).not.toContain(out.webhookSecret);
    await expect(svc.updateSettings(P1, { webhook: { branchMap: { main: 'nope' } } }, OWNER)).rejects.toMatchObject({ code: 'ENVIRONMENT_CODE_UNKNOWN' });
  });

  it('allowlisted commands save directly; a custom command goes through platform.gate and is only stored once approved', async () => {
    const gate = vi.fn().mockResolvedValueOnce({ proceed: false, approval: { id: 'ap1' } }).mockResolvedValueOnce({ proceed: true });
    const { svc, prisma } = setup({ platform: { gate } });
    const direct = await svc.updateSettings(P1, { deploy: { buildCommand: 'npm run build', keepReleases: 3 } }, OWNER);
    expect(direct.settings.deploy.keepReleases).toBe(3);
    expect(gate).not.toHaveBeenCalled();

    const pending = await svc.updateSettings(P1, { deploy: { buildCommand: 'node scripts/build.js' }, approval: { reason: 'need it', rollbackPlan: 'revert' } }, OWNER);
    expect(pending).toEqual({ approvalRequired: true, approval: { id: 'ap1' } });
    expect(gate).toHaveBeenCalledWith(expect.objectContaining({ action: 'deploy.command.approve', resourceType: 'project', resourceId: P1 }), OWNER);
    expect(prisma.projectRuntime.rows[0].metaJson.deploy.buildCommand).toBe('npm run build');

    const done = await svc.updateSettings(P1, { deploy: { buildCommand: 'node scripts/build.js' }, approval: { approvalId: U(77) } }, OWNER);
    expect(done.settings.deploy.approvedCustomCommands).toEqual(['node scripts/build.js']);
  });

  it('unsafe custom commands and paths are rejected before any approval is requested', async () => {
    const gate = vi.fn();
    const { svc } = setup({ platform: { gate } });
    await expect(svc.updateSettings(P1, { deploy: { buildCommand: 'bash -c "id"' } }, OWNER)).rejects.toMatchObject({ code: 'CUSTOM_COMMAND_UNSAFE' });
    await expect(svc.updateSettings(P1, { deploy: { basePath: '/etc/passwd' } }, OWNER)).rejects.toMatchObject({ code: 'DEPLOY_PATH_INVALID' });
    await expect(svc.updateSettings(P1, { repository: { remoteUrl: '--upload-pack=x' } }, OWNER)).rejects.toMatchObject({ code: 'REPO_URL_INVALID' });
    expect(gate).not.toHaveBeenCalled();
    expect(updateSettingsBodySchema.safeParse({ deploy: { evil: 1 } }).success).toBe(false);
  });
});
