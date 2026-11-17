/**
 * TASK-044: GitHub webhooks and public deploy hooks.
 * - GitHub deliveries are verified (HMAC-SHA256, constant time) against a per-project encrypted secret, de-duplicated by
 *   delivery id, and turned into deployment REQUESTS through deploymentsService.create, so RBAC, production approvals and
 *   the operation queue still apply. Nothing here executes a deployment.
 * - Deploy hooks are random tokens stored only as SHA-256; they are scoped to one project + environment.
 */
import { createHash } from 'node:crypto';
import { randomUUID } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { ALLOWED_COMMANDS, normalizeCommand, resolveCommand, resolveDeployConfig, validateRef, validateRepoUrl } from '../deployments/deployments.commands.js';
import { createProjectAccess } from '../projects/projects.access.js';
import { generateHookToken, generateWebhookSecret, hashHookToken, verifyGithubSignature } from './webhooks.crypto.js';

export const GITHUB_EVENTS = Object.freeze(['push', 'pull_request', 'ping']);
const PR_ACTIONS = new Set(['opened', 'synchronize', 'reopened']);
const ZERO_SHA = /^0+$/;

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/** github.com/Owner/Repo for https, ssh://, and scp-style URLs. */
export function normalizeRepoUrl(url) {
  return String(url ?? '')
    .trim()
    .toLowerCase()
    .replace(/^[a-z+]+:\/\//, '')
    .replace(/^[^@/]+@/, '')
    .replace(/^([^/:]+):(?!\d+\/)/, '$1/')
    .replace(/\.git$/, '')
    .replace(/\/+$/, '');
}

export function createWebhooksService({
  prisma,
  auditService = null,
  deploymentsService = null,
  /** TASK-045: when set and enabled for the project, pull_request deliveries create/update/destroy preview environments. */
  previews = null,
  platform = null,
  now = () => new Date(),
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
}) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'project', ...event }) : null);
  const access = createProjectAccess({ prisma, now });

  const delegate = (name) => {
    if (!prisma?.[name]) {
      throw new AppError(501, 'SCHEMA_REQUIRED', 'Webhook tables are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');
    }
    return prisma[name];
  };

  function requireOwner(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage deploy hooks and repository connections');
  }

  async function loadProject(id) {
    const project = await prisma.project.findUnique({ where: { id } });
    if (!project) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
    return project;
  }

  const hookView = (h) => ({
    id: h.id,
    projectId: h.projectId,
    environmentId: h.environmentId,
    label: h.label,
    tokenPrefix: h.tokenPrefix,
    createdAt: h.createdAt,
    lastUsedAt: h.lastUsedAt ?? null,
    useCount: h.useCount ?? 0,
    revokedAt: h.revokedAt ?? null,
  });

  /** Resolves the user whose permissions and approvals govern a webhook/hook triggered request. */
  async function actorFor(userId) {
    if (!userId) return null;
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || user.status !== 'active' || user.disabledAt) return null;
    return { id: user.id, email: user.email, displayName: user.displayName, isOwner: user.ownerFlag };
  }

  async function requestDeployment({ project, env, actor, key, commitSha, branch, source, extra = {} }) {
    if (!deploymentsService) throw new AppError(500, 'DEPLOYMENTS_UNAVAILABLE', 'Deployments service unavailable');
    const result = await deploymentsService.create(
      { projectId: project.id, environmentId: env.id, idempotencyKey: key, commitSha, branch, rollbackPlan: 'Roll back to the previous successful deployment' },
      actor,
    );
    await audit({
      actorId: actor.id,
      action: `deployment.${source}.request`,
      resourceId: project.id,
      environmentId: env.id,
      result: 'success',
      correlationId: result.operation?.correlationId,
      after: { deploymentId: result.deployment?.id, source, ...extra },
    });
    return {
      accepted: true,
      deploymentId: result.deployment?.id ?? null,
      operationStatus: result.operation?.status ?? null,
      approvalRequired: result.operation?.status === 'PENDING_APPROVAL',
    };
  }

  return {
    // ------------------------------------------------------------------ public: GitHub
    /**
     * rawBody must be the exact bytes GitHub signed. Unknown repo, disabled hook and bad signature all return the
     * same 401 so the endpoint reveals nothing about which projects exist.
     */
    async handleGithub({ rawBody, signature, event, deliveryId }) {
      const invalid = () => new AppError(401, 'WEBHOOK_SIGNATURE_INVALID', 'Webhook signature could not be verified');
      if (!Buffer.isBuffer(rawBody) || rawBody.length === 0 || !signature || !event || !deliveryId) throw invalid();
      if (!/^[A-Za-z0-9._-]{8,100}$/.test(String(deliveryId))) throw new AppError(400, 'DELIVERY_ID_INVALID', 'Delivery id is invalid');

      let payload;
      try {
        payload = JSON.parse(rawBody.toString('utf8'));
      } catch {
        throw invalid();
      }
      const candidates = new Set(
        [payload?.repository?.clone_url, payload?.repository?.ssh_url, payload?.repository?.html_url, payload?.repository?.git_url]
          .filter(Boolean)
          .map(normalizeRepoUrl),
      );
      if (candidates.size === 0) throw invalid();

      const repos = await prisma.projectRepository.findMany({ where: { remoteUrl: { not: null } }, take: 1000 });
      const hooks = delegate('projectWebhook');
      let matched = null;
      for (const repo of repos.filter((r) => candidates.has(normalizeRepoUrl(r.remoteUrl)))) {
        const cfg = await hooks.findUnique({ where: { projectId: repo.projectId } });
        if (!cfg?.enabled || !cfg.secretEnc) continue;
        const secret = decrypt(Buffer.from(cfg.secretEnc), credentialKey()).toString('utf8');
        if (verifyGithubSignature(rawBody, signature, secret)) {
          matched = { repo, cfg };
          break;
        }
      }
      if (!matched) throw invalid();
      const projectId = matched.repo.projectId;

      if (!GITHUB_EVENTS.includes(event)) return { accepted: false, ignored: 'event not allowed' };

      const deliveries = delegate('webhookDelivery');
      if (await deliveries.findUnique({ where: { deliveryId } })) return { accepted: false, replayed: true };
      const record = async (outcome) => {
        try {
          await deliveries.create({ data: { deliveryId, projectId, event, outcome } });
        } catch {
          return false; // lost a race on the unique delivery id
        }
        return true;
      };

      if (event === 'ping') {
        if (!(await record('pong'))) return { accepted: false, replayed: true };
        return { accepted: false, pong: true };
      }

      // TASK-045: preview environments take over pull_request events for projects that enabled them.
      if (event === 'pull_request' && previews && (await previews.enabledFor(projectId))) {
        const previewActor = await actorFor(matched.cfg.actorUserId);
        if (!previewActor) {
          await record('ignored');
          return { accepted: false, ignored: 'acting user unavailable' };
        }
        if (!(await record('accepted'))) return { accepted: false, replayed: true };
        return previews.handlePullRequest({ projectId, payload, actor: previewActor });
      }

      // Resolve what to deploy.
      let branch;
      let commitSha;
      let envCode;
      if (event === 'push') {
        const m = /^refs\/heads\/(.+)$/.exec(String(payload.ref ?? ''));
        if (!m || payload.deleted || ZERO_SHA.test(String(payload.after ?? '0'))) {
          await record('ignored');
          return { accepted: false, ignored: 'not a branch update' };
        }
        branch = m[1];
        commitSha = String(payload.after);
        envCode = matched.cfg.branchMapJson?.[branch];
      } else {
        const pr = payload.pull_request;
        const sameRepo = pr?.head?.repo?.full_name && pr.head.repo.full_name === pr.base?.repo?.full_name;
        if (!PR_ACTIONS.has(payload.action) || !sameRepo) {
          await record('ignored');
          return { accepted: false, ignored: 'pull request action or fork not deployable' };
        }
        branch = pr.head.ref;
        commitSha = pr.head.sha;
        envCode = matched.cfg.prMapJson?.[pr.base?.ref];
      }
      try {
        validateRef(branch);
        if (!/^[0-9a-f]{7,40}$/.test(commitSha)) throw new Error('sha');
      } catch {
        await record('ignored');
        return { accepted: false, ignored: 'unsafe ref or commit' };
      }
      if (!envCode) {
        await record('ignored');
        return { accepted: false, ignored: 'branch is not mapped to an environment' };
      }
      const env = await prisma.projectEnvironment.findFirst({ where: { projectId, code: envCode } });
      const project = await prisma.project.findUnique({ where: { id: projectId } });
      const actor = await actorFor(matched.cfg.actorUserId);
      if (!env || !project || !actor) {
        await record('ignored');
        return { accepted: false, ignored: 'environment or acting user unavailable' };
      }
      if (!(await record('accepted'))) return { accepted: false, replayed: true };
      try {
        return await requestDeployment({ project, env, actor, key: `gh-${deliveryId}`, commitSha, branch, source: 'webhook', extra: { event, deliveryId } });
      } catch (error) {
        // 409 busy / 403 permission: the delivery is recorded, the failure is reported to GitHub as 202 with the reason.
        if (error instanceof AppError && error.status < 500) return { accepted: false, rejected: error.code };
        throw error;
      }
    },

    // ------------------------------------------------------------------ public: deploy hook
    async triggerHook({ token, body = {} }) {
      const invalid = () => new AppError(401, 'HOOK_INVALID', 'Deploy hook is invalid or revoked');
      const hook = await delegate('deployHook').findUnique({ where: { tokenHash: hashHookToken(token) } });
      if (!hook || hook.revokedAt) throw invalid();
      const project = await prisma.project.findUnique({ where: { id: hook.projectId } });
      const env = await prisma.projectEnvironment.findUnique({ where: { id: hook.environmentId } });
      const actor = await actorFor(hook.createdById);
      if (!project || !env || env.projectId !== project.id || !actor) throw invalid();
      await prisma.deployHook.update({ where: { id: hook.id }, data: { lastUsedAt: now(), useCount: { increment: 1 } } });
      return requestDeployment({ project, env, actor, key: `hook-${randomUUID()}`, commitSha: body.commitSha, branch: body.branch, source: 'hook', extra: { hookId: hook.id } });
    },

    // ------------------------------------------------------------------ admin: hooks
    async listHooks(projectId, actor) {
      await access.requireView(actor, projectId);
      requireOwner(actor);
      const rows = await delegate('deployHook').findMany({ where: { projectId }, orderBy: { createdAt: 'desc' } });
      return rows.map(hookView);
    },

    async createHook(projectId, input, actor) {
      requireOwner(actor);
      const project = await loadProject(projectId);
      const env = await prisma.projectEnvironment.findUnique({ where: { id: input.environmentId } });
      if (!env || env.projectId !== project.id) throw new AppError(400, 'ENVIRONMENT_MISMATCH', 'Environment does not belong to the project');
      const { token, tokenHash, tokenPrefix } = generateHookToken();
      const row = await delegate('deployHook').create({
        data: { projectId, environmentId: env.id, label: input.label, tokenHash, tokenPrefix, createdById: actor.id },
      });
      await audit({ actorId: actor.id, action: 'deploy_hook.create', resourceId: projectId, environmentId: env.id, result: 'success', after: { hookId: row.id, label: input.label } });
      return { hook: hookView(row), token };
    },

    async rotateHook(projectId, hookId, actor) {
      requireOwner(actor);
      const hook = await delegate('deployHook').findUnique({ where: { id: hookId } });
      if (!hook || hook.projectId !== projectId) throw new AppError(404, 'HOOK_NOT_FOUND', 'Deploy hook not found');
      if (hook.revokedAt) throw new AppError(409, 'HOOK_REVOKED', 'Revoked hooks cannot be rotated');
      const { token, tokenHash, tokenPrefix } = generateHookToken();
      const row = await prisma.deployHook.update({ where: { id: hookId }, data: { tokenHash, tokenPrefix, createdById: actor.id } });
      await audit({ actorId: actor.id, action: 'deploy_hook.rotate', resourceId: projectId, environmentId: hook.environmentId, result: 'success', after: { hookId } });
      return { hook: hookView(row), token };
    },

    async revokeHook(projectId, hookId, actor) {
      requireOwner(actor);
      const hook = await delegate('deployHook').findUnique({ where: { id: hookId } });
      if (!hook || hook.projectId !== projectId) throw new AppError(404, 'HOOK_NOT_FOUND', 'Deploy hook not found');
      const row = await prisma.deployHook.update({ where: { id: hookId }, data: { revokedAt: hook.revokedAt ?? now() } });
      await audit({ actorId: actor.id, action: 'deploy_hook.revoke', resourceId: projectId, environmentId: hook.environmentId, result: 'success', after: { hookId } });
      return hookView(row);
    },

    // ------------------------------------------------------------------ admin: settings
    async getSettings(projectId, actor) {
      await access.requireView(actor, projectId);
      const project = await loadProject(projectId);
      const [repo, runtime, cfg, hooks, envs] = await Promise.all([
        prisma.projectRepository.findUnique({ where: { projectId } }),
        prisma.projectRuntime.findUnique({ where: { projectId } }),
        delegate('projectWebhook').findUnique({ where: { projectId } }),
        actor.isOwner ? delegate('deployHook').findMany({ where: { projectId }, orderBy: { createdAt: 'desc' } }) : [],
        prisma.projectEnvironment.findMany({ where: { projectId } }),
      ]);
      const deploy = resolveDeployConfig({ project, environment: { code: 'env' }, runtimeMeta: runtime?.metaJson ?? null });
      return {
        executor: String(process.env.DEPLOY_EXECUTOR ?? 'simulated').toLowerCase() === 'ssh' ? 'ssh' : 'simulated',
        repository: { remoteUrl: repo?.remoteUrl ?? null, defaultBranch: repo?.defaultBranch ?? null },
        webhook: { enabled: cfg?.enabled ?? false, hasSecret: Boolean(cfg?.secretEnc), branchMap: cfg?.branchMapJson ?? {}, prMap: cfg?.prMapJson ?? {} },
        deploy,
        allowedCommands: Object.keys(ALLOWED_COMMANDS),
        environments: envs.map((e) => ({ id: e.id, code: e.code, displayName: e.displayName })),
        hooks: hooks.map(hookView),
      };
    },

    async updateSettings(projectId, input, actor) {
      requireOwner(actor);
      const project = await loadProject(projectId);
      if (project.archivedAt) throw new AppError(409, 'PROJECT_ARCHIVED', 'Project is archived');
      const runtime = await prisma.projectRuntime.findUnique({ where: { projectId } });
      const meta = { ...(runtime?.metaJson ?? {}) };
      const currentDeploy = { ...(meta.deploy ?? {}) };
      let nextDeploy = currentDeploy;

      if (input.deploy) {
        nextDeploy = { ...currentDeploy, ...input.deploy };
        // Custom commands need a separate approver. Allowlisted ones do not.
        const requested = [nextDeploy.installCommand, nextDeploy.buildCommand].filter(Boolean).map(normalizeCommand);
        const custom = requested.filter((c) => !Object.prototype.hasOwnProperty.call(ALLOWED_COMMANDS, c));
        const alreadyApproved = (currentDeploy.approvedCustomCommands ?? []).map(normalizeCommand);
        const needApproval = custom.filter((c) => !alreadyApproved.includes(c));
        if (needApproval.length > 0) {
          if (!platform) throw new AppError(500, 'PLATFORM_UNAVAILABLE', 'Approval service unavailable');
          // Safety check first so an unsafe command never even reaches an approver.
          for (const c of needApproval) resolveCommand(c, [c]);
          const gate = await platform.gate(
            {
              action: 'deploy.command.approve',
              binding: sha256(JSON.stringify(needApproval.sort())),
              resourceType: 'project',
              resourceId: projectId,
              approvalId: input.approval?.approvalId,
              reason: input.approval?.reason,
              impact: needApproval.map((c) => `Run "${c}" on the server during every deployment`),
              rollbackPlan: input.approval?.rollbackPlan,
              context: { commands: needApproval },
            },
            actor,
          );
          if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
          nextDeploy.approvedCustomCommands = [...new Set([...alreadyApproved, ...needApproval])];
        } else {
          // Drop approvals for commands that are no longer configured.
          nextDeploy.approvedCustomCommands = alreadyApproved.filter((c) => requested.includes(c));
        }
        // Reject unsafe values at write time (paths, names, URLs) with the same rules the executor uses.
        resolveDeployConfig({ project, environment: { code: 'env' }, runtimeMeta: { deploy: nextDeploy } });
        for (const c of requested) resolveCommand(c, nextDeploy.approvedCustomCommands);
      }

      if (input.deploy) {
        const data = { metaJson: { ...meta, deploy: nextDeploy } };
        if (runtime) await prisma.projectRuntime.update({ where: { projectId }, data });
        else await prisma.projectRuntime.create({ data: { projectId, ...data } });
      }

      if (input.repository) {
        const remoteUrl = validateRepoUrl(input.repository.remoteUrl);
        const data = { remoteUrl, ...(input.repository.defaultBranch ? { defaultBranch: input.repository.defaultBranch } : {}) };
        const existing = await prisma.projectRepository.findUnique({ where: { projectId } });
        if (existing) await prisma.projectRepository.update({ where: { projectId }, data });
        else await prisma.projectRepository.create({ data: { projectId, ...data } });
      }

      let webhookSecret = null;
      if (input.webhook) {
        const envs = await prisma.projectEnvironment.findMany({ where: { projectId } });
        const codes = new Set(envs.map((e) => e.code));
        for (const m of [input.webhook.branchMap, input.webhook.prMap]) {
          for (const code of Object.values(m ?? {})) {
            if (!codes.has(code)) throw new AppError(422, 'ENVIRONMENT_CODE_UNKNOWN', `Environment "${code}" does not exist in this project`);
          }
        }
        const existing = await delegate('projectWebhook').findUnique({ where: { projectId } });
        const data = {
          ...(input.webhook.enabled !== undefined ? { enabled: input.webhook.enabled } : {}),
          ...(input.webhook.branchMap ? { branchMapJson: input.webhook.branchMap } : {}),
          ...(input.webhook.prMap ? { prMapJson: input.webhook.prMap } : {}),
          actorUserId: actor.id,
        };
        if (input.webhook.rotateSecret || !existing?.secretEnc) {
          webhookSecret = generateWebhookSecret();
          data.secretEnc = encrypt(webhookSecret, credentialKey());
        }
        if (existing) await prisma.projectWebhook.update({ where: { projectId }, data });
        else await prisma.projectWebhook.create({ data: { projectId, ...data } });
      }

      await audit({
        actorId: actor.id,
        action: 'project.deploy_settings.update',
        resourceId: projectId,
        result: 'success',
        after: { fields: Object.keys(input).filter((k) => k !== 'approval'), secretRotated: Boolean(webhookSecret) },
      });
      return { settings: await this.getSettings(projectId, actor), ...(webhookSecret ? { webhookSecret } : {}) };
    },
  };
}
