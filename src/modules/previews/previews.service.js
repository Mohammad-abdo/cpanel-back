/**
 * TASK-045: PR preview environments.
 *
 * GitHub pull_request opened/reopened/synchronize/closed (verified by the TASK-044 webhook) create, update or destroy a preview:
 * its own `pr-<n>` environment, a port from the configured range, hostname pr-<n>.<slug>.<root domain>, optional basic auth,
 * a subset of the source environment's variables, and an optional PR comment.
 *
 * Everything that runs goes through existing rules: the deployment is requested via deploymentsService.create (operation queue, RBAC,
 * approvals, DEPLOY_EXECUTOR adapter); teardown uses the executor's runner.teardown; publishing the hostname (DNS + proxy) is the
 * High-risk `preview.expose` gate and never happens without a separate approver. Fork PRs are never built (trust rule, TASK-044).
 * Real servers, DNS and GitHub are NOT_RUN; tests use fakes.
 */
import { createHash } from 'node:crypto';
import net from 'node:net';
import { AppError } from '../../common/errors/app-error.js';
import { SYSTEM_ACTOR } from '../../common/system-actor.js';
import { createProjectAccess } from '../projects/projects.access.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { validateRef } from '../deployments/deployments.commands.js';
import { isCaddyEnabled } from '../domains/domains.proxy.js';
import { COMMENT_MARKER, createGithubCommenter, renderComment } from './previews.github.js';
import { PREVIEW_AUTH_USER, createPreviewCredentials, htpasswdLine } from './previews.auth.js';
import { allocatePort, previewHostname, validatePortRange } from './previews.ports.js';

export const LIVE_STATUSES = ['creating', 'deploying', 'awaiting_exposure', 'active'];
const PR_UPSERT_ACTIONS = new Set(['opened', 'reopened', 'synchronize']);
const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|PreviewEnvironment|ProjectPreviewSettings/i;
const DAY = 86400000;
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const schemaRequired = () => new AppError(501, 'SCHEMA_REQUIRED', 'Preview tables are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');

/** nginx server block for a preview. Every interpolated value is validated (hostname regex, integer port). */
export function renderPreviewVhost({ hostname, port, basicAuth = false }) {
  if (!/^[a-z0-9.-]{1,253}$/.test(hostname) || !Number.isInteger(port)) throw new AppError(422, 'PREVIEW_VHOST_INVALID', 'Invalid preview virtual host input');
  const lines = ['server {', '  listen 80;', `  server_name ${hostname};`];
  if (basicAuth) lines.push('  auth_basic "Preview";', `  auth_basic_user_file /etc/nginx/nt-preview/${hostname}.htpasswd;`);
  lines.push(`  location / { proxy_pass http://127.0.0.1:${port}; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; }`, '}');
  return lines.join('\n');
}

export function createPreviewsService({
  prisma,
  auditService = null,
  deploymentsService = null,
  rootDomains = null,
  platform = null,
  adapters = null,
  /** ({ projectId, environmentId, serverId }) -> { ok }. Defaults to the deploy executor's runner.teardown when injected. */
  teardown = null,
  commenter = createGithubCommenter(),
  env = process.env,
  now = () => new Date(),
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
  /** false = await the deployment inside the call (tests). */
  background = true,
}) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'project', ...event }) : null);
  const access = createProjectAccess({ prisma, now });

  const settingsTable = () => {
    if (!prisma?.projectPreviewSettings) throw schemaRequired();
    return prisma.projectPreviewSettings;
  };
  const previews = () => {
    if (!prisma?.previewEnvironment) throw schemaRequired();
    return prisma.previewEnvironment;
  };
  async function guard(fn) {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (STALE.test(String(e?.message))) throw schemaRequired();
      throw e;
    }
  }
  function requireOwner(actor) {
    if (!actor?.id && !actor?.system) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage preview environments');
  }
  async function loadProject(id) {
    const p = await prisma.project.findUnique({ where: { id } });
    if (!p) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
    return p;
  }
  async function loadPreview(projectId, id) {
    const row = await previews().findUnique({ where: { id } });
    if (!row || row.projectId !== projectId) throw new AppError(404, 'PREVIEW_NOT_FOUND', 'Preview environment not found');
    return row;
  }

  const view = async (r) => {
    const deployment = r.deploymentId ? await prisma.deployment.findUnique({ where: { id: r.deploymentId } }) : null;
    return {
      id: r.id, projectId: r.projectId, prNumber: r.prNumber, branch: r.branch, commitSha: r.commitSha, status: r.status, port: r.port,
      hostname: r.hostname, url: r.url, deploymentId: r.deploymentId, deploymentStatus: deployment?.status ?? null,
      hasBasicAuth: Boolean(r.basicAuthHash), basicAuthUser: r.basicAuthUser ?? null, dnsStatus: r.dnsStatus ?? null,
      exposeApprovalId: r.exposeApprovalId ?? null, lastError: r.lastError ?? null, expiresAt: r.expiresAt, closedAt: r.closedAt ?? null,
      createdAt: r.createdAt, updatedAt: r.updatedAt,
    };
  };
  const settingsView = (s) => ({
    enabled: s?.enabled ?? false, rootDomainId: s?.rootDomainId ?? null, sourceEnvCode: s?.sourceEnvCode ?? null, envKeys: s?.envKeysJson ?? [],
    portStart: s?.portStart ?? 20000, portEnd: s?.portEnd ?? 20999, ttlDays: s?.ttlDays ?? 7, maxActive: s?.maxActive ?? 5,
    basicAuth: s?.basicAuth ?? false, dnsMode: s?.dnsMode ?? 'per-pr', commentEnabled: s?.commentEnabled ?? false, hasGithubToken: Boolean(s?.githubTokenEnc),
  });

  const setRow = (id, data) => previews().update({ where: { id }, data });

  // ------------------------------------------------------------------ side effects (each isolated and best effort where noted)
  async function comment(row, settings, project, status = row.status) {
    if (!settings?.commentEnabled || !settings.githubTokenEnc) return;
    try {
      const repo = await prisma.projectRepository.findUnique({ where: { projectId: project.id } });
      const token = decrypt(Buffer.from(settings.githubTokenEnc), credentialKey()).toString('utf8');
      const id = await commenter.upsert({ token, remoteUrl: repo?.remoteUrl, prNumber: row.prNumber, commentId: row.commentId, body: renderComment({ status, url: row.url, commitSha: row.commitSha, basicAuth: Boolean(row.basicAuthHash) }) });
      if (id !== row.commentId) await setRow(row.id, { commentId: id });
    } catch {
      /* a failed comment never fails a preview */
    }
  }

  async function prepareEnvironment(project, settings, row, port) {
    let environment = await prisma.projectEnvironment.findFirst({ where: { projectId: project.id, code: `pr-${row.prNumber}` } });
    if (!environment) environment = await prisma.projectEnvironment.create({ data: { projectId: project.id, code: `pr-${row.prNumber}`, displayName: `PR #${row.prNumber} preview` } });
    const wanted = new Map();
    const source = settings.sourceEnvCode ? await prisma.projectEnvironment.findFirst({ where: { projectId: project.id, code: settings.sourceEnvCode } }) : null;
    const allowed = new Set(Array.isArray(settings.envKeysJson) ? settings.envKeysJson : []);
    if (source && allowed.size > 0) {
      for (const v of await prisma.projectEnvVar.findMany({ where: { environmentId: source.id } })) if (allowed.has(v.key)) wanted.set(v.key, { valueEnc: v.valueEnc, isSecret: v.isSecret });
    }
    // PORT and PREVIEW_URL are always set by the platform and override copied values.
    wanted.set('PORT', { valueEnc: encrypt(String(port), credentialKey()), isSecret: false });
    wanted.set('PREVIEW_URL', { valueEnc: encrypt(row.url, credentialKey()), isSecret: false });
    for (const [key, v] of wanted) {
      const existing = await prisma.projectEnvVar.findFirst({ where: { environmentId: environment.id, key } });
      if (existing) await prisma.projectEnvVar.update({ where: { id: existing.id }, data: { valueEnc: v.valueEnc, isSecret: v.isSecret } });
      else await prisma.projectEnvVar.create({ data: { environmentId: environment.id, key, valueEnc: v.valueEnc, isSecret: v.isSecret } });
    }
    return environment;
  }

  /** Requests (or, with an approved id, performs) the High-risk exposure: DNS record + proxy virtual host. */
  async function exposure(row, settings, project, actor, { approvalId, reason, rollbackNote } = {}) {
    const root = settings.rootDomainId ? await rootDomains.system.byId(settings.rootDomainId) : null;
    if (!root || root.archivedAt) throw new AppError(409, 'PREVIEW_ROOT_DOMAIN_REQUIRED', 'A connected root domain is required for preview hostnames');
    const impact = [`Publish ${row.hostname} -> 127.0.0.1:${row.port} on the project server`, settings.dnsMode === 'wildcard' ? 'No DNS change (wildcard record assumed)' : `Create DNS record for ${row.hostname} in zone ${root.name}`, settings.basicAuth ? 'Protected by basic auth' : 'Publicly reachable'];
    const gate = await platform.gate(
      { action: 'preview.expose', binding: sha256(JSON.stringify([row.hostname, row.port, project.serverId, settings.dnsMode, Boolean(settings.basicAuth)])), resourceType: 'preview', resourceId: row.id, approvalId, reason: reason ?? `Expose preview ${row.hostname}`, impact, rollbackPlan: rollbackNote ?? 'Destroy the preview (removes DNS record, virtual host and files)', context: { projectId: project.id } },
      actor,
    );
    if (!gate.proceed) {
      await setRow(row.id, { exposeApprovalId: gate.approval.id, dnsStatus: 'awaiting_approval', status: row.status === 'active' ? 'awaiting_exposure' : row.status });
      return { approvalRequired: true, approval: gate.approval };
    }
    const done = [];
    try {
      if (settings.dnsMode !== 'wildcard') {
        const cred = await prisma.serverCredential.findUnique({ where: { serverId: row.serverId } });
        const target = String(cred?.host ?? '');
        if (!target) throw new AppError(409, 'PREVIEW_SERVER_HOST_UNKNOWN', 'The project server has no known host for the DNS record');
        const type = net.isIPv4(target) ? 'A' : net.isIPv6(target) ? 'AAAA' : 'CNAME';
        await rootDomains.system.apply(root, 'upsert', { type, name: row.hostname, content: target, ttl: 300, proxied: false });
        done.push('dns');
      }
      const config = renderPreviewVhost({ hostname: row.hostname, port: row.port, basicAuth: Boolean(row.basicAuthHash) });
      const check = await adapters.webserver.validate(config);
      if (!check.ok) throw new AppError(422, 'VHOST_INVALID', 'Preview virtual host failed validation');
      const auxFiles = row.basicAuthHash ? [{ path: `/etc/nginx/nt-preview/${row.hostname}.htpasswd`, content: htpasswdLine(row.basicAuthUser ?? PREVIEW_AUTH_USER, row.basicAuthHash), mode: '0640' }] : [];
      await adapters.webserver.apply({ domain: row.hostname, config, auxFiles, serverId: row.serverId });
      done.push('vhost');
      const domain = await prisma.domain.findUnique({ where: { name: row.hostname } });
      if (!domain) await prisma.domain.create({ data: { name: row.hostname, projectId: project.id, serverId: row.serverId, metaJson: { preview: true, prNumber: row.prNumber, upstreamPort: row.port } } });
      else await prisma.domain.update({ where: { id: domain.id }, data: { archivedAt: null } });
    } catch (error) {
      if (done.includes('vhost')) await adapters.webserver.rollback({ domain: row.hostname }).catch(() => {});
      if (done.includes('dns')) for (const type of ['A', 'AAAA', 'CNAME']) await rootDomains.system.apply(root, 'remove', { type, name: row.hostname }).catch(() => {});
      await setRow(row.id, { dnsStatus: 'failed', lastError: String(error?.code ?? error?.message ?? 'exposure failed').slice(0, 200) });
      await audit({ actorId: actor.id ?? null, action: 'preview.expose', resourceId: project.id, result: 'failure', metadata: { previewId: row.id } });
      throw error instanceof AppError ? error : new AppError(502, 'PREVIEW_EXPOSE_FAILED', 'Publishing the preview failed and was rolled back');
    }
    const fresh = await previews().findUnique({ where: { id: row.id } });
    const deployed = fresh.deploymentId ? (await prisma.deployment.findUnique({ where: { id: fresh.deploymentId } }))?.status === 'Success' : false;
    await setRow(row.id, { dnsStatus: 'applied', exposeApprovalId: null, lastError: null, ...(deployed ? { status: 'active' } : {}) });
    await audit({ actorId: actor.id ?? null, action: 'preview.expose', resourceId: project.id, result: 'success', after: { previewId: row.id, hostname: row.hostname } });
    return { exposed: true };
  }

  async function runDeployment(row, project, settings, deployment, actor) {
    const exec = async () => {
      try {
        await deploymentsService.run(deployment.id, actor);
      } catch (error) {
        await setRow(row.id, { status: 'failed', lastError: String(error?.code ?? error?.message ?? 'deployment failed').slice(0, 200) });
        await comment(await previews().findUnique({ where: { id: row.id } }), settings, project, 'failed');
        return;
      }
      const d = await prisma.deployment.findUnique({ where: { id: deployment.id } });
      const fresh = await previews().findUnique({ where: { id: row.id } });
      if (!fresh || ['destroying', 'destroyed'].includes(fresh.status)) return;
      const status = d?.status === 'Success' ? (fresh.dnsStatus === 'applied' ? 'active' : 'awaiting_exposure') : 'failed';
      await setRow(row.id, { status, lastError: status === 'failed' ? `deployment ${d?.status ?? 'unknown'}` : null });
      await comment({ ...fresh, status }, settings, project, status);
    };
    if (background) setImmediate(() => exec().catch(() => {}));
    else await exec();
  }

  async function kickoffDeployment(row, project, settings, environment, actor) {
    let res;
    try {
      res = await deploymentsService.create(
        { projectId: project.id, environmentId: environment.id, idempotencyKey: `preview-${row.id}-${String(row.commitSha).slice(0, 12)}`, commitSha: row.commitSha, branch: row.branch, rollbackPlan: 'Destroy the preview environment' },
        actor,
      );
    } catch (error) {
      await setRow(row.id, { lastError: String(error?.code ?? 'DEPLOYMENT_REJECTED').slice(0, 200) });
      if (error instanceof AppError && error.status < 500) return { rejected: error.code };
      throw error;
    }
    await setRow(row.id, { deploymentId: res.deployment.id, status: 'deploying', lastError: null });
    const queued = res.operation?.status !== 'PENDING_APPROVAL' && res.deployment.status === 'Queued';
    if (queued) await runDeployment(row, project, settings, res.deployment, actor);
    return { deploymentId: res.deployment.id, approvalRequired: res.operation?.status === 'PENDING_APPROVAL' };
  }

  async function destroyRow(row, { actor = SYSTEM_ACTOR, reason = 'manual' } = {}) {
    if (row.status === 'destroyed') return row;
    const project = await prisma.project.findUnique({ where: { id: row.projectId } });
    const settings = await settingsTable().findUnique({ where: { projectId: row.projectId } });
    await setRow(row.id, { status: 'destroying' });
    const problems = [];
    try {
      if (row.environmentId && teardown) {
        const out = await teardown({ projectId: row.projectId, environmentId: row.environmentId, serverId: row.serverId });
        if (out && out.ok === false) problems.push('teardown');
      }
    } catch {
      problems.push('teardown');
    }
    if (row.dnsStatus === 'applied') {
      try {
        await adapters?.webserver?.rollback?.({ domain: row.hostname });
        const root = row.rootDomainId ? await rootDomains?.system.byId(row.rootDomainId) : null;
        if (root && settings?.dnsMode !== 'wildcard') for (const type of ['A', 'AAAA', 'CNAME']) await rootDomains.system.apply(root, 'remove', { type, name: row.hostname });
      } catch {
        problems.push('exposure');
      }
    }
    if (problems.length) {
      // Keep the port reserved and the row retryable: the cleanup job tries again.
      const failed = await setRow(row.id, { status: 'failed', lastError: `destroy incomplete: ${problems.join(',')}`, closedAt: row.closedAt ?? now() });
      await audit({ actorId: actor.id ?? null, action: 'preview.destroy', resourceId: row.projectId, result: 'failure', metadata: { previewId: row.id, problems } });
      return failed;
    }
    await prisma.domain.updateMany({ where: { name: row.hostname }, data: { archivedAt: now() } });
    if (row.environmentId) await prisma.projectEnvVar.deleteMany({ where: { environmentId: row.environmentId } });
    const done = await setRow(row.id, { status: 'destroyed', port: null, destroyedAt: now(), closedAt: row.closedAt ?? now(), basicAuthHash: null, dnsStatus: null, exposeApprovalId: null, lastError: null });
    await audit({ actorId: actor.id ?? null, action: 'preview.destroy', resourceId: row.projectId, result: 'success', after: { previewId: row.id, prNumber: row.prNumber, reason } });
    if (project && settings) await comment({ ...row, status: 'destroyed' }, settings, project, 'destroyed');
    return done;
  }

  /** Create or update the preview for one PR. */
  async function upsertFromPr({ project, settings, prNumber, branch, commitSha, actor, approvalId }) {
    validateRef(branch);
    if (!/^[0-9a-f]{7,40}$/.test(String(commitSha))) throw new AppError(422, 'COMMIT_SHA_INVALID', 'Commit must be a 7-40 character hex SHA');
    if (project.archivedAt || project.status !== 'active') throw new AppError(409, 'PROJECT_NOT_DEPLOYABLE', 'Project is not active');
    const root = settings.rootDomainId ? await rootDomains.system.byId(settings.rootDomainId) : null;
    if (!root || root.archivedAt) throw new AppError(409, 'PREVIEW_ROOT_DOMAIN_REQUIRED', 'A connected root domain is required for preview hostnames');
    if (settings.basicAuth && isCaddyEnabled(env)) throw new AppError(409, 'PREVIEW_AUTH_NEEDS_BCRYPT', 'Preview basic auth is not supported with CADDY_MODE=on');

    const existing = await previews().findFirst({ where: { projectId: project.id, prNumber } });
    // ---- update: same PR pushed again
    if (existing && existing.status !== 'destroyed') {
      const row = await setRow(existing.id, { branch, commitSha, status: existing.status === 'failed' ? 'deploying' : existing.status, closedAt: null });
      const environment = await prisma.projectEnvironment.findUnique({ where: { id: row.environmentId } });
      const out = await kickoffDeployment(row, project, settings, environment, actor);
      await audit({ actorId: actor.id ?? null, action: 'preview.update', resourceId: project.id, result: out.rejected ? 'failure' : 'success', after: { previewId: row.id, prNumber, commitSha } });
      return { preview: await view(await previews().findUnique({ where: { id: row.id } })), ...out, updated: true };
    }
    // ---- create
    const live = await previews().count({ where: { projectId: project.id, status: { in: LIVE_STATUSES } } });
    if (live >= settings.maxActive) throw new AppError(409, 'PREVIEW_LIMIT_REACHED', `This project allows ${settings.maxActive} active previews`);
    const hostname = previewHostname({ prNumber, slug: project.slug, rootName: root.name });
    const url = `https://${hostname}`;
    const creds = settings.basicAuth ? createPreviewCredentials() : null;
    const data = {
      projectId: project.id, serverId: project.serverId, prNumber, branch, commitSha, status: 'creating', hostname, url, rootDomainId: root.id,
      basicAuthUser: creds?.user ?? null, basicAuthHash: creds?.hash ?? null, dnsStatus: null, exposeApprovalId: null, lastError: null,
      expiresAt: new Date(now().getTime() + settings.ttlDays * DAY), closedAt: null, destroyedAt: null, commentId: null,
    };
    let row = null;
    for (let attempt = 0; attempt < 5 && !row; attempt += 1) {
      const taken = [
        ...(await previews().findMany({ where: { serverId: project.serverId, port: { not: null } } })).map((p) => p.port),
        ...((await prisma.serverPort?.findMany?.({ where: { serverId: project.serverId } })) ?? []).map((p) => p.port),
      ];
      const port = allocatePort({ start: settings.portStart, end: settings.portEnd, taken, seed: prNumber + attempt });
      try {
        row = existing ? await previews().update({ where: { id: existing.id }, data: { ...data, port } }) : await previews().create({ data: { ...data, port } });
      } catch (error) {
        // Lost a race on the unique (serverId, port): pick again.
        if (!/Unique|P2002|duplicate/i.test(String(error?.code ?? error?.message))) throw error;
      }
    }
    if (!row) throw new AppError(409, 'PREVIEW_PORT_CONFLICT', 'Could not reserve a preview port');
    const environment = await prepareEnvironment(project, settings, row, row.port);
    row = await setRow(row.id, { environmentId: environment.id });
    await audit({ actorId: actor.id ?? null, action: 'preview.create', resourceId: project.id, environmentId: environment.id, result: 'success', after: { previewId: row.id, prNumber, hostname, port: row.port } });
    const out = await kickoffDeployment(row, project, settings, environment, actor);
    let expose = null;
    try {
      expose = await exposure(await previews().findUnique({ where: { id: row.id } }), settings, project, actor, { approvalId });
    } catch (error) {
      expose = { error: error.code ?? 'PREVIEW_EXPOSE_FAILED' };
    }
    const fresh = await previews().findUnique({ where: { id: row.id } });
    await comment(fresh, settings, project);
    return { preview: await view(fresh), ...out, expose: expose.approvalRequired ? { approvalRequired: true, approvalId: expose.approval.id } : expose, ...(creds ? { basicAuth: { user: creds.user, password: creds.password } } : {}), created: true };
  }

  return {
    // ------------------------------------------------------------------ admin
    async getSettings(projectId, actor) {
      await access.requireView(actor, projectId);
      return guard(async () => settingsView(await settingsTable().findUnique({ where: { projectId } })));
    },

    async updateSettings(projectId, input, actor) {
      requireOwner(actor);
      return guard(async () => {
        const project = await loadProject(projectId);
        const current = await settingsTable().findUnique({ where: { projectId } });
        const next = { ...settingsView(current), ...Object.fromEntries(Object.entries(input).filter(([k, v]) => v !== undefined && k !== 'githubToken')) };
        validatePortRange(next.portStart, next.portEnd);
        if (next.enabled) {
          const root = next.rootDomainId ? await rootDomains.system.byId(next.rootDomainId) : null;
          if (!root || root.archivedAt) throw new AppError(422, 'PREVIEW_ROOT_DOMAIN_REQUIRED', 'Choose a connected root domain before enabling previews');
        }
        if (next.basicAuth && isCaddyEnabled(env)) throw new AppError(409, 'PREVIEW_AUTH_NEEDS_BCRYPT', 'Preview basic auth is not supported with CADDY_MODE=on');
        if (next.sourceEnvCode && !(await prisma.projectEnvironment.findFirst({ where: { projectId: project.id, code: next.sourceEnvCode } }))) {
          throw new AppError(422, 'ENVIRONMENT_CODE_UNKNOWN', `Environment "${next.sourceEnvCode}" does not exist in this project`);
        }
        const data = {
          enabled: next.enabled, rootDomainId: next.rootDomainId, sourceEnvCode: next.sourceEnvCode, envKeysJson: next.envKeys, portStart: next.portStart, portEnd: next.portEnd,
          ttlDays: next.ttlDays, maxActive: next.maxActive, basicAuth: next.basicAuth, dnsMode: next.dnsMode, commentEnabled: next.commentEnabled,
        };
        if (input.githubToken !== undefined) data.githubTokenEnc = input.githubToken === null ? null : encrypt(input.githubToken, credentialKey());
        const row = current ? await settingsTable().update({ where: { projectId }, data }) : await settingsTable().create({ data: { projectId, ...data } });
        await audit({ actorId: actor.id, action: 'project.preview_settings.update', resourceId: projectId, result: 'success', after: { enabled: row.enabled, tokenChanged: input.githubToken !== undefined } });
        return settingsView(row);
      });
    },

    async list(projectId, actor) {
      await access.requireView(actor, projectId);
      return guard(async () => {
        const rows = await previews().findMany({ where: { projectId }, orderBy: { createdAt: 'desc' }, take: 100 });
        return Promise.all(rows.map(view));
      });
    },

    /** Manual creation (the same lifecycle a webhook triggers). Returns the basic auth password once. */
    async create(projectId, input, actor) {
      requireOwner(actor);
      return guard(async () => {
        const project = await loadProject(projectId);
        const settings = await settingsTable().findUnique({ where: { projectId } });
        if (!settings?.enabled) throw new AppError(409, 'PREVIEWS_DISABLED', 'Preview environments are not enabled for this project');
        return upsertFromPr({ project, settings, prNumber: input.prNumber, branch: input.branch, commitSha: input.commitSha, actor, approvalId: input.approvalId });
      });
    },

    async expose(projectId, previewId, input, actor) {
      requireOwner(actor);
      return guard(async () => {
        const project = await loadProject(projectId);
        const row = await loadPreview(projectId, previewId);
        if (['destroyed', 'destroying'].includes(row.status)) throw new AppError(409, 'PREVIEW_GONE', 'Preview was destroyed');
        const settings = await settingsTable().findUnique({ where: { projectId } });
        const out = await exposure(row, settings, project, actor, input);
        return out.approvalRequired ? out : { ...out, preview: await view(await previews().findUnique({ where: { id: previewId } })) };
      });
    },

    async destroy(projectId, previewId, actor) {
      requireOwner(actor);
      return guard(async () => view(await destroyRow(await loadPreview(projectId, previewId), { actor, reason: 'manual' })));
    },

    async extend(projectId, previewId, { days }, actor) {
      requireOwner(actor);
      return guard(async () => {
        const row = await loadPreview(projectId, previewId);
        if (['destroyed', 'destroying'].includes(row.status)) throw new AppError(409, 'PREVIEW_GONE', 'Preview was destroyed');
        const base = Math.max(new Date(row.expiresAt).getTime(), now().getTime());
        const updated = await setRow(row.id, { expiresAt: new Date(base + days * DAY), closedAt: null });
        await audit({ actorId: actor.id, action: 'preview.extend', resourceId: projectId, result: 'success', after: { previewId, days } });
        return view(updated);
      });
    },

    /** New basic auth password (shown once). Only the hash is stored. */
    async resetAuth(projectId, previewId, actor) {
      requireOwner(actor);
      return guard(async () => {
        const row = await loadPreview(projectId, previewId);
        const settings = await settingsTable().findUnique({ where: { projectId } });
        if (!settings?.basicAuth) throw new AppError(409, 'PREVIEW_AUTH_DISABLED', 'Basic auth is not enabled for this project');
        if (['destroyed', 'destroying'].includes(row.status)) throw new AppError(409, 'PREVIEW_GONE', 'Preview was destroyed');
        const creds = createPreviewCredentials();
        const updated = await setRow(row.id, { basicAuthUser: creds.user, basicAuthHash: creds.hash });
        if (row.dnsStatus === 'applied') {
          await adapters.webserver.apply({ domain: row.hostname, config: renderPreviewVhost({ hostname: row.hostname, port: row.port, basicAuth: true }), auxFiles: [{ path: `/etc/nginx/nt-preview/${row.hostname}.htpasswd`, content: htpasswdLine(creds.user, creds.hash), mode: '0640' }], serverId: row.serverId });
        }
        await audit({ actorId: actor.id, action: 'preview.auth.reset', resourceId: projectId, result: 'success', after: { previewId: row.id } });
        return { preview: await view(updated), basicAuth: { user: creds.user, password: creds.password } };
      });
    },

    async enabledFor(projectId) {
      try {
        return Boolean((await settingsTable().findUnique({ where: { projectId } }))?.enabled);
      } catch {
        return false;
      }
    },

    // ------------------------------------------------------------------ webhook (called by TASK-044 after signature + replay checks)
    /** { handled:false } = previews are off for this project, so the regular PR mapping applies. */
    async handlePullRequest({ projectId, payload, actor }) {
      return guard(async () => {
        const settings = await settingsTable().findUnique({ where: { projectId } });
        if (!settings?.enabled) return { handled: false };
        const pr = payload?.pull_request;
        const action = payload?.action;
        const prNumber = Number(pr?.number ?? payload?.number);
        if (!Number.isInteger(prNumber) || prNumber < 1) return { handled: true, accepted: false, ignored: 'invalid pull request number' };
        const project = await loadProject(projectId);
        if (action === 'closed') {
          const row = await previews().findFirst({ where: { projectId, prNumber } });
          if (!row || row.status === 'destroyed') return { handled: true, accepted: false, ignored: 'no preview for this pull request' };
          await setRow(row.id, { closedAt: now() });
          const out = await destroyRow({ ...row, closedAt: now() }, { actor, reason: 'pr_closed' });
          return { handled: true, accepted: true, destroyed: out.status === 'destroyed', previewId: row.id };
        }
        const sameRepo = pr?.head?.repo?.full_name && pr.head.repo.full_name === pr.base?.repo?.full_name;
        if (!PR_UPSERT_ACTIONS.has(action) || !sameRepo) return { handled: true, accepted: false, ignored: 'pull request action or fork not deployable' };
        try {
          const out = await upsertFromPr({ project, settings, prNumber, branch: pr.head.ref, commitSha: pr.head.sha, actor });
          return { handled: true, accepted: true, previewId: out.preview?.id, created: Boolean(out.created), updated: Boolean(out.updated), approvalRequired: Boolean(out.approvalRequired || out.expose?.approvalRequired) };
        } catch (error) {
          if (error instanceof AppError && error.status < 500) return { handled: true, accepted: false, rejected: error.code };
          throw error;
        }
      });
    },

    // ------------------------------------------------------------------ worker job
    /** Destroys previews whose PR closed or whose TTL elapsed. Retries rows whose earlier teardown failed. */
    async cleanupExpired(at = now()) {
      return guard(async () => {
        const rows = await previews().findMany({
          where: { status: { not: 'destroyed' }, OR: [{ closedAt: { not: null } }, { expiresAt: { lte: at } }] },
          take: 50,
          orderBy: { expiresAt: 'asc' },
        });
        const out = { destroyed: [], failed: [] };
        for (const row of rows) {
          const done = await destroyRow(row, { actor: SYSTEM_ACTOR, reason: row.closedAt ? 'pr_closed' : 'ttl_expired' });
          (done.status === 'destroyed' ? out.destroyed : out.failed).push(row.id);
        }
        return out;
      });
    },
  };
}

export { COMMENT_MARKER };
