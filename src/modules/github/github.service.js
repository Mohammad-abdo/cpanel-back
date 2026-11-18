/**
 * TASK-044 extension + TASK-055: platform GitHub App (Owner-managed).
 * - Every secret (private key, webhook secret, installation ids) is AES-256-GCM encrypted under CREDENTIAL_ENCRYPTION_KEY and
 *   never returned: responses carry "configured" booleans only. Audit records carry field names, never values.
 * - Settings that are not secret (public base URL, health counters, last events) live in the row's metaJson, so no extra table.
 * - The manifest flow uses a signed, single-use, 10 minute `state`; the callback exchanges the temporary code through
 *   github.client.js (fixed host) and stores the result encrypted.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { createGitHubClient, validRepoName } from './github.client.js';
import { parseGithubRepo } from '../previews/previews.github.js';
import { verifyGithubSignature } from '../webhooks/webhooks.crypto.js';

/** Fixed id so the table behaves as a single-row store. */
export const GITHUB_APP_CONFIG_ID = '00000000-0000-0000-0000-000000000001';
export const DEFAULT_PUBLIC_BASE_URL = 'https://cpanel-review.nodeteam.site';
export const STATE_TTL_MS = 10 * 60 * 1000;
const MAX_EVENTS = 15;

const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|GitHubAppConfig/i;
const schemaRequired = () =>
  new AppError(501, 'SCHEMA_REQUIRED', 'GitHub App config is not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');

export function normalizeBaseUrl(raw) {
  let u;
  try {
    u = new URL(String(raw));
  } catch {
    throw new AppError(422, 'PUBLIC_BASE_URL_INVALID', 'Public base URL must be an absolute https URL');
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) throw new AppError(422, 'PUBLIC_BASE_URL_INVALID', 'Public base URL must be an https origin without credentials or query');
  return u.origin;
}

export function createGitHubService({
  prisma,
  auditService = null,
  platform = null,
  client = createGitHubClient(),
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
  env = process.env,
  now = () => new Date(),
}) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'github_app', result: 'success', ...event }) : null);
  /** nonce -> expiry (ms). Process-local: a restart invalidates pending manifest flows, which is the safe direction. */
  const pendingStates = new Map();

  const table = () => {
    if (!prisma?.gitHubAppConfig) throw schemaRequired();
    return prisma.gitHubAppConfig;
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
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage the GitHub App');
  }

  const metaOf = (row) => (row?.metaJson && typeof row.metaJson === 'object' ? row.metaJson : {});

  function baseUrl(row) {
    const raw = metaOf(row).publicBaseUrl || env.PUBLIC_BASE_URL || env.APP_PUBLIC_URL || DEFAULT_PUBLIC_BASE_URL;
    try {
      return normalizeBaseUrl(raw);
    } catch {
      return DEFAULT_PUBLIC_BASE_URL;
    }
  }

  const urls = (row) => {
    const base = baseUrl(row);
    return { publicBaseUrl: base, webhookUrl: `${base}/api/v1/webhooks/github`, callbackUrl: `${base}/api/v1/github/app/callback`, setupUrl: `${base}/settings?github=installed` };
  };

  function readInstallations(row) {
    const enc = metaOf(row).installationsEnc;
    if (!enc) return [];
    try {
      const list = JSON.parse(decrypt(Buffer.from(enc, 'base64'), credentialKey()).toString('utf8'));
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }
  const sealInstallations = (list) => encrypt(Buffer.from(JSON.stringify(list), 'utf8'), credentialKey()).toString('base64');

  /** Public shape; no secret material. */
  function view(row) {
    const meta = metaOf(row);
    const base = {
      id: row?.id ?? null,
      appId: row?.appId ?? null,
      clientId: row?.clientId ?? null,
      slug: row?.slug ?? null,
      installationId: null,
      status: row?.status ?? 'unconfigured',
      hasPrivateKey: Boolean(row?.privateKeyEnc),
      hasWebhookSecret: Boolean(row?.webhookSecretEnc),
      configured: Boolean(row?.privateKeyEnc && row?.appId),
      installationCount: Number(meta.installationCount ?? 0),
      health: { delivered: meta.delivered ?? 0, rejected: meta.rejected ?? 0, lastDeliveryAt: meta.lastDeliveryAt ?? null },
      lastEvents: Array.isArray(meta.lastEvents) ? meta.lastEvents : [],
      meta: { archivedAt: meta.archivedAt ?? null },
      createdAt: row?.createdAt ?? null,
      updatedAt: row?.updatedAt ?? null,
      ...urls(row),
    };
    return base;
  }

  const loadRow = () => guard(() => table().findUnique({ where: { id: GITHUB_APP_CONFIG_ID } }));

  async function saveMeta(patch, extra = {}) {
    const row = await loadRow();
    const meta = { ...metaOf(row), ...patch };
    return guard(() =>
      table().upsert({
        where: { id: GITHUB_APP_CONFIG_ID },
        create: { id: GITHUB_APP_CONFIG_ID, status: 'unconfigured', ...extra, metaJson: meta },
        update: { ...extra, metaJson: meta, updatedAt: now() },
      }),
    );
  }

  /** Decrypted credentials for outbound calls. Never logged or returned. */
  async function credentials(row) {
    const r = row ?? (await loadRow());
    if (!r?.privateKeyEnc || !r?.appId) throw new AppError(422, 'GITHUB_APP_NOT_CONFIGURED', 'Configure the GitHub App id and private key before using installation APIs');
    return { appId: r.appId, privateKeyPem: decrypt(Buffer.from(r.privateKeyEnc), credentialKey()).toString('utf8') };
  }

  async function appWebhookSecret(row) {
    const r = row ?? (await loadRow().catch(() => null));
    if (!r?.webhookSecretEnc) return null;
    try {
      return decrypt(Buffer.from(r.webhookSecretEnc), credentialKey()).toString('utf8');
    } catch {
      return null;
    }
  }

  function buildManifestJson(row) {
    const u = urls(row);
    return {
      name: 'NodeTeam Control',
      url: u.publicBaseUrl,
      hook_attributes: { url: u.webhookUrl, active: true },
      redirect_url: u.callbackUrl,
      setup_url: u.setupUrl,
      setup_on_update: true,
      public: false,
      default_permissions: { contents: 'read', metadata: 'read', pull_requests: 'write', checks: 'write', statuses: 'write' },
      default_events: ['push', 'pull_request'],
    };
  }

  // ---- manifest state -------------------------------------------------------------------------------------------
  const stateKey = () => createHmac('sha256', String(credentialKey() ?? '')).update('github-manifest-state').digest();
  const signState = (payload) => createHmac('sha256', stateKey()).update(payload).digest('base64url');

  function issueState() {
    const nonce = randomBytes(18).toString('base64url');
    const exp = now().getTime() + STATE_TTL_MS;
    for (const [n, e] of pendingStates) if (e <= now().getTime()) pendingStates.delete(n);
    pendingStates.set(nonce, exp);
    const payload = `${nonce}.${exp}`;
    return `${payload}.${signState(payload)}`;
  }

  /** Signature, expiry, then single use. Any failure is the same error. */
  function consumeState(state) {
    const bad = () => new AppError(400, 'GITHUB_STATE_INVALID', 'The GitHub setup link is invalid, expired or already used');
    const parts = String(state ?? '').split('.');
    if (parts.length !== 3) throw bad();
    const [nonce, expRaw, sig] = parts;
    const expected = Buffer.from(signState(`${nonce}.${expRaw}`));
    const given = Buffer.from(sig);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw bad();
    if (Number(expRaw) <= now().getTime()) {
      pendingStates.delete(nonce);
      throw bad();
    }
    if (!pendingStates.delete(nonce)) throw bad();
  }

  async function installationFor(creds, owner, repo) {
    const id = await client.installationForRepo(creds, owner, repo);
    if (!id) throw new AppError(404, 'GITHUB_NOT_INSTALLED', 'The GitHub App is not installed on this repository');
    return id;
  }

  const clampPage = (n) => (Number.isInteger(Number(n)) && Number(n) > 0 ? Number(n) : 1);

  return {
    appWebhookSecret,
    /** Verifies the App-level webhook signature. False when no secret is stored. */
    async verifyAppSignature(rawBody, signature) {
      const secret = await appWebhookSecret();
      return Boolean(secret) && verifyGithubSignature(rawBody, signature, secret);
    },

    async getApp(actor) {
      requireOwner(actor);
      const row = await loadRow();
      return { ...view(row), installations: readInstallations(row) };
    },

    /** Write-only: secrets are accepted, encrypted and never echoed. */
    async upsertApp(input, actor) {
      requireOwner(actor);
      const key = credentialKey();
      encrypt(Buffer.from('check', 'utf8'), key);
      const existing = await loadRow();
      const data = { status: 'active', updatedAt: now() };
      if (input.appId !== undefined) data.appId = input.appId;
      if (input.clientId !== undefined) data.clientId = input.clientId;
      if (input.slug !== undefined) data.slug = input.slug;
      if (input.privateKey !== undefined) data.privateKeyEnc = encrypt(Buffer.from(input.privateKey, 'utf8'), key);
      if (input.webhookSecret !== undefined) data.webhookSecretEnc = encrypt(Buffer.from(input.webhookSecret, 'utf8'), key);
      const meta = { ...metaOf(existing) };
      if (input.publicBaseUrl !== undefined) meta.publicBaseUrl = normalizeBaseUrl(input.publicBaseUrl);
      if (input.installationId !== undefined) {
        const list = readInstallations(existing).filter((i) => String(i.id) !== input.installationId);
        list.push({ id: input.installationId, account: null });
        meta.installationsEnc = sealInstallations(list);
        meta.installationCount = list.length;
        data.installationId = null;
      }
      const row = await guard(() =>
        table().upsert({
          where: { id: GITHUB_APP_CONFIG_ID },
          create: { id: GITHUB_APP_CONFIG_ID, ...data, metaJson: meta },
          update: { ...data, metaJson: meta },
        }),
      );
      client.invalidate();
      audit({ action: 'github.app.upsert', actorId: actor.id, resourceId: row.id, after: { fields: Object.keys(input) } });
      return { ...view(row), installations: readInstallations(row) };
    },

    /** Disconnect. High risk: approval-gated when the platform service is wired. */
    async deleteApp(actor, approval = {}) {
      requireOwner(actor);
      const existing = await loadRow();
      if (!existing) return view(null);
      if (platform) {
        const gate = await platform.gate(
          {
            action: 'github.app.disconnect',
            binding: 'github-app-disconnect',
            resourceType: 'github_app',
            resourceId: GITHUB_APP_CONFIG_ID,
            approvalId: approval.approvalId,
            reason: approval.reason ?? 'Owner request from Settings > GitHub',
            impact: ['GitHub deploy webhooks, repository browsing and private clones stop working until the App is reconnected'],
            rollbackPlan: approval.rollbackPlan ?? 'Reconnect the App with the manifest flow or the manual form',
            context: { binding: 'github-app-disconnect' },
          },
          actor,
        );
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      }
      const row = await guard(() =>
        table().update({
          where: { id: GITHUB_APP_CONFIG_ID },
          data: {
            privateKeyEnc: null,
            webhookSecretEnc: null,
            installationId: null,
            status: 'archived',
            metaJson: { ...metaOf(existing), installationsEnc: null, installationCount: 0, archivedAt: now().toISOString() },
            updatedAt: now(),
          },
        }),
      );
      client.invalidate();
      audit({ action: 'github.app.disconnect', actorId: actor.id, resourceId: row.id });
      return view(row);
    },

    /** Rotates the App-level webhook secret locally; the new value is shown once and must be pasted into the GitHub App. */
    async rotateWebhookSecret(actor, approval = {}) {
      requireOwner(actor);
      const row0 = await loadRow();
      if (!row0?.privateKeyEnc) throw new AppError(422, 'GITHUB_APP_NOT_CONFIGURED', 'GitHub App is not configured');
      if (platform) {
        const gate = await platform.gate(
          {
            action: 'github.app.rotate_secret',
            binding: 'github-app-rotate-secret',
            resourceType: 'github_app',
            resourceId: GITHUB_APP_CONFIG_ID,
            approvalId: approval.approvalId,
            reason: approval.reason ?? 'Owner request from Settings > GitHub',
            impact: ['App-level webhook deliveries fail until the new secret is saved in the GitHub App settings'],
            rollbackPlan: approval.rollbackPlan ?? 'Paste the previous secret back in the GitHub App settings if one was kept',
            context: { binding: 'github-app-rotate-secret' },
          },
          actor,
        );
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      }
      const secret = randomBytes(32).toString('hex');
      const row = await guard(() => table().update({ where: { id: GITHUB_APP_CONFIG_ID }, data: { webhookSecretEnc: encrypt(Buffer.from(secret, 'utf8'), credentialKey()), updatedAt: now() } }));
      audit({ action: 'github.app.rotate_secret', actorId: actor.id, resourceId: row.id });
      return { app: view(row), webhookSecret: secret };
    },

    /** Starts the manifest flow: the page POSTs `manifest` to `postUrl` as a form field together with `state`. */
    async manifest(actor) {
      requireOwner(actor);
      const row = await loadRow();
      const state = issueState();
      audit({ action: 'github.app.manifest.start', actorId: actor.id, resourceId: GITHUB_APP_CONFIG_ID });
      return { manifest: buildManifestJson(row), postUrl: `https://github.com/settings/apps/new?state=${encodeURIComponent(state)}`, state, ...urls(row) };
    },

    /** Public callback target. The signed single-use state is the only authentication. */
    async completeManifest({ code, state }) {
      consumeState(state);
      const out = await client.exchangeManifestCode(code);
      if (!out?.id || !out?.pem || !out?.webhook_secret) throw new AppError(502, 'GITHUB_MANIFEST_INCOMPLETE', 'GitHub did not return complete App credentials');
      const key = credentialKey();
      const existing = await loadRow();
      const data = {
        appId: Number(out.id),
        clientId: out.client_id ? String(out.client_id).slice(0, 64) : null,
        slug: out.slug ? String(out.slug).slice(0, 40) : null,
        privateKeyEnc: encrypt(Buffer.from(String(out.pem), 'utf8'), key),
        webhookSecretEnc: encrypt(Buffer.from(String(out.webhook_secret), 'utf8'), key),
        installationId: null,
        status: 'active',
        updatedAt: now(),
      };
      const meta = { ...metaOf(existing), archivedAt: null };
      const row = await guard(() =>
        table().upsert({
          where: { id: GITHUB_APP_CONFIG_ID },
          create: { id: GITHUB_APP_CONFIG_ID, ...data, metaJson: meta },
          update: { ...data, metaJson: meta },
        }),
      );
      client.invalidate();
      audit({ action: 'github.app.manifest.complete', actorId: null, resourceId: row.id, after: { slug: data.slug } });
      return { redirectTo: `${baseUrl(row)}/settings?github=created`, slug: data.slug };
    },

    async setPublicBaseUrl(url, actor) {
      requireOwner(actor);
      const row = await saveMeta({ publicBaseUrl: normalizeBaseUrl(url) });
      audit({ action: 'github.app.settings.update', actorId: actor.id, resourceId: row.id, after: { fields: ['publicBaseUrl'] } });
      return view(row);
    },

    // ---- reads through the App -------------------------------------------------------------------------------------
    async listInstallations(actor, { page } = {}) {
      requireOwner(actor);
      const creds = await credentials();
      const out = await client.listInstallations(creds, { page: clampPage(page) });
      const items = out.items.map((i) => ({ id: String(i.id), account: i.account?.login ?? null, targetType: i.target_type ?? null, repositorySelection: i.repository_selection ?? null }));
      if (out.page === 1) {
        const row = await loadRow();
        await saveMeta({ installationsEnc: sealInstallations(items.map((i) => ({ id: i.id, account: i.account }))), installationCount: items.length }).catch(() => null);
        void row;
      }
      return { ...out, items };
    },

    async listInstallationRepos(actor, { installationId, page } = {}) {
      requireOwner(actor);
      const creds = await credentials();
      const id = installationId ?? readInstallations(await loadRow())[0]?.id;
      if (!id) return { items: [], page: 1, hasMore: false, notice: 'No installation yet' };
      const out = await client.listRepos(creds, id, { page: clampPage(page) });
      return {
        ...out,
        installationId: String(id),
        items: out.items.map((r) => ({ id: r.id, fullName: r.full_name, private: Boolean(r.private), defaultBranch: r.default_branch ?? null })),
      };
    },

    async listBranches(actor, { installationId, owner, repo, page } = {}) {
      requireOwner(actor);
      if (!validRepoName(owner, repo)) throw new AppError(422, 'GITHUB_REPO_INVALID', 'Repository must be owner/name');
      const creds = await credentials();
      const id = installationId ?? (await installationFor(creds, owner, repo));
      const out = await client.listBranches(creds, id, owner, repo, { page: clampPage(page) });
      return { ...out, items: out.items.map((b) => ({ name: b.name, sha: b.commit?.sha ?? null, protected: Boolean(b.protected) })) };
    },

    // ---- project link (extends TASK-044 repository + webhook rows) ---------------------------------------------------
    async linkProjectRepo(projectId, input, actor) {
      requireOwner(actor);
      const [owner, repo] = String(input.repo ?? '').split('/');
      if (!validRepoName(owner, repo) || String(input.repo).split('/').length !== 2) throw new AppError(422, 'GITHUB_REPO_INVALID', 'Repository must be owner/name');
      const project = await prisma.project.findUnique({ where: { id: projectId } });
      if (!project) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      if (project.archivedAt) throw new AppError(409, 'PROJECT_ARCHIVED', 'Project is archived');
      const creds = await credentials();
      const installId = input.installationId ?? (await installationFor(creds, owner, repo));
      const defaultBranch = input.defaultBranch ?? (await client.getDefaultBranch(creds, installId, owner, repo)) ?? 'main';
      const envs = await prisma.projectEnvironment.findMany({ where: { projectId } });
      const codes = new Set(envs.map((e) => e.code));
      for (const code of Object.values(input.branchMap ?? {})) {
        if (!codes.has(code)) throw new AppError(422, 'ENVIRONMENT_CODE_UNKNOWN', `Environment "${code}" does not exist in this project`);
      }
      const remoteUrl = `https://github.com/${owner}/${repo}.git`;
      const existing = await prisma.projectRepository.findUnique({ where: { projectId } });
      if (existing) await prisma.projectRepository.update({ where: { projectId }, data: { remoteUrl, defaultBranch } });
      else await prisma.projectRepository.create({ data: { projectId, remoteUrl, defaultBranch } });
      if (input.branchMap !== undefined || input.autoDeploy !== undefined) {
        if (!prisma.projectWebhook) throw schemaRequired();
        const hook = await prisma.projectWebhook.findUnique({ where: { projectId } });
        const data = {
          ...(input.autoDeploy !== undefined ? { enabled: input.autoDeploy } : {}),
          ...(input.branchMap !== undefined ? { branchMapJson: input.branchMap } : {}),
          actorUserId: actor.id,
        };
        if (hook) await prisma.projectWebhook.update({ where: { projectId }, data });
        else await prisma.projectWebhook.create({ data: { projectId, enabled: false, branchMapJson: {}, prMapJson: {}, ...data } });
      }
      await saveMeta({ linkedRepos: { ...(metaOf(await loadRow()).linkedRepos ?? {}), [projectId]: `${owner}/${repo}`.toLowerCase() } });
      audit({ action: 'github.project.link', actorId: actor.id, resourceId: projectId, resourceType: 'project', after: { repo: `${owner}/${repo}`, defaultBranch, autoDeploy: input.autoDeploy ?? null } });
      return { projectId, repo: `${owner}/${repo}`, remoteUrl, defaultBranch, autoDeploy: input.autoDeploy ?? null, branchMap: input.branchMap ?? null };
    },

    // ---- consumed by executors / previews / webhooks ------------------------------------------------------------------
    /**
     * Short-lived installation token for a private https clone, or null when the App is not configured/installed.
     * Callers must pass it to executors through stdin or a 0600 file only (never args, env dumps or logs).
     */
    async cloneCredential(remoteUrl, { projectId } = {}) {
      const parsed = parseGithubRepo(remoteUrl);
      if (!parsed) return null;
      if (!projectId) throw new AppError(403, 'GITHUB_REPO_NOT_LINKED', 'Clone credentials are only issued for a repository linked to an existing project');
      const row = await loadRow();
      if (!row?.privateKeyEnc || !row?.appId) return null;
      const wanted = `${parsed.owner}/${parsed.repo}`.toLowerCase();
      const linked = metaOf(row).linkedRepos?.[projectId];
      const stored = await prisma.projectRepository.findUnique({ where: { projectId } });
      const storedParsed = parseGithubRepo(stored?.remoteUrl);
      const storedName = storedParsed ? `${storedParsed.owner}/${storedParsed.repo}`.toLowerCase() : null;
      if (linked !== wanted || storedName !== wanted) {
        throw new AppError(403, 'GITHUB_REPO_NOT_LINKED', 'This repository is not linked to the project by the Owner');
      }
      const creds = await credentials(row);
      const id = await client.installationForRepo(creds, parsed.owner, parsed.repo);
      if (!id) return null;
      return { token: await client.scopedCloneToken(creds, id, parsed.repo), username: 'x-access-token' };
    },

    /** PR comment through the App (previews). Returns the comment id or null when the App cannot serve the repo. */
    async createPrComment(remoteUrl, prNumber, body) {
      const parsed = parseGithubRepo(remoteUrl);
      if (!parsed) return null;
      const creds = await credentials();
      const id = await client.installationForRepo(creds, parsed.owner, parsed.repo);
      return client.createPrComment(creds, id, parsed.owner, parsed.repo, prNumber, body);
    },

    async setCommitStatus(remoteUrl, sha, status) {
      const parsed = parseGithubRepo(remoteUrl);
      if (!parsed) return null;
      const creds = await credentials();
      const id = await client.installationForRepo(creds, parsed.owner, parsed.repo);
      return client.createCommitStatus(creds, id, parsed.owner, parsed.repo, sha, status);
    },

    /** Webhook health: counters and the last events (event name + outcome only; no payload). */
    async recordEvent({ event, outcome }) {
      try {
        const row = await loadRow();
        if (!row) return;
        const meta = metaOf(row);
        const lastEvents = [{ event: String(event).slice(0, 40), outcome: String(outcome).slice(0, 40), at: now().toISOString() }, ...(Array.isArray(meta.lastEvents) ? meta.lastEvents : [])].slice(0, MAX_EVENTS);
        const bad = outcome === 'rejected';
        await saveMeta({ lastEvents, lastDeliveryAt: now().toISOString(), delivered: (meta.delivered ?? 0) + (bad ? 0 : 1), rejected: (meta.rejected ?? 0) + (bad ? 1 : 0) });
      } catch {
        /* health bookkeeping must never fail a delivery */
      }
    },

    /** installation / installation_repositories: refresh the stored (encrypted) installation list. */
    async handleInstallationEvent(event, payload) {
      const inst = payload?.installation;
      if (!inst?.id) return { accepted: false, ignored: 'no installation' };
      const row = await loadRow();
      const list = readInstallations(row).filter((i) => String(i.id) !== String(inst.id));
      if (!(event === 'installation' && payload.action === 'deleted')) list.push({ id: String(inst.id), account: inst.account?.login ?? null });
      await saveMeta({ installationsEnc: sealInstallations(list), installationCount: list.length });
      client.invalidate(String(inst.id));
      return { accepted: true, installations: list.length };
    },
  };
}
