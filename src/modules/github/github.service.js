/**
 * TASK-044 extension: platform GitHub App credentials (Owner-managed). Secrets are AES-256-GCM encrypted
 * under CREDENTIAL_ENCRYPTION_KEY and never returned. Live GitHub API calls are stubbed until Owner adds @octokit.
 */
import { AppError } from '../../common/errors/app-error.js';
import { encrypt } from '../platform/platform.crypto.js';

/** Fixed id so the table behaves as a single-row store. */
export const GITHUB_APP_CONFIG_ID = '00000000-0000-0000-0000-000000000001';

const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|GitHubAppConfig/i;
const schemaRequired = () =>
  new AppError(501, 'SCHEMA_REQUIRED', 'GitHub App config is not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');

export function createGitHubService({
  prisma,
  auditService = null,
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
  env = process.env,
  now = () => new Date(),
}) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'github_app', ...event }) : null);

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

  /** Public shape; no secret material. */
  function view(row) {
    if (!row) {
      return {
        id: null,
        appId: null,
        clientId: null,
        slug: null,
        installationId: null,
        status: 'unconfigured',
        hasPrivateKey: false,
        hasWebhookSecret: false,
        meta: null,
        createdAt: null,
        updatedAt: null,
      };
    }
    return {
      id: row.id,
      appId: row.appId ?? null,
      clientId: row.clientId ?? null,
      slug: row.slug ?? null,
      installationId: row.installationId ?? null,
      status: row.status,
      hasPrivateKey: Boolean(row.privateKeyEnc),
      hasWebhookSecret: Boolean(row.webhookSecretEnc),
      meta: row.metaJson ?? null,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  async function loadRow() {
    return guard(() => table().findUnique({ where: { id: GITHUB_APP_CONFIG_ID } }));
  }

  async function requireConfigured(row) {
    const r = row ?? (await loadRow());
    if (!r?.privateKeyEnc) {
      throw new AppError(422, 'GITHUB_APP_NOT_CONFIGURED', 'Configure the GitHub App private key before using installation APIs');
    }
    return r;
  }

  function publicBaseUrl() {
    const base = (env.APP_PUBLIC_URL ?? '').replace(/\/$/, '');
    return base || 'https://example.invalid';
  }

  function buildManifestJson() {
    const api = publicBaseUrl();
    return {
      name: 'NodeTeam Control',
      url: api,
      hook_attributes: { url: `${api}/webhooks/github`, active: true },
      redirect_url: `${api}/github/app/callback`,
      setup_url: `${api}/settings?github=installed`,
      setup_on_update: true,
      public: false,
      default_permissions: {
        contents: 'read',
        metadata: 'read',
      },
      default_events: ['push', 'pull_request'],
    };
  }

  return {
    async getApp(actor) {
      requireOwner(actor);
      const row = await loadRow();
      return view(row);
    },

    async upsertApp(input, actor) {
      requireOwner(actor);
      const key = credentialKey();
      encrypt(Buffer.from('check', 'utf8'), key);

      const data = {
        appId: input.appId ?? null,
        clientId: input.clientId ?? null,
        slug: input.slug ?? null,
        installationId: input.installationId ?? null,
        status: 'active',
        updatedAt: now(),
      };
      if (input.privateKey !== undefined) {
        data.privateKeyEnc = encrypt(Buffer.from(input.privateKey, 'utf8'), key);
      }
      if (input.webhookSecret !== undefined) {
        data.webhookSecretEnc = encrypt(Buffer.from(input.webhookSecret, 'utf8'), key);
      }

      const row = await guard(() =>
        table().upsert({
          where: { id: GITHUB_APP_CONFIG_ID },
          create: { id: GITHUB_APP_CONFIG_ID, ...data, metaJson: {} },
          update: data,
        }),
      );

      audit({ action: 'github.app.upsert', actorId: actor.id, resourceId: row.id });
      return view(row);
    },

    async deleteApp(actor) {
      requireOwner(actor);
      const existing = await loadRow();
      if (!existing) return view(null);

      const row = await guard(() =>
        table().update({
          where: { id: GITHUB_APP_CONFIG_ID },
          data: {
            privateKeyEnc: null,
            webhookSecretEnc: null,
            installationId: null,
            status: 'archived',
            metaJson: { ...(existing.metaJson && typeof existing.metaJson === 'object' ? existing.metaJson : {}), archivedAt: now().toISOString() },
            updatedAt: now(),
          },
        }),
      );

      audit({ action: 'github.app.archive', actorId: actor.id, resourceId: row.id });
      return view(row);
    },

    async manifest(actor) {
      requireOwner(actor);
      return { manifest: buildManifestJson(), postUrl: 'https://github.com/settings/apps/new' };
    },

    async listInstallationRepos(actor) {
      requireOwner(actor);
      await requireConfigured();
      // @octokit/* is not a dependency yet — Owner must authorize before wiring Octokit here.
      return { items: [], notice: 'Octokit install pending Owner App' };
    },
  };
}