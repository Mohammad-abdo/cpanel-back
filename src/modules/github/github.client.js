/**
 * TASK-055: in-house GitHub App client. No new dependency: RS256 JWT through node:crypto, REST through fetch.
 * The host is pinned to https://api.github.com, redirects are refused, every call has a timeout, and error messages never
 * contain tokens, keys or response bodies.
 */
import { createSign } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';

export const GITHUB_API = 'https://api.github.com';
const NAME = /^[A-Za-z0-9_.-]{1,100}$/;
const CODE = /^[A-Za-z0-9_-]{8,128}$/;
const SHA = /^[0-9a-f]{7,40}$/;
const b64url = (buf) => Buffer.from(buf).toString('base64url');

/** RS256 App JWT. iat is backdated 60 s for clock skew; total lifetime stays under GitHub's 10 minute ceiling. */
export function signAppJwt({ appId, privateKeyPem, nowMs = Date.now() }) {
  if (!appId || !privateKeyPem) throw new AppError(422, 'GITHUB_APP_NOT_CONFIGURED', 'GitHub App id and private key are required');
  const iat = Math.floor(nowMs / 1000) - 60;
  const exp = iat + 9 * 60 + 60 - 1; // = now + 539 s (< 10 min)
  const head = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({ iat, exp, iss: String(appId) }));
  try {
    const sig = createSign('RSA-SHA256').update(`${head}.${body}`).sign(privateKeyPem);
    return `${head}.${body}.${b64url(sig)}`;
  } catch {
    throw new AppError(422, 'GITHUB_PRIVATE_KEY_INVALID', 'The stored GitHub App private key could not be used to sign');
  }
}

export function validRepoName(owner, repo) {
  return NAME.test(String(owner ?? '')) && NAME.test(String(repo ?? ''));
}

export function createGitHubClient({
  fetchImpl = globalThis.fetch,
  timeoutMs = 10_000,
  now = () => Date.now(),
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  maxRetries = 2,
} = {}) {
  /** installationId -> { token, expiresAtMs } */
  const tokenCache = new Map();

  async function request(method, path, { token, body, query, retries = maxRetries } = {}) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')) throw new AppError(500, 'GITHUB_PATH_INVALID', 'Invalid GitHub API path');
    const url = new URL(`${GITHUB_API}${path}`);
    if (url.origin !== GITHUB_API) throw new AppError(500, 'GITHUB_HOST_PINNED', 'Only api.github.com is allowed');
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    for (let attempt = 0; ; attempt += 1) {
      let res;
      try {
        res = await fetchImpl(url.toString(), {
          method,
          redirect: 'error',
          headers: {
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'nodeteam-control',
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
            ...(body ? { 'Content-Type': 'application/json' } : {}),
          },
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch {
        if (attempt < retries) {
          await sleep(250 * 2 ** attempt);
          continue;
        }
        throw new AppError(502, 'GITHUB_UNREACHABLE', 'GitHub could not be reached');
      }
      if (res.ok) return res.status === 204 ? null : res.json();
      const remaining = res.headers?.get?.('x-ratelimit-remaining');
      const retryAfter = Number(res.headers?.get?.('retry-after') ?? 0);
      if (res.status === 429 || (res.status === 403 && (remaining === '0' || retryAfter > 0))) {
        const reset = Number(res.headers?.get?.('x-ratelimit-reset') ?? 0);
        const waitS = retryAfter || (reset ? Math.max(0, reset - Math.floor(now() / 1000)) : 60);
        throw new AppError(429, 'GITHUB_RATE_LIMITED', `GitHub rate limit reached; retry in about ${waitS}s`, { retryAfterSeconds: waitS });
      }
      if (res.status >= 500 && attempt < retries) {
        await sleep(250 * 2 ** attempt);
        continue;
      }
      if (res.status === 401) throw new AppError(502, 'GITHUB_AUTH_FAILED', 'GitHub rejected the App credentials');
      if (res.status === 404) throw new AppError(404, 'GITHUB_NOT_FOUND', 'GitHub resource not found or not accessible to the App');
      throw new AppError(502, 'GITHUB_REQUEST_FAILED', `GitHub answered HTTP ${res.status}`);
    }
  }

  const appJwt = (creds) => signAppJwt({ appId: creds.appId, privateKeyPem: creds.privateKeyPem, nowMs: now() });

  async function installationToken(creds, installationId) {
    const id = String(installationId ?? '');
    if (!/^\d{1,20}$/.test(id)) throw new AppError(422, 'INSTALLATION_ID_INVALID', 'Installation id must be numeric');
    const hit = tokenCache.get(id);
    if (hit && hit.expiresAtMs - 60_000 > now()) return hit.token;
    const out = await request('POST', `/app/installations/${id}/access_tokens`, { token: appJwt(creds) });
    const expiresAtMs = out?.expires_at ? Date.parse(out.expires_at) : now() + 55 * 60_000;
    tokenCache.set(id, { token: out.token, expiresAtMs });
    return out.token;
  }

  const requireRepo = (owner, repo) => {
    if (!validRepoName(owner, repo)) throw new AppError(422, 'GITHUB_REPO_INVALID', 'Repository must be owner/name');
  };

  /** Follows page numbers (never Link URLs) so a response cannot steer us off the pinned host. */
  async function paged(path, token, { page = 1, perPage = 30, key } = {}) {
    const out = await request('GET', path, { token, query: { per_page: Math.min(100, Math.max(1, perPage)), page: Math.max(1, page) } });
    const items = key ? (out?.[key] ?? []) : (out ?? []);
    return { items, page, perPage, hasMore: items.length >= Math.min(100, Math.max(1, perPage)), total: out?.total_count ?? null };
  }

  return {
    request,
    appJwt,
    installationToken,
    invalidate: (installationId) => (installationId === undefined ? tokenCache.clear() : tokenCache.delete(String(installationId))),
    cacheSize: () => tokenCache.size,

    async exchangeManifestCode(code) {
      if (!CODE.test(String(code ?? ''))) throw new AppError(400, 'MANIFEST_CODE_INVALID', 'Invalid manifest code');
      return request('POST', `/app-manifests/${code}/conversions`, { retries: 0 });
    },
    /**
     * Down-scoped clone token: one repository, contents:read only. Never cached or shared with the installation-wide token.
     */
    async scopedCloneToken(creds, installationId, repo) {
      const id = String(installationId ?? '');
      if (!/^\d{1,20}$/.test(id)) throw new AppError(422, 'INSTALLATION_ID_INVALID', 'Installation id must be numeric');
      if (!NAME.test(String(repo ?? ''))) throw new AppError(422, 'GITHUB_REPO_INVALID', 'Repository must be owner/name');
      const out = await request('POST', `/app/installations/${id}/access_tokens`, { token: appJwt(creds), body: { repositories: [repo], permissions: { contents: 'read' } } });
      if (!out?.token) throw new AppError(502, 'GITHUB_REQUEST_FAILED', 'GitHub did not return a token');
      return out.token;
    },
    async listInstallations(creds, opts = {}) {
      return paged('/app/installations', appJwt(creds), opts);
    },
    async installationForRepo(creds, owner, repo) {
      requireRepo(owner, repo);
      const out = await request('GET', `/repos/${owner}/${repo}/installation`, { token: appJwt(creds) });
      return out?.id != null ? String(out.id) : null;
    },
    async listRepos(creds, installationId, opts = {}) {
      return paged('/installation/repositories', await installationToken(creds, installationId), { ...opts, key: 'repositories' });
    },
    async listBranches(creds, installationId, owner, repo, opts = {}) {
      requireRepo(owner, repo);
      return paged(`/repos/${owner}/${repo}/branches`, await installationToken(creds, installationId), opts);
    },
    async getDefaultBranch(creds, installationId, owner, repo) {
      requireRepo(owner, repo);
      const out = await request('GET', `/repos/${owner}/${repo}`, { token: await installationToken(creds, installationId) });
      return out?.default_branch ?? null;
    },
    async getBranchSha(creds, installationId, owner, repo, branch) {
      requireRepo(owner, repo);
      if (!/^[A-Za-z0-9._/-]{1,200}$/.test(String(branch ?? '')) || String(branch).includes('..')) throw new AppError(422, 'GITHUB_REF_INVALID', 'Invalid branch name');
      const out = await request('GET', `/repos/${owner}/${repo}/branches/${branch.split('/').map(encodeURIComponent).join('/')}`, { token: await installationToken(creds, installationId) });
      return out?.commit?.sha ?? null;
    },
    async createPrComment(creds, installationId, owner, repo, prNumber, body) {
      requireRepo(owner, repo);
      if (!Number.isInteger(prNumber) || prNumber < 1) throw new AppError(422, 'PR_NUMBER_INVALID', 'Invalid pull request number');
      const out = await request('POST', `/repos/${owner}/${repo}/issues/${prNumber}/comments`, { token: await installationToken(creds, installationId), body: { body: String(body).slice(0, 60_000) } });
      return out?.id != null ? String(out.id) : null;
    },
    async createCommitStatus(creds, installationId, owner, repo, sha, { state, context = 'nodeteam/deploy', description = '', targetUrl } = {}) {
      requireRepo(owner, repo);
      if (!SHA.test(String(sha ?? ''))) throw new AppError(422, 'GITHUB_SHA_INVALID', 'Invalid commit sha');
      if (!['error', 'failure', 'pending', 'success'].includes(state)) throw new AppError(422, 'GITHUB_STATE_INVALID', 'Invalid commit status state');
      return request('POST', `/repos/${owner}/${repo}/statuses/${sha}`, {
        token: await installationToken(creds, installationId),
        body: { state, context: String(context).slice(0, 100), description: String(description).slice(0, 140), ...(targetUrl ? { target_url: targetUrl } : {}) },
      });
    },
  };
}
