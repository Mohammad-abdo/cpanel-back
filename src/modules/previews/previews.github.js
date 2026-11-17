/**
 * TASK-045: optional PR comment through the GitHub REST API (fetch, fixed base URL). Off by default; the token is a per-project
 * encrypted secret and only ever sent in the Authorization header. Failures never fail a preview.
 */
import { AppError } from '../../common/errors/app-error.js';

export const GITHUB_API = 'https://api.github.com';
export const COMMENT_MARKER = '<!-- nt-preview -->';
const NAME = /^[A-Za-z0-9_.-]{1,100}$/;

/** "https://github.com/Owner/Repo.git", "git@github.com:Owner/Repo.git" -> { owner, repo } or null. */
export function parseGithubRepo(remoteUrl) {
  const m = /^(?:https:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([^/]+)\/([^/]+?)(?:\.git)?\/?$/i.exec(String(remoteUrl ?? '').trim());
  if (!m || !NAME.test(m[1]) || !NAME.test(m[2])) return null;
  return { owner: m[1], repo: m[2] };
}

export function renderComment({ status, url, commitSha, basicAuth }) {
  const short = commitSha ? String(commitSha).slice(0, 7) : 'unknown';
  const lines = [COMMENT_MARKER, '### Preview environment', '', `Status: **${status}**`, `Commit: \`${short}\``];
  if (url && status !== 'destroyed') lines.push(`URL: ${url}`);
  if (basicAuth && status !== 'destroyed') lines.push('', 'This preview is protected with basic auth. Ask the project owner for the credentials.');
  return lines.join('\n');
}

export function createGithubCommenter({ fetchImpl = globalThis.fetch, timeoutMs = 10_000 } = {}) {
  async function call(method, path, token, body) {
    const res = await fetchImpl(`${GITHUB_API}${path}`, {
      method,
      redirect: 'error',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json', 'User-Agent': 'nodeteam-control' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new AppError(502, 'GITHUB_COMMENT_FAILED', `GitHub answered HTTP ${res.status}`);
    return res.json();
  }
  return {
    /** Creates the comment, or edits the one created earlier. Returns the comment id as a string. */
    async upsert({ token, remoteUrl, prNumber, commentId, body }) {
      const repo = parseGithubRepo(remoteUrl);
      if (!repo) throw new AppError(422, 'GITHUB_REPO_UNSUPPORTED', 'Only github.com repositories support PR comments');
      if (!Number.isInteger(prNumber) || prNumber < 1) throw new AppError(422, 'PR_NUMBER_INVALID', 'Invalid pull request number');
      if (commentId && /^\d{1,20}$/.test(String(commentId))) {
        const out = await call('PATCH', `/repos/${repo.owner}/${repo.repo}/issues/comments/${commentId}`, token, { body });
        return String(out.id ?? commentId);
      }
      const out = await call('POST', `/repos/${repo.owner}/${repo.repo}/issues/${prNumber}/comments`, token, { body });
      return String(out.id);
    },
  };
}
