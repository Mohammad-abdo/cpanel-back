/**
 * TASK-043: pure helpers for the real deploy executor. Nothing here touches a server.
 * Every value that reaches a remote shell is validated first and passed as a positional argument
 * ("$1", "$2", ...) by execScriptStdin; scripts are fixed text and never built from user input.
 */
import { AppError } from '../../common/errors/app-error.js';

export const SAFE_SHA = /^[0-9a-f]{7,40}$/;
export const SAFE_REF = /^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,100}$/;
export const SAFE_APP_NAME = /^[A-Za-z0-9._:-]{1,100}$/;
export const SAFE_SLUG = /^[a-z0-9][a-z0-9._-]{0,62}$/;
/** Absolute deploy base. Only these roots are accepted; no "..", no spaces, no shell metacharacters. */
export const SAFE_BASE_PATH = /^\/(?:srv|var\/www|home|opt)\/[A-Za-z0-9._/-]{1,200}$/;
export const SAFE_REL_PATH = /^(?!\/)(?!.*\.\.)[A-Za-z0-9._/-]{1,100}$/;

const HTTPS_URL = /^https:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?\/[A-Za-z0-9._~/-]+?(?:\.git)?\/?$/;
const SCP_URL = /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._~/-]+?(?:\.git)?$/;
const SSH_URL = /^ssh:\/\/[A-Za-z0-9._-]+@[A-Za-z0-9.-]+(?::\d{1,5})?\/[A-Za-z0-9._~/-]+?(?:\.git)?$/;

/** Accepts https://, ssh:// and scp-style git@host:owner/repo.git. Rejects credentials, options, ext:: and file:. */
export function validateRepoUrl(url) {
  const value = String(url ?? '');
  const ok =
    value.length <= 300 &&
    !value.startsWith('-') &&
    !value.includes('..') &&
    (HTTPS_URL.test(value) || SCP_URL.test(value) || SSH_URL.test(value));
  if (!ok) throw new AppError(422, 'REPO_URL_INVALID', 'Repository URL must be https://, ssh:// or git@host:owner/repo');
  return value;
}

export function validateSha(sha) {
  if (!SAFE_SHA.test(String(sha ?? ''))) throw new AppError(422, 'COMMIT_SHA_INVALID', 'Commit must be a 7-40 character hex SHA');
  return sha;
}

export function validateRef(ref) {
  if (!SAFE_REF.test(String(ref ?? ''))) throw new AppError(422, 'BRANCH_INVALID', 'Branch name contains invalid characters');
  return ref;
}

/**
 * Build/install commands. Each id maps to a fixed argv. The user picks an id, never raw text,
 * unless the exact custom command was approved (see resolveCommand).
 */
export const ALLOWED_COMMANDS = Object.freeze({
  'npm ci': ['npm', 'ci'],
  'npm install': ['npm', 'install'],
  'npm run build': ['npm', 'run', 'build'],
  'npm prune --omit=dev': ['npm', 'prune', '--omit=dev'],
  'yarn install --frozen-lockfile': ['yarn', 'install', '--frozen-lockfile'],
  'yarn build': ['yarn', 'build'],
  'pnpm install --frozen-lockfile': ['pnpm', 'install', '--frozen-lockfile'],
  'pnpm build': ['pnpm', 'build'],
  'npx prisma generate': ['npx', 'prisma', 'generate'],
});

const CUSTOM_TOKEN = /^[A-Za-z0-9_./:=@+-]{1,80}$/;
const CUSTOM_BINARIES = new Set(['npm', 'npx', 'yarn', 'pnpm', 'node']);

/** Normalizes whitespace so "npm  ci" matches "npm ci". */
export const normalizeCommand = (cmd) => String(cmd ?? '').trim().replace(/\s+/g, ' ');

/**
 * Returns an argv array. Allowlisted commands pass. A custom command passes only when it appears in
 * `approvedCustom` (recorded through the approval gate) AND it is token-safe; it is still executed as argv,
 * never through a shell.
 */
export function resolveCommand(command, approvedCustom = []) {
  const norm = normalizeCommand(command);
  if (Object.prototype.hasOwnProperty.call(ALLOWED_COMMANDS, norm)) return [...ALLOWED_COMMANDS[norm]];
  const approved = (approvedCustom ?? []).map(normalizeCommand);
  if (!approved.includes(norm)) {
    throw new AppError(409, 'CUSTOM_COMMAND_NOT_APPROVED', 'This command is not on the allowlist and has no recorded approval');
  }
  const tokens = norm.split(' ');
  if (tokens.length > 12 || !CUSTOM_BINARIES.has(tokens[0]) || !tokens.every((t) => CUSTOM_TOKEN.test(t))) {
    throw new AppError(422, 'CUSTOM_COMMAND_UNSAFE', 'Custom command uses a disallowed binary or characters');
  }
  return tokens;
}

/** Framework detection from package.json. Returns defaults the project settings may override. */
export function detectFramework(pkg) {
  const deps = { ...(pkg?.dependencies ?? {}), ...(pkg?.devDependencies ?? {}) };
  const scripts = pkg?.scripts ?? {};
  const has = (n) => Object.prototype.hasOwnProperty.call(deps, n);
  const base = { install: 'npm ci', build: scripts.build ? 'npm run build' : null };
  if (has('next')) return { framework: 'next', static: false, ...base, outputDir: null, start: scripts.start ? 'npm-start' : null };
  if (has('vite')) {
    const ssr = has('express') || has('fastify') || has('koa');
    if (!ssr && !scripts.start) return { framework: 'vite', static: true, ...base, outputDir: 'dist', start: null };
    return { framework: 'vite', static: false, ...base, outputDir: null, start: scripts.start ? 'npm-start' : null };
  }
  if (has('react-scripts')) return { framework: 'cra', static: true, ...base, outputDir: 'build', start: null };
  if (scripts.start) return { framework: 'node', static: false, ...base, outputDir: null, start: 'npm-start' };
  return { framework: 'static', static: true, install: null, build: scripts.build ? 'npm run build' : null, outputDir: scripts.build ? 'dist' : '.', start: null };
}

/** TASK-045: preview environments use the code `pr-<number>`. They never inherit the project's fixed base path, pm2 name or health URL. */
export const PREVIEW_ENV_CODE = /^pr-[1-9][0-9]{0,8}$/;
export const isPreviewEnvCode = (code) => PREVIEW_ENV_CODE.test(String(code ?? ''));
/** Teardown deletes this directory, so it must be exactly /var/www/nt-deploy/<slug>/pr-<n>. */
export const PREVIEW_BASE_PATH = new RegExp("^/var/www/nt-deploy/[a-z0-9][a-z0-9._-]{0,62}/pr-[1-9][0-9]{0,8}$");

/** Normalized deploy settings (ProjectRuntime.metaJson.deploy) with safe defaults. */
export function resolveDeployConfig({ project, environment, runtimeMeta }) {
  const preview = isPreviewEnvCode(environment.code);
  const d = preview ? { ...(runtimeMeta?.deploy ?? {}), basePath: undefined, pm2App: undefined, healthUrl: undefined } : (runtimeMeta?.deploy ?? {});
  const slug = project.slug;
  if (!SAFE_SLUG.test(String(slug))) throw new AppError(422, 'PROJECT_SLUG_UNSAFE', 'Project slug is not safe for filesystem use');
  const basePath = d.basePath ?? `/var/www/nt-deploy/${slug}/${environment.code}`;
  if (!SAFE_BASE_PATH.test(basePath)) throw new AppError(422, 'DEPLOY_PATH_INVALID', 'Deploy base path is not allowed');
  const pm2App = d.pm2App ?? `${slug}-${environment.code}`;
  if (!SAFE_APP_NAME.test(pm2App)) throw new AppError(422, 'PM2_APP_INVALID', 'pm2 app name is invalid');
  const keepReleases = Number.isInteger(d.keepReleases) ? Math.min(Math.max(d.keepReleases, 2), 20) : 5;
  const outputDir = d.outputDir ?? null;
  if (outputDir && !SAFE_REL_PATH.test(outputDir) && outputDir !== '.') throw new AppError(422, 'OUTPUT_DIR_INVALID', 'Output directory is invalid');
  const startFile = d.startFile ?? null;
  if (startFile && !SAFE_REL_PATH.test(startFile)) throw new AppError(422, 'START_FILE_INVALID', 'Start file is invalid');
  const healthUrl = d.healthUrl ?? null;
  if (healthUrl && !/^https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d{1,5})?(?:\/[A-Za-z0-9._~/?=&%-]*)?$/.test(healthUrl)) {
    throw new AppError(422, 'HEALTH_URL_INVALID', 'Health URL must target localhost on the server');
  }
  return {
    basePath,
    pm2App,
    keepReleases,
    outputDir,
    startFile,
    healthUrl,
    healthTimeoutSec: Number.isInteger(d.healthTimeoutSec) ? Math.min(Math.max(d.healthTimeoutSec, 3), 120) : 30,
    installCommand: d.installCommand ?? null,
    buildCommand: d.buildCommand ?? null,
    static: d.static === true,
    framework: d.framework ?? null,
    autoDetect: d.autoDetect !== false,
    approvedCustomCommands: Array.isArray(d.approvedCustomCommands) ? d.approvedCustomCommands : [],
  };
}

/** Per-project(+environment) in-process lock. Returns a release function, or null when already held. */
export function createDeployLocks() {
  const held = new Set();
  return {
    tryAcquire(key) {
      if (held.has(key)) return null;
      held.add(key);
      return () => held.delete(key);
    },
    isHeld: (key) => held.has(key),
  };
}

export const sharedDeployLocks = createDeployLocks();

/** .env text from decrypted variables. Values are quoted/escaped; the result is only ever sent over stdin. */
export function buildEnvFile(vars) {
  return (
    vars
      .filter(({ key }) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(key))
      .map(({ key, value }) => {
        const v = String(value ?? '').replace(/\r?\n/g, '\\n');
        // Single quotes: safe to `source` (no expansion) and understood by dotenv parsers.
        return `${key}='${v.replace(/'/g, `'\\''`)}'`;
      })
      .join('\n') + '\n'
  );
}

// ---------------------------------------------------------------------------
// Fixed remote scripts. Arguments arrive as positional parameters; no script interpolates user text.
// ---------------------------------------------------------------------------

const PREAMBLE = `set -eu
BASE="$1"; shift
case "$BASE" in /*) ;; *) echo "bad base" >&2; exit 64 ;; esac
`;

/** args: BASE REL_ID REPO_URL SHA BRANCH. Clones, pins the commit, prints NT_SHA=<full sha>. */
export const FETCH_SCRIPT = `${PREAMBLE}
REL_ID="$1"; URL="$2"; SHA="$3"; BRANCH="$4"
mkdir -p "$BASE/releases"
REL="$BASE/releases/$REL_ID"
if [ -z "$SHA" ]; then
  SHA=$(git ls-remote -- "$URL" "refs/heads/$BRANCH" | cut -f1 | head -n 1)
fi
case "$SHA" in *[!0-9a-f]*|"") echo "cannot resolve commit" >&2; exit 65 ;; esac
rm -rf -- "$REL"
git clone --no-checkout --quiet -- "$URL" "$REL"
cd "$REL"
git checkout --quiet --detach "$SHA"
FULL=$(git rev-parse HEAD)
printf '%s\\n' "$FULL" > "$REL/.nt-sha"
echo "NT_SHA=$FULL"
if [ -f package.json ]; then echo "NT_PKG_BEGIN"; head -c 65536 package.json; echo; echo "NT_PKG_END"; fi
`;

/** args: BASE REL_ID. Env file content arrives on stdin and is never echoed. */
export const ENV_SCRIPT = `${PREAMBLE}
REL_ID="$1"
umask 077
cat > "$BASE/releases/$REL_ID/.env"
echo "env file written"
`;

/** args: BASE REL_ID CMD ARGV... Runs one allowlisted argv inside the release. No shell parsing. */
export const RUN_SCRIPT = `${PREAMBLE}
REL_ID="$1"; shift
export PATH="/usr/local/bin:/usr/bin:$HOME/.local/bin:$PATH"
if [ -s "$HOME/.nvm/nvm.sh" ]; then . "$HOME/.nvm/nvm.sh" >/dev/null 2>&1 || true; fi
cd "$BASE/releases/$REL_ID"
if [ -f .env ]; then set -a; . ./.env; set +a; fi
"$@" 2>&1
`;

/** args: BASE REL_ID. Atomically repoints current and remembers the previous target. */
export const SWITCH_SCRIPT = `${PREAMBLE}
REL_ID="$1"
REL="$BASE/releases/$REL_ID"
[ -d "$REL" ] || { echo "release directory missing" >&2; exit 66; }
if [ -L "$BASE/current" ]; then PREV=$(readlink "$BASE/current"); ln -sfn "$PREV" "$BASE/previous"; fi
ln -sfn "$REL" "$BASE/current.tmp"
mv -T "$BASE/current.tmp" "$BASE/current"
echo "current -> $REL"
`;

/**
 * args: BASE APP_NAME MODE (npm-start|node-file|none) START_FILE.
 * Reloads when the pm2 app exists, otherwise starts it with cwd = the "current" symlink.
 */
export const PM2_SCRIPT = (pm2Env) => `${PREAMBLE}
APP="$1"; MODE="$2"; FILE="$3"
set +u
${pm2Env}
[ "$MODE" = "none" ] && { echo "static site: no process to reload"; exit 0; }
[ -n "$PM2_BIN" ] || { echo "pm2 not found" >&2; exit 127; }
cd "$BASE/current"
if pm2_exec describe "$APP" >/dev/null 2>&1; then
  pm2_exec reload "$APP" --update-env
else
  case "$MODE" in
    npm-start) pm2_exec start npm --name "$APP" --cwd "$BASE/current" -- start ;;
    node-file) pm2_exec start "$FILE" --name "$APP" --cwd "$BASE/current" ;;
    *) echo "unknown start mode" >&2; exit 64 ;;
  esac
fi
pm2_exec save >/dev/null 2>&1 || true
`;

/** args: BASE APP_NAME HEALTH_URL TIMEOUT_SEC. Succeeds when pm2 reports online (if APP set) and the URL answers 2xx/3xx. */
export const HEALTH_SCRIPT = (pm2Env) => `${PREAMBLE}
APP="$1"; URL="$2"; TIMEOUT="$3"
set +u
${pm2Env}
END=$(( $(date +%s) + TIMEOUT ))
while :; do
  OK=1
  if [ -n "$APP" ] && [ -n "$PM2_BIN" ]; then
    pm2_exec jlist 2>/dev/null | grep -q "\\"name\\":\\"$APP\\"" || OK=0
    pm2_exec describe "$APP" 2>/dev/null | grep -qi "online" || OK=0
  fi
  if [ -n "$URL" ]; then
    CODE=$(curl -s -o /dev/null -m 5 -w '%{http_code}' -- "$URL" || echo 000)
    case "$CODE" in 2*|3*) ;; *) OK=0 ;; esac
  fi
  [ "$OK" = 1 ] && { echo "healthy"; exit 0; }
  [ "$(date +%s)" -ge "$END" ] && { echo "unhealthy after timeout" >&2; exit 1; }
  sleep 2
done
`;

/** args: BASE TARGET_ID TARGET_SHA. Repoints current at an existing release (by id, else by pinned SHA). */
export const ROLLBACK_SCRIPT = `${PREAMBLE}
TARGET_ID="$1"; SHA="$2"
REL=""
if [ -d "$BASE/releases/$TARGET_ID" ]; then REL="$BASE/releases/$TARGET_ID"; fi
if [ -z "$REL" ] && [ -n "$SHA" ]; then
  for d in "$BASE"/releases/*/; do
    [ -f "$d.nt-sha" ] && [ "$(cat "$d.nt-sha")" = "$SHA" ] && REL="\${d%/}"
  done
fi
[ -n "$REL" ] || { echo "no retained release for the rollback target" >&2; exit 66; }
ln -sfn "$REL" "$BASE/current.tmp"
mv -T "$BASE/current.tmp" "$BASE/current"
echo "current -> $REL"
`;

/** args: BASE KEEP. Removes old releases but never the current or previous target. */
/** args: BASE APP_NAME. Stops the preview's pm2 app and removes its directory. Refuses anything that is not a preview path. */
export const TEARDOWN_SCRIPT = (pm2Env) => `set -eu
BASE="$1"; APP="$2"
case "$BASE" in
  /var/www/nt-deploy/*/pr-[1-9]*) ;;
  *) echo "refusing teardown outside preview paths" >&2; exit 64 ;;
esac
case "$BASE" in *..*|*' '*|*[!A-Za-z0-9._/-]*) echo "unsafe path" >&2; exit 64 ;; esac
case "$APP" in ''|*[!A-Za-z0-9._:-]*) echo "bad app" >&2; exit 64 ;; esac
set +u
${pm2Env}
if [ -n "$PM2_BIN" ]; then
  pm2_exec delete "$APP" >/dev/null 2>&1 || true
  pm2_exec save >/dev/null 2>&1 || true
fi
rm -rf -- "$BASE"
echo "teardown done"
`;

export const PRUNE_SCRIPT = `${PREAMBLE}
KEEP="$1"
CUR=$(readlink "$BASE/current" 2>/dev/null || true)
PREV=$(readlink "$BASE/previous" 2>/dev/null || true)
N=0
for d in $(ls -1dt "$BASE"/releases/*/ 2>/dev/null); do
  d="\${d%/}"
  N=$((N+1))
  [ "$N" -le "$KEEP" ] && continue
  [ "$d" = "$CUR" ] && continue
  [ "$d" = "$PREV" ] && continue
  rm -rf -- "$d"
  echo "pruned $d"
done
echo "prune done"
`;
