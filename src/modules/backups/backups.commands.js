import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AppError } from '../../common/errors/app-error.js';

/**
 * Remote command construction for real backups (TASK-049). Rules:
 *  - Scripts are FIXED text (./scripts/*.sh). Variable data is passed only as positional args that are validated
 *    here first (strict allow-lists) and shell-quoted by the SSH connector.
 *  - Credentials travel ONLY on the stdin channel (first line) and are written to a 0600 file inside a 0700 mktemp
 *    directory that is deleted on exit. They never appear in a command line, an arg or a log line.
 *  - Every output is bounded (head -c cap+1) and the sha256 is computed on the server.
 */
const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'scripts');
const sh = (name) => readFileSync(path.join(DIR, name), 'utf8').replace(/\r\n/g, '\n');

export const DB_ENGINES = Object.freeze(['mysql', 'postgres', 'mongodb']);
export const SAFE_DB = /^[A-Za-z0-9_-]{1,64}$/;
export const SAFE_USER = /^[A-Za-z0-9_./@-]{1,64}$/;
export const SAFE_DIR = /^\/tmp\/nt-bk\.[A-Za-z0-9]{8}$/;
export const SAFE_OUT = /^\/tmp\/nt-bk\.[A-Za-z0-9]{8}\/out\.(gz|tgz|archive)$/;
export const SAFE_TREE = /^\/(?:[A-Za-z0-9_.-]+\/?)+$/;
export const VERIFY_PREFIX = 'nt_verify_';
export const RESTORE_PREFIX = 'nt_restore_';
export const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;
export const TREE_EXCLUDES = Object.freeze(['node_modules', '.git', 'vendor', '.next', '.cache', 'storage/logs', '*.log', '.env', '.env.*']);

const bad = (code, msg) => new AppError(422, code, msg);

export function normalizeEngine(engine) {
  const e = String(engine ?? '').toLowerCase();
  if (e === 'mysql' || e === 'mariadb') return 'mysql';
  if (e === 'postgres' || e === 'postgresql') return 'postgres';
  if (e === 'mongo' || e === 'mongodb') return 'mongodb';
  throw bad('BACKUP_ENGINE_UNSUPPORTED', 'Engine must be MySQL/MariaDB, PostgreSQL or MongoDB');
}
export function assertDb(name) {
  if (typeof name !== 'string' || !SAFE_DB.test(name)) throw bad('DB_NAME_INVALID', 'Invalid database name');
  return name;
}
export function assertUser(name) {
  if (typeof name !== 'string' || !SAFE_USER.test(name)) throw bad('DB_USER_INVALID', 'Invalid database username');
  return name;
}
export function assertTreePath(p) {
  if (typeof p !== 'string' || p.length > 255 || !SAFE_TREE.test(p) || p.split('/').some((s) => s === '..' || s === '.') || p === '/') {
    throw bad('PATH_INVALID', 'Invalid project path');
  }
  return p.replace(/\/+$/, '');
}
export function assertCap(n) {
  const v = Number(n);
  if (!Number.isInteger(v) || v < 1 || v > 8 * 1024 * 1024 * 1024) throw bad('SIZE_CAP_INVALID', 'Invalid size cap');
  return v;
}
/** Credentials must be a single line; a newline would corrupt the stdin protocol. */
export function assertPassword(p) {
  const s = String(p ?? '');
  if (/[\r\n\0]/.test(s)) throw bad('DB_PASSWORD_INVALID', 'Password contains unsupported control characters');
  return s;
}
export const isVerifyName = (n) => typeof n === 'string' && n.startsWith(VERIFY_PREFIX) && SAFE_DB.test(n);

/** Isolated restore targets are always a NEW name; never the source database. */
export function isolatedDbName(runId, at = new Date(), rand = '') {
  const stamp = at.toISOString().replace(/\D/g, '').slice(0, 14);
  const tail = String(rand || String(runId).replace(/-/g, '').slice(0, 6)).replace(/[^A-Za-z0-9]/g, '').slice(0, 8);
  return assertDb(`${RESTORE_PREFIX}${stamp}_${tail}`);
}
export const verifyDbName = (rand) => assertDb(`${VERIFY_PREFIX}${String(rand).replace(/[^A-Za-z0-9]/g, '').slice(0, 16)}`);

const PRELUDE = sh('prelude.sh');
const SIZE_CHECK = sh('size-check.sh');
const cfg = (e) => (e === 'mysql' ? sh('mysql-cfg.sh') : e === 'mongodb' ? sh('mongo-cfg.sh') : '');
const METHOD = { mysql: 'mysqldump-single-transaction-gzip', postgres: 'pg_dump-gzip', mongodb: 'mongodump-archive-gzip' };

/** DB dump: args = DB USER CAP; stdin = password line. */
export function buildDbDumpCommand({ engine, db, username, password, maxBytes = DEFAULT_MAX_BYTES }) {
  const e = normalizeEngine(engine);
  const cap = assertCap(maxBytes);
  const script = `${PRELUDE}DB="$1"; USER_="$2"; CAP="$3"; LIMIT=$((CAP+1))
OUT="$WORK/out.${e === 'mongodb' ? 'archive' : 'gz'}"; ERR="$WORK/err"
${cfg(e)}${sh(`dump-${e}.sh`)}${SIZE_CHECK}`;
  return { engine: e, script, args: [assertDb(db), assertUser(username), String(cap)], stdin: `${assertPassword(password)}\n`, method: METHOD[e] };
}

/** Directory archive. tar never dereferences symlinks (no -h); the root must already be its own real path. */
export function buildTreeArchiveCommand({ path: root0, maxBytes = DEFAULT_MAX_BYTES, excludes = TREE_EXCLUDES }) {
  const root = assertTreePath(root0);
  const cap = assertCap(maxBytes);
  const ex = excludes.map((x) => `--exclude='${String(x).replace(/[^A-Za-z0-9_./*-]/g, '')}'`).join(' ');
  const script = `${PRELUDE}ROOT="$1"; CAP="$2"; LIMIT=$((CAP+1))
OUT="$WORK/out.tgz"; ERR="$WORK/err"
${sh('tree.sh').replace('@EXCLUDES@', ex)}${SIZE_CHECK}`;
  return { script, args: [root, String(cap)], stdin: '\n', method: 'tar-gzip-no-dereference' };
}

export const PREPARE_SCRIPT = sh('prepare.sh');
/** Removes a scratch directory; refuses anything that is not an nt-bk mktemp dir. */
export const CLEANUP_SCRIPT = sh('cleanup.sh');

/**
 * Restore the gz file previously uploaded to DIR/in.gz into DB. 'isolated' creates a NEW database and fails if it
 * exists; 'inplace' writes into the existing database (caller must have passed approval + safety backup).
 */
export function buildDbRestoreCommand({ engine, db, sourceDb, username, password, dir, mode }) {
  const e = normalizeEngine(engine);
  if (!['isolated', 'inplace'].includes(mode)) throw bad('RESTORE_MODE_INVALID', 'Restore mode must be isolated or inplace');
  if (!SAFE_DIR.test(String(dir))) throw bad('REMOTE_PATH_INVALID', 'Invalid remote scratch directory');
  const target = assertDb(db);
  const src = assertDb(sourceDb ?? db);
  if (mode === 'isolated' && target === src) throw bad('RESTORE_TARGET_IS_SOURCE', 'Isolated restore must use a new database name');
  const script = `${PRELUDE}DIR="$1"; DB="$2"; USER_="$3"; MODE="$4"; SRC="$5"; ERR="$WORK/err"
[ -s "$DIR/in.gz" ] || { echo "__NT_ERR__input_missing" >&2; exit 2; }
${cfg(e)}${sh(`restore-${e}.sh`)}OK=1
echo "NT_TABLES=$TABLES"
`;
  return { engine: e, script, args: [dir, target, assertUser(username), mode, src], stdin: `${assertPassword(password)}\n` };
}

/** Drops a scratch database. Only nt_verify_* names are ever accepted. MongoDB scratch drop is not supported. */
export function buildScratchDropCommand({ engine, db, username, password }) {
  const e = normalizeEngine(engine);
  if (!isVerifyName(db)) throw bad('SCRATCH_NAME_INVALID', `Only ${VERIFY_PREFIX}* databases may be dropped by verification`);
  if (e === 'mongodb') throw bad('BACKUP_VERIFY_UNSUPPORTED', 'Scratch test-restore is not supported for MongoDB');
  const script = `${PRELUDE}DB="$1"; USER_="$2"
${cfg(e)}${sh(`drop-${e}.sh`)}OK=1
`;
  return { script, args: [db, assertUser(username)], stdin: `${assertPassword(password)}\n` };
}

/** Parses the NT_* result lines of a dump script. The output path is re-validated before it is ever read. */
export function parseDumpResult(stdout) {
  const get = (k) => new RegExp(`^NT_${k}=(.*)$`, 'm').exec(stdout)?.[1]?.trim();
  const out = get('OUT');
  const sha = get('SHA256');
  const size = Number(get('SIZE'));
  const invalid = (m) => new AppError(502, 'BACKUP_REMOTE_OUTPUT_INVALID', m);
  if (!out || !SAFE_OUT.test(out)) throw invalid('Remote backup output path was not recognised');
  if (!sha || !/^[0-9a-f]{64}$/.test(sha)) throw invalid('Remote checksum was not recognised');
  if (!Number.isFinite(size) || size < 1) throw invalid('Remote size was not recognised');
  return { path: out, dir: out.slice(0, out.lastIndexOf('/')), sha256: sha, size };
}

/** Removes every occurrence of each secret and obvious credential assignments from text. */
export function redactSecrets(text, secrets = []) {
  let out = String(text ?? '');
  for (const s of secrets) if (s && String(s).length >= 3) out = out.split(String(s)).join('[REDACTED]');
  return out.replace(/(password|passwd|pwd|secret|token)(["']?\s*[=:]\s*)(["']?)[^\s"']+/gi, '$1$2$3[REDACTED]');
}

/** Maps the script's __NT_ERR__ markers to stable errors (secrets redacted). */
export function mapRemoteError(res, secrets = []) {
  if (res.timedOut) return new AppError(504, 'BACKUP_REMOTE_TIMEOUT', 'The remote backup command timed out');
  const text = redactSecrets(res.stderr ?? '', secrets);
  if (/__NT_ERR__size_cap_exceeded/.test(text)) return new AppError(413, 'BACKUP_TOO_LARGE', 'Backup exceeds the configured size cap');
  const m = /__NT_ERR__([a-z_]+)(?::(.*))?/.exec(text);
  const hint = m?.[2]?.trim().slice(0, 240);
  return new AppError(502, 'BACKUP_REMOTE_FAILED', `Remote backup step failed${m ? ` (${m[1]})` : ''}${hint ? `: ${hint}` : ''}`);
}
