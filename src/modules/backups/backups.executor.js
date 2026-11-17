import { randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { isSystemActor } from '../../common/system-actor.js';
import { sha256 } from '../platform/platform.crypto.js';
import { openSftp } from '../server-access/ssh.connector.js';
import {
  CLEANUP_SCRIPT,
  DEFAULT_MAX_BYTES,
  PREPARE_SCRIPT,
  buildDbDumpCommand,
  buildDbRestoreCommand,
  buildScratchDropCommand,
  buildTreeArchiveCommand,
  mapRemoteError,
  normalizeEngine,
  parseDumpResult,
  redactSecrets,
  verifyDbName,
} from './backups.commands.js';

export const EXECUTOR_MODES = Object.freeze(['simulated', 'ssh']);
/** Fails closed: anything other than the exact string "ssh" keeps the simulated adapters. */
export const resolveExecutorMode = (raw = process.env.BACKUP_EXECUTOR) => (String(raw ?? '').trim().toLowerCase() === 'ssh' ? 'ssh' : 'simulated');
export const GZIP_MAGIC = Buffer.from([0x1f, 0x8b]);
export const isGzip = (b) => Buffer.isBuffer(b) && b.length > 2 && b.subarray(0, 2).equals(GZIP_MAGIC);

const cb = (fn) => new Promise((resolve, reject) => fn((e, v) => (e ? reject(e) : resolve(v))));

/**
 * Real backup executor (TASK-049): DB dumps, directory archives, restores and scratch test-restores over SSH.
 * `remote` is serverAccessService.runRemote (serialized per server, connection always closed). The executor only ever
 * talks to the server through fixed scripts from backups.commands.js; it is a no-op surface unless mode === 'ssh'.
 */
export function createBackupExecutor({ mode = resolveExecutorMode(), remote = null, storage = null, maxBytes = Number(process.env.BACKUP_MAX_BYTES) || DEFAULT_MAX_BYTES, testRestoreEnabled = process.env.BACKUP_VERIFY_TEST_RESTORE === 'true', now = () => new Date(), rand = () => randomBytes(5).toString('hex') } = {}) {
  const enabled = mode === 'ssh';

  function guard(actor) {
    if (!enabled) throw new AppError(409, 'BACKUP_EXECUTOR_DISABLED', 'The real backup executor is disabled (BACKUP_EXECUTOR=simulated)');
    if (!remote) throw new AppError(500, 'BACKUP_EXECUTOR_UNWIRED', 'SSH access is not wired into the backup executor');
    if (!isSystemActor(actor) && !actor?.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner or the scheduler can run real backups');
  }

  async function pull(client, parsed, cap) {
    if (parsed.size > cap) throw new AppError(413, 'BACKUP_TOO_LARGE', 'Backup exceeds the configured size cap');
    const sftp = await openSftp(client);
    const st = await cb((c) => sftp.stat(parsed.path, c));
    if (Number(st.size) !== parsed.size || st.size > cap) throw new AppError(422, 'CHECKSUM_MISMATCH', 'Remote file size changed after the checksum was taken');
    const bytes = await cb((c) => sftp.readFile(parsed.path, c));
    if (bytes.length > cap) throw new AppError(413, 'BACKUP_TOO_LARGE', 'Backup exceeds the configured size cap');
    // Checksum was computed ON the server; recomputing locally detects corruption in transit.
    if (sha256(bytes) !== parsed.sha256) throw new AppError(422, 'CHECKSUM_MISMATCH', 'Pulled backup does not match the checksum computed on the server');
    return bytes;
  }

  async function runDump(serverId, cmd, secrets, cap) {
    return remote(serverId, async ({ client, run }) => {
      let parsed = null;
      try {
        const res = await run(cmd.script, { args: cmd.args, stdin: cmd.stdin, timeoutMs: 600_000, maxBytes: 8 * 1024 });
        if (res.timedOut || res.code !== 0) throw mapRemoteError(res, secrets);
        parsed = parseDumpResult(res.stdout);
        const bytes = await pull(client, parsed, cap);
        return { bytes, serverSha256: parsed.sha256 };
      } finally {
        if (parsed?.dir) await run(CLEANUP_SCRIPT, { args: [parsed.dir], timeoutMs: 30_000 }).catch(() => {});
      }
    });
  }

  async function runRestore(serverId, { engine, db, sourceDb, username, password, bytes, mode: rmode }) {
    if (!Buffer.isBuffer(bytes) || !isGzip(bytes)) throw new AppError(422, 'RESTORE_FORMAT_UNSUPPORTED', 'Only gzip-compressed dumps produced by the SSH executor can be restored this way');
    if (bytes.length > maxBytes) throw new AppError(413, 'BACKUP_TOO_LARGE', 'Backup exceeds the configured size cap');
    return remote(serverId, async ({ client, run }) => {
      let dir = null;
      try {
        const prep = await run(PREPARE_SCRIPT, { timeoutMs: 30_000 });
        dir = /^NT_DIR=(\/tmp\/nt-bk\.[A-Za-z0-9]{8})$/m.exec(prep.stdout ?? '')?.[1];
        if (prep.code !== 0 || !dir) throw new AppError(502, 'BACKUP_REMOTE_FAILED', 'Could not prepare a remote scratch directory');
        const sftp = await openSftp(client);
        await cb((c) => sftp.writeFile(`${dir}/in.gz`, bytes, c));
        const cmd = buildDbRestoreCommand({ engine, db, sourceDb, username, password, dir, mode: rmode });
        const res = await run(cmd.script, { args: cmd.args, stdin: cmd.stdin, timeoutMs: 900_000, maxBytes: 8 * 1024 });
        if (res.timedOut || res.code !== 0) throw mapRemoteError(res, [password]);
        const tables = Number(/^NT_TABLES=(-?\d+)$/m.exec(res.stdout ?? '')?.[1] ?? -1);
        return { restored: true, db, tables, checksum: sha256(bytes) };
      } finally {
        if (dir) await run(CLEANUP_SCRIPT, { args: [dir], timeoutMs: 30_000 }).catch(() => {});
      }
    });
  }

  return {
    mode,
    enabled,
    storage,
    maxBytes,
    testRestoreEnabled,

    status() {
      return { mode, enabled, simulated: !enabled, maxBytes, testRestoreEnabled, encryption: 'aes-256-gcm', checksum: 'sha256-server-side-verified-on-pull', storage: storage?.offsiteActive ? 'offsite' : 'local' };
    },

    /** Dumps one database (MySQL/MariaDB, PostgreSQL, MongoDB). Credentials via stdin only. */
    async dumpDatabase({ serverId, engine, db, username, password }, actor) {
      guard(actor);
      const cmd = buildDbDumpCommand({ engine, db, username, password, maxBytes });
      const started = now().getTime();
      const { bytes, serverSha256 } = await runDump(serverId, cmd, [password], maxBytes);
      return { bytes, consistent: true, method: cmd.method, simulated: false, source: 'ssh-exec', serverSha256, durationMs: now().getTime() - started };
    },

    /** tar.gz of a project directory with exclusions; symlinks are stored, never followed. */
    async archiveDirectory({ serverId, path }, actor) {
      guard(actor);
      const cmd = buildTreeArchiveCommand({ path, maxBytes });
      const started = now().getTime();
      const { bytes, serverSha256 } = await runDump(serverId, cmd, [], maxBytes);
      return { bytes, consistent: true, method: cmd.method, simulated: false, source: 'ssh-exec', serverSha256, durationMs: now().getTime() - started };
    },

    /** Restores a gzip dump into `db`. The caller decides isolated (new name) vs inplace and enforces its gates. */
    async restoreDatabase(input, actor) {
      guard(actor);
      normalizeEngine(input.engine);
      const started = now().getTime();
      const out = await runRestore(input.serverId, input);
      return { ...out, simulated: false, source: 'ssh-exec', durationMs: now().getTime() - started };
    },

    /**
     * Scratch test-restore on the SAME instance into nt_verify_<rand>, then drop it. Runs only when explicitly enabled
     * (BACKUP_VERIFY_TEST_RESTORE=true). The scratch database is dropped even when the restore fails.
     */
    async testRestore({ serverId, engine, sourceDb, username, password, bytes }, actor) {
      guard(actor);
      if (!testRestoreEnabled) throw new AppError(409, 'BACKUP_TEST_RESTORE_DISABLED', 'Scratch test-restore is not enabled (BACKUP_VERIFY_TEST_RESTORE)');
      const e = normalizeEngine(engine);
      if (e === 'mongodb') throw new AppError(422, 'BACKUP_VERIFY_UNSUPPORTED', 'Scratch test-restore is not supported for MongoDB');
      const scratch = verifyDbName(rand());
      try {
        const res = await runRestore(serverId, { engine: e, db: scratch, sourceDb, username, password, bytes, mode: 'isolated' });
        return { ok: res.tables !== 0, scratchDb: scratch, tables: res.tables };
      } finally {
        const drop = buildScratchDropCommand({ engine: e, db: scratch, username, password });
        await remote(serverId, ({ run }) => run(drop.script, { args: drop.args, stdin: drop.stdin, timeoutMs: 60_000 })).catch(() => {});
      }
    },
  };
}

export { redactSecrets };
