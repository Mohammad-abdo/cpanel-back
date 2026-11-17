import { randomBytes, createHash } from 'node:crypto';
import path from 'node:path';
import { AppError } from '../../common/errors/app-error.js';
import { isSystemActor } from '../../common/system-actor.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { redact } from '../audit/audit.service.js';
import { statusFromSummary } from '../agents/agents.service.js';
import { execCommand, execScript, execScriptStdin, openSftp } from './ssh.connector.js';
import { INVENTORY_SCRIPT, isJunkProjectPath, parseInventory } from './server-inventory.scan.js';
import { SITE_LIVE_SCRIPT, assertSafeSitePath, parseSiteLive } from './site-live.scan.js';
import {
  SAFE_ENGINE,
  assertSafeDbName,
  assertSafeIdent,
  buildDumpCommand,
  buildRestoreCommand,
  createDatabaseSql,
  createScopedUserSql,
  describeTableSql,
  dropDatabaseSql,
  filterSchemaNames,
  isMutatingSql,
  listSchemasSql,
  listTablesSql,
  mongoListCollectionsCmd,
  mongoListDatabasesCmd,
  mongoSampleCmd,
  mysqlAdminCmd,
  mysqlCmd,
  parseMysqlBatch,
  parsePsqlAligned,
  postgresCmd,
  postgresCmdInDb,
  selectRowsSql,
} from './db-live.scan.js';
import {
  PM2_ACTIONS,
  assertSafePm2Name,
  parsePm2ActionOutput,
  parsePm2List,
  pm2ActionScript,
  pm2ListScript,
} from './pm2-live.scan.js';

const posix = path.posix;

/** Masks credential-looking literals in a SQL preview before it reaches the audit log. */
export function scrubSqlPreview(sql) {
  return String(sql)
    .replace(/(identified\s+(?:with\s+\w+\s+)?by\s+(?:password\s+)?)(['"])(?:(?!\2).)*\2/gi, '$1$2[REDACTED]$2')
    .replace(/(\b(?:password|passwd|pwd|secret|token|api[-_]?key)\b\s*(?:=|to)?\s*)(['"])(?:(?!\2).)*\2/gi, '$1$2[REDACTED]$2')
    .slice(0, 200);
}

export const MAX_EDIT_BYTES = 1024 * 1024; // view/edit in the browser
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
/** Live SQL dump/restore transfer cap (panel download/upload via SSH). */
export const MAX_DB_DUMP_BYTES = 80 * 1024 * 1024;
/** Project tree archive for backup kind `uploads` (same cap as SQL dumps). */
export const MAX_ARCHIVE_BYTES = MAX_DB_DUMP_BYTES;
/** Directories skipped when packing a project tree for uploads backups. */
export const ARCHIVE_EXCLUDES = Object.freeze([
  'node_modules',
  'vendor',
  '.git',
  '.next',
  'dist',
  'build',
  '__pycache__',
  '.cache',
  '.npm',
  'coverage',
]);
export const MAX_RECURSIVE_DELETE = 5000;
export const TICKET_TTL_MS = 30_000;
export const SERVICE_NAME = /^[A-Za-z0-9@._-]{1,100}$/;
export const SERVICE_ACTIONS = ['start', 'stop', 'restart', 'reload', 'status', 'enable', 'disable'];

/** One fixed, read-only script (no user input) that prints labelled sections. */
export const INFO_SCRIPT = [
  "echo '##os'; (. /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\")",
  "echo '##kernel'; uname -sr",
  "echo '##hostname'; hostname",
  "echo '##uptime'; cut -d' ' -f1 /proc/uptime",
  "echo '##load'; cat /proc/loadavg",
  "echo '##cpus'; nproc",
  "echo '##mem'; free -b | awk 'NR==2{print $2, $3, $7}'",
  "echo '##swap'; free -b | awk 'NR==3{print $2, $3}'",
  "echo '##disk'; df -PB1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | tail -n +2",
  "echo '##procs'; ps -eo pid=,user=,pcpu=,pmem=,comm= --sort=-pcpu | head -n 12",
  "echo '##services'; systemctl list-units --type=service --all --no-legend --no-pager --plain 2>/dev/null | head -n 400",
  "echo '##ports'; ss -tulnH 2>/dev/null | head -n 200",
].join('; ');

/**
 * Fixed read-only htop-style snapshot (no TTY, no interactive htop binary required).
 * Two /proc/stat samples (~350ms apart) give per-CPU usage; process list is capped.
 */
export const HTOP_SCRIPT = [
  "echo '##hostname'; hostname",
  "echo '##uptime'; cut -d' ' -f1 /proc/uptime",
  "echo '##load'; cat /proc/loadavg",
  "echo '##cpus'; nproc",
  "echo '##mem'; free -b | awk 'NR==2{print $2,$3,$4,$6,$7}'",
  "echo '##swap'; free -b | awk 'NR==3{print $2,$3}'",
  "echo '##tasks'; ps -e --no-headers 2>/dev/null | wc -l",
  "echo '##cpusnap1'; grep -E '^cpu[0-9]* ' /proc/stat | head -n 65",
  'sleep 0.35',
  "echo '##cpusnap2'; grep -E '^cpu[0-9]* ' /proc/stat | head -n 65",
  "echo '##procs'; ps -eo pid=,user:16=,state=,pcpu=,pmem=,rss=,etime=,comm:32=,args:100= --sort=-pcpu 2>/dev/null | head -n 80",
].join('; ');

function parseCpuStatLines(lines = []) {
  const out = [];
  for (const line of lines) {
    const p = line.trim().split(/\s+/);
    if (!p[0] || !/^cpu[0-9]*$/.test(p[0])) continue;
    const nums = p.slice(1).map((n) => Number(n)).filter((n) => Number.isFinite(n));
    if (nums.length < 4) continue;
    const idle = (nums[3] || 0) + (nums[4] || 0);
    const total = nums.reduce((a, b) => a + b, 0);
    out.push({ id: p[0], idle, total });
  }
  return out;
}

/** Delta two /proc/stat snapshots into usage percent (0–100). */
export function cpuUsageFromSnaps(snap1, snap2) {
  const a = parseCpuStatLines(snap1);
  const b = parseCpuStatLines(snap2);
  const byId = new Map(a.map((r) => [r.id, r]));
  return b
    .map((row) => {
      const prev = byId.get(row.id);
      if (!prev) return null;
      const dTotal = row.total - prev.total;
      const dIdle = row.idle - prev.idle;
      if (dTotal <= 0) return { id: row.id, usage: 0 };
      const usage = Math.max(0, Math.min(100, (1 - dIdle / dTotal) * 100));
      return { id: row.id, usage: Math.round(usage * 10) / 10 };
    })
    .filter(Boolean);
}

/** Parses HTOP_SCRIPT stdout into a structured live process board. */
export function parseHtopSnapshot(text) {
  const sec = {};
  let cur = null;
  for (const line of String(text).split('\n')) {
    const m = /^##(\w+)$/.exec(line.trim());
    if (m) {
      cur = m[1];
      sec[cur] = [];
    } else if (cur && line.trim()) sec[cur].push(line.trim());
  }
  const ws = /\s+/;
  const num = (v) => (v !== undefined && v !== '' && Number.isFinite(Number(v)) ? Number(v) : null);
  const load = (sec.load?.[0] ?? '').split(ws);
  const memParts = (sec.mem?.[0] ?? '').split(ws).map(num);
  const swapParts = (sec.swap?.[0] ?? '').split(ws).map(num);
  const cpus = cpuUsageFromSnaps(sec.cpusnap1 ?? [], sec.cpusnap2 ?? []);
  const all = cpus.find((c) => c.id === 'cpu');
  const cores = cpus.filter((c) => c.id !== 'cpu');
  const processes = (sec.procs ?? []).map((l) => {
    // pid user state pcpu pmem rss etime comm args...
    const parts = l.trim().split(ws);
    if (parts.length < 8) return null;
    const [pid, user, state, pcpu, pmem, rss, etime, comm, ...args] = parts;
    return {
      pid: num(pid),
      user,
      state,
      cpu: num(pcpu),
      mem: num(pmem),
      rss: num(rss),
      etime,
      command: comm,
      args: args.join(' ').slice(0, 200),
    };
  }).filter(Boolean);

  return {
    hostname: sec.hostname?.[0] ?? null,
    uptimeSec: num(sec.uptime?.[0]) === null ? null : Math.floor(num(sec.uptime[0])),
    load: { m1: num(load[0]), m5: num(load[1]), m15: num(load[2]) },
    cpuCount: num(sec.cpus?.[0]),
    cpu: { all: all?.usage ?? null, cores },
    memory: {
      total: memParts[0] ?? null,
      used: memParts[1] ?? null,
      free: memParts[2] ?? null,
      buffCache: memParts[3] ?? null,
      available: memParts[4] ?? null,
    },
    swap: { total: swapParts[0] ?? null, used: swapParts[1] ?? null },
    taskCount: num(sec.tasks?.[0]),
    processes,
  };
}

/** Parses INFO_SCRIPT output into structured data. Unknown or missing sections stay empty. */
export function parseServerInfo(text) {
  const sec = {};
  let cur = null;
  for (const line of String(text).split('\n')) {
    const m = /^##(\w+)$/.exec(line.trim());
    if (m) {
      cur = m[1];
      sec[cur] = [];
    } else if (cur && line.trim()) sec[cur].push(line.trim());
  }
  const ws = /\s+/;
  const num = (v) => (v !== undefined && v !== '' && Number.isFinite(Number(v)) ? Number(v) : null);
  const [memTotal, memUsed, memAvail] = (sec.mem?.[0] ?? '').split(ws).map(num);
  const [swapTotal, swapUsed] = (sec.swap?.[0] ?? '').split(ws).map(num);
  const load = (sec.load?.[0] ?? '').split(ws);
  return {
    os: sec.os?.[0] ?? null,
    kernel: sec.kernel?.[0] ?? null,
    hostname: sec.hostname?.[0] ?? null,
    uptimeSec: num(sec.uptime?.[0]) === null ? null : Math.floor(num(sec.uptime[0])),
    load: { m1: num(load[0]), m5: num(load[1]), m15: num(load[2]) },
    cpus: num(sec.cpus?.[0]),
    memory: { total: memTotal ?? null, used: memUsed ?? null, available: memAvail ?? null },
    swap: { total: swapTotal ?? null, used: swapUsed ?? null },
    disks: (sec.disk ?? []).map((l) => {
      const [fs, size, used, avail, , mount] = l.split(ws);
      return { fs, mount, size: num(size), used: num(used), available: num(avail) };
    }),
    processes: (sec.procs ?? []).map((l) => {
      const [pid, user, cpu, mem, ...cmd] = l.split(ws);
      return { pid: num(pid), user, cpu: num(cpu), mem: num(mem), command: cmd.join(' ') };
    }),
    services: (sec.services ?? []).map((l) => {
      const [unit, load2, active, sub, ...desc] = l.split(ws);
      return { name: unit.replace(/\.service$/, ''), load: load2, active, sub, description: desc.join(' ') };
    }),
    ports: (sec.ports ?? []).map((l) => {
      const p = l.split(ws);
      const local = p[4] ?? '';
      return { proto: p[0], state: p[1], local, port: num(local.slice(local.lastIndexOf(':') + 1)) };
    }),
  };
}

const S_IFMT = 0o170000;
const TYPE = { 0o040000: 'dir', 0o100000: 'file', 0o120000: 'link' };
const sha = (b) => createHash('sha256').update(b).digest('hex');

/** SFTP status codes -> HTTP errors. */
function sftpError(err, p) {
  if (err instanceof AppError) return err;
  if (err?.code === 2) return new AppError(404, 'PATH_NOT_FOUND', `No such file or folder: ${p}`);
  if (err?.code === 3) return new AppError(403, 'PATH_PERMISSION_DENIED', `Permission denied: ${p}`);
  return new AppError(422, 'SFTP_FAILED', `File operation failed on ${p}`);
}

const call = (fn) =>
  new Promise((resolve, reject) => {
    fn((err, value) => (err ? reject(err) : resolve(value)));
  });

/** Normalizes a remote path. Relative paths resolve against the login home directory. */
export function normalizeRemotePath(p, home = '/') {
  if (typeof p !== 'string' || p.includes('\0')) throw new AppError(400, 'PATH_INVALID', 'Invalid path');
  const raw = p.trim() === '' ? home : p.trim();
  return posix.normalize(raw.startsWith('/') ? raw : posix.join(home, raw));
}

/**
 * Owner-only SSH access: register servers by SSH credentials, file manager over SFTP, terminal tickets.
 * The password is encrypted with CREDENTIAL_ENCRYPTION_KEY (fails closed if missing) and never returned.
 */
/** PM2 actions that interrupt a running process: High risk, approval-gated (platform.risk ACTION_RISK). */
export const GATED_PM2_ACTIONS = Object.freeze(['stop', 'restart', 'reload', 'delete']);
/** Read-only or non-interrupting actions that need no approval. Anything else is gated (fail closed). */
export const UNGATED_PM2_ACTIONS = Object.freeze(['start', 'logs', 'describe']);

export function createServerAccessService({ prisma, connector, auditService = null, platform = null, now = () => new Date(), credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'server', ...event }) : null);
  const tickets = new Map();
  /** Serialize SSH sessions per server so live polls + service actions do not stampede and time out. */
  const sshLocks = new Map();

  function requireOwner(actor) {
    // Scheduled backup jobs use SYSTEM_ACTOR (isOwner, no user id).
    if (isSystemActor(actor)) return;
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can use server SSH access');
  }

  /** Persist SSH info as a ServerSnapshot so /servers list shows CPU/mem/disk without an agent. */
  async function recordSshMetrics(serverId, info) {
    const memPercent =
      info?.memory?.total > 0 ? Math.round((Number(info.memory.used) / Number(info.memory.total)) * 100) : null;
    const root = info?.disks?.find((d) => d.mount === '/') || info?.disks?.[0];
    const diskPercent = root?.size > 0 ? Math.round((Number(root.used) / Number(root.size)) * 100) : null;
    const cpus = Number(info?.cpus) || 0;
    const load1 = info?.load?.m1;
    const cpuPercent =
      cpus > 0 && load1 != null && Number.isFinite(Number(load1))
        ? Math.min(100, Math.round((Number(load1) / cpus) * 100))
        : null;
    const summary = {
      cpuPercent,
      memPercent,
      diskPercent,
      load1: load1 ?? null,
      cpus: cpus || null,
      source: 'ssh',
      hostname: info?.hostname ?? null,
      os: info?.os ?? null,
    };
    const capturedAt = now();
    await prisma.serverSnapshot.create({
      data: { serverId, capturedAt, summaryJson: summary },
    });
    const nums = [cpuPercent, memPercent, diskPercent].filter((n) => typeof n === 'number');
    const status = nums.length ? statusFromSummary({
      cpuPercent: cpuPercent ?? 0,
      memPercent: memPercent ?? 0,
      diskPercent: diskPercent ?? 0,
    }) : 'online';
    // Map agent vocabulary onto list-friendly online/degraded when needed.
    const listStatus = status === 'healthy' ? 'online' : status === 'warning' || status === 'critical' ? 'degraded' : status;
    await prisma.server.update({
      where: { id: serverId },
      data: {
        status: listStatus,
        ...(info?.hostname ? { hostname: info.hostname } : {}),
      },
    });
    return summary;
  }

  function withSshLock(serverId, task) {
    const prev = sshLocks.get(serverId) ?? Promise.resolve();
    const run = prev.catch(() => {}).then(task);
    sshLocks.set(
      serverId,
      run.catch(() => {}),
    );
    return run;
  }

  const summary = (c) =>
    c ? { host: c.host, port: c.port, username: c.username, authType: c.authType, hostKeySha256: c.hostKeySha256, lastConnectedAt: c.lastConnectedAt, updatedAt: c.updatedAt } : null;

  async function loadCredential(serverId) {
    const cred = await prisma.serverCredential.findUnique({ where: { serverId } });
    if (!cred) throw new AppError(409, 'SSH_CREDENTIAL_NOT_FOUND', 'This server has no SSH login saved. Add one first.');
    return cred;
  }

  async function connectWith(cred) {
    const password = decrypt(Buffer.from(cred.secretEnc), credentialKey()).toString('utf8');
    const conn = await connector.connect({ host: cred.host, port: cred.port, username: cred.username, password, expectedHostKey: cred.hostKeySha256 ?? null });
    await prisma.serverCredential.update({ where: { id: cred.id }, data: { lastConnectedAt: now(), ...(cred.hostKeySha256 ? {} : { hostKeySha256: conn.hostKeySha256 }) } });
    return conn;
  }

  /** Opens SFTP, runs fn(sftp, home), always closes the connection. */
  async function withSftp(serverId, fn) {
    const cred = await loadCredential(serverId);
    const { client } = await connectWith(cred);
    try {
      const sftp = await openSftp(client);
      const home = await call((cb) => sftp.realpath('.', cb)).catch(() => '/');
      return await fn(sftp, home);
    } finally {
      client.end();
    }
  }

  async function probe(input) {
    const conn = await connector.connect({ host: input.host, port: input.port, username: input.username, password: input.password });
    try {
      const info = await execCommand(conn.client, 'hostname; uname -sr', { timeoutMs: 5000 }).catch(() => ({ stdout: '' }));
      const [hostname, kernel] = (info.stdout || '').split('\n').map((s) => s.trim());
      return { hostKeySha256: conn.hostKeySha256, hostname: hostname || null, kernel: kernel || null };
    } finally {
      conn.client.end();
    }
  }

  function encryptPassword(password) {
    return encrypt(Buffer.from(password, 'utf8'), credentialKey());
  }

  async function removeTree(sftp, p, counter) {
    const st = await call((cb) => sftp.lstat(p, cb));
    if ((st.mode & S_IFMT) === 0o040000) {
      const list = await call((cb) => sftp.readdir(p, cb));
      for (const e of list) {
        if (++counter.n > MAX_RECURSIVE_DELETE) throw new AppError(422, 'DELETE_TOO_LARGE', `Folder has more than ${MAX_RECURSIVE_DELETE} entries; delete it in parts or from the terminal`);
        await removeTree(sftp, posix.join(p, e.filename), counter);
      }
      await call((cb) => sftp.rmdir(p, cb));
    } else {
      await call((cb) => sftp.unlink(p, cb));
    }
  }

  return {
    /** Tests the login, then creates the server and stores the encrypted credential. */
    async addServer(input, actor) {
      requireOwner(actor);
      encryptPassword('check'); // fail closed (no key) before touching the network
      if (await prisma.server.findUnique({ where: { alias: input.alias } })) throw new AppError(409, 'SERVER_ALIAS_TAKEN', 'A server with this name already exists');
      const info = await probe(input);
      const server = await prisma.server.create({ data: { alias: input.alias, hostname: info.hostname ?? input.host, status: 'online' } });
      const cred = await prisma.serverCredential.create({
        data: { serverId: server.id, host: input.host, port: input.port, username: input.username, authType: 'password', secretEnc: encryptPassword(input.password), hostKeySha256: info.hostKeySha256, lastConnectedAt: now(), createdById: actor.id },
      });
      // Seed list metrics immediately so /servers is not empty dashes for SSH-only hosts.
      try {
        const conn = await connector.connect({
          host: input.host,
          port: input.port,
          username: input.username,
          password: input.password,
          expectedHostKey: info.hostKeySha256,
        });
        try {
          const res = await execCommand(conn.client, INFO_SCRIPT, { maxBytes: 512 * 1024, timeoutMs: 30_000 });
          if (!res.timedOut && res.code === 0) await recordSshMetrics(server.id, parseServerInfo(res.stdout));
        } finally {
          conn.client.end();
        }
      } catch {
        /* metrics seed is best-effort; SSH login itself already succeeded */
      }
      await audit({ actorId: actor.id, action: 'server.ssh.add', resourceId: server.id, result: 'success', after: { alias: input.alias, host: input.host, port: input.port, username: input.username, hostKeySha256: info.hostKeySha256 } });
      return { server, ssh: summary(cred), kernel: info.kernel };
    },

    async getCredential(serverId, actor) {
      requireOwner(actor);
      const cred = await prisma.serverCredential.findUnique({ where: { serverId } });
      return summary(cred);
    },

    /** Replaces the login after testing it. A new host key is pinned (the Owner is changing the target). */
    async setCredential(serverId, input, actor) {
      requireOwner(actor);
      encryptPassword('check');
      if (!(await prisma.server.findUnique({ where: { id: serverId } }))) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
      const info = await probe(input);
      const data = { host: input.host, port: input.port, username: input.username, authType: 'password', secretEnc: encryptPassword(input.password), hostKeySha256: info.hostKeySha256, lastConnectedAt: now() };
      const cred = await prisma.serverCredential.upsert({ where: { serverId }, create: { serverId, createdById: actor.id, ...data }, update: data });
      await audit({ actorId: actor.id, action: 'server.ssh.set', resourceId: serverId, result: 'success', after: { host: input.host, port: input.port, username: input.username, hostKeySha256: info.hostKeySha256 } });
      return summary(cred);
    },

    async removeCredential(serverId, actor) {
      requireOwner(actor);
      await loadCredential(serverId);
      await prisma.serverCredential.delete({ where: { serverId } });
      await audit({ actorId: actor.id, action: 'server.ssh.remove', resourceId: serverId, result: 'success' });
      return { removed: true };
    },

    async test(serverId, actor) {
      requireOwner(actor);
      const cred = await loadCredential(serverId);
      const { client, hostKeySha256 } = await connectWith(cred);
      client.end();
      return { ok: true, hostKeySha256 };
    },

    // ---- file manager ------------------------------------------------------------------------
    async list(serverId, rawPath, actor) {
      requireOwner(actor);
      return withSftp(serverId, async (sftp, home) => {
        const p = normalizeRemotePath(rawPath ?? '', home);
        try {
          const rows = await call((cb) => sftp.readdir(p, cb));
          const entries = rows
            .map((e) => ({
              name: e.filename,
              path: posix.join(p, e.filename),
              type: TYPE[e.attrs.mode & S_IFMT] ?? 'other',
              size: e.attrs.size,
              mode: (e.attrs.mode & 0o7777).toString(8).padStart(4, '0'),
              mtime: new Date(e.attrs.mtime * 1000).toISOString(),
            }))
            .sort((a, b) => (a.type === 'dir') === (b.type === 'dir') ? a.name.localeCompare(b.name) : a.type === 'dir' ? -1 : 1);
          return { path: p, home, parent: p === '/' ? null : posix.dirname(p), entries };
        } catch (err) {
          throw sftpError(err, p);
        }
      });
    },

    async read(serverId, rawPath, actor) {
      requireOwner(actor);
      return withSftp(serverId, async (sftp, home) => {
        const p = normalizeRemotePath(rawPath, home);
        try {
          const st = await call((cb) => sftp.stat(p, cb));
          if ((st.mode & S_IFMT) === 0o040000) throw new AppError(422, 'PATH_IS_FOLDER', 'This is a folder, not a file');
          if (st.size > MAX_EDIT_BYTES) return { path: p, size: st.size, tooLarge: true, content: null };
          const buf = await call((cb) => sftp.readFile(p, cb));
          const binary = buf.includes(0);
          return {
            path: p,
            size: buf.length,
            binary,
            content: binary ? null : buf.toString('utf8'),
            sha256: sha(buf),
            mtimeMs: Number(st.mtime) * 1000,
          };
        } catch (err) {
          throw sftpError(err, p);
        }
      });
    },

    async write(serverId, { path: rawPath, content, expectedMtimeMs }, actor) {
      requireOwner(actor);
      const buf = Buffer.from(content, 'utf8');
      if (buf.length > MAX_EDIT_BYTES) throw new AppError(413, 'FILE_TOO_LARGE', 'Files over 1 MB cannot be edited in the browser');
      return withSftp(serverId, async (sftp, home) => {
        const p = normalizeRemotePath(rawPath, home);
        try {
          if (expectedMtimeMs != null) {
            const st = await call((cb) => sftp.stat(p, cb)).catch((err) => {
              if (err?.code === 2 /* ENOENT */) return null;
              throw err;
            });
            if (st) {
              const remoteMs = Number(st.mtime) * 1000;
              if (remoteMs !== Number(expectedMtimeMs)) {
                throw new AppError(
                  409,
                  'FILE_MTIME_CONFLICT',
                  `The file changed on the server since you opened it (expected mtime ${expectedMtimeMs}, remote ${remoteMs})`,
                );
              }
            }
          }
          await call((cb) => sftp.writeFile(p, buf, cb));
        } catch (err) {
          if (err instanceof AppError) throw err;
          throw sftpError(err, p);
        }
        await audit({ actorId: actor.id, action: 'server.file.write', resourceId: serverId, result: 'success', after: { path: p, size: buf.length, sha256: sha(buf) } });
        return { path: p, size: buf.length };
      });
    },

    /**
     * Filename search under a directory (find -name). Pattern is literal-escaped; depth and count capped.
     * Ported idea from vercel-clone files search — runs over SSH, not a free-form shell from the client.
     */
    async search(serverId, { path: rawPath, q, limit }, actor) {
      requireOwner(actor);
      const needle = String(q || '').trim();
      if (!needle) throw new AppError(400, 'SEARCH_QUERY_REQUIRED', 'Search query is required');
      if (/[\0\n\r]/.test(needle)) throw new AppError(400, 'SEARCH_QUERY_INVALID', 'Invalid search query');
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const sftp = await openSftp(client);
          const home = await call((cb) => sftp.realpath('.', cb)).catch(() => '/');
          const root = normalizeRemotePath(rawPath ?? '', home);
          const lit = needle.replace(/([\\*?[\]{}])/g, '\\$1').replace(/'/g, `'\\''`);
          const rootQ = root.replace(/'/g, `'\\''`);
          const cmd = `find '${rootQ}' -maxdepth 6 \\( -type f -o -type d \\) -name '*${lit}*' 2>/dev/null | head -n ${Number(limit) || 50}`;
          const res = await execCommand(client, cmd, { maxBytes: 256 * 1024, timeoutMs: 45_000 });
          const paths = String(res.stdout || '')
            .split('\n')
            .map((s) => s.trim())
            .filter(Boolean)
            .slice(0, Number(limit) || 50)
            .map((p) => ({ path: p, name: posix.basename(p) }));
          return { path: root, q: needle, items: paths };
        } finally {
          client.end();
        }
      });
    },

    async upload(serverId, { path: rawPath, bytes }, actor) {
      requireOwner(actor);
      if (bytes.length > MAX_UPLOAD_BYTES) throw new AppError(413, 'FILE_TOO_LARGE', 'Uploads are limited to 20 MB');
      return withSftp(serverId, async (sftp, home) => {
        const p = normalizeRemotePath(rawPath, home);
        try {
          await call((cb) => sftp.writeFile(p, bytes, cb));
        } catch (err) {
          throw sftpError(err, p);
        }
        await audit({ actorId: actor.id, action: 'server.file.upload', resourceId: serverId, result: 'success', after: { path: p, size: bytes.length, sha256: sha(bytes) } });
        return { path: p, size: bytes.length };
      });
    },

    /** Reads a whole file for download (bounded by MAX_UPLOAD_BYTES). */
    async download(serverId, rawPath, actor) {
      requireOwner(actor);
      return withSftp(serverId, async (sftp, home) => {
        const p = normalizeRemotePath(rawPath, home);
        try {
          const st = await call((cb) => sftp.stat(p, cb));
          if ((st.mode & S_IFMT) === 0o040000) throw new AppError(422, 'PATH_IS_FOLDER', 'Folders cannot be downloaded; download files one by one');
          if (st.size > MAX_UPLOAD_BYTES) throw new AppError(413, 'FILE_TOO_LARGE', 'Downloads are limited to 20 MB in the panel');
          const bytes = await call((cb) => sftp.readFile(p, cb));
          await audit({ actorId: actor.id, action: 'server.file.download', resourceId: serverId, result: 'success', after: { path: p, size: bytes.length } });
          return { path: p, name: posix.basename(p), bytes };
        } catch (err) {
          throw sftpError(err, p);
        }
      });
    },

    async mkdir(serverId, rawPath, actor) {
      requireOwner(actor);
      return withSftp(serverId, async (sftp, home) => {
        const p = normalizeRemotePath(rawPath, home);
        try {
          await call((cb) => sftp.mkdir(p, cb));
        } catch (err) {
          throw sftpError(err, p);
        }
        await audit({ actorId: actor.id, action: 'server.file.mkdir', resourceId: serverId, result: 'success', after: { path: p } });
        return { path: p };
      });
    },

    async rename(serverId, { from, to }, actor) {
      requireOwner(actor);
      return withSftp(serverId, async (sftp, home) => {
        const a = normalizeRemotePath(from, home);
        const b = normalizeRemotePath(to, home);
        try {
          await call((cb) => sftp.rename(a, b, cb));
        } catch (err) {
          throw sftpError(err, a);
        }
        await audit({ actorId: actor.id, action: 'server.file.rename', resourceId: serverId, result: 'success', before: { path: a }, after: { path: b } });
        return { from: a, to: b };
      });
    },

    async remove(serverId, { path: rawPath, recursive = false }, actor) {
      requireOwner(actor);
      return withSftp(serverId, async (sftp, home) => {
        const p = normalizeRemotePath(rawPath, home);
        if (p === '/' || p === home) throw new AppError(422, 'PATH_PROTECTED', 'Refusing to delete the root or home folder');
        try {
          const st = await call((cb) => sftp.lstat(p, cb));
          const isDir = (st.mode & S_IFMT) === 0o040000;
          if (isDir && !recursive) {
            const list = await call((cb) => sftp.readdir(p, cb));
            if (list.length) throw new AppError(409, 'FOLDER_NOT_EMPTY', 'Folder is not empty; confirm to delete everything inside it');
            await call((cb) => sftp.rmdir(p, cb));
          } else if (isDir) {
            await removeTree(sftp, p, { n: 0 });
          } else {
            await call((cb) => sftp.unlink(p, cb));
          }
        } catch (err) {
          throw sftpError(err, p);
        }
        await audit({ actorId: actor.id, action: 'server.file.delete', resourceId: serverId, result: 'success', before: { path: p, recursive } });
        return { deleted: p };
      });
    },

    // ---- system information and service control ---------------------------------------------
    async info(serverId, actor) {
      requireOwner(actor);
      const cred = await loadCredential(serverId);
      return withSshLock(serverId, async () => {
        const { client } = await connectWith(cred);
        try {
          const res = await execCommand(client, INFO_SCRIPT, { maxBytes: 512 * 1024, timeoutMs: 30_000 });
          if (res.timedOut) throw new AppError(504, 'SSH_INFO_TIMEOUT', 'Server info over SSH timed out');
          const parsed = parseServerInfo(res.stdout);
          const summary = await recordSshMetrics(serverId, parsed);
          return { ...parsed, collectedAt: now().toISOString(), summary };
        } finally {
          client.end();
        }
      });
    },

    /** List all PM2 processes on the server (Owner MFA). */
    async pm2List(serverId, actor) {
      requireOwner(actor);
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const res = await execScript(client, pm2ListScript(), { maxBytes: 1024 * 1024, timeoutMs: 60_000 });
          if (res.timedOut) throw new AppError(504, 'PM2_TIMEOUT', 'PM2 list timed out over SSH');
          const parsed = parsePm2List(res.stdout);
          if (!parsed.pm2Bin || parsed.pm2Bin === 'missing') {
            throw new AppError(404, 'PM2_NOT_FOUND', 'pm2 is not installed or not on PATH for the SSH user');
          }
          return parsed;
        } finally {
          client.end();
        }
      });
    },

    /** Live htop-style process board over SSH (Owner MFA). Read-only; no interactive TTY. */
    async htop(serverId, actor) {
      requireOwner(actor);
      const cred = await loadCredential(serverId);
      return withSshLock(serverId, async () => {
        const { client } = await connectWith(cred);
        try {
          const res = await execCommand(client, HTOP_SCRIPT, { maxBytes: 768 * 1024, timeoutMs: 45_000 });
          if (res.timedOut) throw new AppError(504, 'SSH_HTOP_TIMEOUT', 'Process snapshot over SSH timed out');
          return { ...parseHtopSnapshot(res.stdout), collectedAt: now().toISOString() };
        } finally {
          client.end();
        }
      });
    },

    /**
     * Serialized SSH session for other modules (mail provisioning). `run(script, {args, stdin, timeoutMs})` executes a
     * fixed script; secrets go through stdin only. The connection is always closed.
     */
    async runRemote(serverId, fn) {
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          // `client` is exposed for TASK-037 webmail SSH tunnels (IMAP/SMTP to localhost on the VPS).
          return await fn({ client, run: (script, opts = {}) => execScriptStdin(client, script, opts) });
        } finally {
          client.end();
        }
      });
    },

    /** Control one PM2 process: start|stop|restart|reload|delete|logs|describe. */
    async pm2Control(serverId, { name, action, reason, rollbackNote, approvalId }, actor) {
      requireOwner(actor);
      assertSafePm2Name(name);
      if (!PM2_ACTIONS.includes(action)) throw new AppError(422, 'PM2_ACTION_INVALID', 'Invalid PM2 action');
      if (!UNGATED_PM2_ACTIONS.includes(action)) {
        if (!platform?.gate) throw new AppError(500, 'GATE_UNAVAILABLE', 'Approval service is not wired');
        const gate = await platform.gate(
          {
            action: `pm2.${action}`,
            binding: name,
            resourceType: 'server',
            resourceId: serverId,
            approvalId,
            reason,
            impact: [`PM2 ${action} of process ${name} on this server`, 'Requests handled by this process may be interrupted'],
            rollbackPlan: rollbackNote,
            context: { name },
          },
          actor,
        );
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      }
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const res = await execScript(client, pm2ActionScript(action), {
            args: [name],
            maxBytes: 256 * 1024,
            timeoutMs: 90_000,
          });
          if (res.timedOut) throw new AppError(504, 'PM2_TIMEOUT', `PM2 ${action} timed out over SSH`);
          const parsed = parsePm2ActionOutput(res.stdout);
          const ok =
            action === 'logs' || action === 'describe'
              ? true
              : parsed.exitCode === 0 || (parsed.exitCode == null && res.code === 0);
          if (action !== 'logs' && action !== 'describe') {
            await audit({
              actorId: actor.id,
              action: `server.pm2.${action}`,
              resourceId: serverId,
              result: ok ? 'success' : 'failure',
              after: { name, exitCode: parsed.exitCode ?? res.code },
            });
          }
          if (!ok) {
            throw new AppError(
              502,
              'PM2_ACTION_FAILED',
              parsed.output
                ? `PM2 ${action} failed: ${parsed.output.slice(0, 240)}`
                : `PM2 ${action} failed for ${name}`,
            );
          }
          return { name, action, ok, exitCode: parsed.exitCode ?? res.code, output: parsed.output, collectedAt: parsed.collectedAt };
        } catch (err) {
          if (err instanceof AppError) throw err;
          if (err?.code === 'PM2_NAME_INVALID' || err?.code === 'PM2_ACTION_INVALID') {
            throw new AppError(422, err.code, err.message);
          }
          throw new AppError(502, 'PM2_ACTION_FAILED', err?.message || 'PM2 action failed');
        } finally {
          client.end();
        }
      });
    },

    /** systemctl <action> <name>. The name is validated, so it is a single safe argument. */
    async service(serverId, { name, action }, actor) {
      requireOwner(actor);
      if (!SERVICE_NAME.test(name ?? '')) throw new AppError(422, 'SERVICE_NAME_INVALID', 'Invalid service name');
      if (!SERVICE_ACTIONS.includes(action)) throw new AppError(422, 'SERVICE_ACTION_INVALID', 'Invalid service action');
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const sudo = cred.username === 'root' ? '' : 'sudo -n ';
          const res = await execCommand(client, `${sudo}systemctl ${action} ${name} --no-pager 2>&1`, { timeoutMs: 90_000 });
          if (res.timedOut) throw new AppError(504, 'SERVICE_TIMEOUT', `systemctl ${action} ${name} timed out over SSH`);
          const ok = res.code === 0 || (action === 'status' && res.code !== null && res.code <= 4);
          if (action !== 'status') {
            await audit({ actorId: actor.id, action: `server.service.${action}`, resourceId: serverId, result: ok ? 'success' : 'failure', after: { service: name, exitCode: res.code } });
          }
          return { name, action, ok, exitCode: res.code, output: res.stdout.slice(-8000) };
        } finally {
          client.end();
        }
      });
    },

    /**
     * Live read-only inspect of one site path (PM2 processes, recent logs, listing).
     * Used by project detail so discovered/active apps show real runtime state.
     */
    async inspectSite(serverId, { path, name = '', slug = '' }, actor) {
      requireOwner(actor);
      if (!assertSafeSitePath(path)) throw new AppError(400, 'PATH_INVALID', 'Invalid project path');
      return withSshLock(serverId, async () => {
        let client;
        try {
          const cred = await loadCredential(serverId);
          ({ client } = await connectWith(cred));
          const res = await execScript(client, SITE_LIVE_SCRIPT, {
            maxBytes: 900 * 1024,
            timeoutMs: 60_000,
            args: [path, name || '', slug || ''],
          });
          if (res.timedOut) throw new AppError(504, 'SITE_LIVE_TIMEOUT', 'Live site inspect timed out');
          return parseSiteLive(res.stdout, { path, name, slug });
        } catch (err) {
          if (err instanceof AppError) throw err;
          throw new AppError(502, 'SITE_LIVE_FAILED', err?.message || 'Live site inspect failed');
        } finally {
          try {
            client?.end();
          } catch {
            /* ignore */
          }
        }
      });
    },

    /**
     * Live DB browse over SSH CLI (MySQL / Postgres / MongoDB). Owner MFA only.
     * action: schemas | tables | columns | rows | query
     * MongoDB supports schemas, tables (collections), and row samples via mongosh; columns/query stay SQL-only.
     */
    async dbBrowse(serverId, { engine, action, db, table, sql, limit, offset, auth = null }, actor) {
      requireOwner(actor);
      if (!SAFE_ENGINE.has(engine)) throw new AppError(422, 'DB_ENGINE_INVALID', 'Engine must be mysql, postgres, or mongodb');
      const login = auth?.username ? { username: auth.username, password: auth.password ?? '' } : null;
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const run = async (command) => {
            const res = await execCommand(client, command, { maxBytes: 512 * 1024, timeoutMs: 60_000 });
            if (res.timedOut) throw new AppError(504, 'DB_LIVE_TIMEOUT', 'Database command over SSH timed out');
            const stdout = String(res.stdout || '');
            const stderr = String(res.stderr || '');
            if (res.code !== 0 && !stdout.trim()) {
              const hint = stderr
                .replace(/__NT_ERR__/g, '')
                .trim()
                .split('\n')
                .filter(Boolean)
                .slice(-3)
                .join(' | ')
                .slice(0, 280);
              throw new AppError(
                502,
                'DB_LIVE_FAILED',
                hint
                  ? `Database CLI failed: ${hint}`
                  : 'Database CLI returned no data (missing credentials or privileges?)',
              );
            }
            return stdout;
          };
          const parse = (text) => (engine === 'mysql' ? parseMysqlBatch(text) : parsePsqlAligned(text));

          if (engine === 'mongodb') {
            if (action === 'schemas') {
              const text = await run(mongoListDatabasesCmd(login));
              let names = [];
              try {
                names = JSON.parse(String(text).trim());
              } catch {
                names = String(text)
                  .split('\n')
                  .map((l) => l.trim())
                  .filter(Boolean);
              }
              if (!Array.isArray(names)) names = [];
              return {
                engine,
                schemas: names.filter((n) => typeof n === 'string' && n && n !== 'local' && n !== 'config'),
                collectedAt: now().toISOString(),
                usedLogin: Boolean(login),
              };
            }
            if (action === 'tables') {
              assertSafeDbName(db);
              const text = await run(mongoListCollectionsCmd(db, login));
              let names = [];
              try {
                names = JSON.parse(String(text).trim());
              } catch {
                names = [];
              }
              const tables = (Array.isArray(names) ? names : []).map((name) => ({ name, collection: name }));
              return { engine, db, columns: ['name'], tables, collectedAt: now().toISOString(), usedLogin: Boolean(login) };
            }
            if (action === 'columns') {
              throw new AppError(422, 'DB_ACTION_UNSUPPORTED', 'MongoDB column metadata is not available; use rows to sample documents');
            }
            if (action === 'rows') {
              if (typeof db !== 'string' || !db.trim()) {
                throw new AppError(422, 'DB_NAME_REQUIRED', 'Database name is required');
              }
              if (typeof table !== 'string' || !table.trim()) {
                throw new AppError(422, 'DB_TABLE_REQUIRED', 'Collection name is required');
              }
              assertSafeDbName(db);
              assertSafeIdent(table, 'collection');
              const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
              const text = await run(mongoSampleCmd(db, table, lim, login));
              let docs = [];
              try {
                docs = JSON.parse(String(text).trim());
              } catch {
                throw new AppError(502, 'DB_LIVE_PARSE', 'MongoDB sample response was not valid JSON');
              }
              if (!Array.isArray(docs)) docs = [];
              const rows = docs.map((doc) => {
                const id = doc?._id;
                return {
                  _id: id == null ? '' : typeof id === 'object' ? JSON.stringify(id) : String(id),
                  doc: JSON.stringify(doc ?? {}),
                };
              });
              return {
                engine,
                db,
                table,
                columns: ['_id', 'doc'],
                rows,
                limit: lim,
                collectedAt: now().toISOString(),
                usedLogin: Boolean(login),
              };
            }
            throw new AppError(422, 'DB_ACTION_UNSUPPORTED', 'MongoDB browse does not support arbitrary queries');
          }

          if (action === 'schemas') {
            const text = await run(
              engine === 'mysql' ? mysqlCmd(listSchemasSql(engine), null, login) : postgresCmd(listSchemasSql(engine), login),
            );
            const parsed = parse(text);
            const names =
              engine === 'mysql'
                ? parsed.rows.map((r) => r.Database ?? r.database ?? Object.values(r)[0]).filter(Boolean)
                : parsed.rows.map((r) => r.name ?? r.datname ?? Object.values(r)[0]).filter(Boolean);
            // SHOW DATABASES may return a single column without header named Database when parse fails — also accept raw lines.
            const fallback = !names.length
              ? String(text)
                  .split('\n')
                  .map((l) => l.trim())
                  .filter((l) => l && l !== 'Database' && l !== 'name')
              : names;
            return {
              engine,
              schemas: filterSchemaNames(engine, fallback),
              collectedAt: now().toISOString(),
              usedLogin: Boolean(login),
            };
          }

          if (action === 'tables') {
            assertSafeDbName(db);
            const text =
              engine === 'mysql'
                ? await run(mysqlCmd(listTablesSql(engine, db), db, login))
                : await run(postgresCmdInDb(db, listTablesSql(engine, db), login));
            const { columns, rows } = parse(text);
            return { engine, db, columns, tables: rows, collectedAt: now().toISOString(), usedLogin: Boolean(login) };
          }

          if (action === 'columns') {
            assertSafeDbName(db);
            assertSafeIdent(table, 'table');
            const text =
              engine === 'mysql'
                ? await run(mysqlCmd(describeTableSql(engine, db, table), db, login))
                : await run(postgresCmdInDb(db, describeTableSql(engine, db, table), login));
            const { columns, rows } = parse(text);
            return { engine, db, table, columns, fields: rows, collectedAt: now().toISOString(), usedLogin: Boolean(login) };
          }

          if (action === 'rows') {
            assertSafeDbName(db);
            assertSafeIdent(table, 'table');
            const text =
              engine === 'mysql'
                ? await run(mysqlCmd(selectRowsSql(engine, db, table, limit, offset), db, login))
                : await run(postgresCmdInDb(db, selectRowsSql(engine, db, table, limit, offset), login));
            const { columns, rows } = parse(text);
            return {
              engine,
              db,
              table,
              columns,
              rows,
              limit: Math.min(Math.max(Number(limit) || 50, 1), 200),
              offset: Math.min(Math.max(Number(offset) || 0, 0), 100000),
              collectedAt: now().toISOString(),
              usedLogin: Boolean(login),
            };
          }

          if (action === 'query') {
            if (typeof sql !== 'string' || sql.trim().length < 1 || sql.length > 20_000) {
              throw new AppError(422, 'DB_SQL_INVALID', 'SQL must be 1–20000 characters');
            }
            if (sql.includes(';') && sql.trim().replace(/;+\s*$/, '').includes(';')) {
              throw new AppError(422, 'DB_SQL_MULTI', 'Only a single SQL statement is allowed');
            }
            const mutating = isMutatingSql(sql);
            if (db) assertSafeDbName(db);
            const text =
              engine === 'mysql'
                ? await run(mysqlCmd(sql, db || null, login))
                : await run(db ? postgresCmdInDb(db, sql, login) : postgresCmd(sql, login));
            const { columns, rows } = parse(text);
            await audit({
              actorId: actor.id,
              action: mutating ? 'server.db.query.write' : 'server.db.query.read',
              resourceId: serverId,
              result: 'success',
              after: redact({ engine, db: db || null, mutating, sqlPreview: scrubSqlPreview(sql), usedLogin: Boolean(login) }),
            });
            return {
              engine,
              db: db || null,
              mutating,
              columns,
              rows,
              rowCount: rows.length,
              collectedAt: now().toISOString(),
              usedLogin: Boolean(login),
            };
          }

          throw new AppError(422, 'DB_ACTION_INVALID', 'Unknown database browse action');
        } catch (err) {
          if (err instanceof AppError) throw err;
          if (err?.code === 'DB_IDENT_INVALID' || err?.code === 'DB_NAME_INVALID') {
            throw new AppError(422, err.code, err.message);
          }
          throw new AppError(502, 'DB_LIVE_FAILED', err?.message || 'Database browse failed');
        } finally {
          client.end();
        }
      });
    },

    /**
     * TASK-022: live MySQL CREATE/DROP DATABASE and scoped CREATE USER over SSH.
     * Owner MFA only. Password never appears in argv flags or audit metadata.
     */
    async dbManage(serverId, { engine, auth, op, dbName, username, password, host = '127.0.0.1', grants }, actor) {
      requireOwner(actor);
      if (engine !== 'mysql') throw new AppError(422, 'ENGINE_UNSUPPORTED', 'Live database management supports MySQL only');
      if (!auth?.username) throw new AppError(409, 'DB_LOGIN_REQUIRED', 'Save a MySQL username/password on this instance first');
      let sql;
      try {
        if (op === 'createDatabase') sql = createDatabaseSql(dbName);
        else if (op === 'dropDatabase') sql = dropDatabaseSql(dbName);
        else if (op === 'createUser') sql = createScopedUserSql({ username, password, host, dbName, grants });
        else throw new AppError(422, 'DB_OP_INVALID', 'Unknown database management operation');
      } catch (err) {
        if (err instanceof AppError) throw err;
        throw new AppError(422, err.code || 'DB_IDENT_INVALID', err.message || 'Invalid database identifier');
      }
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const cmd = mysqlAdminCmd(sql, { username: auth.username, password: auth.password ?? '' });
          const res = await execCommand(client, cmd, { maxBytes: 16 * 1024, timeoutMs: 60_000 });
          if (res.timedOut) throw new AppError(504, 'DB_MANAGE_TIMEOUT', 'Database management command timed out');
          if (res.code !== 0) {
            const hint = String(res.stderr || '')
              .replace(/__NT_ERR__/g, '')
              .trim()
              .slice(0, 280);
            throw new AppError(502, 'DB_MANAGE_FAILED', hint ? `MySQL failed: ${hint}` : 'MySQL management command failed');
          }
          await audit({
            actorId: actor.id,
            action: `server.db.${op}`,
            resourceId: serverId,
            result: 'success',
            after: {
              engine,
              op,
              dbName: dbName || null,
              username: username || null,
              host: op === 'createUser' ? host : null,
              grants: op === 'createUser' ? grants : undefined,
              sqlPreview: scrubSqlPreview(sql),
            },
          });
          return { ok: true, simulated: false, op };
        } catch (err) {
          if (err instanceof AppError) throw err;
          throw new AppError(502, 'DB_MANAGE_FAILED', err?.message || 'Database management failed');
        } finally {
          try {
            client.end();
          } catch {
            /* ignore */
          }
        }
      });
    },

    /**
     * Pack a project directory over SSH into a .tar.gz (excludes node_modules/vendor/.git/…).
     * Owner / SYSTEM_ACTOR only. Used by backup kind `uploads`.
     */
    async archiveTree(serverId, { path }, actor) {
      requireOwner(actor);
      if (!assertSafeSitePath(path)) throw new AppError(400, 'PATH_INVALID', 'Invalid project path');
      const stamp = now().toISOString().replace(/[:.]/g, '-');
      const filename = `uploads-${stamp}.tar.gz`;
      const remotePath = `/tmp/nt-arch-${randomBytes(8).toString('hex')}.tgz`;
      const excludes = ARCHIVE_EXCLUDES.map((e) => `--exclude='${e}'`).join(' ');
      // path is assertSafeSitePath-checked (no spaces/metacharacters beyond the allowlist).
      const cmd = [
        `test -d '${path}' || { echo __NT_ERR__not_a_directory >&2; exit 2; }`,
        `tar -C '${path}' ${excludes} -czf '${remotePath}' . 2>/tmp/nt-tar-err.$$; ec=$?`,
        `if [ "$ec" -ne 0 ]; then cat /tmp/nt-tar-err.$$ 2>/dev/null | sed 's/^/__NT_ERR__/'; rm -f '${remotePath}' /tmp/nt-tar-err.$$; exit "$ec"; fi`,
        `rm -f /tmp/nt-tar-err.$$`,
      ].join('; ');
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const res = await execCommand(client, cmd, { maxBytes: 8 * 1024, timeoutMs: 300_000 });
          if (res.timedOut) throw new AppError(504, 'ARCHIVE_TIMEOUT', 'Project archive timed out');
          if (res.code !== 0) {
            const hint = String(res.stderr || '')
              .replace(/__NT_ERR__/g, '')
              .trim()
              .slice(0, 280);
            throw new AppError(502, 'ARCHIVE_FAILED', hint ? `Archive failed: ${hint}` : 'Archive failed on the remote host');
          }
          const sftp = await openSftp(client);
          try {
            const st = await call((cb) => sftp.stat(remotePath, cb));
            if (!st.size) throw new AppError(502, 'ARCHIVE_EMPTY', 'Archive file was empty');
            if (st.size > MAX_ARCHIVE_BYTES) {
              throw new AppError(
                413,
                'ARCHIVE_TOO_LARGE',
                `Archive is larger than ${Math.floor(MAX_ARCHIVE_BYTES / (1024 * 1024))} MB; exclude heavy dirs or use an offsite tool`,
              );
            }
            const bytes = await call((cb) => sftp.readFile(remotePath, cb));
            await audit({
              actorId: actor.id,
              action: 'server.archive.tree',
              resourceId: serverId,
              result: 'success',
              after: { path, size: bytes.length, sha256: sha(bytes), filename, excludes: ARCHIVE_EXCLUDES },
            });
            return { filename, contentType: 'application/gzip', bytes, size: bytes.length, path };
          } finally {
            await call((cb) => sftp.unlink(remotePath, cb)).catch(() => {});
          }
        } catch (err) {
          if (err instanceof AppError) throw err;
          throw new AppError(502, 'ARCHIVE_FAILED', err?.message || 'Project archive failed');
        } finally {
          try {
            client.end();
          } catch {
            /* ignore */
          }
        }
      });
    },

    /**
     * Dump one schema (or all databases) over SSH to a downloadable SQL buffer.
     * MySQL requires saved DB login. Owner MFA only. Not the full TASK-023 restic pipeline.
     */
    async dbDump(serverId, { engine, db = null, auth = null }, actor) {
      requireOwner(actor);
      if (!SAFE_ENGINE.has(engine)) throw new AppError(422, 'DB_ENGINE_INVALID', 'Engine must be mysql or postgres');
      if (db) assertSafeDbName(db);
      if (engine === 'mysql' && !auth?.username) {
        throw new AppError(409, 'DB_LOGIN_REQUIRED', 'Save a MySQL username/password on this instance before dumping');
      }
      const stamp = now().toISOString().replace(/[:.]/g, '-');
      const scope = db || 'all';
      const filename = `${engine}-${scope}-${stamp}.sql`;
      const remotePath = `/tmp/nt-dump-${randomBytes(8).toString('hex')}.sql`;
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const login = auth?.username ? { username: auth.username, password: auth.password ?? '' } : null;
          const cmd = buildDumpCommand(engine, { db, auth: login, outPath: remotePath });
          const res = await execCommand(client, cmd, { maxBytes: 8 * 1024, timeoutMs: 300_000 });
          if (res.timedOut) throw new AppError(504, 'DB_DUMP_TIMEOUT', 'Database dump timed out');
          if (res.code !== 0) {
            const hint = String(res.stderr || '')
              .replace(/__NT_ERR__/g, '')
              .trim()
              .slice(0, 280);
            throw new AppError(502, 'DB_DUMP_FAILED', hint ? `Dump failed: ${hint}` : 'Dump failed on the remote host');
          }
          const sftp = await openSftp(client);
          try {
            const st = await call((cb) => sftp.stat(remotePath, cb));
            if (!st.size) throw new AppError(502, 'DB_DUMP_EMPTY', 'Dump file was empty');
            if (st.size > MAX_DB_DUMP_BYTES) {
              throw new AppError(413, 'DB_DUMP_TOO_LARGE', `Dump is larger than ${Math.floor(MAX_DB_DUMP_BYTES / (1024 * 1024))} MB; use an offsite backup policy instead`);
            }
            const bytes = await call((cb) => sftp.readFile(remotePath, cb));
            await audit({
              actorId: actor.id,
              action: 'server.db.dump',
              resourceId: serverId,
              result: 'success',
              after: { engine, db: db || null, size: bytes.length, sha256: sha(bytes), filename },
            });
            return { filename, contentType: 'application/sql; charset=utf-8', bytes, size: bytes.length, engine, db: db || null };
          } finally {
            await call((cb) => sftp.unlink(remotePath, cb)).catch(() => {});
          }
        } catch (err) {
          if (err instanceof AppError) throw err;
          if (err?.code === 'DB_LOGIN_REQUIRED' || err?.code === 'DB_NAME_INVALID' || err?.code === 'DB_USER_INVALID') {
            throw new AppError(422, err.code, err.message);
          }
          throw new AppError(502, 'DB_DUMP_FAILED', err?.message || 'Database dump failed');
        } finally {
          try {
            client.end();
          } catch {
            /* ignore */
          }
        }
      });
    },

    /**
     * Upload a SQL dump and restore it on the remote host. Destructive — Owner MFA + confirm token.
     * confirm must equal the target db name, or "ALL" when restoring without a target db.
     */
    async dbRestore(serverId, { engine, db = null, auth = null, bytes, confirm }, actor) {
      requireOwner(actor);
      if (!SAFE_ENGINE.has(engine)) throw new AppError(422, 'DB_ENGINE_INVALID', 'Engine must be mysql or postgres');
      if (db) assertSafeDbName(db);
      const expected = db || 'ALL';
      if (confirm !== expected) {
        throw new AppError(422, 'CONFIRM_MISMATCH', `Type ${expected} to confirm restore`);
      }
      if (!Buffer.isBuffer(bytes) || bytes.length < 8) {
        throw new AppError(422, 'DUMP_INVALID', 'Upload a non-empty .sql dump');
      }
      if (bytes.length > MAX_DB_DUMP_BYTES) {
        throw new AppError(413, 'DB_DUMP_TOO_LARGE', `Uploads are limited to ${Math.floor(MAX_DB_DUMP_BYTES / (1024 * 1024))} MB`);
      }
      if (engine === 'mysql' && !auth?.username) {
        throw new AppError(409, 'DB_LOGIN_REQUIRED', 'Save a MySQL username/password on this instance before restore');
      }
      const remotePath = `/tmp/nt-restore-${randomBytes(8).toString('hex')}.sql`;
      return withSshLock(serverId, async () => {
        const cred = await loadCredential(serverId);
        const { client } = await connectWith(cred);
        try {
          const sftp = await openSftp(client);
          await call((cb) => sftp.writeFile(remotePath, bytes, cb));
          const login = auth?.username ? { username: auth.username, password: auth.password ?? '' } : null;
          const cmd = buildRestoreCommand(engine, { db, auth: login, inPath: remotePath });
          const res = await execCommand(client, cmd, { maxBytes: 8 * 1024, timeoutMs: 300_000 });
          await call((cb) => sftp.unlink(remotePath, cb)).catch(() => {});
          if (res.timedOut) throw new AppError(504, 'DB_RESTORE_TIMEOUT', 'Database restore timed out');
          if (res.code !== 0) {
            const hint = String(res.stderr || '')
              .replace(/__NT_ERR__/g, '')
              .trim()
              .slice(0, 280);
            throw new AppError(502, 'DB_RESTORE_FAILED', hint ? `Restore failed: ${hint}` : 'Restore failed on the remote host');
          }
          await audit({
            actorId: actor.id,
            action: 'server.db.restore',
            resourceId: serverId,
            result: 'success',
            after: { engine, db: db || null, size: bytes.length, sha256: sha(bytes) },
          });
          return { restored: true, engine, db: db || null, size: bytes.length };
        } catch (err) {
          if (err instanceof AppError) throw err;
          if (err?.code === 'DB_LOGIN_REQUIRED' || err?.code === 'DB_NAME_INVALID' || err?.code === 'DB_USER_INVALID') {
            throw new AppError(422, err.code, err.message);
          }
          throw new AppError(502, 'DB_RESTORE_FAILED', err?.message || 'Database restore failed');
        } finally {
          try {
            client.end();
          } catch {
            /* ignore */
          }
        }
      });
    },

    // ---- inventory (read-only scan + import into panel records) ------------------------------
    /** SSH scan: projects, vhosts, database engines/schemas. Does not write on the remote host. */
    async scanInventory(serverId, actor) {
      requireOwner(actor);
      const cred = await loadCredential(serverId);
      let client;
      try {
        ({ client } = await connectWith(cred));
        const res = await execScript(client, INVENTORY_SCRIPT, {
          maxBytes: 768 * 1024,
          timeoutMs: 90_000,
        });
        if (res.timedOut) {
          throw new AppError(504, 'INVENTORY_TIMEOUT', 'Inventory scan timed out on the server. Retry in a moment.');
        }
        const inventory = parseInventory(res.stdout);
        inventory.debug = {
          bytes: res.stdout?.length ?? 0,
          exitCode: res.code,
          timedOut: Boolean(res.timedOut),
        };
        await audit({
          actorId: actor.id,
          action: 'server.inventory.scan',
          resourceId: serverId,
          result: 'success',
          after: {
            projects: inventory.projects.length,
            domains: inventory.domains.length,
            databases: inventory.databases.length,
            bytes: inventory.debug.bytes,
          },
        }).catch(() => null);
        return inventory;
      } catch (err) {
        if (err instanceof AppError) throw err;
        throw new AppError(502, 'INVENTORY_SCAN_FAILED', err?.message || 'Inventory scan failed');
      } finally {
        try {
          client?.end();
        } catch {
          /* ignore close errors after disconnect */
        }
      }
    },

    /**
     * Import scanned candidates into panel records (discovered projects, domains, DB instances).
     * Re-scans over SSH so the import matches the live host; selection filters what is written.
     */
    async importInventory(serverId, selection, actor) {
      requireOwner(actor);
      const server = await prisma.server.findUnique({ where: { id: serverId } });
      if (!server || server.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');

      // Archive earlier junk discoveries (e.g. node_modules packages mistaken for sites).
      const discovered = await prisma.project.findMany({
        where: { serverId, status: 'discovered', archivedAt: null },
        include: { runtime: true },
      });
      let cleaned = 0;
      for (const row of discovered) {
        const path = row.runtime?.metaJson?.discoveredPath;
        if (path && isJunkProjectPath(path)) {
          await prisma.project.update({
            where: { id: row.id },
            data: { status: 'archived', archivedAt: now() },
          });
          cleaned += 1;
        }
      }

      const inventory = await this.scanInventory(serverId, actor);
      const importAll = Boolean(selection?.importAll);
      const wantProjects = importAll || selection?.projects === undefined ? null : new Set(selection.projects);
      const wantDomains = importAll || selection?.domains === undefined ? null : new Set(selection.domains.map((d) => d.toLowerCase()));
      const wantDbs = importAll || selection?.databases === undefined ? null : new Set(selection.databases);

      const created = { projects: [], domains: [], databases: [] };
      const skipped = { projects: [], domains: [], databases: [] };

      for (const c of inventory.projects) {
        if (isJunkProjectPath(c.path)) {
          skipped.projects.push({ name: c.name, reason: 'junk-path' });
          continue;
        }
        if (wantProjects && !wantProjects.has(c.path) && !wantProjects.has(c.slug)) {
          skipped.projects.push({ name: c.name, reason: 'not-selected' });
          continue;
        }
        let slug = c.slug;
        const bySlug = await prisma.project.findFirst({ where: { serverId, slug } });
        if (bySlug) {
          const runtime = await prisma.projectRuntime.findFirst({ where: { projectId: bySlug.id } });
          if (runtime?.metaJson?.discoveredPath === c.path) {
            skipped.projects.push({ name: c.name, slug, reason: 'already-known' });
            continue;
          }
          const suffix = createHash('sha256').update(c.path).digest('hex').slice(0, 6);
          slug = `${c.slug}-${suffix}`.slice(0, 63);
          if (await prisma.project.findFirst({ where: { serverId, slug } })) {
            skipped.projects.push({ name: c.name, slug, reason: 'already-known' });
            continue;
          }
        }
        const project = await prisma.project.create({
          data: { serverId, name: c.name, slug, type: c.type, status: 'discovered' },
        });
        await prisma.projectRuntime.create({
          data: {
            projectId: project.id,
            runtime: c.runtime,
            processManager: c.processManager,
            metaJson: { discoveredPath: c.path, discoveredAt: inventory.scannedAt, readOnlyDiscovery: true, marker: c.marker },
          },
        });
        created.projects.push(project);
      }

      for (const d of inventory.domains) {
        if (wantDomains && !wantDomains.has(d.name)) {
          skipped.domains.push({ name: d.name, reason: 'not-selected' });
          continue;
        }
        const existing = await prisma.domain.findUnique({ where: { name: d.name } });
        const matchedProject =
          created.projects.find((p) => p.name === d.name || p.slug === d.name.replace(/\./g, '-')) ||
          (await prisma.project.findFirst({
            where: {
              serverId,
              archivedAt: null,
              OR: [{ name: d.name }, { slug: d.name.replace(/\./g, '-') }],
            },
          }));
        if (existing) {
          if (existing.serverId === serverId || !existing.serverId) {
            const updated = await prisma.domain.update({
              where: { id: existing.id },
              data: {
                serverId,
                projectId: existing.projectId ?? matchedProject?.id ?? null,
                status: existing.status === 'active' ? existing.status : 'discovered',
                metaJson: {
                  ...(existing.metaJson && typeof existing.metaJson === 'object' ? existing.metaJson : {}),
                  confPath: d.confPath ?? null,
                  webserver: d.webserver ?? null,
                  root: d.root ?? null,
                  upstreamPort: d.upstreamPort ?? null,
                  discoveredAt: inventory.scannedAt,
                },
              },
            });
            created.domains.push(updated);
          } else {
            skipped.domains.push({ name: d.name, reason: 'owned-by-other-server' });
          }
          continue;
        }
        const row = await prisma.domain.create({
          data: {
            name: d.name,
            serverId,
            projectId: matchedProject?.id ?? null,
            status: 'discovered',
            metaJson: {
              confPath: d.confPath ?? null,
              webserver: d.webserver ?? null,
              root: d.root ?? null,
              upstreamPort: d.upstreamPort ?? null,
              discoveredAt: inventory.scannedAt,
            },
          },
        });
        created.domains.push(row);
      }

      for (const db of inventory.databases) {
        if (wantDbs && !wantDbs.has(db.engine)) {
          skipped.databases.push({ engine: db.engine, reason: 'not-selected' });
          continue;
        }
        const instanceName = `${server.alias}-${db.engine}`;
        const existing = await prisma.databaseInstance.findFirst({
          where: { serverId, engine: db.engine },
        });
        const metaJson = {
          schemas: db.schemas ?? [],
          discoveredAt: inventory.scannedAt,
          readOnlyDiscovery: true,
        };
        if (existing) {
          const updated = await prisma.databaseInstance.update({
            where: { id: existing.id },
            data: {
              status: 'discovered',
              host: existing.host ?? '127.0.0.1',
              port: existing.port ?? db.port,
              metaJson: {
                ...(existing.metaJson && typeof existing.metaJson === 'object' ? existing.metaJson : {}),
                ...metaJson,
              },
            },
          });
          created.databases.push(updated);
        } else {
          try {
            const row = await prisma.databaseInstance.create({
              data: {
                serverId,
                engine: db.engine,
                name: instanceName,
                status: 'discovered',
                host: '127.0.0.1',
                port: db.port,
                metaJson,
              },
            });
            created.databases.push(row);
          } catch (err) {
            // Older DB without metaJson column: create without it.
            if (!/Unknown argument|metaJson/i.test(String(err?.message))) throw err;
            const row = await prisma.databaseInstance.create({
              data: {
                serverId,
                engine: db.engine,
                name: instanceName,
                status: 'discovered',
                host: '127.0.0.1',
                port: db.port,
              },
            });
            created.databases.push({ ...row, metaJson, schemaPending: true });
          }
        }
      }

      await audit({
        actorId: actor.id,
        action: 'server.inventory.import',
        resourceId: serverId,
        result: 'success',
        after: {
          cleaned,
          created: {
            projects: created.projects.length,
            domains: created.domains.length,
            databases: created.databases.length,
          },
          skipped: {
            projects: skipped.projects.length,
            domains: skipped.domains.length,
            databases: skipped.databases.length,
          },
        },
      }).catch(() => null);

      return { inventory, created, skipped, cleaned };
    },

    // ---- terminal ----------------------------------------------------------------------------
    /**
     * One-time ticket for the terminal WebSocket (browsers cannot send Authorization).
     * Critical gate: reason + rollback note, then approvalId replay. Ticket TTL stays short (TICKET_TTL_MS).
     */
    async createTicket(serverId, { reason, rollbackNote, approvalId } = {}, actor) {
      requireOwner(actor);
      await loadCredential(serverId);
      if (!platform?.gate) throw new AppError(500, 'GATE_UNAVAILABLE', 'Approval service is not wired');
      const gate = await platform.gate(
        {
          action: 'server.terminal.open',
          binding: serverId,
          resourceType: 'server',
          resourceId: serverId,
          approvalId,
          reason: reason ?? 'Open interactive SSH terminal',
          impact: [
            'Opens an interactive shell on this server for the Owner session',
            'Keystrokes are audited; passwords after a password prompt are redacted',
            `Session idle timeout 30 minutes; ticket valid ~${Math.round(TICKET_TTL_MS / 1000)}s`,
          ],
          rollbackPlan: rollbackNote ?? 'Close the terminal tab; revoke Owner MFA session if needed',
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      for (const [k, t] of tickets) if (t.expiresAt <= now().getTime()) tickets.delete(k);
      const ticket = randomBytes(32).toString('base64url');
      const expiresAt = now().getTime() + TICKET_TTL_MS;
      tickets.set(sha(ticket), { serverId, actorId: actor.id, expiresAt });
      await audit({
        actorId: actor.id,
        action: 'server.terminal.ticket',
        resourceId: serverId,
        result: 'success',
        metadata: { approvalId: gate.approval?.id ?? approvalId ?? null },
      });
      return { ticket, expiresAt: new Date(expiresAt).toISOString() };
    },

    /** Consumes a ticket (single use). */
    consumeTicket(ticket) {
      const key = sha(String(ticket ?? ''));
      const t = tickets.get(key);
      tickets.delete(key);
      if (!t || t.expiresAt <= now().getTime()) throw new AppError(401, 'TICKET_INVALID', 'Terminal ticket is invalid, used or expired');
      return t;
    },

    /** Opens an interactive shell for a consumed ticket. Returns { stream, client }. */
    async openShell(serverId, { cols = 100, rows = 30 } = {}) {
      const cred = await loadCredential(serverId);
      const { client } = await connectWith(cred);
      const stream = await new Promise((resolve, reject) => {
        client.shell({ term: 'xterm-256color', cols, rows }, (err, s) => (err ? reject(new AppError(502, 'SSH_SHELL_FAILED', 'Could not open a shell')) : resolve(s)));
      }).catch((e) => {
        client.end();
        throw e;
      });
      return { stream, client };
    },

    audit,
  };
}
