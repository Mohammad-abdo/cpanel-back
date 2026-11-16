import { randomBytes, createHash } from 'node:crypto';
import path from 'node:path';
import { AppError } from '../../common/errors/app-error.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { execCommand, execScript, openSftp } from './ssh.connector.js';
import { INVENTORY_SCRIPT, parseInventory } from './server-inventory.scan.js';

const posix = path.posix;
export const MAX_EDIT_BYTES = 1024 * 1024; // view/edit in the browser
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
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
export function createServerAccessService({ prisma, connector, auditService = null, now = () => new Date(), credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'server', ...event }) : null);
  const tickets = new Map();

  function requireOwner(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can use server SSH access');
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
      const server = await prisma.server.create({ data: { alias: input.alias, hostname: info.hostname ?? input.host } });
      const cred = await prisma.serverCredential.create({
        data: { serverId: server.id, host: input.host, port: input.port, username: input.username, authType: 'password', secretEnc: encryptPassword(input.password), hostKeySha256: info.hostKeySha256, lastConnectedAt: now(), createdById: actor.id },
      });
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
          return { path: p, size: buf.length, binary, content: binary ? null : buf.toString('utf8'), sha256: sha(buf) };
        } catch (err) {
          throw sftpError(err, p);
        }
      });
    },

    async write(serverId, { path: rawPath, content }, actor) {
      requireOwner(actor);
      const buf = Buffer.from(content, 'utf8');
      if (buf.length > MAX_EDIT_BYTES) throw new AppError(413, 'FILE_TOO_LARGE', 'Files over 1 MB cannot be edited in the browser');
      return withSftp(serverId, async (sftp, home) => {
        const p = normalizeRemotePath(rawPath, home);
        try {
          await call((cb) => sftp.writeFile(p, buf, cb));
        } catch (err) {
          throw sftpError(err, p);
        }
        await audit({ actorId: actor.id, action: 'server.file.write', resourceId: serverId, result: 'success', after: { path: p, size: buf.length, sha256: sha(buf) } });
        return { path: p, size: buf.length };
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
      const { client } = await connectWith(cred);
      try {
        const res = await execCommand(client, INFO_SCRIPT, { maxBytes: 512 * 1024, timeoutMs: 15_000 });
        return { ...parseServerInfo(res.stdout), collectedAt: now().toISOString() };
      } finally {
        client.end();
      }
    },

    /** systemctl <action> <name>. The name is validated, so it is a single safe argument. */
    async service(serverId, { name, action }, actor) {
      requireOwner(actor);
      if (!SERVICE_NAME.test(name ?? '')) throw new AppError(422, 'SERVICE_NAME_INVALID', 'Invalid service name');
      if (!SERVICE_ACTIONS.includes(action)) throw new AppError(422, 'SERVICE_ACTION_INVALID', 'Invalid service action');
      const cred = await loadCredential(serverId);
      const { client } = await connectWith(cred);
      try {
        const sudo = cred.username === 'root' ? '' : 'sudo -n ';
        const res = await execCommand(client, `${sudo}systemctl ${action} ${name} --no-pager 2>&1`, { timeoutMs: 60_000 });
        const ok = res.code === 0 || (action === 'status' && res.code !== null && res.code <= 4);
        if (action !== 'status') {
          await audit({ actorId: actor.id, action: `server.service.${action}`, resourceId: serverId, result: ok ? 'success' : 'failure', after: { service: name, exitCode: res.code } });
        }
        return { name, action, ok, exitCode: res.code, output: res.stdout.slice(-8000) };
      } finally {
        client.end();
      }
    },

    // ---- inventory (read-only scan + import into panel records) ------------------------------
    /** SSH scan: projects, vhosts, database engines/schemas. Does not write on the remote host. */
    async scanInventory(serverId, actor) {
      requireOwner(actor);
      const cred = await loadCredential(serverId);
      const { client } = await connectWith(cred);
      try {
        const res = await execScript(client, INVENTORY_SCRIPT, {
          maxBytes: 768 * 1024,
          timeoutMs: 60_000,
        });
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
        });
        return inventory;
      } finally {
        client.end();
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
      const inventory = await this.scanInventory(serverId, actor);
      const importAll = Boolean(selection?.importAll);
      const wantProjects = importAll || selection?.projects === undefined ? null : new Set(selection.projects);
      const wantDomains = importAll || selection?.domains === undefined ? null : new Set(selection.domains.map((d) => d.toLowerCase()));
      const wantDbs = importAll || selection?.databases === undefined ? null : new Set(selection.databases);

      const created = { projects: [], domains: [], databases: [] };
      const skipped = { projects: [], domains: [], databases: [] };

      for (const c of inventory.projects) {
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
        if (existing) {
          if (existing.serverId === serverId || !existing.serverId) {
            const updated = await prisma.domain.update({
              where: { id: existing.id },
              data: {
                serverId,
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
      });

      return { inventory, created, skipped };
    },

    // ---- terminal ----------------------------------------------------------------------------
    /** One-time ticket for the terminal WebSocket (browsers cannot send an Authorization header). */
    async createTicket(serverId, actor) {
      requireOwner(actor);
      await loadCredential(serverId);
      for (const [k, t] of tickets) if (t.expiresAt <= now().getTime()) tickets.delete(k);
      const ticket = randomBytes(32).toString('base64url');
      const expiresAt = now().getTime() + TICKET_TTL_MS;
      tickets.set(sha(ticket), { serverId, actorId: actor.id, expiresAt });
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
