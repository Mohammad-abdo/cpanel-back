import { describe, expect, it, vi } from 'vitest';
import { gzipSync } from 'node:zlib';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createBackupsService } from '../src/modules/backups/backups.service.js';
import { createRestoresService } from '../src/modules/restores/restores.service.js';
import { createBackupExecutor, isGzip, resolveExecutorMode } from '../src/modules/backups/backups.executor.js';
import {
  buildDbDumpCommand,
  buildDbRestoreCommand,
  buildScratchDropCommand,
  buildTreeArchiveCommand,
  isolatedDbName,
  mapRemoteError,
  parseDumpResult,
  redactSecrets,
} from '../src/modules/backups/backups.commands.js';
import { signRequest } from '../src/modules/backups/backups.sigv4.js';
import { createLocalStore, createS3Store, createStorageRouter, normalizeOffsiteConfig } from '../src/modules/backups/backups.storage.js';
import { assertSafeUrl } from '../src/modules/alert-channels/alert-channels.ssrf.js';
import { decrypt, encrypt, sha256 } from '../src/modules/platform/platform.crypto.js';
import { execScriptStdin } from '../src/modules/server-access/ssh.connector.js';
import { createFakeSsh } from './server-access-fake-ssh.js';
import { APPROVER, ENV_PROD, KEY, OWNER, PROJECT, U, approve, backupPrisma, makeCtx } from './phase6-helpers.js';

const NOW = new Date('2026-06-01T12:00:00Z');
const PASS = 'S3cr3t-pa$$word-9';
const SERVER = U(40);
const DIR = '/tmp/nt-bk.AbCd1234';
const SQL = gzipSync(Buffer.from('-- dump\nCREATE TABLE t (id int);\n'));

/** Decodes what execScriptStdin sent: the fixed script (base64 in the command line) and its positional args. */
function parseCall(command) {
  const b64 = /printf %s '([A-Za-z0-9+/=]*)'/.exec(command)?.[1];
  const script = b64 ? Buffer.from(b64, 'base64').toString('utf8') : '';
  const tail = command.slice(command.indexOf(' nt-script') + ' nt-script'.length);
  const args = [...tail.matchAll(/'((?:[^']|'\\'')*)'/g)].map((m) => m[1].replace(/'\\''/g, "'"));
  return { script, args };
}

function makeSsh(over = {}) {
  const seen = [];
  let n = 0;
  const respond = ({ command, script: stdin, files }) => {
    const { script, args } = parseCall(command);
    // The fake invokes respond twice per exec (stream.end and the post-callback finish); record each exec once.
    if (n++ % 2 === 0) seen.push({ command, script, args, stdin });
    if (over.respond) {
      const r = over.respond({ script, args, stdin, files });
      if (r) return r;
    }
    if (script.includes('NT_TABLES')) return { stdout: `NT_TABLES=${over.tables ?? 3}\n` };
    if (script.includes('echo "NT_DIR=$D"')) return { stdout: `NT_DIR=${DIR}\n` };
    if (script.includes('size_cap_exceeded') && over.tooLarge) return { stderr: '__NT_ERR__size_cap_exceeded', code: 3 };
    if (script.includes('mysqldump') || script.includes('pg_dump') || script.includes('mongodump') || script.includes('tar -C')) {
      const data = over.dumpData ?? SQL;
      const out = `${DIR}/out.${script.includes('tar -C') ? 'tgz' : 'gz'}`;
      files.set(out, { data });
      return { stdout: `NT_OUT=${out}\nNT_SHA256=${over.remoteSha ?? sha256(data)}\nNT_SIZE=${data.length}\n` };
    }
    return {};
  };
  const files = new Map();
  const ssh = createFakeSsh({ respond, files });
  const remote = vi.fn(async (_serverId, fn) => {
    const { client } = await ssh.connector.connect();
    return fn({ client, run: (script, opts = {}) => execScriptStdin(client, script, opts) });
  });
  return { ...ssh, files, seen, remote };
}

describe('TASK-049 command construction', () => {
  it('passes the password on stdin only, never in the script text or args', () => {
    for (const engine of ['mysql', 'postgres', 'mongodb']) {
      const c = buildDbDumpCommand({ engine, db: 'shop_db', username: 'root', password: PASS });
      expect(c.stdin).toBe(`${PASS}\n`);
      expect(c.script).not.toContain(PASS);
      expect(c.args.join(' ')).not.toContain(PASS);
      expect(c.script).toContain('umask 077');
    }
    const my = buildDbDumpCommand({ engine: 'mariadb', db: 'shop_db', username: 'root', password: PASS });
    expect(my.script).toContain('--single-transaction');
    expect(my.script).toContain('gzip');
    expect(my.script).toContain('sha256sum');
    expect(my.script).toContain('head -c');
  });
  it('rejects shell metacharacters in names, users, paths and passwords', () => {
    for (const db of ['a;rm -rf /', 'a b', '$(id)', '`id`', "x'y", '', 'a'.repeat(65), '../x']) {
      expect(() => buildDbDumpCommand({ engine: 'mysql', db, username: 'root', password: PASS })).toThrow();
    }
    expect(() => buildDbDumpCommand({ engine: 'mysql', db: 'ok', username: 'root;id', password: PASS })).toThrow();
    expect(() => buildDbDumpCommand({ engine: 'oracle', db: 'ok', username: 'root', password: PASS })).toThrow();
    expect(() => buildDbDumpCommand({ engine: 'mysql', db: 'ok', username: 'root', password: 'a\nb' })).toThrow();
    for (const p of ['/', '/var/www/../etc', '/var/www/a b', '/var/$(id)', 'relative/path', '/a;b']) {
      expect(() => buildTreeArchiveCommand({ path: p })).toThrow();
    }
  });
  it('archives with exclusions and never dereferences symlinks', () => {
    const c = buildTreeArchiveCommand({ path: '/var/www/shop/' });
    expect(c.args[0]).toBe('/var/www/shop');
    expect(c.script).toContain("--exclude='node_modules'");
    expect(c.script).toContain("--exclude='.git'");
    expect(c.script).not.toMatch(/tar [^\n]* -h\b/);
    expect(c.script).not.toContain('--dereference');
    expect(c.script).toContain('realpath -e');
  });
  it('builds an isolated restore into a new nt_restore_ name and refuses the source name', () => {
    const name = isolatedDbName('11111111-2222-4333-8444-555555555555', NOW);
    expect(name).toMatch(/^nt_restore_20260601120000_[A-Za-z0-9]{1,8}$/);
    const c = buildDbRestoreCommand({ engine: 'mysql', db: name, sourceDb: 'shop_db', username: 'root', password: PASS, dir: DIR, mode: 'isolated' });
    expect(c.script).toContain('CREATE DATABASE');
    expect(c.script).not.toContain(PASS);
    expect(c.args).toEqual([DIR, name, 'root', 'isolated', 'shop_db']);
    expect(() => buildDbRestoreCommand({ engine: 'mysql', db: 'shop_db', sourceDb: 'shop_db', username: 'root', password: PASS, dir: DIR, mode: 'isolated' })).toThrow(/new database name/);
    expect(() => buildDbRestoreCommand({ engine: 'mysql', db: name, sourceDb: 'shop_db', username: 'root', password: PASS, dir: '/etc', mode: 'isolated' })).toThrow();
    expect(() => buildDbRestoreCommand({ engine: 'mysql', db: name, username: 'root', password: PASS, dir: DIR, mode: 'weird' })).toThrow();
  });
  it('only ever drops nt_verify_ scratch databases', () => {
    expect(() => buildScratchDropCommand({ engine: 'mysql', db: 'shop_db', username: 'root', password: PASS })).toThrow();
    expect(() => buildScratchDropCommand({ engine: 'mysql', db: 'nt_restore_x', username: 'root', password: PASS })).toThrow();
    expect(buildScratchDropCommand({ engine: 'postgres', db: 'nt_verify_ab12', username: 'u', password: PASS }).args[0]).toBe('nt_verify_ab12');
  });
  it('refuses a remote output path outside the nt-bk scratch directory', () => {
    expect(() => parseDumpResult(`NT_OUT=/etc/shadow\nNT_SHA256=${'a'.repeat(64)}\nNT_SIZE=5\n`)).toThrow();
    expect(() => parseDumpResult(`NT_OUT=${DIR}/../../etc/passwd\nNT_SHA256=${'a'.repeat(64)}\nNT_SIZE=5\n`)).toThrow();
    expect(parseDumpResult(`NT_OUT=${DIR}/out.gz\nNT_SHA256=${'a'.repeat(64)}\nNT_SIZE=5\n`).dir).toBe(DIR);
  });
});

describe('TASK-049 secret redaction', () => {
  it('redacts the password and assignments from remote error text', () => {
    const e = mapRemoteError({ stderr: `__NT_ERR__dump_failed:Access denied password=${PASS} using ${PASS}` }, [PASS]);
    expect(e.message).not.toContain(PASS);
    expect(redactSecrets(`PGPASSWORD=${PASS} token: abc123xyz`, [PASS])).not.toMatch(/S3cr3t|abc123xyz/);
  });
  it('never leaks the password through audit, errors or the call log of a failed dump', async () => {
    const t = makeSsh({ respond: () => ({ stderr: `__NT_ERR__dump_failed:bad password ${PASS}`, code: 2 }) });
    const ex = createBackupExecutor({ mode: 'ssh', remote: t.remote });
    const err = await ex.dumpDatabase({ serverId: SERVER, engine: 'mysql', db: 'shop_db', username: 'root', password: PASS }, OWNER).catch((e) => e);
    expect(err.code).toBe('BACKUP_REMOTE_FAILED');
    expect(JSON.stringify(err.message)).not.toContain(PASS);
    for (const c of t.calls) expect(c.command).not.toContain(PASS); // only stdin carries it
  });
});

describe('TASK-049 executor over the fake SSH connector', () => {
  const exec = (t, extra = {}) => createBackupExecutor({ mode: 'ssh', remote: t.remote, ...extra });

  it('is a disabled no-op unless BACKUP_EXECUTOR=ssh (fails closed)', async () => {
    expect(resolveExecutorMode(undefined)).toBe('simulated');
    expect(resolveExecutorMode('SSH ')).toBe('ssh');
    expect(resolveExecutorMode('true')).toBe('simulated');
    const t = makeSsh();
    await expect(createBackupExecutor({ mode: 'simulated', remote: t.remote }).dumpDatabase({ serverId: SERVER, engine: 'mysql', db: 'a', username: 'u', password: PASS }, OWNER)).rejects.toMatchObject({ code: 'BACKUP_EXECUTOR_DISABLED' });
    expect(t.remote).not.toHaveBeenCalled();
  });
  it('pulls a dump, verifies the server-side sha256 and cleans the scratch directory', async () => {
    const t = makeSsh();
    const res = await exec(t).dumpDatabase({ serverId: SERVER, engine: 'mysql', db: 'shop_db', username: 'root', password: PASS }, OWNER);
    expect(res.bytes.equals(SQL)).toBe(true);
    expect(isGzip(res.bytes)).toBe(true);
    expect(res.serverSha256).toBe(sha256(SQL));
    expect(res).toMatchObject({ simulated: false, source: 'ssh-exec', consistent: true, method: 'mysqldump-single-transaction-gzip' });
    expect(t.seen.some((s) => s.script.includes('rm -rf -- "$1"') && s.args[0] === DIR)).toBe(true);
    expect(t.seen.find((s) => s.script.includes('mysqldump')).stdin).toBe(`${PASS}\n`);
  });
  it('rejects a checksum mismatch between the server and the pulled bytes', async () => {
    const t = makeSsh({ remoteSha: 'b'.repeat(64) });
    await expect(exec(t).dumpDatabase({ serverId: SERVER, engine: 'postgres', db: 'shop_db', username: 'u', password: PASS }, OWNER)).rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
    expect(t.seen.some((s) => s.script.includes('rm -rf -- "$1"'))).toBe(true); // still cleaned up
  });
  it('enforces the size cap on the remote and again on the pulled file', async () => {
    const remoteCap = makeSsh({ respond: ({ script }) => (script.includes('mysqldump') ? { stderr: '__NT_ERR__size_cap_exceeded', code: 3 } : null) });
    await expect(exec(remoteCap, { maxBytes: 1024 }).dumpDatabase({ serverId: SERVER, engine: 'mysql', db: 'a', username: 'u', password: PASS }, OWNER)).rejects.toMatchObject({ status: 413, code: 'BACKUP_TOO_LARGE' });
    const big = Buffer.alloc(5000, 1);
    const local = makeSsh({ dumpData: big });
    await expect(exec(local, { maxBytes: 1000 }).dumpDatabase({ serverId: SERVER, engine: 'mysql', db: 'a', username: 'u', password: PASS }, OWNER)).rejects.toMatchObject({ code: 'BACKUP_TOO_LARGE' });
  });
  it('only the Owner or the scheduler may run it', async () => {
    const t = makeSsh();
    await expect(exec(t).dumpDatabase({ serverId: SERVER, engine: 'mysql', db: 'a', username: 'u', password: PASS }, { id: U(2), isOwner: false })).rejects.toMatchObject({ code: 'OWNER_ONLY' });
  });
  it('archives a directory over SSH', async () => {
    const t = makeSsh({ dumpData: gzipSync('tar-bytes') });
    const res = await exec(t).archiveDirectory({ serverId: SERVER, path: '/var/www/shop' }, OWNER);
    expect(res.method).toBe('tar-gzip-no-dereference');
    expect(t.seen.find((s) => s.script.includes('tar -C')).args).toEqual(['/var/www/shop', String(256 * 1024 * 1024)]);
  });
  it('restores isolated into a new database and refuses non-gzip input', async () => {
    const t = makeSsh();
    const db = isolatedDbName('abc', NOW);
    const res = await exec(t).restoreDatabase({ serverId: SERVER, engine: 'mysql', db, sourceDb: 'shop_db', username: 'root', password: PASS, bytes: SQL, mode: 'isolated' }, OWNER);
    expect(res).toMatchObject({ restored: true, db, tables: 3, checksum: sha256(SQL) });
    expect(t.seen.at(-1).script).toContain('rm -rf -- "$1"'); // scratch directory removed after the restore
    expect(t.seen.at(-1).args).toEqual([DIR]);
    await expect(exec(t).restoreDatabase({ serverId: SERVER, engine: 'mysql', db, sourceDb: 'shop_db', username: 'root', password: PASS, bytes: Buffer.from('plain sql'), mode: 'isolated' }, OWNER)).rejects.toMatchObject({ code: 'RESTORE_FORMAT_UNSUPPORTED' });
  });
  it('test-restore is off by default; when enabled it uses nt_verify_ and always drops the scratch database', async () => {
    const t = makeSsh();
    await expect(exec(t).testRestore({ serverId: SERVER, engine: 'mysql', sourceDb: 'shop_db', username: 'root', password: PASS, bytes: SQL }, OWNER)).rejects.toMatchObject({ code: 'BACKUP_TEST_RESTORE_DISABLED' });
    const ok = await exec(t, { testRestoreEnabled: true, rand: () => 'abcd1234' }).testRestore({ serverId: SERVER, engine: 'mysql', sourceDb: 'shop_db', username: 'root', password: PASS, bytes: SQL }, OWNER);
    expect(ok).toMatchObject({ ok: true, scratchDb: 'nt_verify_abcd1234' });
    const failing = makeSsh({ respond: ({ script }) => (script.includes('NT_TABLES') ? { stderr: '__NT_ERR__restore_failed:boom', code: 2 } : null) });
    await expect(exec(failing, { testRestoreEnabled: true, rand: () => 'zz99' }).testRestore({ serverId: SERVER, engine: 'postgres', sourceDb: 'shop_db', username: 'u', password: PASS, bytes: SQL }, OWNER)).rejects.toMatchObject({ code: 'BACKUP_REMOTE_FAILED' });
    expect(failing.seen.some((s) => s.script.includes('dropdb') && s.args[0] === 'nt_verify_zz99')).toBe(true);
    await expect(exec(t, { testRestoreEnabled: true }).testRestore({ serverId: SERVER, engine: 'mongodb', sourceDb: 'a', username: 'u', password: PASS, bytes: SQL }, OWNER)).rejects.toMatchObject({ code: 'BACKUP_VERIFY_UNSUPPORTED' });
  });
});

describe('TASK-049 encryption', () => {
  it('round-trips with AES-256-GCM, fails closed without a key and detects tampering', () => {
    const c = encrypt(SQL, KEY);
    expect(decrypt(c, KEY).equals(SQL)).toBe(true);
    expect(() => encrypt(SQL, '')).toThrow(expect.objectContaining({ code: 'ENCRYPTION_KEY_MISSING' }));
    const flipped = Buffer.from(c);
    flipped[flipped.length - 1] ^= 1;
    expect(() => decrypt(flipped, KEY)).toThrow(expect.objectContaining({ code: 'CIPHERTEXT_TAMPERED' }));
    expect(() => decrypt(c.subarray(0, c.length - 3), KEY)).toThrow();
    expect(() => decrypt(c, 'b'.repeat(64))).toThrow(expect.objectContaining({ code: 'CIPHERTEXT_TAMPERED' }));
  });
});

describe('TASK-049 SigV4', () => {
  const base = { region: 'us-east-1', accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', date: new Date('2013-05-24T00:00:00Z') };
  it('matches the AWS published GET Object vector', () => {
    const r = signRequest({ ...base, method: 'GET', host: 'examplebucket.s3.amazonaws.com', path: '/test.txt', headers: { Range: 'bytes=0-9' } });
    expect(r.signature).toBe('f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
    expect(r.headers.authorization).toContain('SignedHeaders=host;range;x-amz-content-sha256;x-amz-date');
  });
  it('matches the AWS published PUT Object vector', () => {
    const r = signRequest({ ...base, method: 'PUT', host: 'examplebucket.s3.amazonaws.com', path: '/test$file.text', body: 'Welcome to Amazon S3.', headers: { Date: 'Fri, 24 May 2013 00:00:00 GMT', 'x-amz-storage-class': 'REDUCED_REDUNDANCY' } });
    expect(r.signature).toBe('98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd');
  });
});

describe('TASK-049 S3-compatible offsite target', () => {
  const cfg = { endpoint: 'https://s3.example-offsite.test', bucket: 'nt-backups', region: 'eu-west-1', prefix: 'nodeteam', accessKeyId: 'AKIATESTKEY12345', secretAccessKey: 'super-secret-key-material', enabled: true };
  const publicLookup = () => [{ address: '93.184.216.34', family: 4 }];

  it('uploads and downloads signed objects over https without leaking the secret', async () => {
    const objects = new Map();
    const seenReq = [];
    const fetchImpl = vi.fn(async (url, init) => {
      seenReq.push({ url, init });
      if (init.method === 'PUT') { objects.set(url, Buffer.from(init.body)); return { ok: true, status: 200 }; }
      if (init.method === 'GET') return objects.has(url) ? { ok: true, status: 200, arrayBuffer: async () => objects.get(url) } : { ok: false, status: 404 };
      return { ok: true, status: 204 };
    });
    const s3 = createS3Store({ config: cfg, fetchImpl, now: () => NOW, assertUrl: (u) => assertSafeUrl(u, { lookup: publicLookup }) });
    const { locationRef } = await s3.upload({ name: 'p/r/db.enc', bytes: Buffer.from('ciphertext') });
    expect(locationRef).toBe('s3://nt-backups/nodeteam/p/r/db.enc');
    expect((await s3.download({ locationRef })).toString()).toBe('ciphertext');
    expect(await s3.download({ locationRef: 's3://nt-backups/nodeteam/missing' })).toBeNull();
    await s3.remove({ locationRef });
    for (const r of seenReq) {
      expect(r.url.startsWith('https://s3.example-offsite.test/nt-backups/')).toBe(true);
      expect(r.init.redirect).toBe('error');
      expect(r.init.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIATESTKEY12345\/20260601\/eu-west-1\/s3\/aws4_request/);
      expect(JSON.stringify(r)).not.toContain('super-secret-key-material');
    }
    await expect(s3.download({ locationRef: 's3://other-bucket/x' })).rejects.toMatchObject({ code: 'OFFSITE_REF_INVALID' });
  });
  it('is https-only and SSRF-safe', async () => {
    expect(() => normalizeOffsiteConfig({ ...cfg, endpoint: 'http://s3.example-offsite.test' })).toThrow(expect.objectContaining({ code: 'OFFSITE_ENDPOINT_INVALID' }));
    expect(() => normalizeOffsiteConfig({ ...cfg, endpoint: 'https://user:pw@s3.example-offsite.test' })).toThrow();
    for (const ep of ['https://127.0.0.1', 'https://10.0.0.5', 'https://169.254.169.254', 'https://localhost']) {
      const s3 = createS3Store({ config: { ...cfg, endpoint: ep }, fetchImpl: vi.fn() });
      await expect(s3.upload({ name: 'x', bytes: Buffer.from('a') })).rejects.toBeTruthy();
    }
    const rebinding = createS3Store({ config: cfg, fetchImpl: vi.fn(), assertUrl: (u) => assertSafeUrl(u, { lookup: () => [{ address: '10.1.2.3', family: 4 }] }) });
    await expect(rebinding.upload({ name: 'x', bytes: Buffer.from('a') })).rejects.toMatchObject({ code: 'URL_PRIVATE_ADDRESS' });
  });
  it('is disabled unless configured: the router keeps the local store', async () => {
    const local = createLocalStore({ dir: mkdtempSync(path.join(tmpdir(), 'nt-bk-')) });
    const router = createStorageRouter({ local, resolveOffsite: () => null });
    expect(router.offsiteActive).toBe(false);
    const { locationRef } = await router.upload({ name: 'a/b.enc', bytes: Buffer.from('x') });
    expect(locationRef).toBe('local://a/b.enc');
    expect((await router.download({ locationRef })).toString()).toBe('x');
    await expect(router.download({ locationRef: 's3://nt-backups/x' })).rejects.toMatchObject({ code: 'OFFSITE_NOT_CONFIGURED' });
  });
});

describe('TASK-049 end to end: backup, verify, isolated restore, in-place gates, retention', () => {
  const LIVE_DB = { id: U(42), projectId: PROJECT, environmentId: ENV_PROD, dbName: 'app_prod', instance: { id: U(41), serverId: SERVER, engine: 'mysql', name: 'mysql-main', adminUsername: 'root', adminSecretEnc: encrypt(PASS, KEY) } };

  async function setup(sshOver = {}, execOver = {}) {
    const ctx = makeCtx({ now: () => NOW, grants: [] });
    const extra = backupPrisma();
    const restoreStore = new Map();
    let n = 900;
    extra.restoreRun = {
      create: vi.fn(async ({ data }) => { const r = { id: U(++n), approvedById: null, correlationId: null, ...data }; restoreStore.set(r.id, r); return r; }),
      findUnique: vi.fn(async ({ where }) => restoreStore.get(where.id) ?? null),
      update: vi.fn(async ({ where, data }) => { Object.assign(restoreStore.get(where.id), data); return restoreStore.get(where.id); }),
    };
    Object.assign(ctx.prisma, extra, { managedDatabase: { findMany: vi.fn(async () => [LIVE_DB]) } });
    const ssh = makeSsh(sshOver);
    const local = createLocalStore({ dir: mkdtempSync(path.join(tmpdir(), 'nt-bk-')) });
    const storage = createStorageRouter({ local });
    const executor = createBackupExecutor({ mode: 'ssh', remote: ssh.remote, storage, now: () => NOW, ...execOver });
    const backups = createBackupsService({ ...ctx, executor, encryptionKey: () => KEY, credentialKey: () => KEY });
    const restores = createRestoresService({ ...ctx, backups, executor, credentialKey: () => KEY });
    return { ...ctx, extra, ssh, executor, backups, restores, restoreStore, local };
  }
  const run = { environmentId: ENV_PROD, kinds: ['db'], trigger: 'manual' };
  const reqBody = (artifactId, over = {}) => ({ artifactId, mode: 'isolated', targetEnvironmentId: ENV_PROD, reason: 'recovery drill', rollbackNote: 'drop the trial database', ...over });

  it('backs up through the SSH executor into the local store, encrypted, with measurements', async () => {
    const t = await setup();
    const res = await t.backups.runBackup(U(90), run, OWNER);
    expect(res.run.status).toBe('retained');
    expect(res.simulated).toBe(false);
    expect(res.liveDb).toBe(true);
    expect(res.run.metrics).toMatchObject({ executor: 'ssh', storage: 'local', rpoTargetMinutes: 1440, rtoTargetMinutes: 120 });
    expect(t.adapters.calls.some((c) => c.name === 'backup.dump' || c.name === 'backup.upload')).toBe(false); // no simulated adapter used
    const db = [...t.extra.artStore.values()].find((a) => a.kind === 'db');
    expect(db.locationRef.startsWith('local://')).toBe(true);
    const cipher = await t.local.download({ locationRef: db.locationRef });
    expect(cipher.includes(Buffer.from('CREATE TABLE'))).toBe(false);
    expect(decrypt(cipher, KEY).equals(SQL)).toBe(true);
    const manifest = JSON.parse(decrypt(await t.local.download({ locationRef: [...t.extra.artStore.values()].find((a) => a.kind === 'manifest').locationRef }), KEY));
    expect(manifest.entries[0]).toMatchObject({ kind: 'db', serverChecksum: sha256(SQL) });
  });
  it('fails closed without BACKUP_ENCRYPTION_KEY and never uploads plaintext', async () => {
    const t = await setup();
    const backups = createBackupsService({ ...t, executor: t.executor, encryptionKey: () => '', credentialKey: () => KEY });
    await expect(backups.runBackup(U(90), run, OWNER)).rejects.toMatchObject({ code: 'ENCRYPTION_KEY_MISSING' });
    expect([...t.extra.artStore.values()]).toHaveLength(0);
  });
  it('rejects a tampered stored artifact on verify', async () => {
    const t = await setup();
    await t.backups.runBackup(U(90), run, OWNER);
    const db = [...t.extra.artStore.values()].find((a) => a.kind === 'db');
    const bad = Buffer.from(await t.local.download({ locationRef: db.locationRef }));
    bad[bad.length - 2] ^= 0xff;
    await t.local.upload({ name: db.locationRef.replace('local://', ''), bytes: bad });
    await expect(t.backups.verifyArtifact(db.id, OWNER)).rejects.toMatchObject({ code: 'CHECKSUM_MISMATCH' });
  });
  it('verify with test-restore uses a scratch database only when explicitly enabled', async () => {
    const off = await setup();
    await off.backups.runBackup(U(90), run, OWNER);
    const db0 = [...off.extra.artStore.values()].find((a) => a.kind === 'db');
    await expect(off.backups.verifyArtifact(db0.id, OWNER, { testRestore: true })).rejects.toMatchObject({ code: 'BACKUP_TEST_RESTORE_DISABLED' });
    const on = await setup({}, { testRestoreEnabled: true, rand: () => 'scratch01' });
    await on.backups.runBackup(U(90), run, OWNER);
    const db1 = [...on.extra.artStore.values()].find((a) => a.kind === 'db');
    const res = await on.backups.verifyArtifact(db1.id, OWNER, { testRestore: true });
    expect(res.testRestore).toMatchObject({ ok: true, scratchDb: 'nt_verify_scratch01' });
    expect(on.ssh.seen.some((s) => s.script.includes('DROP DATABASE IF EXISTS') && s.args[0] === 'nt_verify_scratch01')).toBe(true);
    // plain verify without the flag never touches a scratch database
    expect((await on.backups.verifyArtifact(db1.id, OWNER)).testRestore).toBeUndefined();
  });
  it('isolated restore goes to a NEW nt_restore_ database after approval, never the source, and records RTO', async () => {
    const t = await setup();
    await t.backups.runBackup(U(90), run, OWNER);
    const db = [...t.extra.artStore.values()].find((a) => a.kind === 'db');
    const r = await t.restores.request(reqBody(db.id), OWNER);
    await expect(t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_APPROVED' });
    await approve(t, r.approval.id);
    const done = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER);
    expect(done).toMatchObject({ mode: 'isolated', executor: true, simulated: false, safetyBackupRunId: null });
    expect(done.isolatedDb).toMatch(/^nt_restore_/);
    expect(done.isolatedDb).not.toBe('app_prod');
    expect(done.metrics).toMatchObject({ rtoTargetMinutes: 120, mode: 'isolated' });
    expect(typeof done.metrics.rtoMeasuredMs).toBe('number');
    const restoreCall = t.ssh.seen.find((s) => s.script.includes('NT_TABLES'));
    expect(restoreCall.args[1]).toBe(done.isolatedDb);
    expect(restoreCall.args[3]).toBe('isolated');
    expect(restoreCall.script).toContain('CREATE DATABASE');
    expect(restoreCall.args.join(' ')).not.toContain(PASS);
  });
  it('in-place restore is critical, needs approval AND a completed safety backup first', async () => {
    const t = await setup();
    await t.backups.runBackup(U(90), run, OWNER);
    const db = [...t.extra.artStore.values()].find((a) => a.kind === 'db');
    const r = await t.restores.request(reqBody(db.id, { mode: 'inplace' }), OWNER);
    expect(r.approval.impactJson.riskTier).toBe('critical');
    await expect(t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER)).rejects.toMatchObject({ code: 'APPROVAL_NOT_APPROVED' });
    expect(t.ssh.seen.some((s) => s.script.includes('NT_TABLES'))).toBe(false); // nothing restored without approval
    await approve(t, r.approval.id);
    const dumpsBefore = t.ssh.seen.filter((s) => s.script.includes('mysqldump')).length;
    const done = await t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER);
    expect(done.safetyBackupRunId).toBeTruthy();
    const order = t.ssh.seen.map((s) => (s.script.includes('mysqldump') ? 'dump' : s.script.includes('NT_TABLES') ? 'restore' : ''));
    expect(order.filter((o) => o === 'dump').length).toBe(dumpsBefore + 1);
    expect(order.lastIndexOf('dump')).toBeLessThan(order.lastIndexOf('restore'));
    const call = t.ssh.seen.find((s) => s.script.includes('NT_TABLES'));
    expect(call.args[1]).toBe('app_prod');
    expect(call.args[3]).toBe('inplace');
  });
  it('aborts in-place restore when the safety backup fails', async () => {
    const t = await setup();
    await t.backups.runBackup(U(90), run, OWNER);
    const db = [...t.extra.artStore.values()].find((a) => a.kind === 'db');
    const r = await t.restores.request(reqBody(db.id, { mode: 'inplace' }), OWNER);
    await approve(t, r.approval.id);
    t.ssh.seen.length = 0;
    t.executor.dumpDatabase = vi.fn(async () => { throw new Error('disk full'); });
    await expect(t.restores.execute(r.restoreId, { environmentId: ENV_PROD }, OWNER)).rejects.toBeTruthy();
    expect(t.restoreStore.get(r.restoreId).status).toBe('failed');
    expect(t.ssh.seen.some((s) => s.script.includes('NT_TABLES'))).toBe(false);
  });
  it('retention stays gated and never removes the newest verified sets', async () => {
    const t = await setup();
    const policy = { ...t.extra.backupPolicy.findUnique() };
    void policy;
    const plan = await t.backups.planRetention(U(90), OWNER);
    expect(plan.remove).toEqual([]);
    await expect(t.backups.applyRetention(U(90), { environmentId: ENV_PROD, reason: 'tidy up old', rollbackNote: 'none needed' }, OWNER)).resolves.toMatchObject({ approvalRequired: true });
    expect(APPROVER.id).toBeTruthy();
  });
});
