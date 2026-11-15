import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import WebSocket from 'ws';
import { startSshTestServer } from '../scripts/lib/ssh-test-server.mjs';
import { createServerAccessService, normalizeRemotePath } from '../src/modules/server-access/server-access.service.js';
import { createSshConnector } from '../src/modules/server-access/ssh.connector.js';
import { attachTerminal, createTranscript, TERMINAL_PATH } from '../src/modules/server-access/server-access.terminal.js';
import { addServerBodySchema } from '../src/modules/server-access/server-access.validator.js';

const KEY = 'a'.repeat(64);
const OWNER = { id: randomUUID(), isOwner: true };
const DEV = { id: randomUUID(), isOwner: false };

function fakePrisma() {
  const servers = new Map();
  const creds = new Map();
  return {
    servers,
    creds,
    server: {
      findUnique: vi.fn(async ({ where }) => [...servers.values()].find((s) => (where.id ? s.id === where.id : s.alias === where.alias)) ?? null),
      create: vi.fn(async ({ data }) => {
        const s = { id: randomUUID(), ...data };
        servers.set(s.id, s);
        return s;
      }),
    },
    serverCredential: {
      findUnique: vi.fn(async ({ where }) => creds.get(where.serverId) ?? null),
      create: vi.fn(async ({ data }) => {
        const c = { id: randomUUID(), updatedAt: new Date(), ...data };
        creds.set(data.serverId, c);
        return c;
      }),
      update: vi.fn(async ({ where, data }) => {
        const c = [...creds.values()].find((x) => x.id === where.id);
        Object.assign(c, data);
        return c;
      }),
      upsert: vi.fn(async ({ where, create, update }) => {
        const c = creds.get(where.serverId);
        if (c) return Object.assign(c, update);
        const n = { id: randomUUID(), ...create };
        creds.set(where.serverId, n);
        return n;
      }),
      delete: vi.fn(async ({ where }) => creds.delete(where.serverId)),
    },
  };
}

let ssh;
let root;
beforeAll(async () => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'nt-ssh-'));
  ssh = await startSshTestServer({ root });
});
afterAll(async () => {
  await ssh.close();
  fs.rmSync(root, { recursive: true, force: true });
});

function setup({ key = KEY } = {}) {
  const prisma = fakePrisma();
  const auditService = { record: vi.fn(async () => ({})) };
  const svc = createServerAccessService({ prisma, connector: createSshConnector({ timeoutMs: 3000 }), auditService, credentialKey: () => key });
  return { prisma, auditService, svc };
}
const login = (over = {}) => ({ alias: 'web-1', host: '127.0.0.1', port: ssh.port, username: ssh.username, password: ssh.password, ...over });
async function added() {
  const t = setup();
  const res = await t.svc.addServer(login(), OWNER);
  return { ...t, serverId: res.server.id, res };
}

describe('add server by SSH', () => {
  it('tests the login, stores the password encrypted and pins the host key', async () => {
    const t = await added();
    expect(t.res.server.hostname).toBe('test-host');
    expect(t.res.ssh).toMatchObject({ host: '127.0.0.1', username: 'tester', hostKeySha256: expect.stringMatching(/^SHA256:/) });
    expect(JSON.stringify(t.res)).not.toContain(ssh.password);
    const stored = t.prisma.creds.get(t.serverId).secretEnc;
    expect(stored.toString('latin1')).not.toContain(ssh.password);
    const auditText = JSON.stringify(t.auditService.record.mock.calls);
    expect(auditText).not.toContain(ssh.password);
    expect(auditText).toContain('server.ssh.add');
  });
  it('rejects a wrong password and creates nothing', async () => {
    const t = setup();
    await expect(t.svc.addServer(login({ password: 'wrong' }), OWNER)).rejects.toMatchObject({ code: 'SSH_AUTH_FAILED' });
    expect(t.prisma.servers.size).toBe(0);
  });
  it('rejects an unreachable host', async () => {
    const t = setup();
    await expect(t.svc.addServer(login({ port: 1 }), OWNER)).rejects.toMatchObject({ code: 'SSH_UNREACHABLE' });
  });
  it('fails closed without an encryption key, before connecting', async () => {
    const t = setup({ key: '' });
    await expect(t.svc.addServer(login(), OWNER)).rejects.toMatchObject({ code: 'ENCRYPTION_KEY_MISSING' });
    expect(t.prisma.servers.size).toBe(0);
  });
  it('only the Owner can use SSH access', async () => {
    const t = await added();
    await expect(t.svc.addServer(login({ alias: 'web-2' }), DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    await expect(t.svc.list(t.serverId, '/', DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
    await expect(t.svc.createTicket(t.serverId, DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
  });
  it('refuses to connect when the host key changed', async () => {
    const t = await added();
    t.prisma.creds.get(t.serverId).hostKeySha256 = 'SHA256:someoneelse';
    await expect(t.svc.test(t.serverId, OWNER)).rejects.toMatchObject({ code: 'SSH_HOST_KEY_MISMATCH' });
  });
  it('validator requires a lowercase alias and a host', () => {
    expect(addServerBodySchema.safeParse(login({ alias: 'Bad Name' })).success).toBe(false);
    expect(addServerBodySchema.safeParse(login()).success).toBe(true);
  });
});

describe('file manager over SFTP', () => {
  it('lists, writes, reads, renames, uploads, downloads and deletes', async () => {
    const t = await added();
    const home = await t.svc.list(t.serverId, '', OWNER);
    expect(home.path).toBe('/home/tester');
    await t.svc.mkdir(t.serverId, 'site', OWNER);
    await t.svc.write(t.serverId, { path: 'site/index.html', content: '<h1>hi</h1>' }, OWNER);
    const listing = await t.svc.list(t.serverId, '/home/tester/site', OWNER);
    expect(listing.entries).toEqual([expect.objectContaining({ name: 'index.html', type: 'file', size: 11 })]);
    expect((await t.svc.read(t.serverId, 'site/index.html', OWNER)).content).toBe('<h1>hi</h1>');
    await t.svc.rename(t.serverId, { from: 'site/index.html', to: 'site/home.html' }, OWNER);
    await t.svc.upload(t.serverId, { path: 'site/logo.bin', bytes: Buffer.from([0, 1, 2, 3]) }, OWNER);
    expect((await t.svc.read(t.serverId, 'site/logo.bin', OWNER)).binary).toBe(true);
    const dl = await t.svc.download(t.serverId, 'site/home.html', OWNER);
    expect(dl.bytes.toString()).toBe('<h1>hi</h1>');
    await expect(t.svc.remove(t.serverId, { path: 'site' }, OWNER)).rejects.toMatchObject({ code: 'FOLDER_NOT_EMPTY' });
    await t.svc.remove(t.serverId, { path: 'site', recursive: true }, OWNER);
    await expect(t.svc.list(t.serverId, 'site', OWNER)).rejects.toMatchObject({ code: 'PATH_NOT_FOUND' });
    const actions = t.auditService.record.mock.calls.map((c) => c[0].action);
    expect(actions).toEqual(expect.arrayContaining(['server.file.write', 'server.file.rename', 'server.file.upload', 'server.file.download', 'server.file.delete']));
  });
  it('protects the root and home folders and limits edit size', async () => {
    const t = await added();
    await expect(t.svc.remove(t.serverId, { path: '/', recursive: true }, OWNER)).rejects.toMatchObject({ code: 'PATH_PROTECTED' });
    await expect(t.svc.remove(t.serverId, { path: '/home/tester', recursive: true }, OWNER)).rejects.toMatchObject({ code: 'PATH_PROTECTED' });
    await expect(t.svc.write(t.serverId, { path: 'big.txt', content: 'x'.repeat(1024 * 1024 + 1) }, OWNER)).rejects.toMatchObject({ code: 'FILE_TOO_LARGE' });
  });
  it('normalizes paths', () => {
    expect(normalizeRemotePath('a/../b', '/home/u')).toBe('/home/u/b');
    expect(normalizeRemotePath('', '/home/u')).toBe('/home/u');
    expect(() => normalizeRemotePath('a\0b', '/')).toThrow();
  });
});

describe('system information and services over SSH', () => {
  it('collects and parses system information', async () => {
    const t = await added();
    const info = await t.svc.info(t.serverId, OWNER);
    expect(info).toMatchObject({ os: 'Ubuntu 24.04.1 LTS', cpus: 4, uptimeSec: 864123, load: { m1: 0.42 } });
    expect(info.memory.total).toBe(8335548416);
    expect(info.disks.map((d) => d.mount)).toEqual(['/', '/var/lib/mysql']);
    expect(info.services.find((s) => s.name === 'nginx')).toMatchObject({ active: 'active', sub: 'running' });
    expect(info.ports.map((p) => p.port)).toEqual([80, 443, 3306, 22]);
    expect(info.processes[0]).toMatchObject({ command: 'mysqld', cpu: 12.5 });
  });
  it('restarts a service, reports failures, and audits changes', async () => {
    const t = await added();
    expect(await t.svc.service(t.serverId, { name: 'nginx', action: 'restart' }, OWNER)).toMatchObject({ ok: true, exitCode: 0 });
    expect(await t.svc.service(t.serverId, { name: 'missing-svc', action: 'restart' }, OWNER)).toMatchObject({ ok: false, exitCode: 5 });
    const events = t.auditService.record.mock.calls.map((c) => c[0]).filter((e) => e.action === 'server.service.restart');
    expect(events.map((e) => e.result)).toEqual(['success', 'failure']);
  });
  it('rejects injection in service names and non-owners', async () => {
    const t = await added();
    for (const name of ['nginx; rm -rf /', 'a b', '$(id)', '`id`', '']) {
      await expect(t.svc.service(t.serverId, { name, action: 'restart' }, OWNER)).rejects.toMatchObject({ code: 'SERVICE_NAME_INVALID' });
    }
    await expect(t.svc.service(t.serverId, { name: 'nginx', action: 'reboot' }, OWNER)).rejects.toMatchObject({ code: 'SERVICE_ACTION_INVALID' });
    await expect(t.svc.info(t.serverId, DEV)).rejects.toMatchObject({ code: 'OWNER_ONLY' });
  });
});

describe('terminal', () => {
  it('records commands and redacts a sudo password', () => {
    const tr = createTranscript();
    tr.input('ls -la\r');
    tr.output('[sudo] password for tester: ');
    tr.input('hunter2\r');
    tr.input('whoami\r');
    expect(tr.lines()).toEqual(['ls -la', '[REDACTED]', 'whoami']);
  });

  it('opens a live shell with a single-use ticket and audits the session', async () => {
    const t = await added();
    const httpServer = http.createServer();
    attachTerminal(httpServer, t.svc, { log: () => {} });
    await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
    const base = `ws://127.0.0.1:${httpServer.address().port}${TERMINAL_PATH}`;
    try {
      const { ticket } = await t.svc.createTicket(t.serverId, OWNER);
      const ws = new WebSocket(`${base}?ticket=${ticket}`);
      let out = '';
      ws.on('message', (d) => (out += d.toString()));
      await new Promise((r, j) => (ws.on('open', r), ws.on('error', j)));
      const waitFor = (re) =>
        new Promise((r, j) => {
          const start = Date.now();
          const tick = () => (re.test(out) ? r() : Date.now() - start > 4000 ? j(new Error(`timeout waiting for ${re}: ${out}`)) : setTimeout(tick, 20));
          tick();
        });
      await waitFor(/\$ $/);
      ws.send(JSON.stringify({ t: 'in', d: 'echo hello-terminal\r' }));
      await waitFor(/hello-terminal\r\n.*\$ $/s);
      ws.send(JSON.stringify({ t: 'in', d: 'sudo apt update\r' }));
      await waitFor(/password for tester: $/);
      ws.send(JSON.stringify({ t: 'in', d: 'topsecret\r' }));
      await waitFor(/ran: apt update/);
      ws.close();
      await new Promise((r) => setTimeout(r, 150));
      const closeEv = t.auditService.record.mock.calls.map((c) => c[0]).find((e) => e.action === 'server.terminal.close');
      expect(closeEv.metadata.transcript).toEqual(['echo hello-terminal', 'sudo apt update', '[REDACTED]']);
      expect(JSON.stringify(t.auditService.record.mock.calls)).not.toContain('topsecret');

      // The same ticket cannot be used twice.
      const reuse = new WebSocket(`${base}?ticket=${ticket}`);
      const err = await new Promise((r) => reuse.on('unexpected-response', (_req, res) => r(res.statusCode)).on('error', () => r('error')));
      expect(err).toBe(401);
    } finally {
      await new Promise((r) => httpServer.close(r));
    }
  });
});
