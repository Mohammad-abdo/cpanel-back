/**
 * Local SSH test server for trying "Add server by SSH", the file manager and the terminal without a
 * real VPS. Development only. Files live in cpanel-back/.data/dev-ssh (shown as "/" over SFTP).
 *
 *   npm run dev:ssh      then add a server with host 127.0.0.1, port 2222, user tester, password secret-pass
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ssh2 from 'ssh2';
import { startSshTestServer } from './lib/ssh-test-server.mjs';

const base = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '.data');
const root = path.join(base, 'dev-ssh');
const keyFile = path.join(base, 'dev-ssh-hostkey');
fs.mkdirSync(root, { recursive: true });
// Keep the host key stable across restarts, otherwise the panel (correctly) refuses the changed key.
if (!fs.existsSync(keyFile)) fs.writeFileSync(keyFile, ssh2.utils.generateKeyPairSync('ed25519').private);
fs.mkdirSync(path.join(root, 'var', 'www', 'demo-shop'), { recursive: true });
const index = path.join(root, 'var', 'www', 'demo-shop', 'index.html');
if (!fs.existsSync(index)) fs.writeFileSync(index, '<!doctype html>\n<h1>demo-shop</h1>\n');

const port = Number(process.env.NT_DEV_SSH_PORT || 2222);
const s = await startSshTestServer({ root, port, hostKey: fs.readFileSync(keyFile, 'utf8'), hostname: 'dev-ssh-host' });
console.info(`Dev SSH server on ${s.host}:${s.port}  user: ${s.username}  password: ${s.password}  files: ${root}`);
