/**
 * Control-plane recovery drill (TASK-030, local MySQL only): dump the panel database, restore it into a
 * temporary database, compare row counts per table, measure backup and restore time, drop the copy.
 *   npm run drill:recovery
 * Needs mysqldump/mysql (Laragon is detected automatically, or set MYSQL_BIN to the bin folder).
 * The dump is kept in .data/drills/ (gitignored) so it can also be used as a manual backup.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const url = new URL(process.env.DATABASE_URL ?? '');
if (!['127.0.0.1', 'localhost'].includes(url.hostname)) {
  console.error(`Refusing to run against a non-local database: ${url.hostname}`);
  process.exit(1);
}
const db = url.pathname.slice(1);
const drillDb = `${db}_restore_drill`;

function findBin() {
  if (process.env.MYSQL_BIN) return process.env.MYSQL_BIN;
  const laragon = 'C:/laragon/bin/mysql';
  if (fs.existsSync(laragon)) {
    const v = fs.readdirSync(laragon).filter((d) => d.startsWith('mysql')).sort().pop();
    if (v) return path.join(laragon, v, 'bin');
  }
  return '';
}
const bin = findBin();
const exe = (name) => (bin ? path.join(bin, process.platform === 'win32' ? `${name}.exe` : name) : name);
const auth = ['-h', url.hostname, '-P', url.port || '3306', '-u', decodeURIComponent(url.username)];
const env = { ...process.env, MYSQL_PWD: decodeURIComponent(url.password) }; // keeps the password off the command line

function mysql(args, input) {
  const r = spawnSync(exe('mysql'), [...auth, ...args], { env, input, encoding: 'utf8', maxBuffer: 1024 * 1024 * 512 });
  if (r.status !== 0) throw new Error(`mysql failed: ${r.stderr || r.error}`);
  return r.stdout;
}
function counts(database) {
  const tables = mysql(['-N', '-e', `SELECT table_name FROM information_schema.tables WHERE table_schema='${database}' AND table_type='BASE TABLE' ORDER BY table_name`]).trim().split(/\r?\n/).filter(Boolean);
  const sql = tables.map((t) => `SELECT '${t}', COUNT(*) FROM \`${database}\`.\`${t}\``).join(' UNION ALL ');
  const out = tables.length ? mysql(['-N', '-e', sql]) : '';
  return Object.fromEntries(out.trim().split(/\r?\n/).filter(Boolean).map((l) => l.split('\t')).map(([t, n]) => [t, Number(n)]));
}

const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const dir = path.join(root, '.data', 'drills');
fs.mkdirSync(dir, { recursive: true });
const dumpFile = path.join(dir, `${db}-${stamp}.sql`);

console.log(`Recovery drill for ${db} (copy: ${drillDb})`);
let t0 = Date.now();
const dump = spawnSync(exe('mysqldump'), [...auth, '--single-transaction', '--routines', '--triggers', '--set-gtid-purged=OFF', '--result-file', dumpFile, db], { env, encoding: 'utf8' });
if (dump.status !== 0) {
  console.error(`mysqldump failed: ${dump.stderr || dump.error}`);
  process.exit(1);
}
const backupMs = Date.now() - t0;
const size = fs.statSync(dumpFile).size;

t0 = Date.now();
mysql(['-e', `DROP DATABASE IF EXISTS \`${drillDb}\`; CREATE DATABASE \`${drillDb}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`]);
mysql([drillDb], fs.readFileSync(dumpFile, 'utf8'));
const restoreMs = Date.now() - t0;

const a = counts(db);
const b = counts(drillDb);
const tables = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
const diff = tables.filter((t) => a[t] !== b[t]);
mysql(['-e', `DROP DATABASE \`${drillDb}\``]);

console.log(`backup  ${backupMs} ms, ${(size / 1024).toFixed(0)} KB -> ${path.relative(root, dumpFile)}`);
console.log(`restore ${restoreMs} ms into ${drillDb} (dropped afterwards)`);
console.log(`tables  ${tables.length}, rows ${Object.values(a).reduce((x, y) => x + y, 0)}, mismatches ${diff.length}`);
for (const t of diff) console.log(`  MISMATCH ${t}: live ${a[t]} vs restored ${b[t]}`);
console.log(diff.length ? 'RESULT: FAIL' : 'RESULT: PASS (restored copy matches the live database)');
process.exitCode = diff.length ? 1 : 0;
