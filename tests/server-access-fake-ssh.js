import { EventEmitter } from 'node:events';
import { vi } from 'vitest';

/**
 * In-memory SSH double. It stands in for the connector returned by createSshConnector(), so no network
 * and no ssh2 server are involved. `execCommand`/`execScript`/`openSftp` from ssh.connector.js run unchanged on
 * top of the fake client.
 *
 * respond({ command, script, args }) -> { stdout?, stderr?, code? }. `script` is the stdin of `bash -s`.
 */
export function createFakeSsh({ respond = () => ({}), files = new Map(), home = '/home/tester' } = {}) {
  const calls = [];

  const sftp = {
    realpath: (_p, cb) => setImmediate(() => cb(null, home)),
    stat: (p, cb) =>
      setImmediate(() => {
        const f = files.get(p);
        if (!f) return cb(Object.assign(new Error('No such file'), { code: 2 }));
        return cb(null, { size: f.size ?? f.data.length, mode: f.mode ?? 0o100644 });
      }),
    readFile: (p, cb) =>
      setImmediate(() => {
        const f = files.get(p);
        return f ? cb(null, f.data) : cb(Object.assign(new Error('No such file'), { code: 2 }));
      }),
    writeFile: (p, data, cb) =>
      setImmediate(() => {
        files.set(p, { data: Buffer.from(data) });
        cb(null);
      }),
    unlink: (p, cb) =>
      setImmediate(() => {
        files.delete(p);
        cb(null);
      }),
  };

  function makeClient() {
    return {
      end: vi.fn(),
      sftp: (cb) => cb(null, sftp),
      exec(command, cb) {
        const stream = new EventEmitter();
        stream.stderr = new EventEmitter();
        stream.close = () => {};
        let script = '';
        const finish = () => {
          const args = [...command.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
          calls.push({ command, script, args });
          const r = respond({ command, script, args, files }) ?? {};
          setImmediate(() => {
            if (r.stdout) stream.emit('data', Buffer.from(r.stdout));
            if (r.stderr) stream.stderr.emit('data', Buffer.from(r.stderr));
            stream.emit('close', r.code ?? 0);
          });
        };
        stream.end = (d) => {
          script = String(d ?? '');
          finish();
        };
        cb(null, stream);
        if (!command.startsWith('bash -s')) finish();
      },
    };
  }

  const connector = {
    connect: vi.fn(async () => ({ client: makeClient(), hostKeySha256: 'SHA256:fake-host-key' })),
  };
  return { connector, calls, files };
}

/** Fake prisma for the service-level tests: one server with an encrypted login. */
export const CANNED = {
  jlist: JSON.stringify([
    { name: 'shop-api', pm_id: 0, pid: 111, monit: { cpu: 1, memory: 1000 }, pm2_env: { status: 'online', pm_cwd: '/var/www/shop', pm_exec_path: '/var/www/shop/server.js', restart_time: 2 } },
    { name: 'worker', pm_id: 1, pid: 222, pm2_env: { status: 'stopped', pm_cwd: '/srv/worker' } },
  ]),
};

export const pm2ListOutput = `##meta\n2026-11-16T00:00:00Z\npm2=/usr/bin/pm2\nhome=/root/.pm2\n##pm2\n${CANNED.jlist}\n`;
export const pm2ActionOutput = (body = 'done', exit = 0) => `##meta\n2026-11-16T00:00:00Z\n##out\n${body}\nEXIT:${exit}\n`;
export const siteLiveOutput = `##meta\n/var/www/shop\n2026-11-16T00:00:00Z\npm2=/usr/bin/pm2\n##pm2\n${CANNED.jlist}\n##pm2logs\nNAME:shop-api\nlistening on 3000\n##applog\n##files\n##git\n`;
export const inventoryOutput = `##meta
root
host
Linux
##roots
/var/www/shop.example.com
##projects
/var/www/shop.example.com/artisan
/var/www/api.example.com/package.json
/var/www/api.example.com/node_modules/lodash/package.json
##pm2
[]
##vhosts_nginx
FILE:/etc/nginx/sites-enabled/shop
  server_name shop.example.com;
  root /var/www/shop.example.com/public;
##vhosts_apache
##vhosts_grep
##mysql
shop_db
mysql
##postgres
##engines
mysql
`;

/** Default responder covering every remote command used by the live features. */
export function liveResponder(over = {}) {
  return ({ command, script, args, files }) => {
    if (over.respond) {
      const r = over.respond({ command, script, args, files });
      if (r) return r;
    }
    if (script.includes('##pm2logs')) return { stdout: siteLiveOutput };
    if (script.includes('##vhosts_nginx')) return { stdout: inventoryOutput };
    if (script.includes('jlist')) return { stdout: pm2ListOutput };
    if (/pm2_exec (start|stop|restart|reload|delete) "\$NAME"/.test(script)) return { stdout: pm2ActionOutput('[PM2] ok') };
    if (/pm2_exec (logs|describe)/.test(script)) return { stdout: '##meta\n2026-11-16T00:00:00Z\n##out\nlog line\n' };
    if (/mysqldump|pg_dump/.test(command)) {
      const out = /\/tmp\/nt-dump-[0-9a-f]+\.sql/.exec(command)?.[0];
      if (out) files.set(out, over.dumpFile ?? { data: Buffer.from('-- dump\nCREATE TABLE t (id int);\n') });
      return {};
    }
    if (/mysql|psql/.test(command)) {
      if (/SHOW DATABASES/i.test(command)) return { stdout: 'Database\nshop_db\nmysql\n' };
      return { stdout: 'id\tname\n1\tAda\n2\tNULL\n' };
    }
    if (command.startsWith('hostname')) return { stdout: 'test-host\nLinux 6.8\n' };
    return {};
  };
}
