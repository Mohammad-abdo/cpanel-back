/**
 * Small SSH server for tests and local development (never production). Speaks the real SSH protocol
 * (ssh2): password login, `exec`, an interactive shell with a few commands, and SFTP backed by a local
 * folder that appears as `/` to the client. Home directory: /home/<username>.
 */
import fs from 'node:fs';
import path from 'node:path';
import ssh2 from 'ssh2';

const { Server, utils } = ssh2;
const { STATUS_CODE, flagsToString } = utils.sftp;

export function startSshTestServer({ root, port = 0, host = '127.0.0.1', username = 'tester', password = 'secret-pass', hostname = 'test-host', hostKey = null } = {}) {
  const key = hostKey ?? utils.generateKeyPairSync('ed25519').private;
  const home = `/home/${username}`;
  fs.mkdirSync(path.join(root, 'home', username), { recursive: true });
  const real = (p) => {
    const v = path.posix.normalize(p.startsWith('/') ? p : path.posix.join(home, p));
    const r = path.join(root, ...v.split('/').filter(Boolean));
    if (!r.startsWith(path.resolve(root))) throw Object.assign(new Error('outside root'), { code: 'EACCES' });
    return r;
  };
  const virt = (p) => path.posix.normalize(p.startsWith('/') ? p : path.posix.join(home, p));
  const attrsOf = (st) => ({ mode: st.mode, uid: 0, gid: 0, size: st.size, atime: Math.floor(st.atimeMs / 1000), mtime: Math.floor(st.mtimeMs / 1000) });

  const server = new Server({ hostKeys: [key] }, (client) => {
    client.on('authentication', (ctx) => {
      if (ctx.method === 'password' && ctx.username === username && ctx.password === password) return ctx.accept();
      return ctx.reject(['password']);
    });
    client.on('error', () => {});
    client.on('ready', () => {
      client.on('session', (acceptSession) => {
        const session = acceptSession();
        session.on('pty', (accept) => accept?.());
        session.on('window-change', (accept) => accept?.());
        session.on('env', (accept) => accept?.());

        session.on('exec', (accept, _reject, info) => {
          const stream = accept();
          const out = info.command.includes('hostname') ? `${hostname}\nLinux 6.8.0-test\n` : 'ok\n';
          stream.write(out);
          stream.exit(0);
          stream.end();
        });

        session.on('shell', (accept) => {
          const stream = accept();
          const prompt = () => stream.write(`${username}@${hostname}:~$ `);
          let line = '';
          let awaitingSudo = null;
          stream.write(`Welcome to ${hostname} (test SSH server)\r\n`);
          prompt();
          stream.on('data', (data) => {
            for (const ch of data.toString('utf8')) {
              if (ch === '\r' || ch === '\n') {
                stream.write('\r\n');
                const cmd = line.trim();
                line = '';
                if (awaitingSudo !== null) {
                  stream.write(`${awaitingSudo}\r\n`);
                  awaitingSudo = null;
                  prompt();
                  continue;
                }
                if (cmd === 'exit') {
                  stream.write('logout\r\n');
                  stream.exit(0);
                  stream.end();
                  return;
                }
                if (cmd.startsWith('sudo ')) {
                  awaitingSudo = `ran: ${cmd.slice(5)}`;
                  stream.write(`[sudo] password for ${username}: `);
                  continue;
                }
                const reply = { pwd: home, whoami: username, hostname }[cmd] ?? (cmd.startsWith('echo ') ? cmd.slice(5) : cmd ? `${cmd}: command simulated` : '');
                if (reply) stream.write(`${reply}\r\n`);
                prompt();
              } else if (ch === '\u007f') {
                if (line) {
                  line = line.slice(0, -1);
                  if (awaitingSudo === null) stream.write('\b \b');
                }
              } else {
                line += ch;
                if (awaitingSudo === null) stream.write(ch); // password input is not echoed
              }
            }
          });
        });

        session.on('sftp', (accept) => {
          const sftp = accept();
          const handles = new Map();
          let next = 0;
          const newHandle = (value) => {
            const h = Buffer.alloc(4);
            h.writeUInt32BE(++next);
            handles.set(next, value);
            return h;
          };
          const get = (h) => handles.get(h.readUInt32BE(0));
          const fail = (reqid, err) => sftp.status(reqid, err?.code === 'ENOENT' ? STATUS_CODE.NO_SUCH_FILE : err?.code === 'EACCES' || err?.code === 'EPERM' ? STATUS_CODE.PERMISSION_DENIED : STATUS_CODE.FAILURE);
          const guard = (reqid, fn) => {
            try {
              fn();
            } catch (err) {
              fail(reqid, err);
            }
          };

          sftp.on('REALPATH', (reqid, p) => guard(reqid, () => sftp.name(reqid, [{ filename: virt(p === '.' ? home : p), longname: virt(p), attrs: {} }])));
          for (const ev of ['STAT', 'LSTAT']) sftp.on(ev, (reqid, p) => guard(reqid, () => sftp.attrs(reqid, attrsOf(fs.statSync(real(p))))));
          sftp.on('OPENDIR', (reqid, p) =>
            guard(reqid, () => {
              const r = real(p);
              if (!fs.statSync(r).isDirectory()) throw Object.assign(new Error('not dir'), { code: 'ENOTDIR' });
              sftp.handle(reqid, newHandle({ dir: r, done: false }));
            }),
          );
          sftp.on('READDIR', (reqid, h) =>
            guard(reqid, () => {
              const d = get(h);
              if (!d || d.done) return sftp.status(reqid, STATUS_CODE.EOF);
              d.done = true;
              const names = fs.readdirSync(d.dir).map((n) => ({ filename: n, longname: n, attrs: attrsOf(fs.statSync(path.join(d.dir, n))) }));
              return names.length ? sftp.name(reqid, names) : sftp.status(reqid, STATUS_CODE.EOF);
            }),
          );
          sftp.on('OPEN', (reqid, p, flags) => guard(reqid, () => sftp.handle(reqid, newHandle({ fd: fs.openSync(real(p), flagsToString(flags)) }))));
          sftp.on('READ', (reqid, h, offset, length) =>
            guard(reqid, () => {
              const buf = Buffer.alloc(length);
              const n = fs.readSync(get(h).fd, buf, 0, length, offset);
              return n ? sftp.data(reqid, buf.subarray(0, n)) : sftp.status(reqid, STATUS_CODE.EOF);
            }),
          );
          sftp.on('WRITE', (reqid, h, offset, data) => guard(reqid, () => (fs.writeSync(get(h).fd, data, 0, data.length, offset), sftp.status(reqid, STATUS_CODE.OK))));
          sftp.on('FSTAT', (reqid, h) => guard(reqid, () => sftp.attrs(reqid, attrsOf(fs.fstatSync(get(h).fd)))));
          sftp.on('CLOSE', (reqid, h) =>
            guard(reqid, () => {
              const v = get(h);
              if (v?.fd !== undefined) fs.closeSync(v.fd);
              handles.delete(h.readUInt32BE(0));
              sftp.status(reqid, STATUS_CODE.OK);
            }),
          );
          sftp.on('MKDIR', (reqid, p) => guard(reqid, () => (fs.mkdirSync(real(p)), sftp.status(reqid, STATUS_CODE.OK))));
          sftp.on('RMDIR', (reqid, p) => guard(reqid, () => (fs.rmdirSync(real(p)), sftp.status(reqid, STATUS_CODE.OK))));
          sftp.on('REMOVE', (reqid, p) => guard(reqid, () => (fs.unlinkSync(real(p)), sftp.status(reqid, STATUS_CODE.OK))));
          sftp.on('RENAME', (reqid, a, b) => guard(reqid, () => (fs.renameSync(real(a), real(b)), sftp.status(reqid, STATUS_CODE.OK))));
          for (const ev of ['SETSTAT', 'FSETSTAT']) sftp.on(ev, (reqid) => sftp.status(reqid, STATUS_CODE.OK));
        });
      });
    });
  });

  return new Promise((resolve) => {
    server.listen(port, host, () => resolve({ server, port: server.address().port, host, username, password, home, close: () => new Promise((r) => server.close(r)) }));
  });
}
