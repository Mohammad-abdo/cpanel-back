import { prisma } from '../src/config/prisma.js';
import { createSshConnector } from '../src/modules/server-access/ssh.connector.js';
import { decrypt } from '../src/modules/platform/platform.crypto.js';
import { INVENTORY_SCRIPT, parseInventory } from '../src/modules/server-access/server-inventory.scan.js';

const sid = process.argv[2] || process.env.NT_SERVER_ID;
if (!sid) throw new Error('usage: node scripts/debug-inventory.mjs <serverId> (or set NT_SERVER_ID)');
const cred = await prisma.serverCredential.findUnique({ where: { serverId: sid } });
if (!cred) throw new Error('no credential');
const password = decrypt(Buffer.from(cred.secretEnc), process.env.CREDENTIAL_ENCRYPTION_KEY).toString('utf8');
const connector = createSshConnector({ timeoutMs: 25000 });
const { client } = await connector.connect({
  host: cred.host,
  port: cred.port,
  username: cred.username,
  password,
  expectedHostKey: cred.hostKeySha256,
});

function run(cmd) {
  return new Promise((resolve, reject) => {
    client.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      let out = '';
      let errOut = '';
      stream.on('data', (d) => {
        out += d.toString();
      });
      stream.stderr.on('data', (d) => {
        errOut += d.toString();
      });
      stream.on('close', (code) => resolve({ code, out, errOut }));
    });
  });
}

const simple = await run('echo META; whoami; hostname; ls -1d /var/www /home/*/public_html 2>/dev/null | head');
console.log('simple', simple);

const scripted = await new Promise((resolve, reject) => {
  client.exec('bash -s', (err, stream) => {
    if (err) return reject(err);
    let out = '';
    let errOut = '';
    stream.on('data', (d) => {
      out += d.toString();
    });
    stream.stderr.on('data', (d) => {
      errOut += d.toString();
    });
    stream.on('close', (code) => resolve({ code, out, errOut }));
    stream.end(INVENTORY_SCRIPT.replace(/\r\n/g, '\n'));
  });
});
console.log('script code', scripted.code, 'outLen', scripted.out.length, 'err', scripted.errOut.slice(0, 500));
console.log('script head', scripted.out.slice(0, 800));
if (scripted.out) {
  const inv = parseInventory(scripted.out);
  console.log('parsed', {
    projects: inv.projects.length,
    domains: inv.domains.length,
    databases: inv.databases,
    meta: inv.meta,
  });
}

client.end();
await prisma.$disconnect();
