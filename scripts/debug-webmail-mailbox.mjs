import { prisma } from '../src/config/prisma.js';
import { verifyMailboxLogin } from '../src/common/webmail-imap.js';

const domain = await prisma.domain.findFirst({
  where: { name: 'rasad.nodeteam.site' },
  include: {
    mailConfig: true,
    mailboxes: true,
    server: { include: { mailService: true, credential: true } },
  },
});

const host = domain?.server?.mailService?.mailHostname || domain?.server?.credential?.host;
console.log(
  JSON.stringify(
    {
      domain: domain?.name,
      enabled: domain?.mailConfig?.enabled,
      boxes: domain?.mailboxes?.map((m) => ({ local: m.localPart, status: m.status, provisioned: m.provisioned })),
      mailHost: domain?.server?.mailService?.mailHostname,
      sshHost: domain?.server?.credential?.host,
      provisioned: domain?.server?.mailService?.provisioned,
      resolvedHost: host,
    },
    null,
    2,
  ),
);

if (host && process.env.WM_TEST_PASSWORD) {
  try {
    await verifyMailboxLogin({
      host,
      address: 'info@rasad.nodeteam.site',
      password: process.env.WM_TEST_PASSWORD,
      tlsInsecure: true,
    });
    console.log('IMAP_OK');
  } catch (e) {
    console.log('IMAP_FAIL', e.code || e.status, e.message);
  }
}

await prisma.$disconnect();
