import { beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

// ---- Fake IMAP / SMTP (no real mail server is ever contacted) ----
const world = vi.hoisted(() => ({ boxes: {}, sent: [], nextUid: 100 }));

vi.mock('imapflow', () => {
  class FakeImap {
    constructor(opts) {
      this.user = opts.auth.user;
      this.box = null;
    }
    get mb() {
      return (world.boxes[this.user] ||= { INBOX: [], Drafts: [], Sent: [], Trash: [], Junk: [], Archive: [] });
    }
    async connect() {}
    async logout() {}
    close() {}
    async list() {
      return Object.keys(this.mb).map((p) => ({ path: p, name: p, delimiter: '/', specialUse: p === 'INBOX' ? null : `\\${p}`, listed: true, subscribed: true }));
    }
    async mailboxCreate(p) {
      this.mb[p] ||= [];
    }
    async status(p) {
      const l = this.mb[p] || [];
      return { messages: l.length, unseen: l.filter((m) => !m.flags.has('\\Seen')).length };
    }
    async getMailboxLock(p) {
      if (!this.mb[p]) throw new Error('no such mailbox');
      this.box = p;
      this.mailbox = { exists: this.mb[p].length };
      return { release() {} };
    }
    pick(range, opts) {
      const list = this.mb[this.box];
      if (opts?.uid) {
        const ids = Array.isArray(range) ? range : String(range).split(',').map(Number);
        return list.filter((m) => ids.includes(m.uid));
      }
      const [a, b] = String(range).split(':').map(Number);
      return list.slice(a - 1, b);
    }
    async *fetch(range, query, opts) {
      for (const m of this.pick(range, opts)) {
        const out = { uid: m.uid, seq: 1, flags: m.flags, size: m.source.length };
        if (query.envelope) out.envelope = m.envelope;
        if (query.headers) out.headers = Buffer.from(m.source.toString().match(/^References:.*$/im)?.[0] || '');
        if (query.source) out.source = m.source;
        yield out;
      }
    }
    async messageFlagsAdd(range, flags, opts) {
      const r = range?.uid ? [range.uid] : range;
      this.pick(r, opts).forEach((m) => flags.forEach((f) => m.flags.add(f)));
    }
    async messageFlagsRemove(range, flags, opts) {
      this.pick(range, opts).forEach((m) => flags.forEach((f) => m.flags.delete(f)));
    }
    async messageDelete(range, opts) {
      const ids = this.pick(range, opts).map((m) => m.uid);
      this.mb[this.box] = this.mb[this.box].filter((m) => !ids.includes(m.uid));
    }
    async append(path, raw, flags) {
      const uid = world.nextUid++;
      this.mb[path].push({ uid, flags: new Set(flags), source: Buffer.from(raw), envelope: {} });
      return { uid };
    }
  }
  return { ImapFlow: FakeImap };
});

vi.mock('nodemailer', () => ({
  default: {
    createTransport: () => ({
      sendMail: async (msg) => {
        world.sent.push(msg);
        return { messageId: '<sent@test>', accepted: msg.envelope.to };
      },
      close() {},
    }),
  },
}));

vi.mock('../src/modules/webmail-auth/webmail-auth.wiring.js', async () => {
  const { AppError } = await import('../src/common/errors/app-error.js');
  const sessions = {
    'tok-alice': { sessionId: 's1', mailboxId: 'mb-alice', serverId: 'srv', address: 'alice@example.test', password: 'x', host: 'h' },
    'tok-bob': { sessionId: 's2', mailboxId: 'mb-bob', serverId: 'srv', address: 'bob@example.test', password: 'x', host: 'h' },
  };
  return {
    webmailAuthService: {
      cookieName: 'nt_wm',
      async resolveSession(token) {
        if (!sessions[token]) throw new AppError(401, 'WEBMAIL_SESSION_EXPIRED', 'Webmail session expired');
        return sessions[token];
      },
      async withMail(session, fn) {
        return fn({ host: '127.0.0.1', address: session.address, password: session.password });
      },
      me: () => ({}),
    },
  };
});

import { createWebmailApp } from '../src/webmail-app.js';
import { sanitizeFilename, attachmentDisposition, groupThreads, parseRecipients } from '../src/common/webmail-mime.js';

const app = createWebmailApp();
const alice = (r) => r.set('Cookie', 'nt_wm=tok-alice');
const bob = (r) => r.set('Cookie', 'nt_wm=tok-bob');

const MULTIPART = [
  'From: Carol <carol@x.test>',
  'To: alice@example.test',
  'Subject: =?UTF-8?B?2YXYsdit2KjYpw==?=',
  'Message-ID: <m1@x.test>',
  'Date: Mon, 16 Nov 2026 10:00:00 +0000',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="BB"',
  '',
  '--BB',
  'Content-Type: multipart/alternative; boundary="AA"',
  '',
  '--AA',
  'Content-Type: text/plain; charset=utf-8',
  'Content-Transfer-Encoding: quoted-printable',
  '',
  'caf=C3=A9 plain',
  '--AA',
  'Content-Type: text/html; charset=utf-8',
  'Content-Transfer-Encoding: base64',
  '',
  Buffer.from('<p>café <b>html</b></p><script>alert(1)</script>').toString('base64'),
  '--AA--',
  '--BB',
  'Content-Type: application/pdf; name="r.pdf"',
  'Content-Disposition: attachment; filename="../../r.pdf"',
  'Content-Transfer-Encoding: base64',
  '',
  Buffer.from('%PDF-fake').toString('base64'),
  '--BB--',
  '',
].join('\r\n');

function put(user, folder, uid, source, flags = []) {
  (world.boxes[user] ||= { INBOX: [], Drafts: [], Sent: [], Trash: [], Junk: [], Archive: [] });
  world.boxes[user][folder].push({
    uid,
    flags: new Set(flags),
    source: Buffer.from(source),
    envelope: { subject: 'S', messageId: (source.match(/^Message-ID: (.*)$/im) || [])[1], inReplyTo: (source.match(/^In-Reply-To: (.*)$/im) || [])[1] },
  });
}

beforeEach(() => {
  world.boxes = {};
  world.sent = [];
  put('alice@example.test', 'INBOX', 1, MULTIPART);
  put('bob@example.test', 'INBOX', 1, 'From: z@x.test\r\nSubject: bob secret\r\n\r\nbob only');
});

describe('webmail mail: session guard', () => {
  it.each([
    ['get', '/wm/v1/mail/messages/1/attachments/0'],
    ['post', '/wm/v1/mail/messages/flags'],
    ['post', '/wm/v1/mail/drafts'],
    ['post', '/wm/v1/mail/send'],
  ])('%s %s needs a mailbox session', async (m, p) => {
    expect((await request(app)[m](p).send({})).status).toBe(401);
  });

  it('rejects an Owner-style bearer token', async () => {
    const res = await request(app).post('/wm/v1/mail/send').set('Authorization', 'Bearer owner-token-123').send({ to: 'a@b.test' });
    expect(res.status).toBe(401);
  });
});

describe('webmail mail: decoded message, attachments, flags', () => {
  it('decodes MIME: text, html, subject, attachment metadata (no bytes)', async () => {
    const res = await alice(request(app).get('/wm/v1/mail/messages/1?folder=INBOX'));
    expect(res.status).toBe(200);
    const d = res.body.data;
    expect(d.subject).toBe('مرحبا');
    expect(d.bodyText).toContain('café plain');
    expect(d.bodyHtml).toContain('<b>html</b>');
    expect(d.attachments).toHaveLength(1);
    expect(d.attachments[0]).toMatchObject({ index: 0, filename: '_.._r.pdf', contentType: 'application/pdf' });
    expect(d.attachments[0]).not.toHaveProperty('content');
    expect(d.flags).toContain('\\Seen');
  });

  it('downloads an attachment with Content-Disposition: attachment and nosniff', async () => {
    const res = await alice(request(app).get('/wm/v1/mail/messages/1/attachments/0?folder=INBOX'));
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toMatch(/^attachment; filename="/);
    expect(res.headers['content-disposition']).not.toMatch(/\.\.\/|\//);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.body.toString()).toBe('%PDF-fake');
    expect((await alice(request(app).get('/wm/v1/mail/messages/1/attachments/5?folder=INBOX'))).status).toBe(404);
  });

  it('marks unread and flags via /messages/flags; rejects other flags', async () => {
    const ok = await alice(request(app).post('/wm/v1/mail/messages/flags')).send({ uids: [1], add: ['\\Flagged'], remove: ['\\Seen'] });
    expect(ok.status).toBe(200);
    const flags = [...world.boxes['alice@example.test'].INBOX[0].flags];
    expect(flags).toContain('\\Flagged');
    expect(flags).not.toContain('\\Seen');
    const bad = await alice(request(app).post('/wm/v1/mail/messages/flags')).send({ uids: [1], add: ['\\Deleted'] });
    expect(bad.status).toBe(400);
  });

  it('list items carry threadId and threadCount from References/In-Reply-To', async () => {
    put('alice@example.test', 'INBOX', 2, 'Message-ID: <m2@x.test>\r\nIn-Reply-To: <m1@x.test>\r\nReferences: <m1@x.test>\r\n\r\nre');
    put('alice@example.test', 'INBOX', 3, 'Message-ID: <m3@x.test>\r\n\r\nother');
    const res = await alice(request(app).get('/wm/v1/mail/messages?folder=INBOX'));
    const by = Object.fromEntries(res.body.data.items.map((i) => [i.uid, i]));
    expect(by[1].threadId).toBe(by[2].threadId);
    expect(by[3].threadId).not.toBe(by[1].threadId);
    expect(by[1].threadCount).toBe(2);
  });

  it('rejects out-of-range pagination', async () => {
    expect((await alice(request(app).get('/wm/v1/mail/messages?limit=101'))).status).toBe(400);
  });
});

describe('webmail mail: cross-mailbox isolation', () => {
  it("bob cannot read, download or flag alice's message; each session sees only its own box", async () => {
    // Bob's uid 1 is bob's own message, never alice's.
    const read = await bob(request(app).get('/wm/v1/mail/messages/1?folder=INBOX'));
    expect(read.body.data.bodyText).toContain('bob only');
    expect(JSON.stringify(read.body)).not.toContain('caf');
    expect((await bob(request(app).get('/wm/v1/mail/messages/1/attachments/0?folder=INBOX'))).status).toBe(404);
    await bob(request(app).post('/wm/v1/mail/messages/flags')).send({ uids: [1], add: ['\\Flagged'] });
    expect(world.boxes['alice@example.test'].INBOX[0].flags.has('\\Flagged')).toBe(false);
    // Credentials/mailbox cannot be chosen by input: extra fields are rejected.
    const forged = await bob(request(app).get('/wm/v1/mail/messages/1?folder=INBOX&address=alice@example.test'));
    expect(forged.status).toBe(400);
    const forgedSend = await bob(request(app).post('/wm/v1/mail/send')).send({ to: 'a@b.test', from: 'alice@example.test' });
    expect(forgedSend.status).toBe(400);
  });
});

describe('webmail mail: send, Bcc, attachments, injection', () => {
  const base = { to: 'c@d.test', subject: 'hello', text: 'body' };

  it('sends with Bcc in the envelope only and an attachment', async () => {
    const res = await alice(request(app).post('/wm/v1/mail/send')).send({
      ...base,
      cc: 'cc@d.test',
      bcc: 'hidden@d.test',
      inReplyTo: '<m1@x.test>',
      references: ['<m1@x.test>'],
      attachments: [{ filename: '../evil/a.txt', contentBase64: Buffer.from('hi').toString('base64') }],
    });
    expect(res.status).toBe(200);
    const msg = world.sent[0];
    expect(msg.envelope.to).toEqual(['c@d.test', 'cc@d.test', 'hidden@d.test']);
    const raw = msg.raw.toString();
    expect(raw).not.toMatch(/^Bcc:/im);
    expect(raw).not.toContain('hidden@d.test');
    expect(raw).toMatch(/^In-Reply-To: <m1@x.test>/im);
    expect(raw).toContain('filename=_evil_a.txt');
    expect(world.boxes['alice@example.test'].Sent).toHaveLength(1);
  });

  it.each([
    ['subject', { subject: 'hi\r\nBcc: evil@x.test' }],
    ['to', { to: 'a@b.test\r\nBcc: evil@x.test' }],
    ['cc', { cc: 'a@b.test\nX: y' }],
    ['bcc', { bcc: 'a@b.test\r\nX: y' }],
    ['inReplyTo', { inReplyTo: '<a@b>\r\nX: y' }],
    ['to angle', { to: 'x@y.test, <bad address@z>' }],
  ])('blocks header injection via %s', async (_n, over) => {
    const res = await alice(request(app).post('/wm/v1/mail/send')).send({ ...base, ...over });
    expect([400, 422]).toContain(res.status);
    expect(world.sent).toHaveLength(0);
  });

  it('rejects attachments over 20 MB total', async () => {
    const big = Buffer.alloc(11 * 1024 * 1024, 1).toString('base64');
    const res = await alice(request(app).post('/wm/v1/mail/send')).send({
      ...base,
      attachments: [
        { filename: 'a.bin', contentBase64: big },
        { filename: 'b.bin', contentBase64: big },
      ],
    });
    expect(res.status).toBe(413);
    expect(world.sent).toHaveLength(0);
  });

  it('rate limits send per mailbox, not across mailboxes', async () => {
    let last;
    for (let i = 0; i < 61; i += 1) last = await bob(request(app).post('/wm/v1/mail/send')).send({ ...base, to: 'bad' });
    expect(last.status).toBe(429);
    expect((await alice(request(app).post('/wm/v1/mail/send')).send(base)).status).toBe(200);
  });
});

describe('webmail mail: server-side drafts', () => {
  it('APPENDs to Drafts with \\Draft, keeps Bcc in the draft copy, replaces an older draft', async () => {
    const r1 = await alice(request(app).post('/wm/v1/mail/drafts')).send({ to: '', bcc: 'b@d.test', subject: 'wip', text: 'x' });
    expect(r1.status).toBe(200);
    const drafts = world.boxes['alice@example.test'].Drafts;
    expect(drafts).toHaveLength(1);
    expect(drafts[0].flags.has('\\Draft')).toBe(true);
    expect(drafts[0].source.toString()).toMatch(/^Bcc: b@d.test/im);
    const r2 = await alice(request(app).post('/wm/v1/mail/drafts')).send({ subject: 'wip2', replaceUid: r1.body.data.uid });
    expect(r2.status).toBe(200);
    expect(world.boxes['alice@example.test'].Drafts).toHaveLength(1);
    expect(world.sent).toHaveLength(0);
  });

  it('blocks injection in drafts', async () => {
    const res = await alice(request(app).post('/wm/v1/mail/drafts')).send({ subject: 'a\r\nBcc: x@y.test' });
    expect([400, 422]).toContain(res.status);
  });
});

describe('webmail-mime helpers', () => {
  it('sanitizes filenames and builds a safe Content-Disposition', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('.._.._etc_passwd'.replace(/^\.+/, ''));
    expect(sanitizeFilename('a"\r\nb.txt')).toBe('ab.txt');
    expect(sanitizeFilename('')).toBe('attachment');
    expect(attachmentDisposition('x"\r\n.html')).not.toMatch(/[\r\n]/);
  });
  it('parseRecipients rejects CRLF and bad addresses', () => {
    expect(parseRecipients('A <a@b.test>, c@d.test', 'to')).toEqual(['a@b.test', 'c@d.test']);
    expect(() => parseRecipients('a@b.test\r\nX: y', 'to')).toThrow();
    expect(() => parseRecipients('nope', 'to')).toThrow();
  });
  it('groupThreads links by references and message-id', () => {
    const t = groupThreads([
      { uid: 1, messageId: '<a>' },
      { uid: 2, messageId: '<b>', references: ['<a>'] },
      { uid: 3, messageId: '<c>', inReplyTo: '<b>' },
      { uid: 4, messageId: '<d>' },
    ]);
    expect(new Set(t.slice(0, 3).map((i) => i.threadId)).size).toBe(1);
    expect(t[3].threadCount).toBe(1);
  });
});
