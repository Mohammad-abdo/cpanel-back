import { ImapFlow } from 'imapflow';
import nodemailer from 'nodemailer';
import { AppError } from './errors/app-error.js';

const MAX_LIST = 100;
const MAX_BODY = 2_000_000;

/** Build IMAP/SMTP endpoints for a provisioned mail host. */
export function mailEndpoints(host, { tlsInsecure = false } = {}) {
  if (!host) throw new AppError(409, 'MAIL_HOST_UNKNOWN', 'Mail hostname is not configured for this server');
  return {
    imap: { host, port: 993, secure: true, tls: { rejectUnauthorized: !tlsInsecure } },
    smtp: { host, port: 465, secure: true, tls: { rejectUnauthorized: !tlsInsecure } },
  };
}

export async function verifyMailboxLogin({ host, address, password, tlsInsecure }) {
  const ep = mailEndpoints(host, { tlsInsecure });
  const client = new ImapFlow({
    ...ep.imap,
    auth: { user: address, pass: password },
    logger: false,
    connectionTimeout: 20_000,
    greetingTimeout: 20_000,
  });
  try {
    await client.connect();
    await client.logout();
    return true;
  } catch (err) {
    const msg = String(err?.responseText || err?.message || '');
    if (/auth|credential|login|password|invalid/i.test(msg) || err?.authenticationFailed) {
      throw new AppError(401, 'WEBMAIL_AUTH_FAILED', 'Invalid email or password');
    }
    throw new AppError(502, 'WEBMAIL_IMAP_UNREACHABLE', `Mail server unreachable: ${msg.slice(0, 160) || 'connection failed'}`);
  } finally {
    try {
      client.close();
    } catch {
      /* ignore */
    }
  }
}

async function withImap({ host, address, password, tlsInsecure }, fn) {
  const ep = mailEndpoints(host, { tlsInsecure });
  const client = new ImapFlow({
    ...ep.imap,
    auth: { user: address, pass: password },
    logger: false,
    connectionTimeout: 25_000,
  });
  try {
    await client.connect();
    return await fn(client);
  } catch (err) {
    if (err instanceof AppError) throw err;
    const msg = String(err?.responseText || err?.message || '');
    if (/auth|credential|login|password|invalid/i.test(msg) || err?.authenticationFailed) {
      throw new AppError(401, 'WEBMAIL_AUTH_FAILED', 'Session expired or credentials rejected');
    }
    throw new AppError(502, 'WEBMAIL_IMAP_FAILED', msg.slice(0, 200) || 'IMAP operation failed');
  } finally {
    try {
      await client.logout();
    } catch {
      try {
        client.close();
      } catch {
        /* ignore */
      }
    }
  }
}

function decodeAddressList(list) {
  if (!list) return [];
  return (Array.isArray(list) ? list : [list]).map((a) => ({
    name: a.name || null,
    address: a.address || String(a),
  }));
}

export async function listFolders(ctx) {
  return withImap(ctx, async (client) => {
    const boxes = await client.list();
    return boxes.map((b) => ({
      path: b.path,
      name: b.name,
      delimiter: b.delimiter,
      specialUse: b.specialUse || null,
      listed: Boolean(b.listed),
      subscribed: Boolean(b.subscribed),
    }));
  });
}

export async function listMessages(ctx, { folder = 'INBOX', limit = 50, page = 1 }) {
  const take = Math.min(Math.max(Number(limit) || 50, 1), MAX_LIST);
  const pageNum = Math.max(Number(page) || 1, 1);
  return withImap(ctx, async (client) => {
    const lock = await client.getMailboxLock(folder);
    try {
      const total = client.mailbox.exists || 0;
      if (!total) return { folder, total: 0, page: pageNum, limit: take, items: [] };
      const end = Math.max(total - (pageNum - 1) * take, 1);
      const start = Math.max(end - take + 1, 1);
      const items = [];
      for await (const msg of client.fetch(`${start}:${end}`, { envelope: true, flags: true, uid: true, size: true })) {
        items.push({
          uid: msg.uid,
          seq: msg.seq,
          subject: msg.envelope?.subject || '(no subject)',
          from: decodeAddressList(msg.envelope?.from),
          to: decodeAddressList(msg.envelope?.to),
          date: msg.envelope?.date ? new Date(msg.envelope.date).toISOString() : null,
          flags: [...(msg.flags || [])],
          seen: msg.flags?.has('\\Seen') ?? false,
          size: msg.size ?? null,
        });
      }
      items.reverse();
      return { folder, total, page: pageNum, limit: take, items };
    } finally {
      lock.release();
    }
  });
}

export async function getMessage(ctx, { folder = 'INBOX', uid }) {
  const id = Number(uid);
  if (!Number.isFinite(id) || id < 1) throw new AppError(422, 'INVALID_UID', 'Invalid message id');
  return withImap(ctx, async (client) => {
    const lock = await client.getMailboxLock(folder);
    try {
      let found = null;
      for await (const msg of client.fetch(String(id), { uid: true, envelope: true, flags: true, source: { maxLength: MAX_BODY } }, { uid: true })) {
        const source = msg.source ? msg.source.toString('utf8').slice(0, MAX_BODY) : '';
        const textMatch = source.match(/\r?\n\r?\n([\s\S]*)$/);
        found = {
          uid: msg.uid,
          subject: msg.envelope?.subject || '(no subject)',
          from: decodeAddressList(msg.envelope?.from),
          to: decodeAddressList(msg.envelope?.to),
          cc: decodeAddressList(msg.envelope?.cc),
          date: msg.envelope?.date ? new Date(msg.envelope.date).toISOString() : null,
          flags: [...(msg.flags || [])],
          bodyText: (textMatch?.[1] || source).slice(0, MAX_BODY),
          truncated: Boolean(msg.source && msg.source.length >= MAX_BODY),
        };
      }
      if (!found) throw new AppError(404, 'MESSAGE_NOT_FOUND', 'Message not found');
      try {
        await client.messageFlagsAdd({ uid: id }, ['\\Seen'], { uid: true });
      } catch {
        /* non-fatal */
      }
      return found;
    } finally {
      lock.release();
    }
  });
}

export async function sendMessage(ctx, { to, subject, text, cc }) {
  const recipients = String(to || '')
    .split(/[,;]/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!recipients.length) throw new AppError(422, 'TO_REQUIRED', 'At least one recipient is required');
  if (recipients.length > 50) throw new AppError(422, 'TOO_MANY_RECIPIENTS', 'Too many recipients');
  const body = String(text || '');
  if (body.length > MAX_BODY) throw new AppError(413, 'BODY_TOO_LARGE', 'Message body is too large');
  const ep = mailEndpoints(ctx.host, { tlsInsecure: ctx.tlsInsecure });
  const transport = nodemailer.createTransport({
    host: ep.smtp.host,
    port: ep.smtp.port,
    secure: true,
    auth: { user: ctx.address, pass: ctx.password },
    tls: ep.smtp.tls,
  });
  try {
    const info = await transport.sendMail({
      from: ctx.address,
      to: recipients.join(', '),
      ...(cc ? { cc } : {}),
      subject: String(subject || '').slice(0, 998) || '(no subject)',
      text: body,
    });
    return { messageId: info.messageId || null, accepted: info.accepted || recipients };
  } catch (err) {
    const msg = String(err?.message || '');
    if (/auth|credential|login|password/i.test(msg)) throw new AppError(401, 'WEBMAIL_AUTH_FAILED', 'SMTP rejected credentials');
    throw new AppError(502, 'WEBMAIL_SMTP_FAILED', msg.slice(0, 200) || 'Send failed');
  } finally {
    transport.close();
  }
}
