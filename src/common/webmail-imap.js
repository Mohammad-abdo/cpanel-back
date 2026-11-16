import { ImapFlow } from 'imapflow';
import nodemailer from 'nodemailer';
import { AppError } from './errors/app-error.js';
import { openMailForwards } from './webmail-ssh-tunnel.js';

const MAX_LIST = 100;
const MAX_BODY = 2_000_000;

/** Direct IMAP/SMTP endpoints (public host). Prefer SSH tunnel for panel-hosted webmail. */
export function mailEndpoints(host, { port, tlsInsecure = false } = {}) {
  if (!host) throw new AppError(409, 'MAIL_HOST_UNKNOWN', 'Mail hostname is not configured for this server');
  return {
    imap: { host, port: port ?? 993, secure: true, tls: { rejectUnauthorized: !tlsInsecure } },
    smtp: { host, port: 465, secure: true, tls: { rejectUnauthorized: !tlsInsecure } },
  };
}

function mapImapError(err, fallbackCode = 'WEBMAIL_IMAP_FAILED') {
  if (err instanceof AppError) throw err;
  const msg = String(err?.responseText || err?.message || '');
  if (/auth|credential|login|password|invalid/i.test(msg) || err?.authenticationFailed) {
    throw new AppError(401, 'WEBMAIL_AUTH_FAILED', 'Invalid email or password');
  }
  throw new AppError(502, fallbackCode, `Mail server unreachable: ${msg.slice(0, 160) || 'connection failed'}`);
}

/**
 * Run fn with IMAP (+ optional SMTP) reached via SSH local forward to 127.0.0.1 on the VPS.
 * Avoids wrong public DNS (e.g. mail.* pointing elsewhere) and closed public 993/465.
 */
export async function withSshMailTunnel(sshClient, { address, password }, fn) {
  const fwd = await openMailForwards(sshClient);
  try {
    const ctx = {
      host: '127.0.0.1',
      imapPort: fwd.imapPort,
      smtpPort: fwd.smtpPort,
      address,
      password,
      tlsInsecure: true, // localhost tunnel; cert is for the public mail name
    };
    return await fn(ctx);
  } finally {
    await fwd.close();
  }
}

export async function verifyMailboxLogin(ctx) {
  const client = new ImapFlow({
    host: ctx.host,
    port: ctx.imapPort ?? 993,
    secure: true,
    auth: { user: ctx.address, pass: ctx.password },
    logger: false,
    connectionTimeout: 25_000,
    greetingTimeout: 25_000,
    tls: { rejectUnauthorized: !ctx.tlsInsecure },
  });
  try {
    await client.connect();
    await client.logout();
    return true;
  } catch (err) {
    mapImapError(err, 'WEBMAIL_IMAP_UNREACHABLE');
  } finally {
    try {
      client.close();
    } catch {
      /* ignore */
    }
  }
}

async function withImap(ctx, fn) {
  const client = new ImapFlow({
    host: ctx.host,
    port: ctx.imapPort ?? 993,
    secure: true,
    auth: { user: ctx.address, pass: ctx.password },
    logger: false,
    connectionTimeout: 25_000,
    tls: { rejectUnauthorized: !ctx.tlsInsecure },
  });
  try {
    await client.connect();
    return await fn(client);
  } catch (err) {
    mapImapError(err);
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

const ROLE_SPECIAL = {
  inbox: '\\Inbox',
  sent: '\\Sent',
  drafts: '\\Drafts',
  trash: '\\Trash',
  junk: '\\Junk',
  archive: '\\Archive',
};

const ROLE_FALLBACK_NAMES = {
  inbox: ['INBOX'],
  sent: ['Sent', 'Sent Messages', 'Sent Items', 'INBOX.Sent'],
  drafts: ['Drafts', 'INBOX.Drafts'],
  trash: ['Trash', 'Deleted Messages', 'INBOX.Trash'],
  junk: ['Junk', 'Spam', 'Junk E-mail', 'INBOX.Junk', 'INBOX.Spam'],
  archive: ['Archive', 'Archives', 'INBOX.Archive'],
};

function normalizeBoxes(boxes) {
  return boxes.map((b) => ({
    path: b.path,
    name: b.name,
    delimiter: b.delimiter,
    specialUse: b.specialUse || null,
    listed: Boolean(b.listed),
    subscribed: Boolean(b.subscribed),
  }));
}

function pickRolePath(boxes, role) {
  const special = ROLE_SPECIAL[role];
  const bySpecial = boxes.find((b) => b.specialUse === special);
  if (bySpecial) return bySpecial.path;
  const names = ROLE_FALLBACK_NAMES[role] || [];
  const lower = names.map((n) => n.toLowerCase());
  const byName = boxes.find((b) => lower.includes(String(b.path).toLowerCase()) || lower.includes(String(b.name).toLowerCase()));
  return byName?.path || null;
}

async function ensureMailbox(client, path) {
  try {
    await client.mailboxCreate(path);
  } catch {
    /* already exists or server refuses — non-fatal */
  }
}

async function statusOf(client, path) {
  if (!path) return { messages: 0, unseen: 0 };
  try {
    const st = await client.status(path, { messages: true, unseen: true });
    return {
      messages: Number(st.messages) || 0,
      unseen: Number(st.unseen) || 0,
    };
  } catch {
    return { messages: 0, unseen: 0 };
  }
}

/** List folders and ensure standard roles (Sent/Trash/Junk/Archive) exist when possible. */
export async function listFolders(ctx) {
  return withImap(ctx, async (client) => {
    let boxes = normalizeBoxes(await client.list());
    const rolesNeeded = ['sent', 'trash', 'junk', 'archive'];
    for (const role of rolesNeeded) {
      if (!pickRolePath(boxes, role)) {
        const createAs = ROLE_FALLBACK_NAMES[role][0];
        await ensureMailbox(client, createAs);
      }
    }
    boxes = normalizeBoxes(await client.list());
    const roles = {
      inbox: pickRolePath(boxes, 'inbox') || 'INBOX',
      sent: pickRolePath(boxes, 'sent'),
      drafts: pickRolePath(boxes, 'drafts'),
      trash: pickRolePath(boxes, 'trash'),
      junk: pickRolePath(boxes, 'junk'),
      archive: pickRolePath(boxes, 'archive'),
    };

    const counts = {};
    const roleKeys = ['inbox', 'sent', 'drafts', 'trash', 'junk', 'archive'];
    for (const key of roleKeys) {
      const path = roles[key];
      if (!path) continue;
      counts[path] = await statusOf(client, path);
    }

    const stats = {
      inbox: counts[roles.inbox] || { messages: 0, unseen: 0 },
      sent: counts[roles.sent] || { messages: 0, unseen: 0 },
      junk: counts[roles.junk] || { messages: 0, unseen: 0 },
      trash: counts[roles.trash] || { messages: 0, unseen: 0 },
      archive: counts[roles.archive] || { messages: 0, unseen: 0 },
      /** Convenience aliases for the SPA KPI strip */
      delivered: counts[roles.sent]?.messages || 0,
      failed: counts[roles.junk]?.messages || 0,
      deleted: counts[roles.trash]?.messages || 0,
      unread: counts[roles.inbox]?.unseen || 0,
    };

    return { folders: boxes, roles, counts, stats };
  });
}

function mapListedMessage(msg) {
  return {
    uid: msg.uid,
    seq: msg.seq,
    subject: msg.envelope?.subject || '(no subject)',
    from: decodeAddressList(msg.envelope?.from),
    to: decodeAddressList(msg.envelope?.to),
    date: msg.envelope?.date ? new Date(msg.envelope.date).toISOString() : null,
    flags: [...(msg.flags || [])],
    seen: msg.flags?.has('\\Seen') ?? false,
    size: msg.size ?? null,
  };
}

export async function listMessages(ctx, { folder = 'INBOX', limit = 50, page = 1, q = '' }) {
  const take = Math.min(Math.max(Number(limit) || 50, 1), MAX_LIST);
  const pageNum = Math.max(Number(page) || 1, 1);
  const query = String(q || '').trim().slice(0, 200);
  return withImap(ctx, async (client) => {
    const lock = await client.getMailboxLock(folder);
    try {
      if (query) {
        const uids = await client.search(
          {
            or: [{ subject: query }, { from: query }, { to: query }, { body: query }],
          },
          { uid: true },
        );
        const all = Array.isArray(uids) ? uids : [];
        const total = all.length;
        if (!total) return { folder, total: 0, page: pageNum, limit: take, q: query, items: [] };
        const sorted = [...all].sort((a, b) => b - a);
        const start = (pageNum - 1) * take;
        const slice = sorted.slice(start, start + take);
        if (!slice.length) return { folder, total, page: pageNum, limit: take, q: query, items: [] };
        const items = [];
        for await (const msg of client.fetch(slice, { envelope: true, flags: true, uid: true, size: true }, { uid: true })) {
          items.push(mapListedMessage(msg));
        }
        items.sort((a, b) => b.uid - a.uid);
        return { folder, total, page: pageNum, limit: take, q: query, items };
      }

      const total = client.mailbox.exists || 0;
      if (!total) return { folder, total: 0, page: pageNum, limit: take, q: '', items: [] };
      const end = Math.max(total - (pageNum - 1) * take, 1);
      const start = Math.max(end - take + 1, 1);
      const items = [];
      for await (const msg of client.fetch(`${start}:${end}`, { envelope: true, flags: true, uid: true, size: true })) {
        items.push(mapListedMessage(msg));
      }
      items.reverse();
      return { folder, total, page: pageNum, limit: take, q: '', items };
    } finally {
      lock.release();
    }
  });
}

async function resolveRolePath(client, role) {
  const boxes = normalizeBoxes(await client.list());
  let path = pickRolePath(boxes, role);
  if (!path && ROLE_FALLBACK_NAMES[role]) {
    path = ROLE_FALLBACK_NAMES[role][0];
    await ensureMailbox(client, path);
  }
  if (!path) throw new AppError(409, 'MAIL_FOLDER_MISSING', `Mailbox folder for ${role} is not available`);
  return path;
}

function normalizeUids(uids) {
  const list = (Array.isArray(uids) ? uids : [uids])
    .map((u) => Number(u))
    .filter((u) => Number.isFinite(u) && u > 0)
    .slice(0, 50);
  if (!list.length) throw new AppError(422, 'UIDS_REQUIRED', 'At least one message id is required');
  return [...new Set(list)];
}

/** Move messages to another folder (Archive / Spam / custom). */
export async function moveMessages(ctx, { folder = 'INBOX', uids, target }) {
  const idList = normalizeUids(uids);
  const dest = String(target || '').trim();
  if (!dest || dest.length > 255) throw new AppError(422, 'TARGET_REQUIRED', 'Target folder is required');
  if (dest === folder) return { moved: 0, folder, target: dest, uids: idList };
  return withImap(ctx, async (client) => {
    const lock = await client.getMailboxLock(folder);
    try {
      await client.messageMove(idList, dest, { uid: true });
      return { moved: idList.length, folder, target: dest, uids: idList };
    } finally {
      lock.release();
    }
  });
}

/**
 * Delete: move to Trash when not already there; permanent delete inside Trash.
 * `action` archive|junk|trash maps to standard folders when `target` is omitted.
 */
export async function actionMessages(ctx, { folder = 'INBOX', uids, action, target }) {
  const idList = normalizeUids(uids);
  const act = String(action || '').toLowerCase();
  if (!['archive', 'junk', 'trash', 'delete', 'move'].includes(act)) {
    throw new AppError(422, 'ACTION_INVALID', 'Unsupported mail action');
  }
  return withImap(ctx, async (client) => {
    let dest = target ? String(target).trim() : null;
    if (act === 'archive') dest = await resolveRolePath(client, 'archive');
    if (act === 'junk') dest = await resolveRolePath(client, 'junk');
    if (act === 'trash' || act === 'delete') dest = await resolveRolePath(client, 'trash');
    if (act === 'move' && !dest) throw new AppError(422, 'TARGET_REQUIRED', 'Target folder is required');

    const trashPath = await resolveRolePath(client, 'trash');
    const inTrash = folder === trashPath || /^trash$/i.test(folder);
    const permanent = act === 'delete' && inTrash;

    const lock = await client.getMailboxLock(folder);
    try {
      if (permanent) {
        await client.messageDelete(idList, { uid: true });
        return { action: 'delete', permanent: true, folder, uids: idList, moved: idList.length };
      }
      if (!dest) throw new AppError(409, 'MAIL_FOLDER_MISSING', 'Destination folder is not available');
      if (dest === folder) return { action: act, permanent: false, folder, target: dest, uids: idList, moved: 0 };
      await client.messageMove(idList, dest, { uid: true });
      return { action: act === 'delete' ? 'trash' : act, permanent: false, folder, target: dest, uids: idList, moved: idList.length };
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
  const subj = String(subject || '').slice(0, 998) || '(no subject)';
  const transport = nodemailer.createTransport({
    host: ctx.host,
    port: ctx.smtpPort ?? 465,
    secure: true,
    auth: { user: ctx.address, pass: ctx.password },
    tls: { rejectUnauthorized: !ctx.tlsInsecure },
  });
  let info;
  try {
    info = await transport.sendMail({
      from: ctx.address,
      to: recipients.join(', '),
      ...(cc ? { cc } : {}),
      subject: subj,
      text: body,
    });
  } catch (err) {
    const msg = String(err?.message || '');
    if (/auth|credential|login|password/i.test(msg)) throw new AppError(401, 'WEBMAIL_AUTH_FAILED', 'SMTP rejected credentials');
    throw new AppError(502, 'WEBMAIL_SMTP_FAILED', msg.slice(0, 200) || 'Send failed');
  } finally {
    transport.close();
  }

  // Best-effort copy into Sent so Inbox/Sent stay separated in the UI.
  let savedToSent = false;
  try {
    await withImap(ctx, async (client) => {
      const sentPath = await resolveRolePath(client, 'sent');
      const raw =
        info?.message ||
        [
          `From: ${ctx.address}`,
          `To: ${recipients.join(', ')}`,
          cc ? `Cc: ${cc}` : null,
          `Subject: ${subj}`,
          `Date: ${new Date().toUTCString()}`,
          'MIME-Version: 1.0',
          'Content-Type: text/plain; charset=utf-8',
          '',
          body,
        ]
          .filter((line) => line != null)
          .join('\r\n');
      await client.append(sentPath, raw, ['\\Seen']);
      savedToSent = true;
    });
  } catch {
    /* non-fatal — SMTP already succeeded */
  }

  return { messageId: info.messageId || null, accepted: info.accepted || recipients, savedToSent };
}
