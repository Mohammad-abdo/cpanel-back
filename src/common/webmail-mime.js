import { simpleParser } from 'mailparser';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import { AppError } from './errors/app-error.js';

export const MAX_ATTACH_TOTAL = 20 * 1024 * 1024; // 20 MB across all attachments of one message
export const MAX_ATTACH_COUNT = 20;
export const MAX_SOURCE = 30 * 1024 * 1024; // raw RFC 822 read cap
export const MAX_RECIPIENTS = 50;

const ALLOWED_FLAGS = new Set(['\\Seen', '\\Flagged']);
export function assertFlags(list) {
  const out = [...new Set(list || [])];
  for (const f of out) if (!ALLOWED_FLAGS.has(f)) throw new AppError(422, 'FLAG_NOT_ALLOWED', 'Unsupported flag');
  return out;
}

/** True when the string holds control chars (CR/LF/NUL/DEL, Unicode line separators). lineOnly: any C0 is not required. */
function hasControl(value, strict) {
  for (const ch of String(value ?? '')) {
    const c = ch.codePointAt(0);
    if (c < 32 || c === 127 || c === 0x2028 || c === 0x2029) {
      if (strict ? (c === 10 || c === 13 || c === 0 || c === 0x2028 || c === 0x2029) : true) return true;
    }
  }
  return false;
}

/** Reject CR/LF/NUL (header injection) in any single-line header value. */
export function assertNoCrlf(value, field) {
  if (hasControl(value, true)) {
    throw new AppError(422, 'HEADER_INJECTION', `Invalid characters in ${field}`);
  }
  return String(value ?? '');
}

const ADDR_RE = /^[^\s<>"(),;:\\@]+@[^\s<>"(),;:\\@]+\.[^\s<>"(),;:\\@]+$/;

/** Parse a comma/semicolon separated recipient string into validated bare addresses (display names are dropped). */
export function parseRecipients(raw, field) {
  const text = assertNoCrlf(raw || '', field);
  return text
    .split(/[,;]/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const m = s.match(/<([^<>]+)>\s*$/);
      const addr = (m ? m[1] : s).trim();
      if (!ADDR_RE.test(addr) || addr.length > 254) throw new AppError(422, 'INVALID_RECIPIENT', `Invalid address in ${field}`);
      return addr;
    });
}

/** Strip path parts, control chars and quotes; keep it a safe, non-empty basename. */
export function sanitizeFilename(name, fallback = 'attachment') {
  let n = Array.from(String(name ?? '')).filter((ch) => !hasControl(ch, false) && ch !== '"').join('')
    .replace(/[\\/]+/g, '_')
    .replace(/[<>:|?*]/g, '_')
    .replace(/^\.+/, '')
    .trim();
  if (n.length > 150) {
    const dot = n.lastIndexOf('.');
    const ext = dot > 0 && n.length - dot <= 12 ? n.slice(dot) : '';
    n = n.slice(0, 150 - ext.length) + ext;
  }
  return n || fallback;
}

/** Content-Disposition: attachment with ASCII fallback + RFC 5987 filename*. */
export function attachmentDisposition(filename) {
  const safe = sanitizeFilename(filename);
  const ascii = safe.replace(/[^\x20-\x7e]/g, '_').replace(/[%;]/g, '_');
  const star = encodeURIComponent(safe).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename="${ascii}"; filename*=UTF-8''${star}`;
}

/** Active-content types are never served with their own type. */
export function downloadContentType(ct) {
  return /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/i.test(ct || '') && !/html|xml|javascript|svg/i.test(ct) ? ct : 'application/octet-stream';
}

function addrList(v) {
  return (v?.value || []).map((a) => ({ name: a.name || null, address: a.address || '' })).filter((a) => a.address);
}

/** Decode a raw RFC 822 source with mailparser (multipart, base64, quoted-printable, charsets). */
export async function parseSource(source) {
  const p = await simpleParser(source, { skipImageLinks: true, skipTextToHtml: true, skipTextLinks: true });
  const attachments = (p.attachments || []).map((a, index) => ({
    index,
    filename: sanitizeFilename(a.filename, `attachment-${index + 1}`),
    contentType: a.contentType || 'application/octet-stream',
    size: a.size ?? a.content?.length ?? 0,
    inline: a.contentDisposition === 'inline' || Boolean(a.related),
    cid: a.cid || null,
    content: a.content,
  }));
  return {
    subject: p.subject || '',
    from: addrList(p.from),
    to: addrList(p.to),
    cc: addrList(p.cc),
    date: p.date ? p.date.toISOString() : null,
    messageId: p.messageId || null,
    inReplyTo: p.inReplyTo || null,
    references: Array.isArray(p.references) ? p.references : p.references ? [p.references] : [],
    // Raw HTML (not sanitized server-side; the client sanitizes with DOMPurify) + text alternative.
    bodyText: p.text || '',
    bodyHtml: typeof p.html === 'string' ? p.html : '',
    attachments,
  };
}

/**
 * Group list items into threads by References / In-Reply-To / Message-ID (union-find).
 * Adds `threadId` and `threadCount` to each item.
 */
export function groupThreads(items) {
  const parent = new Map();
  const find = (x) => {
    if (!parent.has(x)) parent.set(x, x);
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r);
    parent.set(x, r);
    return r;
  };
  const union = (a, b) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };
  for (const it of items) {
    const uidKey = `u:${it.uid}`;
    if (it.messageId) union(uidKey, `m:${it.messageId}`);
    for (const ref of [...(it.references || []), ...(it.inReplyTo ? [it.inReplyTo] : [])]) union(uidKey, `m:${ref}`);
  }
  const counts = new Map();
  for (const it of items) {
    const root = find(`u:${it.uid}`);
    counts.set(root, (counts.get(root) || 0) + 1);
  }
  const ids = new Map();
  return items.map((it) => {
    const root = find(`u:${it.uid}`);
    if (!ids.has(root)) ids.set(root, `t${ids.size + 1}`);
    return { ...it, threadId: ids.get(root), threadCount: counts.get(root) };
  });
}

/**
 * Validate and build a MIME message with MailComposer.
 * attachments: [{filename, contentType?, contentBase64}]. Bcc is kept in the header only for drafts.
 */
export async function buildMessage({ from, to, cc, bcc, subject, text, inReplyTo, references, attachments = [], draft = false }) {
  const toList = parseRecipients(to, 'to');
  const ccList = parseRecipients(cc, 'cc');
  const bccList = parseRecipients(bcc, 'bcc');
  if (!draft && !toList.length) throw new AppError(422, 'TO_REQUIRED', 'At least one recipient is required');
  if (toList.length + ccList.length + bccList.length > MAX_RECIPIENTS) {
    throw new AppError(422, 'TOO_MANY_RECIPIENTS', 'Too many recipients');
  }
  const subj = assertNoCrlf(subject || '', 'subject').slice(0, 998);
  const irt = inReplyTo ? assertNoCrlf(inReplyTo, 'inReplyTo') : undefined;
  if (irt && !/^<[^<>\s]+>$/.test(irt)) throw new AppError(422, 'INVALID_HEADER', 'Invalid In-Reply-To');
  const refs = (references || []).map((r) => assertNoCrlf(r, 'references'));
  if (refs.some((r) => !/^<[^<>\s]+>$/.test(r))) throw new AppError(422, 'INVALID_HEADER', 'Invalid References');
  const body = String(text || '');
  if (body.length > 2_000_000) throw new AppError(413, 'BODY_TOO_LARGE', 'Message body is too large');
  if (attachments.length > MAX_ATTACH_COUNT) throw new AppError(422, 'TOO_MANY_ATTACHMENTS', 'Too many attachments');
  let total = 0;
  const files = attachments.map((a, i) => {
    const content = Buffer.from(a.contentBase64 || '', 'base64');
    total += content.length;
    if (total > MAX_ATTACH_TOTAL) throw new AppError(413, 'ATTACHMENTS_TOO_LARGE', 'Attachments exceed 20 MB in total');
    return {
      filename: sanitizeFilename(a.filename, `attachment-${i + 1}`),
      contentType: downloadContentType(a.contentType),
      content,
      contentDisposition: 'attachment',
    };
  });
  const mail = new MailComposer({
    from,
    to: toList,
    cc: ccList,
    bcc: bccList,
    subject: subj || (draft ? '' : '(no subject)'),
    text: body,
    ...(irt ? { inReplyTo: irt } : {}),
    ...(refs.length ? { references: refs } : {}),
    attachments: files,
  });
  const node = mail.compile();
  node.keepBcc = draft;
  const raw = await node.build();
  return { raw, to: toList, cc: ccList, bcc: bccList, subject: subj, attachments: files, text: body, inReplyTo: irt, references: refs };
}
