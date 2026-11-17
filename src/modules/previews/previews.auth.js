/**
 * TASK-045: preview basic-auth credentials. Only an Apache/nginx compatible htpasswd hash (apr1-MD5, salted, 1000 rounds) is stored;
 * the generated password is returned once and never persisted. In-house implementation: no new dependency was authorized.
 * bcrypt would be stronger but needs a dependency decision; Caddy basic auth also needs bcrypt, so previews with basic auth are
 * rejected under CADDY_MODE=on.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const md5 = (buf) => createHash('md5').update(buf).digest();

function to64(value, count) {
  let out = '';
  let v = value;
  for (let i = 0; i < count; i += 1) {
    out += ITOA64[v & 0x3f];
    v >>= 6;
  }
  return out;
}

/** Apache htpasswd "$apr1$" digest. */
export function apr1(password, salt) {
  const pw = Buffer.from(String(password), 'utf8');
  const s = Buffer.from(String(salt).slice(0, 8), 'utf8');
  const alt = md5(Buffer.concat([pw, s, pw]));
  const parts = [pw, Buffer.from('$apr1$'), s];
  for (let n = pw.length; n > 0; n -= 16) parts.push(alt.subarray(0, Math.min(16, n)));
  for (let i = pw.length; i; i >>= 1) parts.push(i & 1 ? Buffer.from([0]) : pw.subarray(0, 1));
  let f = md5(Buffer.concat(parts));
  for (let i = 0; i < 1000; i += 1) {
    f = md5(Buffer.concat([i & 1 ? pw : f, i % 3 ? s : Buffer.alloc(0), i % 7 ? pw : Buffer.alloc(0), i & 1 ? f : pw]));
  }
  const group = (a, b, c) => to64((f[a] << 16) | (f[b] << 8) | f[c], 4);
  return `$apr1$${s.toString('utf8')}$${group(0, 6, 12)}${group(1, 7, 13)}${group(2, 8, 14)}${group(3, 9, 15)}${group(4, 10, 5)}${to64(f[11], 2)}`;
}

const salt8 = () => Array.from(randomBytes(8), (b) => ITOA64[b & 0x3f]).join('');

export function hashPassword(password, salt = salt8()) {
  return apr1(password, salt);
}

export function verifyPassword(password, hash) {
  const m = /^\$apr1\$([./0-9A-Za-z]{1,8})\$/.exec(String(hash ?? ''));
  if (!m) return false;
  const a = Buffer.from(apr1(password, m[1]));
  const b = Buffer.from(String(hash));
  return a.length === b.length && timingSafeEqual(a, b);
}

/** 128 bits of randomness in an unambiguous alphabet. */
export function generatePassword() {
  return randomBytes(16).toString('base64url');
}

export const PREVIEW_AUTH_USER = 'preview';

/** { user, password (show once), hash (store) } */
export function createPreviewCredentials() {
  const password = generatePassword();
  return { user: PREVIEW_AUTH_USER, password, hash: hashPassword(password) };
}

export const htpasswdLine = (user, hash) => `${user}:${hash}\n`;
