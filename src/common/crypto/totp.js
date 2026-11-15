import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(bytes = 20) {
  const buf = randomBytes(bytes);
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    out += BASE32[parseInt(bits.slice(i, i + 5), 2)];
  }
  return out;
}

export function decodeBase32(secret) {
  const cleaned = secret.replace(/=+$/g, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const ch of cleaned) {
    const val = BASE32.indexOf(ch);
    if (val < 0) throw new Error('Invalid base32 secret');
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

export function generateTotp(secret, { step = 30, digits = 6, now = Date.now() } = {}) {
  const key = typeof secret === 'string' ? decodeBase32(secret) : secret;
  const counter = Math.floor(now / 1000 / step);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 10 ** digits).padStart(digits, '0');
}

export function verifyTotp(secret, token, { window = 1, step = 30, digits = 6, now = Date.now() } = {}) {
  const expectedLen = digits;
  if (!token || token.length !== expectedLen || !/^\d+$/.test(token)) return false;
  const provided = Buffer.from(token);
  for (let w = -window; w <= window; w += 1) {
    const candidate = generateTotp(secret, { step, digits, now: now + w * step * 1000 });
    const expected = Buffer.from(candidate);
    if (provided.length === expected.length && timingSafeEqual(provided, expected)) {
      return true;
    }
  }
  return false;
}
