import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const PREFIX = 'scrypt$';

/** Hash a password with scrypt (node:crypto, no extra dependency). Format: scrypt$<saltHex>$<hashHex>. */
export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, 64);
  return `${PREFIX}${salt.toString('hex')}$${hash.toString('hex')}`;
}

function safeEqual(a, b) {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Verify scrypt hashes; legacy unsalted SHA-256 hashes still verify so existing seeds work. */
export function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || !stored) return false;
  if (stored.startsWith(PREFIX)) {
    const [, saltHex, hashHex] = stored.split('$');
    if (!saltHex || !hashHex) return false;
    const expected = Buffer.from(hashHex, 'hex');
    return safeEqual(scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length), expected);
  }
  return safeEqual(Buffer.from(createHash('sha256').update(password).digest('hex')), Buffer.from(stored));
}

export function isLegacyPasswordHash(stored) {
  return typeof stored === 'string' && !stored.startsWith(PREFIX);
}
