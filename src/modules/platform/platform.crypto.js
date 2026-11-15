import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');

/** Accepts a 32-byte key as 64 hex chars or base64. The key always comes from the environment, never source. */
export function parseKey(raw) {
  if (!raw) throw new AppError(500, 'ENCRYPTION_KEY_MISSING', 'Encryption key is not configured');
  const buf = /^[0-9a-f]{64}$/i.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64');
  if (buf.length !== 32) throw new AppError(500, 'ENCRYPTION_KEY_INVALID', 'Encryption key must be 32 bytes');
  return buf;
}

/** AES-256-GCM. Output layout: iv(12) | tag(16) | ciphertext. */
export function encrypt(plain, rawKey) {
  const key = parseKey(rawKey);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain))), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

export function decrypt(blob, rawKey) {
  const key = parseKey(rawKey);
  if (!Buffer.isBuffer(blob) || blob.length < 29) throw new AppError(422, 'CIPHERTEXT_INVALID', 'Ciphertext is malformed');
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
    decipher.setAuthTag(blob.subarray(12, 28));
    return Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]);
  } catch {
    throw new AppError(422, 'CIPHERTEXT_TAMPERED', 'Ciphertext failed authentication');
  }
}
