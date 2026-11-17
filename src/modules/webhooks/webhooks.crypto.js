import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** GitHub X-Hub-Signature-256 verification: HMAC-SHA256 of the raw body, constant-time compare. */
export function githubSignature(rawBody, secret) {
  return `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`;
}

export function verifyGithubSignature(rawBody, header, secret) {
  if (!Buffer.isBuffer(rawBody) || typeof header !== 'string' || !secret) return false;
  const expected = Buffer.from(githubSignature(rawBody, secret));
  const given = Buffer.from(header);
  // timingSafeEqual throws on unequal lengths; equal-length check first leaks only the (public) format length.
  return given.length === expected.length && timingSafeEqual(given, expected);
}

export const HOOK_TOKEN_PATTERN = /^ntdh_[A-Za-z0-9_-]{43}$/;
export const hashHookToken = (token) => createHash('sha256').update(String(token)).digest('hex');

/** 256-bit random token. Only its SHA-256 is stored. */
export function generateHookToken() {
  const token = `ntdh_${randomBytes(32).toString('base64url')}`;
  return { token, tokenHash: hashHookToken(token), tokenPrefix: token.slice(0, 9) };
}

export const generateWebhookSecret = () => randomBytes(32).toString('hex');
