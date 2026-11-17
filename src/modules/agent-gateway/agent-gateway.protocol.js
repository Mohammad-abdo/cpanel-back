/**
 * Control-plane <-> agent protocol primitives (TASK-046). Dependency-free (node:crypto only).
 * The API keeps a byte-identical copy at apps/api/src/modules/agent-gateway/agent-gateway.protocol.js;
 * a unit test asserts both interoperate. Keep the two files in sync.
 *
 * Envelope: { v, agentId, commandId, type, args, nonce, iat, exp, hash, sig }
 *   hash = sha256(canonical({type,args})); sig = HMAC-SHA256(signKey, canonical(envelope without sig)).
 * Keys are derived per agent from the control-plane master secret (HKDF), so a stolen socket token
 * (the agent credential) cannot mint commands.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

export const PROTOCOL_VERSION = 1;
export const MAX_ENVELOPE_TTL_MS = 5 * 60_000;
export const CLOCK_SKEW_MS = 30_000;

/** Deterministic JSON: sorted keys, no undefined. */
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value === undefined ? null : value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

export const sha256Hex = (s) => createHash('sha256').update(s).digest('hex');

export function deriveAgentKeys(masterSecret, agentId, generation = 1) {
  if (typeof masterSecret !== 'string' || masterSecret.length < 32) throw new Error('control secret too short');
  const salt = Buffer.from(String(agentId));
  const d = (info) => Buffer.from(hkdfSync('sha256', Buffer.from(masterSecret), salt, `nt-agent:${info}:${generation}`, 32));
  return { signKey: d('sign'), encKey: d('enc') };
}

const hmac = (key, data) => createHmac('sha256', key).update(data).digest('base64url');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

export function signEnvelope({ signKey, agentId, commandId, type, args = {}, now = Date.now(), ttlMs = 60_000, nonce = randomBytes(16).toString('base64url') }) {
  if (ttlMs > MAX_ENVELOPE_TTL_MS) throw new Error('ttl too long');
  const body = {
    v: PROTOCOL_VERSION,
    agentId,
    commandId,
    type,
    args,
    nonce,
    iat: now,
    exp: now + ttlMs,
    hash: sha256Hex(canonical({ type, args })),
  };
  return { ...body, sig: hmac(signKey, canonical(body)) };
}

export class ReplayCache {
  constructor({ max = 10_000 } = {}) {
    this.seen = new Map();
    this.max = max;
  }
  /** Returns false when the key was already seen (replay). */
  remember(key, expiresAt, now = Date.now()) {
    for (const [k, exp] of this.seen) if (exp <= now) this.seen.delete(k);
    if (this.seen.has(key)) return false;
    if (this.seen.size >= this.max) throw Object.assign(new Error('replay cache full'), { code: 'REPLAY_CACHE_FULL' });
    this.seen.set(key, expiresAt);
    return true;
  }
}

const fail = (code, message) => Object.assign(new Error(message), { code });

/** Verifies shape, agent binding, expiry, hash, signature and replay. Returns the envelope. */
export function verifyEnvelope(env, { signKey, agentId, replay, now = Date.now() }) {
  if (!env || typeof env !== 'object' || env.v !== PROTOCOL_VERSION) throw fail('ENVELOPE_INVALID', 'Unsupported envelope');
  for (const k of ['agentId', 'commandId', 'type', 'nonce', 'hash', 'sig']) if (typeof env[k] !== 'string') throw fail('ENVELOPE_INVALID', `Missing ${k}`);
  if (!Number.isFinite(env.iat) || !Number.isFinite(env.exp)) throw fail('ENVELOPE_INVALID', 'Missing times');
  const { sig, ...body } = env;
  if (!safeEq(sig, hmac(signKey, canonical(body)))) throw fail('ENVELOPE_BAD_SIGNATURE', 'Bad signature');
  if (env.agentId !== agentId) throw fail('ENVELOPE_WRONG_AGENT', 'Envelope is for another agent');
  if (env.exp <= now) throw fail('ENVELOPE_EXPIRED', 'Envelope expired');
  if (env.exp - env.iat > MAX_ENVELOPE_TTL_MS) throw fail('ENVELOPE_INVALID', 'Lifetime too long');
  if (env.iat - now > CLOCK_SKEW_MS) throw fail('ENVELOPE_INVALID', 'Issued in the future');
  if (!safeEq(env.hash, sha256Hex(canonical({ type: env.type, args: env.args ?? {} })))) throw fail('ENVELOPE_BAD_HASH', 'Command hash mismatch');
  if (replay && !(replay.remember(`n:${env.nonce}`, env.exp, now) && replay.remember(`c:${env.commandId}`, env.exp, now))) throw fail('ENVELOPE_REPLAY', 'Replay detected');
  return env;
}

/** Result envelope the agent returns; the control plane verifies it came from this agent's key. */
export function signResult({ signKey, agentId, commandId, result }) {
  const body = { agentId, commandId, result };
  return { ...body, sig: hmac(signKey, canonical(body)) };
}
export function verifyResult(msg, { signKey, agentId }) {
  if (!msg || msg.agentId !== agentId || typeof msg.commandId !== 'string') return false;
  const { sig, ...body } = msg;
  return safeEq(sig, hmac(signKey, canonical(body)));
}

/** AES-256-GCM secret field. aad binds it to the command and field so it cannot be moved. */
export function encryptField(encKey, plaintext, aad) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', encKey, iv);
  c.setAAD(Buffer.from(String(aad)));
  const ct = Buffer.concat([c.update(String(plaintext), 'utf8'), c.final()]);
  return { enc: 'a256gcm', iv: iv.toString('base64url'), ct: ct.toString('base64url'), tag: c.getAuthTag().toString('base64url') };
}
export function decryptField(encKey, field, aad) {
  if (!field || field.enc !== 'a256gcm') throw fail('FIELD_INVALID', 'Not an encrypted field');
  try {
    const d = createDecipheriv('aes-256-gcm', encKey, Buffer.from(field.iv, 'base64url'));
    d.setAAD(Buffer.from(String(aad)));
    d.setAuthTag(Buffer.from(field.tag, 'base64url'));
    return Buffer.concat([d.update(Buffer.from(field.ct, 'base64url')), d.final()]).toString('utf8');
  } catch {
    throw fail('FIELD_DECRYPT_FAILED', 'Encrypted field could not be decrypted');
  }
}
export const isEncryptedField = (v) => Boolean(v) && typeof v === 'object' && v.enc === 'a256gcm';
