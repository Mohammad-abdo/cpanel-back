const PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[REDACTED_PRIVATE_KEY]'],
  [/\b(authorization|proxy-authorization|cookie|set-cookie)(["']?\s*[:=]\s*)[^\r\n]+/gi, '$1$2[REDACTED]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer [REDACTED]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, '[REDACTED_JWT]'],
  [/\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{16,}/g, '[REDACTED_TOKEN]'],
  [/\bsk-[A-Za-z0-9_-]{16,}/g, '[REDACTED_TOKEN]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED_TOKEN]'],
  [/\b([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)[^\s@/]+@/gi, '$1[REDACTED]@'],
  [
    /\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|session[_-]?id)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&"']+)/gi,
    '$1$2[REDACTED]',
  ],
];

const SECRET_KEY = /pass(word|wd)?|pwd|secret|token|authorization|cookie|api[-_]?key|private[-_]?key|credential/i;

/** Redact secret-looking substrings in free text. Applied before storage, again before display/export. */
export function redactText(value) {
  if (typeof value !== 'string' || value.length === 0) return value;
  let out = value;
  for (const [pattern, replacement] of PATTERNS) out = out.replace(pattern, replacement);
  return out;
}

/** Deep redaction for structured fields: secret-named keys are masked, string values are scrubbed. */
export function redactDeep(value, depth = 0) {
  if (depth > 6) return '[TRUNCATED]';
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => redactDeep(v, depth + 1));
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 100)
        .map(([k, v]) => [k, SECRET_KEY.test(k) ? '[REDACTED]' : redactDeep(v, depth + 1)]),
    );
  }
  return value;
}
