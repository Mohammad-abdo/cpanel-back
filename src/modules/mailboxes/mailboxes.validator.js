import { z } from 'zod';

/** Local part: lowercase letters, digits and ._+- ; 1-64 chars; no leading/trailing/consecutive dots. Blocks config/header injection. */
export const localPart = z
  .string()
  .trim()
  .toLowerCase()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9]([a-z0-9._+-]*[a-z0-9])?$/, 'Invalid mailbox name')
  .refine((v) => !v.includes('..'), { message: 'Invalid mailbox name' });

/** Mailbox password policy. Plaintext is accepted only on the wire, hashed immediately, never stored or logged. */
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password12', 'password123', 'passw0rd', 'letmein', 'welcome', 'welcome1', 'qwerty', 'qwertyuiop', 'iloveyou', 'admin', 'administrator',
  'changeme', 'trustno1', 'abc123', 'monkey', 'dragon', 'football', 'baseball', 'master', 'login', 'princess', 'sunshine', 'shadow', 'superman', 'whatever',
]);

/** True for runs like abcdefgh / 12345678 / 98765432 (ascending or descending by one) of 6+ characters, or a single repeated character. */
export function hasSequentialRun(value, run = 6) {
  const v = String(value).toLowerCase();
  let up = 1;
  let down = 1;
  let same = 1;
  for (let i = 1; i < v.length; i += 1) {
    const d = v.charCodeAt(i) - v.charCodeAt(i - 1);
    up = d === 1 ? up + 1 : 1;
    down = d === -1 ? down + 1 : 1;
    same = d === 0 ? same + 1 : 1;
    if (up >= run || down >= run || same >= run) return true;
  }
  return false;
}

/** Policy check shared by create/reset. `localPart` (optional) must not equal or be contained in the password. */
export function checkMailboxPassword(password, localPart) {
  const pw = String(password ?? '');
  const lower = pw.toLowerCase();
  if (pw.length < 12) return 'Password must be at least 12 characters';
  if (pw.length > 128) return 'Password must be at most 128 characters';
  const base = lower.replace(/[^a-z0-9]/g, '').replace(/[0-9]+$/, '');
  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(base)) return 'Password is too common';
  if (hasSequentialRun(pw)) return 'Password must not contain long sequential or repeated characters';
  if (localPart && (lower === String(localPart).toLowerCase() || (String(localPart).length >= 4 && lower.includes(String(localPart).toLowerCase())))) return 'Password must not contain the mailbox name';
  return null;
}

/** Mailbox password policy: min 12, no common/sequential/repeated passwords. Plaintext is accepted only on the wire, hashed immediately, never stored or logged. */
export const mailboxPassword = z.string().min(12).max(128).superRefine((v, ctx) => {
  const msg = checkMailboxPassword(v);
  if (msg) ctx.addIssue({ code: 'custom', message: msg });
});

const quotaMb = z.number().int().min(10).max(102400);

export const mailboxIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const listMailboxesQuerySchema = z
  .object({
    /** Optional: omit to list across every visible domain (admin Mail dashboard). */
    domainId: z.string().uuid().optional(),
    serverId: z.string().uuid().optional(),
    q: z.string().trim().min(1).max(100).optional(),
    status: z.enum(['active', 'suspended', 'deleted']).optional(),
    limit: z.coerce.number().int().min(1).max(500).default(100),
    offset: z.coerce.number().int().min(0).max(100000).default(0),
  })
  .strict();

export const createMailboxBodySchema = z
  .object({
    domainId: z.string().uuid(),
    localPart,
    displayName: z.string().trim().min(1).max(120).optional(),
    quotaMb: quotaMb.optional(),
    password: mailboxPassword,
  })
  .strict()
  .superRefine((v, ctx) => {
    const msg = checkMailboxPassword(v.password, v.localPart);
    if (msg) ctx.addIssue({ code: 'custom', path: ['password'], message: msg });
  });

export const updateMailboxBodySchema = z
  .object({
    displayName: z.string().trim().min(1).max(120).nullable().optional(),
    quotaMb: quotaMb.optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, { message: 'At least one field is required' });

export const setMailboxPasswordBodySchema = z.object({ password: mailboxPassword }).strict();

export const mailboxReasonBodySchema = z.object({ reason: z.string().min(5).max(500).optional() }).strict();

export const mailboxAuditQuerySchema = z.object({ limit: z.coerce.number().int().min(1).max(200).default(50) }).strict();

export const deleteMailboxQuerySchema = z.object({ reason: z.string().min(5).max(500).optional() }).strict();
