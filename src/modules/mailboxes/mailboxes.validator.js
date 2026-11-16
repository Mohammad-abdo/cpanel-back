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
export const mailboxPassword = z.string().min(12).max(128);

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
  .strict();

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
