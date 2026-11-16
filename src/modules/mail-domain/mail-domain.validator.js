import { z } from 'zod';

export const mailDomainIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

const selector = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$/, 'Invalid DKIM selector');

const quotaMb = z.number().int().min(10).max(102400);

export const enableMailDomainBodySchema = z
  .object({
    quotaDefaultMb: quotaMb.optional(),
    dkimSelector: selector.optional(),
  })
  .strict();

export const disableMailDomainBodySchema = z.object({ reason: z.string().min(5).max(500).optional() }).strict();

export const updateMailDomainBodySchema = z
  .object({
    quotaDefaultMb: quotaMb.optional(),
    dkimSelector: selector.optional(),
    /** Existing active mailbox of this domain, or null to turn the catch-all off. */
    catchAllMailboxId: z.string().uuid().nullable().optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, { message: 'At least one field is required' });
