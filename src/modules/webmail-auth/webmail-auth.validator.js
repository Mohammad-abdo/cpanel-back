import { z } from 'zod';

const address = z
  .string()
  .trim()
  .email()
  .max(254)
  .transform((v) => v.toLowerCase());

export const webmailLoginBodySchema = z
  .object({
    address,
    password: z.string().min(1).max(256),
  })
  .strict();
