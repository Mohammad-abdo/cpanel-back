import { z } from 'zod';

export const listMessagesQuerySchema = z
  .object({
    folder: z.string().trim().min(1).max(255).default('INBOX'),
    limit: z.coerce.number().int().min(1).max(100).default(50),
    page: z.coerce.number().int().min(1).max(1000).default(1),
  })
  .strict();

export const messageParamsSchema = z
  .object({
    uid: z.coerce.number().int().positive(),
  })
  .strict();

export const messageQuerySchema = z
  .object({
    folder: z.string().trim().min(1).max(255).default('INBOX'),
  })
  .strict();

export const sendMessageBodySchema = z
  .object({
    to: z.string().trim().min(3).max(2000),
    subject: z.string().trim().max(998).default(''),
    text: z.string().max(2_000_000).default(''),
    cc: z.string().trim().max(2000).optional(),
  })
  .strict();
