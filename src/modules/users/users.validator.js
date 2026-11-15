import { z } from 'zod';

export const createUserBodySchema = z
  .object({
    email: z.string().trim().email().max(320),
    displayName: z.string().trim().min(1).max(120),
    password: z.string().min(8).max(200),
    isOwner: z.boolean().optional().default(false),
  })
  .strict();

export const userIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const listUsersQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(200).default(100),
  })
  .strict();

export const patchUserBodySchema = z
  .object({
    displayName: z.string().trim().min(1).max(120).optional(),
    status: z.enum(['active', 'disabled']).optional(),
    isOwner: z.boolean().optional(),
  })
  .strict();
