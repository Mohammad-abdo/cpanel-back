import { z } from 'zod';

export const serverIdParamsSchema = z.object({ serverId: z.string().uuid() }).strict();
export const reservationIdParamsSchema = z
  .object({
    serverId: z.string().uuid(),
    reservationId: z.string().uuid(),
  })
  .strict();

export const reserveBodySchema = z
  .object({
    port: z.number().int().min(1).max(65535),
    label: z.string().trim().min(1).max(100),
  })
  .strict();

export const checkQuerySchema = z
  .object({
    port: z.coerce.number().int().min(1).max(65535),
  })
  .strict();
