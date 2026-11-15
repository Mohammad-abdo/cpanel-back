import { z } from 'zod';
import { PERMISSION_LIST } from '@nodeteam/permission-catalog';

const permissionKeySchema = z
  .string()
  .refine((value) => PERMISSION_LIST.includes(value), { message: 'Unknown permission key' });

export const grantBodySchema = z
  .object({
    userId: z.string().uuid(),
    permissionKey: permissionKeySchema,
    resourceType: z.string().min(1).max(80),
    resourceId: z.string().min(1).max(80),
    environmentId: z.string().uuid().optional().nullable(),
    conditionsJson: z.record(z.string(), z.unknown()).optional().nullable(),
  })
  .strict();

export const grantIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const listGrantsQuerySchema = z
  .object({
    userId: z.string().uuid().optional(),
    resourceType: z.string().max(80).optional(),
    resourceId: z.string().max(80).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(50),
  })
  .strict();
