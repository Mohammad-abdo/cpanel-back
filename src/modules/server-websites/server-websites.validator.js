import { z } from 'zod';

export const serverIdParamsSchema = z.object({ serverId: z.string().uuid() }).strict();
