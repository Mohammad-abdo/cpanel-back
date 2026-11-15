import { z } from 'zod';

export const EVENT_KINDS = ['approval.requested', 'approval.decided', 'incident.assigned', 'alert.opened'];
export const CHANNEL_TYPES = ['in_app', 'email'];

export const listNotificationsQuerySchema = z
  .object({
    cursor: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    unread: z.enum(['true', 'false']).optional(),
  })
  .strict();

export const notificationIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const emptyBodySchema = z.object({}).strict();

export const updatePreferencesBodySchema = z
  .object({
    preferences: z
      .array(
        z
          .object({
            eventKind: z.enum(EVENT_KINDS),
            channelType: z.enum(CHANNEL_TYPES),
            enabled: z.boolean(),
          })
          .strict(),
      )
      .min(1)
      .max(EVENT_KINDS.length * CHANNEL_TYPES.length),
  })
  .strict();
