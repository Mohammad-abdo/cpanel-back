import { z } from 'zod';
import { ALERT_EVENT_KINDS, ALLOW_HOSTS, CHANNEL_TYPES, SEVERITIES } from './alert-channels.senders.js';

const httpsUrl = z.string().trim().max(500).url().refine((u) => u.toLowerCase().startsWith('https://'), 'Only https URLs are allowed');

const common = {
  name: z.string().trim().min(1).max(120),
  minSeverity: z.enum(SEVERITIES).default('info'),
  eventKinds: z.array(z.enum(ALERT_EVENT_KINDS)).max(ALERT_EVENT_KINDS.length).nullable().optional(),
  enabled: z.boolean().default(true),
  dedupeSeconds: z.number().int().min(0).max(86400).default(300),
};

const secretFields = {
  botToken: z.string().trim().regex(/^\d{3,20}:[A-Za-z0-9_-]{20,80}$/, 'Telegram bot token format is invalid').optional(),
  chatId: z.string().trim().regex(/^-?\d{1,20}$|^@[A-Za-z0-9_]{4,64}$/, 'chatId must be a numeric id or @channel').optional(),
  webhookUrl: httpsUrl.optional(),
  url: httpsUrl.optional(),
  signingSecret: z.string().min(16).max(128).optional(),
};

function requireByType(v, ctx) {
  const need = (k, msg = 'Required for this channel type') => {
    if (!v[k]) ctx.addIssue({ code: 'custom', path: [k], message: msg });
  };
  if (v.type === 'telegram') {
    need('botToken');
    need('chatId');
  } else if (v.type === 'slack' || v.type === 'discord') {
    need('webhookUrl');
  } else if (v.type === 'webhook') {
    need('url');
    need('signingSecret');
  }
  if (v.webhookUrl && (v.type === 'slack' || v.type === 'discord')) {
    const host = new URL(v.webhookUrl).hostname.toLowerCase();
    if (!ALLOW_HOSTS[v.type].some((h) => host === h || host.endsWith(`.${h}`))) {
      ctx.addIssue({ code: 'custom', path: ['webhookUrl'], message: `Host is not allowed for ${v.type}` });
    }
  }
}

export const createChannelBodySchema = z
  .object({ type: z.enum(CHANNEL_TYPES), ...common, ...secretFields })
  .strict()
  .superRefine(requireByType);

/** Type is immutable. Secret fields are optional on update: omitted keeps the stored secret, any provided field replaces it. */
export const updateChannelBodySchema = z
  .object({
    name: common.name.optional(),
    minSeverity: z.enum(SEVERITIES).optional(),
    eventKinds: common.eventKinds,
    enabled: z.boolean().optional(),
    dedupeSeconds: z.number().int().min(0).max(86400).optional(),
    ...secretFields,
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0, 'At least one field is required');

export const channelIdParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const emptyBodySchema = z.object({}).strict();

export const deliveriesQuerySchema = z
  .object({
    cursor: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    status: z.enum(['pending', 'sent', 'failed', 'dead', 'suppressed']).optional(),
  })
  .strict();
