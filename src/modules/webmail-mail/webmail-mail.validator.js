import { z } from 'zod';

export const listMessagesQuerySchema = z
  .object({
    folder: z.string().trim().min(1).max(255).default('INBOX'),
    limit: z.coerce.number().int().min(1).max(100).default(50),
    page: z.coerce.number().int().min(1).max(1000).default(1),
    q: z.string().trim().max(200).optional().default(''),
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

const noCrlf = (v) => !/[\r\n\0]/.test(v);
const addrField = z.string().trim().max(2000).refine(noCrlf, 'Line breaks are not allowed');
const headerId = z.string().trim().max(998).regex(/^<[^<>\s]+>$/, 'Invalid message id');

export const attachmentInputSchema = z
  .object({
    filename: z.string().trim().min(1).max(255),
    contentType: z.string().trim().max(127).optional(),
    // base64 of at most 20 MB of raw bytes
    contentBase64: z
      .string()
      .max(Math.ceil((20 * 1024 * 1024 * 4) / 3) + 8)
      .regex(/^[A-Za-z0-9+/]*={0,2}$/, 'Invalid base64'),
  })
  .strict();

const composeShape = {
  to: addrField,
  cc: addrField.optional(),
  bcc: addrField.optional(),
  subject: z.string().trim().max(998).refine(noCrlf, 'Line breaks are not allowed').default(''),
  text: z.string().max(2_000_000).default(''),
  inReplyTo: headerId.optional(),
  references: z.array(headerId).max(50).optional(),
  attachments: z.array(attachmentInputSchema).max(20).default([]),
};

export const sendMessageBodySchema = z
  .object({ ...composeShape, to: addrField.min(3) })
  .strict();

export const saveDraftBodySchema = z
  .object({ ...composeShape, to: addrField.default(''), replaceUid: z.coerce.number().int().positive().optional() })
  .strict();

export const attachmentParamsSchema = z
  .object({
    uid: z.coerce.number().int().positive(),
    index: z.coerce.number().int().min(0).max(999),
  })
  .strict();

export const flagsBodySchema = z
  .object({
    folder: z.string().trim().min(1).max(255).default('INBOX'),
    uids: z.array(z.coerce.number().int().positive()).min(1).max(50),
    add: z.array(z.enum(['\\Seen', '\\Flagged'])).max(2).default([]),
    remove: z.array(z.enum(['\\Seen', '\\Flagged'])).max(2).default([]),
  })
  .strict()
  .refine((v) => v.add.length + v.remove.length > 0, { message: 'add or remove is required' });

export const actionMessagesBodySchema = z
  .object({
    folder: z.string().trim().min(1).max(255).default('INBOX'),
    uids: z.union([z.array(z.coerce.number().int().positive()).min(1).max(50), z.coerce.number().int().positive()]),
    action: z.enum(['archive', 'junk', 'trash', 'delete', 'move']),
    target: z.string().trim().min(1).max(255).optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    if (val.action === 'move' && !val.target) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'target is required for move', path: ['target'] });
    }
  });
