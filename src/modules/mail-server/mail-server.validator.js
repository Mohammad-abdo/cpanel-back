import { z } from 'zod';

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const hostname = z.string().trim().toLowerCase().regex(HOSTNAME, 'Invalid hostname');

export const mailServerIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const enableMailServerBodySchema = z.object({ mailHostname: hostname.optional() }).strict();

export const disableMailServerBodySchema = z.object({ reason: z.string().min(5).max(500).optional() }).strict();

export const provisionPreviewBodySchema = z.object({ mailHostname: hostname.optional() }).strict();

export const provisionApplyBodySchema = z
  .object({
    mailHostname: hostname.optional(),
    reason: z.string().min(5).max(500).optional(),
    rollbackNote: z.string().min(5).max(500).optional(),
    approvalId: z.string().uuid().optional(),
    confirmAlias: z.string().min(1).max(100).optional(),
  })
  .strict();

export const firewallPreviewBodySchema = z.object({ webmail: z.boolean().optional() }).strict();

export const firewallApplyBodySchema = z
  .object({
    webmail: z.boolean().optional(),
    reason: z.string().min(5).max(500).optional(),
    rollbackNote: z.string().min(5).max(500).optional(),
    approvalId: z.string().uuid().optional(),
    confirmAlias: z.string().min(1).max(100).optional(),
  })
  .strict();
