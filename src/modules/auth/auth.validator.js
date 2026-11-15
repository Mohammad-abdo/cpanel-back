import { z } from 'zod';

export const loginBodySchema = z
  .object({
    email: z.string().trim().email().max(320),
    password: z.string().min(8).max(200),
  })
  .strict();

export const mfaVerifyBodySchema = z
  .object({
    sessionId: z.string().uuid(),
    code: z.string().trim().regex(/^\d{6}$/),
  })
  .strict();

export const mfaEnrollBodySchema = z.object({}).strict();

export const mfaConfirmBodySchema = z
  .object({
    factorId: z.string().uuid(),
    code: z.string().trim().regex(/^\d{6}$/),
  })
  .strict();

export const logoutBodySchema = z.object({}).strict();

export const changePasswordBodySchema = z
  .object({
    currentPassword: z.string().min(1).max(200),
    newPassword: z.string().min(12).max(200),
  })
  .strict();

export const sessionIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const sessionsBodySchema = z.object({}).strict();
