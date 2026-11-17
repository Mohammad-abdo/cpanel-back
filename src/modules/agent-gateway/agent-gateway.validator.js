import { z } from 'zod';

/** No whitespace or shell metacharacters in identifiers the agent turns into argv. Agent re-validates independently. */
const safe = (max = 100) => z.string().min(1).max(max).regex(/^[A-Za-z0-9][A-Za-z0-9._\/@-]*$/);
const name = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);
const absPath = z.string().min(1).max(512).regex(/^\/[^\0\\]*$/);

const strict = (shape) => z.object(shape).strict();

/** Per-command argument schemas (control-plane side). `password` is accepted for backup.dump and encrypted before sending. */
export const COMMAND_ARGS = {
  stats: strict({}),
  'file.list': strict({ path: absPath }),
  'file.read': strict({ path: absPath, maxBytes: z.number().int().min(1).max(262144).optional() }),
  'file.search': strict({ path: absPath, q: z.string().min(1).max(120), limit: z.number().int().min(1).max(200).optional() }),
  'file.write': strict({
    path: absPath,
    content: z.string().max(1024 * 1024),
    expectedMtimeMs: z.number().int().min(0).optional(),
  }),
  'file.move': strict({ from: absPath, to: absPath }),
  'file.remove': strict({ path: absPath, recursive: z.boolean().optional() }),
  'ports.list': strict({}),
  'tls.inspect': strict({
    hostname: z.string().trim().toLowerCase().regex(/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/),
    port: z.number().int().min(1).max(65535).optional(),
  }),
  'agent.info': strict({}),
  'deploy.step': strict({
    step: z.enum(['git_fetch', 'git_checkout', 'npm_ci', 'npm_script', 'prisma_migrate_deploy']),
    dir: absPath,
    ref: safe(100).optional(),
    script: z.enum(['build', 'test', 'lint']).optional(),
  }),
  'pm2.control': strict({ action: z.enum(['list', 'restart', 'reload', 'stop', 'start', 'delete']), name: name.optional() }),
  'pm2.logs': strict({ name, lines: z.number().int().min(1).max(500).optional() }),
  ufw: strict({
    action: z.enum(['status', 'allow', 'deny', 'delete_allow']),
    port: z.number().int().min(1).max(65535).optional(),
    proto: z.enum(['tcp', 'udp']).optional(),
    from: z.string().regex(/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/).optional(),
  }),
  'cron.run': strict({ job: name }),
  'backup.dump': strict({
    kind: z.enum(['mysql', 'postgres', 'files']),
    database: name.optional(),
    user: name.optional(),
    password: z.string().min(1).max(256).optional(),
    sourceDir: absPath.optional(),
    outPath: absPath,
  }),
  'service.restart': strict({ unit: z.string().regex(/^[a-z0-9][a-z0-9@_.-]{0,62}$/) }),
};

/** Commands that need an explicit reason prompt in the UI (high/critical risk or mutating). */
export const COMMAND_NEEDS_REASON = new Set([
  'file.write',
  'file.move',
  'file.remove',
  'deploy.step',
  'pm2.control',
  'pm2.logs',
  'ufw',
  'cron.run',
  'backup.dump',
  'service.restart',
]);
export const COMMAND_TYPES = Object.keys(COMMAND_ARGS);

export const serverIdParamsSchema = z.object({ id: z.string().uuid() }).strict();

export const sendCommandBodySchema = z
  .object({
    type: z.enum(COMMAND_TYPES),
    args: z.record(z.string(), z.unknown()).default({}),
    approvalId: z.string().uuid().optional(),
    reason: z.string().trim().min(3).max(500).optional(),
  })
  .strict();

export const historyQuerySchema = z
  .object({
    status: z.enum(['sent', 'succeeded', 'failed', 'expired']).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(25),
  })
  .strict();

export const rotateBodySchema = z.object({ approvalId: z.string().uuid().optional(), reason: z.string().trim().min(3).max(500).optional() }).strict();
export const terminalBodySchema = z.object({ enabled: z.boolean(), approvalId: z.string().uuid().optional(), reason: z.string().trim().min(3).max(500).optional() }).strict();
