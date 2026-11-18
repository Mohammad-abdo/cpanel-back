/**
 * TASK-053: strict validators for the "Add project to server" flow. Every value that can reach a remote shell, an Apache
 * config or a generated file is validated here first. Nothing is ever interpolated into a shell string: scripts are fixed text
 * and receive values as positional arguments (see project-provisioning.scripts.js).
 */
import { z } from 'zod';
import { AppError } from '../../common/errors/app-error.js';
import { ALLOWED_COMMANDS, SAFE_REL_PATH, validateRef, validateRepoUrl, validateSha } from '../deployments/deployments.commands.js';

export const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
export const PROVISION_SLUG = /^[a-z0-9][a-z0-9-]{0,26}[a-z0-9]$|^[a-z0-9]$/;
export const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]{0,99}$/;
const GIT_TOKEN = /^[A-Za-z0-9_.-]{10,255}$/;
/** App roots the executor may create directories under. Never a path taken from the request. */
export const APP_ROOT = /^\/(?:srv|var\/www|opt)(?:\/[A-Za-z0-9._-]{1,60}){0,3}$/;

export const FRAMEWORKS = ['auto', 'node', 'next', 'vite', 'static'];
const INSTALL_IDS = Object.keys(ALLOWED_COMMANDS).filter((k) => /install|ci$/.test(k));
const BUILD_IDS = Object.keys(ALLOWED_COMMANDS).filter((k) => /build|prisma generate|prune/.test(k));

export function validateHostname(value) {
  const v = String(value ?? '').trim().toLowerCase();
  if (!HOSTNAME.test(v)) throw new AppError(422, 'DOMAIN_INVALID', 'Domain must be a plain hostname such as app.example.com');
  return v;
}
export const validateSlug = (value) => {
  if (!PROVISION_SLUG.test(String(value ?? ''))) throw new AppError(422, 'SLUG_INVALID', 'Slug must be 1-28 chars: lowercase letters, digits and hyphens');
  return value;
};
export const validatePort = (value) => {
  if (!Number.isInteger(value) || value < 1024 || value > 65535) throw new AppError(422, 'PORT_INVALID', 'Port must be an integer between 1024 and 65535');
  return value;
};
export function validateAppRoot(value) {
  if (!APP_ROOT.test(String(value)) || String(value).includes('..')) throw new AppError(422, 'APP_ROOT_INVALID', 'App root must be under /srv, /var/www or /opt');
  return value;
}

const hostname = z.string().max(253).transform((v) => v.trim().toLowerCase()).refine((v) => HOSTNAME.test(v), 'invalid hostname');
const noCtl = (s) => !/[\0\r\n]/.test(s);

export const planSchema = z
  .object({
    serverId: z.string().uuid(),
    name: z.string().trim().min(1).max(120).refine(noCtl, 'invalid name'),
    slug: z.string().regex(PROVISION_SLUG),
    repoUrl: z.string().max(300).refine((v) => { try { validateRepoUrl(v); return true; } catch { return false; } }, 'invalid repo url'),
    branch: z.string().max(100).refine((v) => { try { validateRef(v); return true; } catch { return false; } }, 'invalid branch').default('main'),
    commitSha: z.string().refine((v) => { try { validateSha(v); return true; } catch { return false; } }, 'invalid sha').nullable().optional(),
    framework: z.enum(FRAMEWORKS).default('auto'),
    installCommand: z.enum(INSTALL_IDS.length ? INSTALL_IDS : ['npm ci']).nullable().optional(),
    buildCommand: z.enum(BUILD_IDS.length ? BUILD_IDS : ['npm run build']).nullable().optional(),
    /** node/next: `npm start` unless a start file (relative path, no "..") is given. */
    startFile: z.string().max(100).regex(SAFE_REL_PATH).nullable().optional(),
    outputDir: z.string().max(100).refine((v) => v === '.' || SAFE_REL_PATH.test(v), 'invalid output dir').nullable().optional(),
    port: z.number().int().min(1024).max(65535).nullable().optional(),
    domains: z.array(hostname).min(1).max(6).refine((a) => new Set(a).size === a.length, 'duplicate domain'),
    ssl: z.boolean().default(true),
    dnsMode: z.enum(['manual', 'cloudflare']).default('manual'),
    renewalDryRun: z.boolean().default(false),
    sslStaging: z.boolean().default(false),
    envVars: z
      .array(z.object({ key: z.string().regex(ENV_KEY), value: z.string().max(4096).refine(noCtl, 'newline or NUL in value'), isSecret: z.boolean().default(true) }).strict())
      .max(100)
      .default([])
      .refine((a) => new Set(a.map((e) => e.key)).size === a.length, 'duplicate env key'),
  })
  .strict();

/** Secrets travel in their own object so they are never part of the stored plan, the approval binding or the audit row. */
export const secretsSchema = z
  .object({
    gitToken: z.string().regex(GIT_TOKEN).optional(),
    deployKey: z.string().max(8192).regex(/^-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+-----END [A-Z ]*PRIVATE KEY-----\s*$/).optional(),
  })
  .strict()
  .refine((s) => !(s.gitToken && s.deployKey), 'give either a token or a deploy key');

const approvalFields = { approvalId: z.string().uuid().optional(), reason: z.string().trim().min(5).max(500).optional(), rollbackNote: z.string().trim().min(5).max(1000).optional() };
export const confirmSchema = z.object({ serverAlias: z.string().min(1).max(120), domain: hostname }).strict();

export const previewBodySchema = z.object({ plan: planSchema }).strict();
export const createRunBodySchema = z.object({ plan: planSchema, confirm: confirmSchema, secrets: secretsSchema.optional(), ...approvalFields }).strict();
export const resumeBodySchema = z.object({ secrets: secretsSchema.optional(), ...approvalFields }).strict();
export const runParamsSchema = z.object({ id: z.string().uuid() }).strict();
export const projectParamsSchema = z.object({ projectId: z.string().uuid() }).strict();
export const listQuerySchema = z.object({ projectId: z.string().uuid().optional(), serverId: z.string().uuid().optional(), limit: z.coerce.number().int().min(1).max(100).default(30) }).strict();
export const decommissionBodySchema = z.object({ preview: z.boolean().default(false), confirm: confirmSchema.optional(), ...approvalFields }).strict();
export const vhostBodySchema = z.object({ preview: z.boolean().default(false), ...approvalFields }).strict();
export const redeployBodySchema = z.object({ secrets: secretsSchema.optional(), confirm: confirmSchema.optional(), ...approvalFields }).strict();
