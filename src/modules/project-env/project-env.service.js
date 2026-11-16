import { AppError } from '../../common/errors/app-error.js';
import { assertCan } from '../platform/platform.service.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { PERMISSIONS } from '../../common/permission-catalog.js';

export const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_.]{0,127}$/;
export const MAX_VALUE = 32 * 1024;
export const MAX_VARS = 500;
/** Keys that look sensitive are marked secret automatically on import. */
const SECRET_HINT = /(SECRET|PASSWORD|PASSWD|PWD|TOKEN|PRIVATE|CREDENTIAL|API_?KEY|ACCESS_?KEY|_KEY$|DSN|DATABASE_URL)/i;
export const looksSecret = (key) => SECRET_HINT.test(key);

/** Best-effort DB name from common .env keys (never returns credentials). */
export function guessDbName(vars) {
  const map = Object.fromEntries((vars ?? []).map((v) => [v.key, v.value]));
  for (const k of ['DB_NAME', 'MYSQL_DATABASE', 'POSTGRES_DB', 'DATABASE_NAME', 'PGDATABASE']) {
    if (map[k] && /^[A-Za-z0-9_-]{1,64}$/.test(map[k])) return { name: map[k], source: k };
  }
  const url = map.DATABASE_URL || map.MYSQL_URL || map.POSTGRES_URL;
  if (typeof url === 'string') {
    try {
      const u = new URL(url.replace(/^jdbc:/, ''));
      const name = decodeURIComponent((u.pathname || '').replace(/^\//, '').split('?')[0] || '');
      if (name && /^[A-Za-z0-9_-]{1,64}$/.test(name)) return { name, source: 'DATABASE_URL' };
    } catch {
      /* ignore */
    }
  }
  return null;
}

/** Parses .env text: KEY=VALUE, optional `export`, # comments, single/double quotes, \n escapes in double quotes. */
export function parseDotenv(text) {
  const out = [];
  const errors = [];
  String(text ?? '')
    .split(/\r?\n/)
    .forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith('#')) return;
      const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$/.exec(line);
      if (!m) return errors.push(i + 1);
      let value = m[2];
      if (/^"(.*)"$/s.test(value)) value = value.slice(1, -1).replace(/\\n/g, '\n').replace(/\\"/g, '"');
      else if (/^'(.*)'$/s.test(value)) value = value.slice(1, -1);
      else value = value.replace(/\s+#.*$/, '').trim();
      out.push({ key: m[1], value });
    });
  return { vars: out, errors };
}

/** Formats variables as a .env file. Values with spaces, quotes, # or newlines are double-quoted. */
export function toDotenv(vars) {
  return (
    vars
      .map(({ key, value }) => {
        const needsQuotes = /[\s"'#\\]/.test(value) || value === '';
        return `${key}=${needsQuotes ? `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"` : value}`;
      })
      .join('\n') + '\n'
  );
}

export function createProjectEnvService({ prisma, rbac, auditService = null, serverAccess = null, credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY }) {
  const audit = (e) => (auditService?.record ? auditService.record({ resourceType: 'project', ...e }) : null);
  const enc = (v) => encrypt(Buffer.from(v, 'utf8'), credentialKey());
  const dec = (b) => decrypt(Buffer.from(b), credentialKey()).toString('utf8');

  async function load(projectId, environmentId) {
    const env = await prisma.projectEnvironment.findUnique({ where: { id: environmentId }, include: { project: true } });
    if (!env || env.projectId !== projectId) throw new AppError(404, 'ENVIRONMENT_NOT_FOUND', 'Environment not found for this project');
    if (env.project.archivedAt) throw new AppError(409, 'PROJECT_ARCHIVED', 'Project is archived');
    return env;
  }
  const can = (actor, env, permissionKey) =>
    assertCan(rbac, actor, { permissionKey, resourceType: 'project', resourceId: env.projectId, environmentId: env.id });
  const canConfigure = async (actor, env) => {
    try {
      await can(actor, env, PERMISSIONS.PROJECT_CONFIGURE);
      return true;
    } catch {
      return false;
    }
  };

  async function upsertMany(env, vars, actor) {
    for (const v of vars) {
      if (!ENV_KEY.test(v.key)) throw new AppError(422, 'ENV_KEY_INVALID', `Invalid variable name: ${String(v.key).slice(0, 60)}`);
      if (Buffer.byteLength(v.value ?? '', 'utf8') > MAX_VALUE) throw new AppError(413, 'ENV_VALUE_TOO_LARGE', `Value of ${v.key} is larger than 32 KB`);
    }
    const existing = await prisma.projectEnvVar.findMany({ where: { environmentId: env.id }, select: { key: true } });
    const keys = new Set(existing.map((e) => e.key));
    const added = vars.filter((v) => !keys.has(v.key)).length;
    if (keys.size + added > MAX_VARS) throw new AppError(422, 'ENV_TOO_MANY', `An environment can hold at most ${MAX_VARS} variables`);
    for (const v of vars) {
      const data = { valueEnc: enc(v.value ?? ''), isSecret: Boolean(v.isSecret), updatedById: actor.id };
      await prisma.projectEnvVar.upsert({ where: { environmentId_key: { environmentId: env.id, key: v.key } }, create: { environmentId: env.id, key: v.key, ...data }, update: data });
    }
    return { added, updated: vars.length - added };
  }

  return {
    /** Lists variables. Secret values are masked; `canEdit` tells the UI whether reveal/edit is allowed. */
    async list(projectId, environmentId, actor) {
      const env = await load(projectId, environmentId);
      await can(actor, env, PERMISSIONS.PROJECT_ENV_METADATA_READ);
      const rows = await prisma.projectEnvVar.findMany({ where: { environmentId }, orderBy: { key: 'asc' } });
      const editable = await canConfigure(actor, env);
      return {
        environment: { id: env.id, code: env.code, displayName: env.displayName },
        canEdit: editable,
        vars: rows.map((r) => ({ key: r.key, isSecret: r.isSecret, value: r.isSecret ? null : dec(r.valueEnc), updatedAt: r.updatedAt })),
      };
    },

    async reveal(projectId, environmentId, key, actor) {
      const env = await load(projectId, environmentId);
      await can(actor, env, PERMISSIONS.PROJECT_CONFIGURE);
      const row = await prisma.projectEnvVar.findUnique({ where: { environmentId_key: { environmentId, key } } });
      if (!row) throw new AppError(404, 'ENV_VAR_NOT_FOUND', 'Variable not found');
      await audit({ actorId: actor.id, action: 'project.env.reveal', resourceId: projectId, environmentId, result: 'success', after: { key } });
      return { key, value: dec(row.valueEnc) };
    },

    async set(projectId, environmentId, { vars }, actor) {
      const env = await load(projectId, environmentId);
      await can(actor, env, PERMISSIONS.PROJECT_CONFIGURE);
      const res = await upsertMany(env, vars, actor);
      await audit({ actorId: actor.id, action: 'project.env.set', resourceId: projectId, environmentId, result: 'success', after: { keys: vars.map((v) => v.key), ...res } });
      return res;
    },

    async importText(projectId, environmentId, { text, markSecrets = true }, actor) {
      const env = await load(projectId, environmentId);
      await can(actor, env, PERMISSIONS.PROJECT_CONFIGURE);
      const { vars, errors } = parseDotenv(text);
      if (!vars.length) throw new AppError(422, 'ENV_IMPORT_EMPTY', errors.length ? `No valid lines (check lines ${errors.slice(0, 5).join(', ')})` : 'Nothing to import');
      const res = await upsertMany(env, vars.map((v) => ({ ...v, isSecret: markSecrets && looksSecret(v.key) })), actor);
      await audit({ actorId: actor.id, action: 'project.env.import', resourceId: projectId, environmentId, result: 'success', after: { keys: vars.map((v) => v.key), skippedLines: errors, ...res } });
      return { ...res, skippedLines: errors };
    },

    async remove(projectId, environmentId, key, actor) {
      const env = await load(projectId, environmentId);
      await can(actor, env, PERMISSIONS.PROJECT_CONFIGURE);
      const row = await prisma.projectEnvVar.findUnique({ where: { environmentId_key: { environmentId, key } } });
      if (!row) throw new AppError(404, 'ENV_VAR_NOT_FOUND', 'Variable not found');
      await prisma.projectEnvVar.delete({ where: { id: row.id } });
      await audit({ actorId: actor.id, action: 'project.env.delete', resourceId: projectId, environmentId, result: 'success', before: { key } });
      return { deleted: key };
    },

    async exportText(projectId, environmentId, actor) {
      const env = await load(projectId, environmentId);
      await can(actor, env, PERMISSIONS.PROJECT_CONFIGURE);
      const rows = await prisma.projectEnvVar.findMany({ where: { environmentId }, orderBy: { key: 'asc' } });
      await audit({ actorId: actor.id, action: 'project.env.export', resourceId: projectId, environmentId, result: 'success', after: { count: rows.length } });
      return { text: toDotenv(rows.map((r) => ({ key: r.key, value: dec(r.valueEnc) }))), count: rows.length };
    },

    /** Writes the .env file on the project's server over SFTP (Owner, server needs an SSH login). */
    async writeToServer(projectId, environmentId, { path }, actor) {
      const env = await load(projectId, environmentId);
      await can(actor, env, PERMISSIONS.PROJECT_CONFIGURE);
      if (!serverAccess) throw new AppError(501, 'SSH_UNAVAILABLE', 'Server access is not configured');
      const rows = await prisma.projectEnvVar.findMany({ where: { environmentId }, orderBy: { key: 'asc' } });
      const text = toDotenv(rows.map((r) => ({ key: r.key, value: dec(r.valueEnc) })));
      const res = await serverAccess.write(env.project.serverId, { path, content: text }, actor);
      await audit({ actorId: actor.id, action: 'project.env.write_server', resourceId: projectId, environmentId, result: 'success', after: { path: res.path, count: rows.length } });
      return { path: res.path, count: rows.length };
    },

    /**
     * Pulls a .env (or similar) file from the project server over SFTP.
     * Defaults to runtime.discoveredPath/.env when path is omitted.
     */
    async pullFromServer(projectId, environmentId, { path: rawPath, import: doImport = false, markSecrets = true } = {}, actor) {
      const env = await load(projectId, environmentId);
      await can(actor, env, PERMISSIONS.PROJECT_CONFIGURE);
      if (!serverAccess?.read) throw new AppError(501, 'SSH_UNAVAILABLE', 'Server access is not configured');
      let path = rawPath;
      if (!path) {
        const runtime = await prisma.projectRuntime.findUnique({ where: { projectId } });
        const root = runtime?.metaJson?.discoveredPath;
        if (!root || typeof root !== 'string' || !root.startsWith('/')) {
          throw new AppError(409, 'PROJECT_PATH_UNKNOWN', 'No discovered project path. Provide an absolute .env path or re-run inventory.');
        }
        path = `${String(root).replace(/\/+$/, '')}/.env`;
      }
      const file = await serverAccess.read(env.project.serverId, path, actor);
      if (file.tooLarge) throw new AppError(413, 'ENV_FILE_TOO_LARGE', 'Remote .env is larger than 1 MB');
      if (file.binary || file.content == null) throw new AppError(422, 'ENV_FILE_BINARY', 'Remote file is not readable text');
      const text = String(file.content);
      const parsed = parseDotenv(text);
      let imported = null;
      if (doImport) {
        if (!parsed.vars.length) throw new AppError(422, 'ENV_IMPORT_EMPTY', 'Remote file has no KEY=VALUE lines to import');
        imported = await upsertMany(
          env,
          parsed.vars.map((v) => ({ ...v, isSecret: markSecrets && looksSecret(v.key) })),
          actor,
        );
      }
      await audit({
        actorId: actor.id,
        action: 'project.env.pull_server',
        resourceId: projectId,
        environmentId,
        result: 'success',
        after: { path: file.path, bytes: file.size, keys: parsed.vars.length, imported: Boolean(doImport) },
      });
      return {
        path: file.path,
        text,
        size: file.size,
        keys: parsed.vars.map((v) => v.key),
        guessedDb: guessDbName(parsed.vars),
        imported,
      };
    },

    /** Adds an environment (staging, development, ...) to an existing project. */
    async addEnvironment(projectId, { code, displayName }, actor) {
      if (!actor?.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can add environments');
      const project = await prisma.project.findUnique({ where: { id: projectId } });
      if (!project || project.archivedAt) throw new AppError(404, 'PROJECT_NOT_FOUND', 'Project not found');
      if (await prisma.projectEnvironment.findFirst({ where: { projectId, code } })) throw new AppError(409, 'ENVIRONMENT_EXISTS', `Environment ${code} already exists`);
      const env = await prisma.projectEnvironment.create({ data: { projectId, code, displayName } });
      await audit({ actorId: actor.id, action: 'project.environment.add', resourceId: projectId, environmentId: env.id, result: 'success', after: { code } });
      return env;
    },
  };
}
