import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { fakeModel } from '../phase3-helpers.js';
import { hashPassword } from '../../src/common/crypto/password.js';

/** Flatten Prisma compound-unique selectors (teamId_userId: {teamId, userId}) into plain fields. */
function flatten(where = {}) {
  const out = {};
  for (const [k, v] of Object.entries(where)) {
    if (/^[a-zA-Z]+_[a-zA-Z_]+$/.test(k) && v && typeof v === 'object' && !(v instanceof Date)) Object.assign(out, v);
    else out[k] = v;
  }
  return out;
}

/**
 * In-memory Prisma double for HTTP integration tests. One instance per test file (module isolation).
 * Wraps the shared fakeModel with compound-key selectors, a few relation filters/includes,
 * and `$transaction`. `reset()` clears every table between tests.
 */
export function createFakePrisma() {
  const models = {};
  const tables = () => models;

  const wrapModel = (name) => {
    const base = fakeModel([]);
    const prep = (args = {}) => {
      const where = flatten(args.where ?? {});
      // team.members.some.userId -> id in (teamMember rows for that user)
      if (name === 'team' && where.members?.some) {
        const ids = proxy.teamMember.rows.filter((m) => m.userId === where.members.some.userId).map((m) => m.teamId);
        delete where.members;
        where.id = { in: ids };
      }
      return { ...args, where };
    };
    const include = (row, args = {}) => {
      if (row && args.select) return Object.fromEntries(Object.keys(args.select).filter((k) => args.select[k]).map((k) => [k, row[k]]));
      if (!row || !args.include) return row;
      const out = { ...row };
      if (name === 'session' && args.include.user) {
        const user = proxy.user.rows.find((u) => u.id === row.userId) ?? null;
        out.user = user && {
          ...user,
          mfaFactors: proxy.mfaFactor.rows.filter((f) => f.userId === user.id && f.verifiedAt != null).map((f) => ({ id: f.id })),
        };
      }
      if (name === 'auditEvent' && args.include.actor) {
        const a = proxy.user.rows.find((u) => u.id === row.actorId);
        out.actor = a ? { id: a.id, displayName: a.displayName, email: a.email } : null;
      }
      if (name === 'project' && args.include.runtime) out.runtime = proxy.projectRuntime.rows.find((r) => r.projectId === row.id) ?? null;
      if (name === 'projectEnvironment' && args.include.project) out.project = proxy.project.rows.find((r) => r.id === row.projectId) ?? null;
      return out;
    };
    return {
      ...base,
      findUnique: async (a) => include(await base.findUnique(prep(a)), a),
      findFirst: async (a) => include(await base.findFirst(prep(a)), a),
      findMany: async (a = {}) => (await base.findMany({ ...prep(a), take: undefined })).slice(0, a.take ?? undefined).map((r) => include(r, a)),
      count: (a) => base.count(prep(a)),
      update: (a) => base.update(prep(a)),
      updateMany: (a) => base.updateMany(prep(a)),
      upsert: (a) => base.upsert(prep(a)),
      delete: (a) => base.delete(prep(a)),
      deleteMany: (a) => base.deleteMany(prep(a)),
      create: async (a) => base.create({ ...a, data: { ...a.data } }),
    };
  };

  const proxy = new Proxy(
    {},
    {
      get(_t, name) {
        if (name === 'then' || typeof name === 'symbol') return undefined;
        if (name === '$transaction') return async (fn) => (typeof fn === 'function' ? fn(proxy) : Promise.all(fn));
        if (name === '$disconnect' || name === '$connect') return async () => {};
        if (name === '__reset') return () => Object.keys(models).forEach((k) => { models[k].rows.length = 0; });
        if (!models[name]) models[name] = wrapModel(name);
        return models[name];
      },
    },
  );
  void tables;
  return proxy;
}

export const sha = (v) => createHash('sha256').update(v).digest('hex');
export const PASSWORD = 'correct-horse-battery';

/** Seed a user (password PASSWORD unless overridden). Returns the stored row. */
export async function seedUser(prisma, over = {}) {
  const id = over.id ?? randomUUID();
  return prisma.user.create({
    data: {
      id,
      email: over.email ?? `${id.slice(0, 8)}@example.test`,
      displayName: over.displayName ?? 'Test User',
      passwordHash: hashPassword(over.password ?? PASSWORD),
      status: 'active',
      disabledAt: null,
      ownerFlag: false,
      ...over.fields,
      ...(over.ownerFlag != null ? { ownerFlag: over.ownerFlag } : {}),
      ...(over.status ? { status: over.status } : {}),
      ...(over.disabledAt ? { disabledAt: over.disabledAt } : {}),
    },
  });
}

/** Seed a session; returns { token, session } where token is the raw bearer value. */
export async function seedSession(prisma, user, over = {}) {
  const token = randomBytes(24).toString('base64url');
  const session = await prisma.session.create({
    data: {
      userId: user.id,
      tokenHash: sha(token),
      expiresAt: over.expiresAt ?? new Date(Date.now() + 3600_000),
      revokedAt: over.revokedAt ?? null,
      mfaSatisfied: over.mfaSatisfied ?? true,
    },
  });
  return { token, session };
}

export const bearer = (token) => ({ Authorization: `Bearer ${token}` });
