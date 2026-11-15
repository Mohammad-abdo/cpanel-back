import { randomUUID } from 'node:crypto';

/** Minimal in-memory Prisma double for service tests (equality, in, comparisons, OR/AND, contains). */
function matchValue(actual, cond) {
  if (cond === null) return actual === null || actual === undefined;
  if (cond instanceof Date) return actual instanceof Date && actual.getTime() === cond.getTime();
  if (typeof cond === 'object' && !Array.isArray(cond)) {
    return Object.entries(cond).every(([op, v]) => {
      const a = actual instanceof Date ? actual.getTime() : actual;
      const b = v instanceof Date ? v.getTime() : v;
      switch (op) {
        case 'in': return v.includes(actual);
        case 'notIn': return !v.includes(actual);
        case 'not': return v === null ? actual != null : !matchValue(actual, v);
        case 'gt': return a != null && a > b;
        case 'gte': return a != null && a >= b;
        case 'lt': return a != null && a < b;
        case 'lte': return a != null && a <= b;
        case 'contains': return typeof actual === 'string' && actual.toLowerCase().includes(String(v).toLowerCase());
        case 'startsWith': return typeof actual === 'string' && actual.startsWith(v);
        case 'equals': return actual === v;
        default: return false;
      }
    });
  }
  return actual === cond;
}

export function matches(row, where = {}) {
  return Object.entries(where).every(([k, cond]) => {
    if (k === 'OR') return cond.some((w) => matches(row, w));
    if (k === 'AND') return (Array.isArray(cond) ? cond : [cond]).every((w) => matches(row, w));
    if (k === 'NOT') return !matches(row, cond);
    return matchValue(row[k], cond);
  });
}

function applyData(row, data) {
  for (const [k, v] of Object.entries(data)) {
    row[k] = v && typeof v === 'object' && 'increment' in v ? (row[k] ?? 0) + v.increment : v;
  }
}

export function fakeModel(seed = [], { defaults = () => ({}) } = {}) {
  const rows = seed.map((r) => ({ ...r }));
  const find = (args = {}) => rows.filter((r) => matches(r, args.where));
  const orderBy = (list, ob) => {
    if (!ob) return list;
    const [[k, dir]] = Object.entries(Array.isArray(ob) ? ob[0] : ob);
    return [...list].sort((a, b) => (a[k] > b[k] ? 1 : a[k] < b[k] ? -1 : 0) * (dir === 'desc' ? -1 : 1));
  };
  return {
    rows,
    findUnique: async (args) => find(args)[0] ?? null,
    findFirst: async (args) => orderBy(find(args), args?.orderBy)[0] ?? null,
    findMany: async (args = {}) => {
      const list = orderBy(find(args), args.orderBy);
      return args.take ? list.slice(0, args.take) : list;
    },
    count: async (args = {}) => find(args).length,
    create: async ({ data }) => {
      const row = { id: randomUUID(), createdAt: new Date(), ...defaults(), ...data };
      rows.push(row);
      return row;
    },
    createMany: async ({ data }) => {
      for (const d of data) rows.push({ id: randomUUID(), createdAt: new Date(), ...defaults(), ...d });
      return { count: data.length };
    },
    update: async ({ where, data }) => {
      const row = find({ where })[0];
      if (!row) throw new Error('record not found');
      applyData(row, data);
      return row;
    },
    updateMany: async ({ where, data }) => {
      const list = find({ where });
      list.forEach((r) => applyData(r, data));
      return { count: list.length };
    },
    upsert: async ({ where, create, update }) => {
      const row = find({ where })[0];
      if (row) {
        applyData(row, update);
        return row;
      }
      const made = { id: randomUUID(), createdAt: new Date(), ...create };
      rows.push(made);
      return made;
    },
    delete: async ({ where }) => {
      const row = find({ where })[0];
      rows.splice(rows.indexOf(row), 1);
      return row;
    },
    deleteMany: async ({ where }) => {
      const list = find({ where });
      list.forEach((r) => rows.splice(rows.indexOf(r), 1));
      return { count: list.length };
    },
  };
}

/** Builds a prisma double whose models are created lazily; `seed` maps model name -> rows. */
export function fakePrisma(seed = {}) {
  const models = {};
  return new Proxy(
    {},
    {
      get(_t, name) {
        if (name === 'then') return undefined;
        if (name === '$transaction') return async (fn) => (typeof fn === 'function' ? fn(this) : Promise.all(fn));
        if (!models[name]) models[name] = fakeModel(seed[name] ?? []);
        return models[name];
      },
    },
  );
}

export const U = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
