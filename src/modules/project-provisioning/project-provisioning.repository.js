/**
 * TASK-053: persistence boundary for provisioning runs. Uses prisma.provisioningRun when the generated client has it
 * (table created by migration 20261118120000_provisioning_runs). With a stale client (or a missing table) it falls back to an
 * in-process Map so the flow still works; runs are then lost on API restart and `durable` is false.
 */
import { randomUUID } from 'node:crypto';

const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|ProvisioningRun/i;

export function createProvisioningRunRepository({ prisma, now = () => new Date() }) {
  const memory = new Map();
  let useMemory = !prisma?.provisioningRun;

  async function attempt(dbFn, memFn) {
    if (!useMemory) {
      try {
        return await dbFn(prisma.provisioningRun);
      } catch (e) {
        if (!STALE.test(String(e?.message))) throw e;
        useMemory = true;
      }
    }
    return memFn();
  }

  return {
    get durable() {
      return !useMemory;
    },
    create(data) {
      return attempt(
        (t) => t.create({ data }),
        () => {
          const row = { id: randomUUID(), createdAt: now(), updatedAt: now(), projectId: null, contextJson: null, rollbackNote: null, ...data };
          memory.set(row.id, row);
          return row;
        },
      );
    },
    find(id) {
      return attempt(
        (t) => t.findUnique({ where: { id } }),
        () => memory.get(id) ?? null,
      );
    },
    update(id, data) {
      return attempt(
        (t) => t.update({ where: { id }, data }),
        () => {
          const row = memory.get(id);
          if (!row) return null;
          Object.assign(row, data, { updatedAt: now() });
          return row;
        },
      );
    },
    list({ projectId, serverId, limit = 30 } = {}) {
      return attempt(
        (t) => t.findMany({ where: { ...(projectId ? { projectId } : {}), ...(serverId ? { serverId } : {}) }, orderBy: { createdAt: 'desc' }, take: limit }),
        () =>
          [...memory.values()]
            .filter((r) => (!projectId || r.projectId === projectId) && (!serverId || r.serverId === serverId))
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
            .slice(0, limit),
      );
    },
  };
}
