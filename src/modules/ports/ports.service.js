/**
 * Port reservations + free-port hints (TASK-043 / vercel-clone ports parity).
 * Listening data still comes from agent-reported ServerPort rows; reservations are control-plane holds.
 */
import { AppError } from '../../common/errors/app-error.js';
import { APP_PORT_RANGE, PLATFORM_FIXED_PORTS } from './ports.constants.js';

const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|PortReservation/i;
const schemaRequired = () =>
  new AppError(501, 'SCHEMA_REQUIRED', 'Port reservations are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');

export function createPortsService({ prisma, auditService = null }) {
  const audit = (event) => (auditService?.record ? auditService.record({ resourceType: 'port_reservation', ...event }) : null);

  const table = () => {
    if (!prisma?.portReservation) throw schemaRequired();
    return prisma.portReservation;
  };

  async function guard(fn) {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (STALE.test(String(e?.message))) throw schemaRequired();
      throw e;
    }
  }

  function requireOwner(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage port reservations');
  }

  async function requireServer(serverId) {
    const server = await prisma.server.findUnique({ where: { id: serverId } });
    if (!server || server.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
    return server;
  }

  const view = (r) => ({
    id: r.id,
    serverId: r.serverId,
    port: r.port,
    label: r.label,
    createdById: r.createdById ?? null,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
  });

  return {
    async overview(serverId, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      await requireServer(serverId);
      return guard(async () => {
        const [listening, reserved] = await Promise.all([
          prisma.serverPort.findMany({ where: { serverId }, orderBy: { port: 'asc' }, take: 500 }),
          table().findMany({ where: { serverId }, orderBy: { port: 'asc' }, take: 500 }),
        ]);
        const taken = new Set([...listening.map((p) => p.port), ...reserved.map((r) => r.port), ...PLATFORM_FIXED_PORTS]);
        const freeSample = [];
        for (let p = APP_PORT_RANGE.start; p <= APP_PORT_RANGE.end && freeSample.length < 8; p += 1) {
          if (!taken.has(p)) freeSample.push(p);
        }
        return {
          serverId,
          range: APP_PORT_RANGE,
          platformFixed: [...PLATFORM_FIXED_PORTS].sort((a, b) => a - b),
          listening: listening.map((p) => ({
            id: p.id,
            port: p.port,
            proto: p.proto,
            processHint: p.processHint ?? null,
          })),
          reserved: reserved.map(view),
          freeSample,
        };
      });
    },

    async check(serverId, port, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      await requireServer(serverId);
      return guard(async () => {
        const inAppRange = port >= APP_PORT_RANGE.start && port <= APP_PORT_RANGE.end;
        const platform = PLATFORM_FIXED_PORTS.has(port);
        const [listening, reserved] = await Promise.all([
          prisma.serverPort.findMany({ where: { serverId, port } }),
          table().findFirst({ where: { serverId, port } }),
        ]);
        const owner = reserved
          ? { type: 'reserved', name: reserved.label, reservationId: reserved.id }
          : listening[0]
            ? { type: 'listening', name: listening[0].processHint || `${listening[0].proto}/${port}` }
            : null;
        return {
          port,
          valid: true,
          inAppRange,
          platform,
          listening: listening.map((l) => ({ protocol: l.proto, process: l.processHint })),
          owner,
          free: !platform && !owner,
        };
      });
    },

    async listReservations(serverId, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      await requireServer(serverId);
      return guard(async () => (await table().findMany({ where: { serverId }, orderBy: { port: 'asc' } })).map(view));
    },

    async reserve(serverId, input, actor) {
      requireOwner(actor);
      await requireServer(serverId);
      return guard(async () => {
        if (PLATFORM_FIXED_PORTS.has(input.port)) {
          throw new AppError(400, 'PORT_PLATFORM_FIXED', `Port ${input.port} is reserved for platform infrastructure`);
        }
        const listening = await prisma.serverPort.findFirst({ where: { serverId, port: input.port } });
        if (listening) throw new AppError(409, 'PORT_IN_USE', `Port ${input.port} is already reported as listening`);
        const existing = await table().findUnique({ where: { serverId_port: { serverId, port: input.port } } }).catch(() =>
          table().findFirst({ where: { serverId, port: input.port } }),
        );
        if (existing) throw new AppError(409, 'PORT_ALREADY_RESERVED', `Port ${input.port} is already reserved`);
        const row = await table().create({
          data: { serverId, port: input.port, label: input.label.trim(), createdById: actor.id },
        });
        await audit({ actorId: actor.id, action: 'port.reserve', resourceId: row.id, result: 'success', after: { serverId, port: row.port, label: row.label } });
        return view(row);
      });
    },

    async unreserve(serverId, reservationId, actor) {
      requireOwner(actor);
      await requireServer(serverId);
      return guard(async () => {
        const row = await table().findFirst({ where: { id: reservationId, serverId } });
        if (!row) throw new AppError(404, 'PORT_RESERVATION_NOT_FOUND', 'Reservation not found');
        await table().delete({ where: { id: row.id } });
        await audit({ actorId: actor.id, action: 'port.unreserve', resourceId: row.id, result: 'success', after: { serverId, port: row.port } });
        return view(row);
      });
    },
  };
}
