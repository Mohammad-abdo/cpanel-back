import { realtime } from './agent-gateway.realtime.js';

/** Holder the service wiring reads lazily (the hub attaches after the HTTP server is listening). */
export const hubRef = { current: null };

const ROOM = /^(server|deployment|alerts):([0-9a-f-]{36})$/i;
const PM2_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const REQUIRE_ANY_STATUS_ERROR = (cb) => cb({ ok: false, error: 'FORBIDDEN' });

export function pm2Room(serverId, appName) {
  return `pm2:${serverId}:${appName}`;
}

/**
 * Pure-ish hub factory (io injected so tests use a fake). Two namespaces:
 *  /agents  agent credential auth (handshake.auth {agentId,key,version}); receives signed `command`, emits `result`/`stats`/`pm2:log`.
 *  /rt      browser realtime; authenticates with the existing Bearer session token (handshake.auth.token);
 *           `subscribe` {room} joins server:<id> | deployment:<id> | alerts:<serverId> after a scope check;
 *           `pm2:logs:subscribe` / `pm2:logs:unsubscribe` join pm2:<serverId>:<app> and ask the agent to start/stop the bus.
 */
export function createHub({ io, agentsService, gateway, authenticateSession, scope, getDeploymentProjectId, log = console.warn, sendTimeoutMs = 15_000 }) {
  const agents = new Map(); // agentPublicId -> socket
  const agentByServer = new Map(); // serverId -> agentPublicId
  const pm2Subs = new Map(); // room -> subscriber count
  const agentNs = io.of('/agents');
  const rtNs = io.of('/rt');

  const tellAgent = (serverId, event, payload) => {
    const publicId = agentByServer.get(serverId);
    const sock = publicId ? agents.get(publicId) : null;
    if (sock) sock.emit(event, payload);
  };

  const bumpPm2 = (room, delta, serverId, appName) => {
    const next = Math.max(0, (pm2Subs.get(room) ?? 0) + delta);
    if (next === 0) {
      pm2Subs.delete(room);
      tellAgent(serverId, 'pm2:logs:stop', { appName });
    } else {
      pm2Subs.set(room, next);
      if (delta > 0 && next === 1) tellAgent(serverId, 'pm2:logs:start', { appName });
    }
    return next;
  };

  agentNs.use(async (socket, next) => {
    try {
      const { agentId, key } = socket.handshake?.auth ?? {};
      const agent = await agentsService.authenticate(`Agent ${agentId}.${key}`);
      socket.data.agent = agent;
      next();
    } catch {
      next(new Error('AGENT_AUTH_INVALID'));
    }
  });

  agentNs.on('connection', (socket) => {
    const agent = socket.data.agent;
    const previous = agents.get(agent.agentPublicId);
    if (previous && previous !== socket) previous.disconnect(true);
    agents.set(agent.agentPublicId, socket);
    agentByServer.set(agent.serverId, agent.agentPublicId);
    gateway.markConnected(agent, { version: socket.handshake?.auth?.version }).catch(() => {});
    realtime.publish(`server:${agent.serverId}`, 'agent.state', { connected: true });

    // Resume any open PM2 log subscriptions after reconnect.
    for (const [room, count] of pm2Subs) {
      if (count < 1 || !room.startsWith(`pm2:${agent.serverId}:`)) continue;
      const appName = room.slice(`pm2:${agent.serverId}:`.length);
      if (PM2_NAME.test(appName)) socket.emit('pm2:logs:start', { appName });
    }

    socket.on('result', (msg) => {
      gateway.recordResult(agent.agentPublicId, msg).catch((e) => log('agent result failed', e?.message));
    });
    let lastStats = 0;
    socket.on('stats', (stats) => {
      const t = Date.now();
      if (t - lastStats < 5000 || !stats || typeof stats !== 'object') return;
      lastStats = t;
      realtime.publish(`server:${agent.serverId}`, 'agent.stats', {
        cpuPercent: Number(stats.cpuPercent) || 0,
        memPercent: Number(stats.memPercent) || 0,
        load1: Number(stats.load1) || 0,
        uptimeSec: Number(stats.uptimeSec) || 0,
      });
    });
    socket.on('pm2:log', (payload) => {
      const appName = typeof payload?.appName === 'string' ? payload.appName : '';
      if (!PM2_NAME.test(appName)) return;
      const line = typeof payload?.line === 'string' ? payload.line.slice(0, 4000) : '';
      if (!line) return;
      const stream = payload?.stream === 'stderr' ? 'stderr' : 'stdout';
      realtime.publish(pm2Room(agent.serverId, appName), 'pm2.log', { appName, stream, line, serverId: agent.serverId });
    });
    socket.on('disconnect', () => {
      if (agents.get(agent.agentPublicId) === socket) agents.delete(agent.agentPublicId);
      if (agentByServer.get(agent.serverId) === agent.agentPublicId) agentByServer.delete(agent.serverId);
      realtime.publish(`server:${agent.serverId}`, 'agent.state', { connected: false });
    });
  });

  rtNs.use(async (socket, next) => {
    try {
      socket.data.user = await authenticateSession(socket.handshake?.auth?.token);
      next();
    } catch {
      next(new Error('AUTH_REQUIRED'));
    }
  });

  rtNs.on('connection', (socket) => {
    /** Rooms this browser socket has opened so disconnect can release agent stream refcounts. */
    const heldPm2 = new Set();

    socket.on('subscribe', async (payload, cb = () => {}) => {
      try {
        const m = ROOM.exec(String(payload?.room ?? ''));
        if (!m) return cb({ ok: false, error: 'BAD_ROOM' });
        const [, kind, id] = m;
        const actor = socket.data.user;
        let allowed = false;
        if (kind === 'server' || kind === 'alerts') allowed = await scope.canSeeServer(actor, id);
        else if (kind === 'deployment') {
          const projectId = await getDeploymentProjectId(id);
          allowed = projectId ? await scope.canSeeProject(actor, projectId) : false;
        }
        if (!allowed) return REQUIRE_ANY_STATUS_ERROR(cb); // same answer for unknown and out-of-scope ids
        await socket.join(`${kind}:${id}`);
        cb({ ok: true });
      } catch {
        cb({ ok: false, error: 'SUBSCRIBE_FAILED' });
      }
    });
    socket.on('unsubscribe', (payload) => {
      if (ROOM.test(String(payload?.room ?? ''))) socket.leave(payload.room);
    });

    socket.on('pm2:logs:subscribe', async (payload, cb = () => {}) => {
      try {
        const serverId = String(payload?.serverId ?? '');
        const appName = String(payload?.appName ?? '');
        if (!/^[0-9a-f-]{36}$/i.test(serverId) || !PM2_NAME.test(appName)) return cb({ ok: false, error: 'BAD_ROOM' });
        const allowed = await scope.canSeeServer(socket.data.user, serverId);
        if (!allowed) return REQUIRE_ANY_STATUS_ERROR(cb);
        const room = pm2Room(serverId, appName);
        await socket.join(room);
        if (!heldPm2.has(room)) {
          heldPm2.add(room);
          bumpPm2(room, 1, serverId, appName);
        }
        const live = Boolean(agentByServer.get(serverId) && agents.has(agentByServer.get(serverId)));
        cb({ ok: true, live, room });
      } catch {
        cb({ ok: false, error: 'SUBSCRIBE_FAILED' });
      }
    });

    socket.on('pm2:logs:unsubscribe', (payload) => {
      const serverId = String(payload?.serverId ?? '');
      const appName = String(payload?.appName ?? '');
      if (!/^[0-9a-f-]{36}$/i.test(serverId) || !PM2_NAME.test(appName)) return;
      const room = pm2Room(serverId, appName);
      socket.leave(room);
      if (heldPm2.delete(room)) bumpPm2(room, -1, serverId, appName);
    });

    socket.on('disconnect', () => {
      for (const room of heldPm2) {
        const parts = /^pm2:([0-9a-f-]{36}):(.+)$/i.exec(room);
        if (parts) bumpPm2(room, -1, parts[1], parts[2]);
      }
      heldPm2.clear();
    });
  });

  const hub = {
    available: true,
    isConnected: (agentPublicId) => agents.has(agentPublicId),
    send(agentPublicId, envelope) {
      const socket = agents.get(agentPublicId);
      if (!socket) return Promise.reject(Object.assign(new Error('Agent offline'), { code: 'AGENT_OFFLINE' }));
      return new Promise((resolve, reject) => {
        socket.timeout(sendTimeoutMs).emit('command', envelope, (err, ack) => {
          if (err) return reject(err);
          if (ack?.commandId) gateway.recordResult(agentPublicId, ack).catch(() => {});
          resolve(true);
        });
      });
    },
    publish: (room, event, payload) => rtNs.to(room).emit(event, payload),
  };
  realtime.attach(hub.publish);
  hubRef.current = hub;
  return hub;
}

/**
 * Mounts Socket.IO on the existing HTTP server. When the socket.io package is absent, logs once and returns an
 * unavailable hub: HTTP routes keep working (agent commands answer 409 AGENT_OFFLINE) and the web falls back to polling.
 */
export async function attachAgentGateway(httpServer, deps, { importer = () => import('socket.io'), log = console.info } = {}) {
  let Server;
  try {
    ({ Server } = await importer());
  } catch {
    log('socket.io is not installed: agent gateway and realtime are disabled (polling fallback in effect)');
    hubRef.current = { available: false, isConnected: () => false };
    return hubRef.current;
  }
  const io = new Server(httpServer, { path: '/socket.io', serveClient: false, maxHttpBufferSize: 256 * 1024, transports: ['websocket', 'polling'] });
  return createHub({ io, ...deps });
}
