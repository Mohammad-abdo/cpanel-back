import { prisma } from '../../config/prisma.js';
import { getDeps } from '../platform/platform.wiring.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { createAgentGatewayService } from './agent-gateway.service.js';
import { hubRef } from './agent-gateway.hub.js';
import { realtime } from './agent-gateway.realtime.js';

let service;
/** Singleton gateway service shared by the HTTP routes and the Socket.IO hub. The hub is resolved lazily (it attaches after listen). */
export function getAgentGatewayService() {
  if (!service) {
    const { auditService, platform } = getDeps();
    service = createAgentGatewayService({
      prisma,
      auditService,
      platform,
      realtime,
      serverAccessService,
      hub: {
        get available() {
          return hubRef.current?.available === true;
        },
        isConnected: (id) => hubRef.current?.isConnected(id) ?? false,
        send: (id, env) => {
          if (!hubRef.current?.available) throw new Error('socket hub unavailable');
          return hubRef.current.send(id, env);
        },
      },
    });
  }
  return service;
}
