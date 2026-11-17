import { prisma } from '../../config/prisma.js';
import { createScope } from '../../common/scope.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { createAgentsService } from '../agents/agents.service.js';
import { createAuditService } from '../audit/audit.service.js';
import { attachAgentGateway } from './agent-gateway.hub.js';
import { getAgentGatewayService } from './agent-gateway.wiring.js';

/** Resolves a Bearer session token through the same middleware the HTTP API uses (MFA, expiry, disabled users). */
export function authenticateSessionToken(token, middleware = requireSession()) {
  return new Promise((resolve, reject) => {
    const req = { get: (h) => (String(h).toLowerCase() === 'authorization' && token ? `Bearer ${token}` : '') };
    middleware(req, null, (err) => (err ? reject(err) : resolve(req.user)));
  });
}

/** Called once from server.js after listen(). Never throws: a failure only disables realtime. */
export async function startAgentGateway(httpServer) {
  try {
    return await attachAgentGateway(httpServer, {
      agentsService: createAgentsService({ prisma, auditService: createAuditService({ prisma }) }),
      gateway: getAgentGatewayService(),
      authenticateSession: (token) => authenticateSessionToken(token),
      scope: createScope({ prisma }),
      getDeploymentProjectId: async (id) => (await prisma.deployment.findUnique({ where: { id }, select: { projectId: true } }))?.projectId ?? null,
    });
  } catch (e) {
    console.error('agent gateway failed to start:', e?.message);
    return null;
  }
}
