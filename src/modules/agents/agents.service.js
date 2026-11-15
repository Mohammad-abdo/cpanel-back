import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';

const sha = (v) => createHash('sha256').update(v).digest('hex');

export const STALE_AFTER_MS = 3 * 60 * 1000;

/** Healthy / Warning / Critical from the worst resource (required.md section 3). */
export function statusFromSummary({ cpuPercent, memPercent, diskPercent }) {
  const worst = Math.max(cpuPercent, memPercent, diskPercent);
  if (worst >= 95) return 'critical';
  if (worst >= 80) return 'warning';
  return 'healthy';
}

/**
 * Agent enrollment and read-only reporting.
 * INTERIM: agents authenticate with a secret key issued once at enrollment (its hash is stored in
 * certFingerprint). Real mTLS certificates need infrastructure and stay REQUIRES DECISION; this is not mTLS.
 */
export function createAgentsService({ prisma, now = () => new Date(), auditService = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  return {
    async enroll({ token, hostname, capabilities }) {
      const enrollment = await prisma.agentEnrollment.findUnique({ where: { tokenHash: sha(token) } });
      if (!enrollment || enrollment.usedAt || enrollment.expiresAt <= now()) {
        throw new AppError(401, 'ENROLLMENT_INVALID', 'Enrollment token invalid or expired');
      }
      const agentKey = randomBytes(32).toString('base64url');
      const agentPublicId = randomUUID();
      await prisma.$transaction(async (tx) => {
        const claimed = await tx.agentEnrollment.updateMany({
          where: { id: enrollment.id, usedAt: null },
          data: { usedAt: now() },
        });
        if (claimed.count !== 1) throw new AppError(401, 'ENROLLMENT_INVALID', 'Enrollment token already used');
        await tx.serverAgent.deleteMany({ where: { serverId: enrollment.serverId, revokedAt: { not: null } } });
        await tx.serverAgent.create({
          data: {
            serverId: enrollment.serverId,
            agentPublicId,
            certFingerprint: sha(agentKey),
            capabilitiesJson: capabilities ?? undefined,
            lastSeenAt: now(),
          },
        });
        await tx.server.update({
          where: { id: enrollment.serverId },
          data: { agentBoundAt: now(), ...(hostname ? { hostname } : {}) },
        });
      });
      await audit({
        action: 'agent.enroll',
        resourceType: 'server',
        resourceId: enrollment.serverId,
        result: 'success',
        after: { agentPublicId },
      });
      return { agentId: agentPublicId, agentKey, serverId: enrollment.serverId };
    },

    /** Resolve "Agent <agentId>.<key>" credentials; throws on any mismatch. */
    async authenticate(header) {
      const m = /^Agent ([0-9a-f-]{36})\.(\S+)$/.exec(header || '');
      if (!m) throw new AppError(401, 'AGENT_AUTH_REQUIRED', 'Agent credentials required');
      const agent = await prisma.serverAgent.findUnique({ where: { agentPublicId: m[1] } });
      const given = Buffer.from(sha(m[2]));
      const stored = Buffer.from(agent?.certFingerprint ?? '');
      if (!agent || agent.revokedAt || given.length !== stored.length || !timingSafeEqual(given, stored)) {
        throw new AppError(401, 'AGENT_AUTH_INVALID', 'Agent credentials invalid or revoked');
      }
      return agent;
    },

    async report(agent, input) {
      const capturedAt = input.capturedAt ? new Date(input.capturedAt) : now();
      const status = statusFromSummary(input);
      await prisma.$transaction(async (tx) => {
        await tx.serverSnapshot.create({
          data: {
            serverId: agent.serverId,
            capturedAt,
            summaryJson: {
              cpuPercent: input.cpuPercent,
              memPercent: input.memPercent,
              swapPercent: input.swapPercent ?? null,
              diskPercent: input.diskPercent,
              load1: input.load1 ?? null,
              uptimeSec: input.uptimeSec ?? null,
            },
          },
        });
        await tx.serverService.deleteMany({ where: { serverId: agent.serverId } });
        if (input.services.length) {
          await tx.serverService.createMany({
            data: input.services.map((s) => ({
              serverId: agent.serverId,
              name: s.name,
              manager: s.manager,
              state: s.state ?? null,
            })),
          });
        }
        await tx.serverPort.deleteMany({ where: { serverId: agent.serverId } });
        if (input.ports.length) {
          await tx.serverPort.createMany({
            data: input.ports.map((p) => ({
              serverId: agent.serverId,
              port: p.port,
              proto: p.proto,
              processHint: p.processHint ?? null,
            })),
            skipDuplicates: true,
          });
        }
        await tx.server.update({ where: { id: agent.serverId }, data: { status } });
        await tx.serverAgent.update({ where: { id: agent.id }, data: { lastSeenAt: now() } });
      });
      return { accepted: true, status };
    },

    async revoke(agentId, actor) {
      if (!actor?.isOwner) throw new AppError(403, 'FORBIDDEN', 'Only Owner can revoke agents');
      const agent = await prisma.serverAgent.findUnique({ where: { id: agentId } });
      if (!agent || agent.revokedAt) throw new AppError(404, 'AGENT_NOT_FOUND', 'Agent not found');
      const updated = await prisma.serverAgent.update({ where: { id: agentId }, data: { revokedAt: now() } });
      await audit({
        actorId: actor.id,
        action: 'agent.revoke',
        resourceType: 'server',
        resourceId: agent.serverId,
        result: 'success',
      });
      return { id: updated.id, revokedAt: updated.revokedAt };
    },
  };
}
