import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { COMMAND_ARGS } from './agent-gateway.validator.js';
import { canonical, deriveAgentKeys, encryptField, sha256Hex, signEnvelope, verifyResult } from './agent-gateway.protocol.js';

const sha = (v) => createHash('sha256').update(v).digest('hex');
const OWNER_ONLY = () => new AppError(403, 'FORBIDDEN', 'Only Owner can control agents');
const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|AgentCommand/i;
const MAX_RESULT_CHARS = 16_000;

/**
 * Agent gateway (TASK-046): signs typed command envelopes, tracks them, audits every result.
 * Keys are derived per agent from AGENT_CONTROL_SECRET (HKDF), never stored. The agent credential
 * (socket token) alone cannot produce a valid envelope.
 */
export function createAgentGatewayService({ prisma, auditService = null, platform = null, hub = null, env = process.env, now = () => Date.now(), realtime = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const secret = () => {
    const s = env.AGENT_CONTROL_SECRET;
    if (!s || s.length < 32) throw new AppError(501, 'CONFIG_REQUIRED', 'AGENT_CONTROL_SECRET (32+ characters) must be configured before agents can be controlled');
    return s;
  };
  const guard = async (fn) => {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (STALE.test(String(e?.message))) throw new AppError(501, 'SCHEMA_REQUIRED', 'Agent command tables are not available until the Prisma client is regenerated');
      throw e;
    }
  };
  const keysFor = (agent, generation = agent.keyGeneration ?? 1) => deriveAgentKeys(secret(), agent.agentPublicId, generation);

  async function activeAgent(serverId) {
    const agent = await prisma.serverAgent.findFirst({ where: { serverId, revokedAt: null } });
    if (!agent) throw new AppError(404, 'AGENT_NOT_FOUND', 'No active agent on this server');
    return agent;
  }

  /** Validates args, applies the approval gate, signs and dispatches. Returns {approvalRequired} or {commandId}. */
  async function dispatch(serverId, { type, args = {}, approvalId, reason, bindingExtra = null, build }, actor) {
    if (!actor?.isOwner) throw OWNER_ONLY();
    const agent = await activeAgent(serverId);
    const action = type.startsWith('agent.') ? type : `agent.${type}`;
    const bindingArgs = canonical({ type, args, extra: bindingExtra });
    if (platform?.gate) {
      const gate = await platform.gate(
        {
          action,
          resourceType: 'server',
          resourceId: serverId,
          approvalId,
          binding: sha256Hex(bindingArgs),
          reason: reason ?? `Agent command ${type}`,
          impact: `Run agent command ${type} on the server`,
          rollbackPlan: 'Review the command audit entry and revert manually or with a compensating command',
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
    }
    if (!hub?.isConnected(agent.agentPublicId)) throw new AppError(409, 'AGENT_OFFLINE', 'Agent is not connected');
    const commandId = randomUUID();
    const keys = keysFor(agent);
    // Secrets leave the API only as AES-256-GCM fields bound to this command (never in clear on the socket).
    const built = build ? await build({ commandId, keys, agent }) : { sendArgs: args, storedArgs: args };
    const envelope = signEnvelope({ signKey: keys.signKey, agentId: agent.agentPublicId, commandId, type, args: built.sendArgs });
    await guard(() =>
      prisma.agentCommand.create({
        data: {
          id: commandId,
          serverId,
          agentPublicId: agent.agentPublicId,
          type,
          argsHash: envelope.hash,
          argsJson: built.storedArgs,
          status: 'sent',
          riskTier: null,
          approvalId: approvalId ?? null,
          requestedBy: actor.id,
          expiresAt: new Date(envelope.exp),
        },
      }),
    );
    await audit({ actorId: actor.id, action: 'agent.command.send', resourceType: 'server', resourceId: serverId, result: 'success', metadata: { commandId, type, argsHash: envelope.hash } });
    try {
      await hub.send(agent.agentPublicId, envelope);
    } catch (e) {
      await guard(() => prisma.agentCommand.updateMany({ where: { id: commandId, status: 'sent' }, data: { status: 'failed', resultJson: { error: 'DELIVERY_FAILED' }, completedAt: new Date(now()) } }));
      throw new AppError(502, 'AGENT_DELIVERY_FAILED', 'Command could not be delivered to the agent');
    }
    return { commandId, status: 'sent' };
  }

  return {
    dispatch,

    async sendCommand(serverId, body, actor) {
      const schema = COMMAND_ARGS[body.type];
      if (!schema) throw new AppError(400, 'COMMAND_UNKNOWN', 'Unknown command type');
      const parsed = schema.safeParse(body.args ?? {});
      if (!parsed.success) throw new AppError(400, 'VALIDATION_ERROR', 'Invalid command arguments');
      const args = parsed.data;
      return dispatch(
        serverId,
        {
          type: body.type,
          args,
          approvalId: body.approvalId,
          reason: body.reason,
          build: async ({ commandId, keys }) => {
            if (body.type !== 'backup.dump') return { sendArgs: args, storedArgs: args };
            const { password, ...rest } = args;
            if (rest.kind === 'mysql' || rest.kind === 'postgres') {
              if (!password || !rest.database || !rest.user) {
                throw new AppError(400, 'VALIDATION_ERROR', `${rest.kind} dump needs database, user and password`);
              }
              const passwordEnc = encryptField(keys.encKey, password, `${commandId}:passwordEnc`);
              return { sendArgs: { ...rest, passwordEnc }, storedArgs: { ...rest, passwordEnc: '[ENCRYPTED]' } };
            }
            if (!rest.sourceDir) throw new AppError(400, 'VALIDATION_ERROR', 'files backup needs sourceDir');
            return { sendArgs: rest, storedArgs: rest };
          },
        },
        actor,
      );
    },

    /** Rotation: new credential + keys travel encrypted under the OLD key; DB switches only after a verified ok result. */
    async rotateCredential(serverId, { approvalId, reason } = {}, actor) {
      if (!actor?.isOwner) throw OWNER_ONLY();
      const generation = ((await activeAgent(serverId)).keyGeneration ?? 1) + 1;
      const newKey = randomBytes(32).toString('base64url');
      return dispatch(
        serverId,
        {
          type: 'agent.rotate',
          args: {},
          approvalId,
          reason,
          bindingExtra: { generation },
          build: async ({ commandId, keys, agent }) => {
            const next = deriveAgentKeys(secret(), agent.agentPublicId, generation);
            const f = (v, n) => encryptField(keys.encKey, v, `${commandId}:${n}`);
            return {
              sendArgs: { generation, agentKeyEnc: f(newKey, 'agentKeyEnc'), signKeyEnc: f(next.signKey.toString('base64url'), 'signKeyEnc'), encKeyEnc: f(next.encKey.toString('base64url'), 'encKeyEnc') },
              storedArgs: { generation, agentKeyHash: sha(newKey) },
            };
          },
        },
        actor,
      );
    },

    async setTerminal(serverId, { enabled, approvalId, reason }, actor) {
      if (!enabled) {
        // Turning it OFF is the safe direction and needs no approval.
        return dispatchNoGate(serverId, actor, 'agent.terminal', { enabled: false });
      }
      return dispatch(serverId, { type: 'agent.terminal', args: { enabled: true }, approvalId, reason }, actor);
    },

    async status(serverId, actor) {
      if (!actor?.isOwner) throw OWNER_ONLY();
      const agent = await prisma.serverAgent.findFirst({ where: { serverId, revokedAt: null } });
      if (!agent) return { enrolled: false, connected: false };
      return {
        enrolled: true,
        connected: Boolean(hub?.isConnected(agent.agentPublicId)),
        socketAvailable: Boolean(hub?.available),
        agentId: agent.agentPublicId,
        version: agent.agentVersion ?? null,
        lastSeenAt: agent.lastSeenAt,
        keyGeneration: agent.keyGeneration ?? 1,
        terminalEnabled: Boolean(agent.terminalEnabledAt),
        controlConfigured: Boolean(env.AGENT_CONTROL_SECRET && env.AGENT_CONTROL_SECRET.length >= 32),
      };
    },

    async listCommands(serverId, { status, limit = 25 } = {}, actor) {
      if (!actor?.isOwner) throw OWNER_ONLY();
      return guard(() => prisma.agentCommand.findMany({ where: { serverId, ...(status ? { status } : {}) }, orderBy: { createdAt: 'desc' }, take: limit }));
    },

    /** Called by the hub on socket connect (after credential auth). */
    async markConnected(agent, { version } = {}) {
      await prisma.serverAgent.update({ where: { id: agent.id }, data: { lastSeenAt: new Date(now()), ...(typeof version === 'string' ? { agentVersion: version.slice(0, 40) } : {}) } }).catch(() => {});
    },

    /** Verifies the agent-signed result, updates the command, audits it. Idempotent (first result wins). */
    async recordResult(agentPublicId, msg) {
      return guard(async () => {
        const cmd = await prisma.agentCommand.findUnique({ where: { id: String(msg?.commandId ?? '') } });
        if (!cmd || cmd.agentPublicId !== agentPublicId || cmd.status !== 'sent') return { recorded: false };
        const agent = await prisma.serverAgent.findFirst({ where: { agentPublicId, revokedAt: null } });
        if (!agent) return { recorded: false };
        const generation = cmd.type === 'agent.rotate' ? cmd.argsJson?.generation : agent.keyGeneration ?? 1;
        const keys = deriveAgentKeys(secret(), agentPublicId, generation);
        if (!verifyResult(msg, { signKey: keys.signKey, agentId: agentPublicId })) {
          await audit({ action: 'agent.command.result', resourceType: 'server', resourceId: cmd.serverId, result: 'failure', metadata: { commandId: cmd.id, reason: 'BAD_RESULT_SIGNATURE' } });
          return { recorded: false };
        }
        const r = msg.result ?? {};
        const ok = r.ok === true;
        const stored = JSON.stringify(r).length > MAX_RESULT_CHARS ? { ok, exitCode: r.exitCode, error: r.error, truncated: true, stdout: String(r.stdout ?? '').slice(0, 4000), stderr: String(r.stderr ?? '').slice(0, 4000) } : r;
        const claimed = await prisma.agentCommand.updateMany({ where: { id: cmd.id, status: 'sent' }, data: { status: ok ? 'succeeded' : 'failed', resultJson: stored, completedAt: new Date(now()) } });
        if (claimed.count !== 1) return { recorded: false };
        if (ok && cmd.type === 'agent.rotate') {
          // Switch the stored credential hash only after the agent confirmed (verified with the NEW key).
          await prisma.serverAgent.update({ where: { id: agent.id }, data: { certFingerprint: cmd.argsJson.agentKeyHash, keyGeneration: cmd.argsJson.generation } });
        }
        if (ok && cmd.type === 'agent.terminal') {
          await prisma.serverAgent.update({ where: { id: agent.id }, data: { terminalEnabledAt: cmd.argsJson?.enabled ? new Date(now()) : null } });
        }
        await audit({ action: 'agent.command.result', resourceType: 'server', resourceId: cmd.serverId, result: ok ? 'success' : 'failure', metadata: { commandId: cmd.id, type: cmd.type, exitCode: r.exitCode, error: r.error ?? null, durationMs: r.durationMs } });
        realtime?.publish(`server:${cmd.serverId}`, 'agent.command', { commandId: cmd.id, type: cmd.type, ok });
        return { recorded: true, ok };
      });
    },
  };

  async function dispatchNoGate(serverId, actor, _action, args) {
    if (!actor?.isOwner) throw OWNER_ONLY();
    // Same pipeline without the approval gate (safe direction only).
    const noGate = createAgentGatewayService({ prisma, auditService, platform: null, hub, env, now, realtime });
    return noGate.dispatch(serverId, { type: 'agent.terminal', args, reason: 'Disable terminal' }, actor);
  }
}
