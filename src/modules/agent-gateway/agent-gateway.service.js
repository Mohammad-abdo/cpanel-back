import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';
import { COMMAND_ARGS } from './agent-gateway.validator.js';
import { parseRecoverOutput, RECOVER_SCRIPT } from './agent-gateway.recover.js';
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
export function createAgentGatewayService({
  prisma,
  auditService = null,
  platform = null,
  hub = null,
  env = process.env,
  now = () => Date.now(),
  realtime = null,
  serverAccessService = null,
  connectWaitMs = 20_000,
}) {
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

    /** Fleet view: every server’s agent version + live socket presence (vercel-clone agents/info parity). */
    async fleetOverview(actor) {
      if (!actor?.isOwner) throw OWNER_ONLY();
      const controlConfigured = Boolean(env.AGENT_CONTROL_SECRET && env.AGENT_CONTROL_SECRET.length >= 32);
      const servers = await prisma.server.findMany({
        where: { archivedAt: null },
        orderBy: { alias: 'asc' },
        take: 200,
        include: {
          agent: {
            select: {
              agentPublicId: true,
              agentVersion: true,
              lastSeenAt: true,
              revokedAt: true,
              keyGeneration: true,
              terminalEnabledAt: true,
            },
          },
        },
      });
      const rows = servers.map((s) => {
        const agent = s.agent && !s.agent.revokedAt ? s.agent : null;
        return {
          serverId: s.id,
          alias: s.alias,
          hostname: s.hostname,
          enrolled: Boolean(agent),
          connected: agent ? Boolean(hub?.isConnected(agent.agentPublicId)) : false,
          version: agent?.agentVersion ?? null,
          lastSeenAt: agent?.lastSeenAt ?? null,
          keyGeneration: agent?.keyGeneration ?? null,
          terminalEnabled: Boolean(agent?.terminalEnabledAt),
        };
      });
      return {
        socketAvailable: Boolean(hub?.available),
        controlConfigured,
        totals: {
          servers: rows.length,
          enrolled: rows.filter((r) => r.enrolled).length,
          connected: rows.filter((r) => r.connected).length,
        },
        servers: rows,
      };
    },

    async listCommands(serverId, { status, limit = 25 } = {}, actor) {
      if (!actor?.isOwner) throw OWNER_ONLY();
      return guard(() => prisma.agentCommand.findMany({ where: { serverId, ...(status ? { status } : {}) }, orderBy: { createdAt: 'desc' }, take: limit }));
    },

    /**
     * Restart an offline agent over SSH (systemd unit or PM2). High risk / Owner MFA.
     * No-op success when the agent socket is already connected.
     */
    async recoverAgent(serverId, { approvalId, reason } = {}, actor) {
      if (!actor?.isOwner) throw OWNER_ONLY();
      const agent = await activeAgent(serverId);
      if (hub?.isConnected(agent.agentPublicId)) {
        return { ok: true, alreadyConnected: true, connected: true, steps: [{ step: 'socket', ok: true, detail: 'already connected' }] };
      }
      if (platform?.gate) {
        const gate = await platform.gate(
          {
            action: 'agent.recover',
            resourceType: 'server',
            resourceId: serverId,
            approvalId,
            binding: sha256Hex(canonical({ type: 'agent.recover', serverId })),
            reason: reason ?? 'Recover offline exec agent over SSH',
            impact: 'Restart the NodeTeam exec agent (systemd or PM2) on the server',
            rollbackPlan: 'Stop the agent unit or PM2 process if the restart is unwanted',
          },
          actor,
        );
        if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      }
      if (!serverAccessService?.runRemote) throw new AppError(500, 'SSH_UNAVAILABLE', 'Server access is not wired');
      const res = await serverAccessService.runRemote(serverId, ({ run }) =>
        run(RECOVER_SCRIPT, { timeoutMs: 90_000, maxBytes: 64 * 1024 }),
      );
      if (res.timedOut) throw new AppError(504, 'AGENT_RECOVER_TIMEOUT', 'Agent recovery over SSH timed out');
      const parsed = parseRecoverOutput(res.stdout);
      if (!parsed) {
        await audit({
          actorId: actor.id,
          action: 'agent.recover',
          resourceType: 'server',
          resourceId: serverId,
          result: 'failure',
          metadata: { failure: 'watchdog-failed', stderr: String(res.stderr ?? '').slice(0, 400) },
        });
        throw new AppError(502, 'AGENT_RECOVER_FAILED', 'Recovery script returned no usable result');
      }
      let connected = Boolean(hub?.isConnected(agent.agentPublicId));
      if (parsed.ok && !connected && connectWaitMs > 0) {
        const deadline = now() + connectWaitMs;
        while (now() < deadline) {
          await new Promise((r) => setTimeout(r, 1000));
          if (hub?.isConnected(agent.agentPublicId)) {
            connected = true;
            break;
          }
        }
      }
      await audit({
        actorId: actor.id,
        action: 'agent.recover',
        resourceType: 'server',
        resourceId: serverId,
        result: parsed.ok ? 'success' : 'failure',
        metadata: {
          method: parsed.method ?? null,
          failure: parsed.failure ?? null,
          connected,
          steps: parsed.steps ?? [],
        },
      });
      realtime?.publish(`server:${serverId}`, 'agent.state', { connected, recovering: false });
      return {
        ok: Boolean(parsed.ok),
        failure: parsed.failure,
        error: parsed.error,
        method: parsed.method,
        steps: parsed.steps ?? [],
        connected,
      };
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
