import { AppError } from '../../common/errors/app-error.js';
import { assertCan } from '../platform/platform.service.js';
import { PERM } from '../platform/platform.risk.js';
import { createScope } from '../../common/scope.js';
import { sha256 } from '../platform/platform.crypto.js';
import { lockoutProblems, portReachable } from './firewall.ufw.js';

/** Management ports that must stay reachable. Removing them risks locking everyone out. */
export const PROTECTED_PORTS = [22];
export const SENSITIVE_PORTS = [3306, 5432, 6379, 27017, 11211];
const SHARED_PORTS = { 80: 'HTTP for every site on this server', 443: 'HTTPS for every site on this server', 3306: 'MySQL used by all databases on this server' };
export const MAX_WINDOW_MS = 4 * 3600 * 1000;

const key = (r) => `${r.port}/${r.proto ?? 'tcp'}`;

/** Pure evaluation of a proposed change set against the current rules. */
export function evaluate(current, changes, ctx = {}) {
  const live = ctx.sshPort != null; // real executor: guard uses the SSH port in use and the panel address
  const protectedPorts = live ? [ctx.sshPort] : PROTECTED_PORTS;
  const next = current.map((r) => ({ ...r, proto: r.proto ?? 'tcp' }));
  const diff = [];
  for (const c of changes) {
    if (c.op === 'delete') {
      const i = next.findIndex((r) => (key(r) === key(c) || (r.proto === 'any' && r.port === c.port)) && r.source === c.source);
      if (i >= 0) next.splice(i, 1);
      diff.push(`- ${c.port}/${c.proto} from ${c.source}`);
    } else if (live && next.some((r) => r.port === c.port && (r.proto === c.proto || r.proto === 'any') && r.source === c.source && r.action === c.op)) {
      diff.push(`= ${c.op} ${c.port}/${c.proto} from ${c.source} (already present)`);
    } else {
      next.push({ action: c.op, port: c.port, proto: c.proto, source: c.source });
      diff.push(`+ ${c.op} ${c.port}/${c.proto} from ${c.source}`);
    }
  }
  const problems = [];
  if (live) {
    let probe = next;
    if (ctx.enable && ctx.active === false && !portReachable(next, ctx.sshPort, ctx.panelIp, ctx.defaultIncoming)) {
      probe = [{ action: 'allow', port: ctx.sshPort, proto: 'tcp', source: 'any' }, ...next];
      diff.push(`+ allow ${ctx.sshPort}/tcp from any (SSH, added before enabling the firewall)`);
    }
    problems.push(...lockoutProblems(probe, { sshPort: ctx.sshPort, panelIp: ctx.panelIp, defaultIncoming: ctx.defaultIncoming, active: ctx.active !== false || Boolean(ctx.enable) }));
    if (ctx.enable && ctx.active === false) diff.push('+ enable firewall (default deny incoming)');
  }
  for (const p of live ? [] : protectedPorts) {
    const open = next.some((r) => r.port === p && r.action === 'allow');
    const denied = next.some((r) => r.port === p && r.action === 'deny' && r.source === 'any');
    if (!open || denied) problems.push({ code: 'LOCKOUT_RISK', message: `Port ${p} would no longer be reachable for management` });
  }
  for (const c of changes) {
    if (c.op === 'allow' && c.source === 'any' && SENSITIVE_PORTS.includes(c.port)) {
      problems.push({ code: 'SENSITIVE_EXPOSURE', message: `Port ${c.port} must not be open to any source` });
    }
  }
  const impact = [];
  for (const c of changes) if (SHARED_PORTS[c.port]) impact.push(`Port ${c.port}: ${SHARED_PORTS[c.port]}`);
  const touchesProtected = changes.some((c) => protectedPorts.includes(c.port)) || Boolean(ctx.enable);
  return { diff, problems, impact, touchesProtected, next };
}

export function createFirewallService({ prisma, now = () => new Date(), auditService = null, rbac = null, platform = null, adapters = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);

  async function loadServer(serverId, actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    const s = await prisma.server.findUnique({ where: { id: serverId } });
    if (!s || s.archivedAt) throw new AppError(404, 'SERVER_NOT_FOUND', 'Server not found');
    await assertCan(rbac, actor, { permissionKey: PERM.FIREWALL, resourceType: 'server', resourceId: serverId, environmentId: null });
    return s;
  }

  const scope = createScope({ prisma, now });

  /** Rules plus guard context. The real executor reads both in one SSH session; the simulated one has no context. */
  async function readState(serverId) {
    if (adapters.firewall.snapshot) return adapters.firewall.snapshot(serverId);
    return { rules: await adapters.firewall.list(serverId), context: {} };
  }

  return {
    /** Read-only history of firewall changes from the audit trail, for visible servers. */
    async history({ serverId, limit }, actor) {
      if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
      const idClause = await scope.serverClause(actor, serverId);
      const rows = await prisma.auditEvent.findMany({
        where: { action: { startsWith: 'firewall.change' }, resourceType: 'server', ...(idClause ? { resourceId: idClause } : {}) },
        take: limit,
        orderBy: { occurredAt: 'desc' },
        select: { id: true, action: true, result: true, resourceId: true, actorId: true, occurredAt: true, afterJson: true, approvalRequestId: true, correlationId: true },
      });
      const ids = [...new Set(rows.map((r) => r.resourceId).filter(Boolean))];
      const servers = ids.length ? await prisma.server.findMany({ where: { id: { in: ids } }, select: { id: true, alias: true } }) : [];
      const alias = new Map(servers.map((s) => [s.id, s.alias]));
      return rows.map(({ afterJson, ...r }) => ({ ...r, serverAlias: alias.get(r.resourceId) ?? null, diff: afterJson?.diff ?? null }));
    },

    async rules(serverId, actor) {
      await loadServer(serverId, actor);
      return adapters.firewall.list(serverId);
    },

    /** Live state for the UI: rules plus firewall status, SSH port in use and the executor kind. */
    async state(serverId, actor) {
      await loadServer(serverId, actor);
      const snap = await readState(serverId);
      return { rules: snap.rules, ...snap.context, executor: adapters.firewall.kind ?? 'simulated', simulated: Boolean(adapters.simulated) && adapters.firewall.kind !== 'ssh' };
    },

    async preview(serverId, { changes, enable = false }, actor) {
      await loadServer(serverId, actor);
      const snap = await readState(serverId);
      const current = snap.rules;
      const ev = evaluate(current, changes, { ...snap.context, enable: Boolean(enable) });
      const risk = ev.touchesProtected ? 'critical' : 'high';
      return { diff: ev.diff, problems: ev.problems, impact: ev.impact, risk, safe: ev.problems.length === 0, simulated: Boolean(adapters.simulated) && adapters.firewall.kind !== 'ssh', executor: adapters.firewall.kind ?? 'simulated', rulesBefore: current, rulesAfter: ev.next };
    },

    async apply(serverId, input, actor) {
      await loadServer(serverId, actor);
      const start = new Date(input.windowStart).getTime();
      const end = new Date(input.windowEnd).getTime();
      if (!(end > start) || end - start > MAX_WINDOW_MS) throw new AppError(422, 'WINDOW_INVALID', 'Maintenance window must be positive and at most 4 hours');
      if (now().getTime() < start || now().getTime() > end) throw new AppError(409, 'OUTSIDE_MAINTENANCE_WINDOW', 'Firewall changes can only be applied inside the approved maintenance window');
      const snap = await readState(serverId);
      const current = snap.rules;
      const enable = Boolean(input.enable);
      const ev = evaluate(current, input.changes, { ...snap.context, enable });
      if (ev.problems.length) {
        await audit({ actorId: actor.id, action: 'firewall.change', resourceType: 'server', resourceId: serverId, result: 'denied', metadata: { problems: ev.problems.map((p) => p.code) } });
        throw new AppError(422, ev.problems[0].code, ev.problems[0].message);
      }
      const action = ev.touchesProtected ? 'firewall.change.sensitive' : 'firewall.change';
      const gate = await platform.gate(
        { action, binding: sha256(JSON.stringify({ changes: input.changes, ...(enable ? { enable } : {}), windowStart: new Date(start).toISOString(), windowEnd: new Date(end).toISOString() })), resourceType: 'server', resourceId: serverId, approvalId: input.approvalId, reason: input.reason, impact: [...ev.diff, ...ev.impact, `Window ${input.windowStart} to ${input.windowEnd}`], rollbackPlan: input.rollbackNote, context: { window: [input.windowStart, input.windowEnd] } },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      const applied = await adapters.firewall.apply({ serverId, changes: input.changes, enable });
      // Lockout guard: if the server stops answering after the change, revert immediately.
      let reachable = false;
      try {
        reachable = Boolean((await adapters.fleet.probe(serverId)).reachable);
      } catch {
        reachable = false;
      }
      if (!reachable) {
        let rolledBack = true;
        try {
          await adapters.firewall.rollback({ serverId, rollbackToken: applied.rollbackToken });
        } catch {
          rolledBack = false; // unreachable: the server-side dead-man switch restores the rules by itself
        }
        await audit({ actorId: actor.id, action: 'firewall.change', resourceType: 'server', resourceId: serverId, result: 'failure', metadata: { rolledBack, deadman: !rolledBack, reason: 'unreachable_after_change' }, before: { rules: current } });
        if (!rolledBack) throw new AppError(409, 'LOCKOUT_DEADMAN_PENDING', `Server did not answer after the change; the dead-man switch restores the previous rules within ${applied.deadmanSeconds ?? 120} seconds`);
        throw new AppError(409, 'LOCKOUT_ROLLED_BACK', 'Server became unreachable after the change; the previous rules were restored');
      }
      if (adapters.firewall.confirm) await adapters.firewall.confirm({ serverId, rollbackToken: applied.rollbackToken });
      await audit({ actorId: actor.id, action: 'firewall.change', resourceType: 'server', resourceId: serverId, result: 'success', before: { rules: current }, after: { diff: ev.diff, rules: applied.after ?? ev.next, noop: applied.noop || undefined } });
      return { applied: true, rollbackToken: applied.rollbackToken, diff: ev.diff, simulated: Boolean(adapters.simulated) && adapters.firewall.kind !== 'ssh', executor: adapters.firewall.kind ?? 'simulated' };
    },
  };
}
