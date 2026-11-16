import { AppError } from '../../common/errors/app-error.js';
import { createMailAccess, guardSchema, mailDelegate, provisioningState } from '../../common/mail-support.js';
import { sha256 } from '../platform/platform.crypto.js';
import {
  MAIL_FIREWALL_PORTS,
  PROVISION_STEPS,
  PROVISION_STEP_ORDER,
  ROLLBACK_NOTES,
  WEBMAIL_PORT,
  assertSafeArgs,
  evaluateHealth,
  evaluatePrerequisites,
  firewallScript,
  firewallStatusScript,
  healthScript,
  parseKeyValues,
  preflightScript,
  stepScript,
} from '../../common/mail-provision.scripts.js';

/** Mail ports. Opening them is a separate CRITICAL approval (mail.firewall.open); 2096 only when webmail is enabled. */
export const MAIL_PORTS = Object.freeze([
  { port: 25, protocol: 'smtp', role: 'Inbound SMTP (receive)' },
  { port: 465, protocol: 'smtps', role: 'Submission (implicit TLS)' },
  { port: 587, protocol: 'submission', role: 'Submission (STARTTLS)' },
  { port: 993, protocol: 'imaps', role: 'IMAPS' },
  { port: 2096, protocol: 'https', role: 'Webmail (TASK-037)' },
]);

/** Pure planner: the exact ordered steps apply runs. The firewall is a separate CRITICAL action (never part of apply). */
export function planProvisioning({ serverAlias, mailHostname }) {
  const host = mailHostname ?? '<mail hostname>';
  return [
    { id: 'preflight', title: 'Preflight checks', detail: 'Read-only: OS version, root, ports 25/465/587/993, existing MTA, ufw state, free disk', risk: 'low', requiresApproval: false },
    ...PROVISION_STEPS.map((st) => ({ ...st, detail: st.id === 'postfix' ? `myhostname=${host}; ${st.detail}` : st.detail, requiresApproval: true })),
    { id: 'health', title: 'Health probe', detail: 'Services active, ports listening, open-relay self-test must be rejected', risk: 'low', requiresApproval: false },
  ].map((st) => ({ ...st, server: serverAlias }));
}

export function createMailServerService({ prisma, now = () => new Date(), auditService = null, rbac = null, platform = null, config = {}, ssh = null }) {
  const audit = (event) => (auditService?.record ? auditService.record(event) : null);
  const access = createMailAccess({ prisma, rbac, now });
  const killSwitch = () => provisioningState(config).killSwitch;
  const killCheck = () => {
    if (killSwitch()) throw new AppError(403, 'MAIL_PROVISIONING_DISABLED', 'Mail remote actions are disabled by the operator kill switch (MAIL_PROVISIONING_DISABLED=true).');
  };
  const requireExecutor = () => {
    if (!ssh?.runRemote) throw new AppError(501, 'MAIL_EXECUTOR_NOT_IMPLEMENTED', 'No SSH executor is wired for mail provisioning');
  };
  const runSession = (serverId, fn) => ssh.runRemote(serverId, fn);
  const firewallPorts = (webmail) => (webmail ? [...MAIL_FIREWALL_PORTS, WEBMAIL_PORT] : [...MAIL_FIREWALL_PORTS]);

  async function persist(serverId, row, data) {
    const d = mailDelegate(prisma, 'serverMailService');
    return guardSchema(() => (row ? d.update({ where: { serverId }, data }) : d.upsert({ where: { serverId }, create: { serverId, ...data }, update: data })));
  }

  const ownerOnly = (actor) => {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (!actor.isOwner) throw new AppError(403, 'OWNER_ONLY', 'Only the Owner can manage the server mail service');
  };

  const view = (server, row, domainsEnabled) => ({
    serverId: server.id,
    serverAlias: server.alias,
    status: row?.status ?? 'disabled',
    provisioned: row?.provisioned ?? false,
    mailHostname: row?.mailHostname ?? null,
    stackVersion: row?.stackVersion ?? null,
    lastHealthAt: row?.lastHealthAt ?? null,
    plannedPorts: MAIL_PORTS,
    domainsEnabled,
    provisioning: provisioningState(config),
    lastProvision: row?.lastHealthJson?.provision ?? null,
  });

  async function countEnabled(serverId) {
    try {
      if (!prisma.domainMailConfig?.count) return { count: 0, pending: true };
      return { count: await prisma.domainMailConfig.count({ where: { enabled: true, domain: { serverId } } }) };
    } catch {
      return { count: 0, pending: true };
    }
  }

  async function current(serverId) {
    if (!prisma.serverMailService?.findUnique) return { row: null, pending: true };
    try {
      return { row: await prisma.serverMailService.findUnique({ where: { serverId } }) };
    } catch (e) {
      if (/doesn't exist|does not exist|Unknown/i.test(String(e?.message))) return { row: null, pending: true };
      throw e;
    }
  }

  return {
    async get(serverId, actor) {
      const server = await access.requireServerVisible(actor, serverId);
      const { row, pending } = await current(serverId);
      const enabled = await countEnabled(serverId);
      const out = view(server, row, enabled.count);
      return pending || enabled.pending ? { ...out, schemaPending: true } : out;
    },

    /** Records intent only. Never installs or configures anything. */
    async enable(serverId, { mailHostname }, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      const d = mailDelegate(prisma, 'serverMailService');
      const row = await guardSchema(() =>
        d.upsert({
          where: { serverId },
          create: { serverId, status: 'enabled', mailHostname: mailHostname ?? null, portsJson: MAIL_PORTS.map((p) => p.port) },
          update: { status: 'enabled', ...(mailHostname ? { mailHostname } : {}) },
        }),
      );
      await audit({ actorId: actor.id, action: 'mail.server.enable', resourceType: 'server', resourceId: serverId, result: 'success', after: { status: 'enabled', mailHostname: mailHostname ?? null, provisioned: row?.provisioned ?? false } });
      return view(server, row, (await countEnabled(serverId)).count);
    },

    async disable(serverId, { reason }, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      const d = mailDelegate(prisma, 'serverMailService');
      const existing = await guardSchema(() => d.findUnique({ where: { serverId } }));
      if (!existing) throw new AppError(404, 'MAIL_SERVICE_NOT_FOUND', 'Mail service is not enabled for this server');
      const row = await guardSchema(() => d.update({ where: { serverId }, data: { status: 'disabled' } }));
      await audit({ actorId: actor.id, action: 'mail.server.disable', resourceType: 'server', resourceId: serverId, result: 'success', metadata: { reason: reason ?? null } });
      return view(server, row, (await countEnabled(serverId)).count);
    },

    /** Stored health only (any viewer). The live probe is POST /mail/health/probe (Owner). */
    async health(serverId, actor) {
      const server = await access.requireServerVisible(actor, serverId);
      const { row } = await current(serverId);
      const stored = row?.lastHealthJson?.health ?? null;
      return {
        serverId: server.id,
        checked: Boolean(row?.lastHealthAt),
        lastHealthAt: row?.lastHealthAt ?? null,
        probe: stored ? 'STORED' : 'NOT_RUN',
        ok: stored?.ok ?? null,
        checks: stored?.checks ?? [],
        openRelay: stored?.openRelay ?? 'unknown',
        tls: stored?.tls ?? 'unknown',
        services: { postfix: 'unknown', dovecot: 'unknown', opendkim: 'unknown' },
        ports: MAIL_PORTS.map((p) => ({ port: p.port, state: 'unknown' })),
        detail: row?.lastHealthJson?.provision ?? null,
      };
    },

    /** Live read-only probe over SSH: services, ports, open-relay self-test. Stores the result. */
    async probeHealth(serverId, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      killCheck();
      requireExecutor();
      const { row } = await current(serverId);
      const health = await runSession(serverId, async (s) => evaluateHealth(parseKeyValues((await s.run(healthScript(), { timeoutMs: 60_000 })).stdout)));
      await persist(serverId, row, { lastHealthAt: now(), lastHealthJson: { ...(row?.lastHealthJson ?? {}), health, checkedAt: now().toISOString() }, ...(health.stackVersion ? { stackVersion: health.stackVersion } : {}) });
      await audit({ actorId: actor.id, action: 'mail.health.probe', resourceType: 'server', resourceId: serverId, result: health.ok ? 'success' : 'failure', metadata: { checks: health.checks.map((c) => ({ id: c.id, pass: c.pass })) } });
      return { serverId, serverAlias: server.alias, ...health, checkedAt: now() };
    },

    /** Read-only plan plus a read-only SSH probe of prerequisites. Nothing is changed on the server. */
    async previewProvision(serverId, { mailHostname }, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      const { row } = await current(serverId);
      const host = mailHostname ?? row?.mailHostname ?? null;
      const steps = planProvisioning({ serverAlias: server.alias, mailHostname: host });
      let prerequisites = { available: false, reason: ssh?.runRemote ? 'probe_failed' : 'no_executor' };
      if (ssh?.runRemote && !killSwitch()) {
        try {
          const kv = await runSession(serverId, async (s) => parseKeyValues((await s.run(preflightScript(), { timeoutMs: 30_000 })).stdout));
          prerequisites = { available: true, detected: kv, ...evaluatePrerequisites(kv) };
        } catch (e) {
          prerequisites = { available: false, reason: 'probe_failed', error: e?.code ?? 'SSH_ERROR' };
        }
      }
      return {
        serverId,
        serverAlias: server.alias,
        mailHostname: host,
        steps,
        prerequisites,
        rollbackNotes: ROLLBACK_NOTES,
        impact: ['Installs Postfix, Dovecot, OpenDKIM and Rspamd', 'Adds an internet-facing MTA (attack surface)', 'Opening firewall ports is a separate CRITICAL approval (Open mail ports)'],
        executes: false,
        provisioning: provisioningState(config),
      };
    },

    /** Approval-gated (HIGH). Typed alias confirmation, second-person approval, then step-by-step apply under the SSH lock. */
    async applyProvision(serverId, input, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      if (killSwitch()) {
        await audit({ actorId: actor.id, action: 'mail.provision.apply', resourceType: 'server', resourceId: serverId, result: 'denied', metadata: { reason: 'kill_switch' } });
        killCheck();
      }
      if (input.confirmAlias !== server.alias) throw new AppError(422, 'CONFIRM_ALIAS_MISMATCH', 'Type the exact server alias to confirm provisioning');
      const { row } = await current(serverId);
      const host = input.mailHostname ?? row?.mailHostname ?? null;
      if (!host) throw new AppError(422, 'MAIL_HOSTNAME_REQUIRED', 'A mail hostname is required to provision');
      const steps = planProvisioning({ serverAlias: server.alias, mailHostname: host });
      if (!platform?.gate) throw new AppError(500, 'GATE_UNAVAILABLE', 'Approval service is not wired');
      const gate = await platform.gate(
        {
          action: 'mail.provision.apply',
          binding: sha256(JSON.stringify(PROVISION_STEP_ORDER.concat([serverId, host]))),
          resourceType: 'server',
          resourceId: serverId,
          approvalId: input.approvalId,
          reason: input.reason,
          impact: steps.filter((s) => s.requiresApproval).map((s) => s.title),
          rollbackPlan: input.rollbackNote ?? ROLLBACK_NOTES[2],
          context: { host },
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      requireExecutor();

      const results = [];
      let failedStep = null;
      let stackVersion = null;
      let health = null;
      const mark = (id, status, detail = null) => results.push({ id, status, detail, at: now().toISOString() });
      try {
        await runSession(serverId, async (s) => {
          const kv = parseKeyValues((await s.run(preflightScript(), { timeoutMs: 30_000 })).stdout);
          const pre = evaluatePrerequisites(kv);
          if (!pre.ok) {
            mark('preflight', 'failed', pre.blockers.join('; ').slice(0, 400));
            failedStep = 'preflight';
            return;
          }
          mark('preflight', 'ok', pre.warnings.join('; ') || null);
          for (const id of PROVISION_STEP_ORDER) {
            let res;
            try {
              // services waits up to ~15s per unit; packages can take several minutes on first apt.
              const timeoutMs = id === 'packages' ? 900_000 : id === 'services' ? 300_000 : 120_000;
              res = await s.run(stepScript(id), { args: assertSafeArgs([host]), timeoutMs });
            } catch (e) {
              mark(id, 'failed', String(e?.code ?? 'SSH_ERROR'));
              failedStep = id;
              return;
            }
            if (res.timedOut || res.code !== 0) {
              mark(id, 'failed', res.timedOut ? 'timed out' : String(res.stderr || `exit ${res.code}`).trim().slice(0, 240));
              failedStep = id;
              return;
            }
            const out = parseKeyValues(res.stdout);
            if (out.stack_version) stackVersion = out.stack_version;
            mark(id, 'ok', out.tls ? `tls=${out.tls}` : null);
          }
          try {
            health = evaluateHealth(parseKeyValues((await s.run(healthScript(), { timeoutMs: 60_000 })).stdout));
            mark('health', health.ok ? 'ok' : 'warning', health.checks.filter((c) => !c.pass).map((c) => c.id).join(', ') || null);
          } catch (e) {
            mark('health', 'warning', String(e?.code ?? 'SSH_ERROR'));
          }
        });
      } catch (e) {
        if (!failedStep) {
          failedStep = 'session';
          mark('session', 'failed', String(e?.code ?? e?.message ?? 'SSH_ERROR').slice(0, 240));
        }
      }
      const ok = failedStep === null;
      // Soft-fail: put the single-use approval back so Finish / Apply now can retry.
      if (!ok && input.approvalId && platform.releaseFailedExecution) {
        await platform.releaseFailedExecution(input.approvalId, actor);
      }
      await persist(serverId, row, {
        status: ok ? 'enabled' : 'error',
        provisioned: ok ? true : (row?.provisioned ?? false),
        mailHostname: host,
        ...(stackVersion ? { stackVersion } : {}),
        lastHealthAt: now(),
        lastHealthJson: { provision: { steps: results, failedStep, at: now().toISOString() }, ...(health ? { health } : {}) },
      });
      await audit({ actorId: actor.id, action: 'mail.provision.apply', resourceType: 'server', resourceId: serverId, result: ok ? 'success' : 'failure', metadata: { host, failedStep, steps: results.map((r) => ({ id: r.id, status: r.status })) } });
      return { approvalRequired: false, ok, serverId, mailHostname: host, steps: results, failedStep, stackVersion, health, rollbackNotes: failedStep ? ROLLBACK_NOTES : [] };
    },

    /** Firewall plan: exactly the allow rules that would be added. Read-only. */
    async previewFirewall(serverId, { webmail = false }, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      const ports = firewallPorts(webmail);
      let state = { available: false, reason: ssh?.runRemote ? 'probe_failed' : 'no_executor' };
      if (ssh?.runRemote && !killSwitch()) {
        try {
          const kv = await runSession(serverId, async (s) => parseKeyValues((await s.run(firewallStatusScript(), { args: assertSafeArgs(ports.map(String)), timeoutMs: 30_000 })).stdout));
          state = { available: true, ufw: kv.ufw, rules: ports.map((p) => ({ port: p, state: kv[`rule_${p}`] ?? 'unknown' })) };
        } catch (e) {
          state = { available: false, reason: 'probe_failed', error: e?.code ?? 'SSH_ERROR' };
        }
      }
      return {
        serverId,
        serverAlias: server.alias,
        ports,
        state,
        impact: [`Adds ufw allow rules for TCP ${ports.join(', ')}`, 'Exposes the mail services to the internet', 'Never enables ufw, never changes or removes any other rule'],
        risk: 'critical',
        executes: false,
      };
    },

    /** Approval-gated (CRITICAL). Only adds the mail allow rules; reports when ufw is inactive instead of enabling it. */
    async applyFirewall(serverId, input, actor) {
      ownerOnly(actor);
      const server = await access.requireServerVisible(actor, serverId);
      killCheck();
      if (input.confirmAlias !== server.alias) throw new AppError(422, 'CONFIRM_ALIAS_MISMATCH', 'Type the exact server alias to confirm opening mail ports');
      const { row } = await current(serverId);
      if (!row?.provisioned) throw new AppError(409, 'MAIL_NOT_PROVISIONED', 'Provision the mail stack before opening its ports');
      const ports = firewallPorts(input.webmail === true);
      if (!platform?.gate) throw new AppError(500, 'GATE_UNAVAILABLE', 'Approval service is not wired');
      const gate = await platform.gate(
        {
          action: 'mail.firewall.open',
          binding: sha256(JSON.stringify(['fw', serverId, ...ports])),
          resourceType: 'server',
          resourceId: serverId,
          approvalId: input.approvalId,
          reason: input.reason,
          impact: [`Allow inbound TCP ${ports.join(', ')} (mail)`],
          rollbackPlan: input.rollbackNote ?? `ufw delete allow <port>/tcp for each of ${ports.join(', ')}`,
          context: { ports },
        },
        actor,
      );
      if (!gate.proceed) return { approvalRequired: true, approval: gate.approval };
      requireExecutor();
      const kv = await runSession(serverId, async (s) => {
        const res = await s.run(firewallScript(), { args: assertSafeArgs(ports.map(String)), timeoutMs: 60_000 });
        if (res.timedOut || res.code !== 0) throw new AppError(502, 'MAIL_FIREWALL_FAILED', 'Firewall command failed on the server');
        return parseKeyValues(res.stdout);
      });
      const applied = kv.ufw === 'active';
      await audit({ actorId: actor.id, action: 'mail.firewall.open', resourceType: 'server', resourceId: serverId, result: applied ? 'success' : 'skipped', metadata: { ports, ufw: kv.ufw ?? 'unknown', changed: kv.changed ?? 'no' } });
      return {
        approvalRequired: false,
        serverId,
        ports,
        ufw: kv.ufw ?? 'unknown',
        changed: kv.changed === 'yes',
        applied,
        note: applied ? null : `ufw is ${kv.ufw ?? 'unknown'}: nothing was changed. The panel never enables a firewall; open the ports in your own firewall.`,
      };
    },
  };
}
