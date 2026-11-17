import { randomBytes } from 'node:crypto';
import { AppError } from '../../common/errors/app-error.js';

/**
 * TASK-051 real ufw executor (SSH). Everything here is either a pure function (parsers, guards, script builders; unit
 * tested with fixtures) or a thin runner that sends a FIXED script over the existing server-access SSH session.
 * The default executor stays `simulated`; this one is only used when FIREWALL_EXECUTOR=ssh.
 *
 * Safety model:
 *  - allowlisted verbs only: allow | deny | limit | delete. `ufw reset`, `ufw disable`, raw strings: never accepted.
 *  - every value is validated (port 1-65535, tcp|udp, IPv4 or IPv4/CIDR or any, comment charset) then single-quoted.
 *  - lockout guard: first-match evaluation of the resulting rule list must still allow the SSH port in use (read from
 *    $SSH_CONNECTION of the live session) for the panel's source address.
 *  - delete is by rule specification (never by number, which races with concurrent edits) and is idempotent.
 *  - `ufw --force enable` only when `enable` is requested, the firewall is inactive, and the SSH allow rule exists first.
 *  - dead-man switch: before any change the rule files are backed up and a revert is scheduled (systemd-run timer, else
 *    `at`; if neither exists the apply is refused). The caller confirms after a fresh SSH connectivity check, which
 *    cancels the timer. If the check fails the timer restores the backup (or runs `ufw --force disable`).
 */

export const UFW_OPS = Object.freeze(['allow', 'deny', 'limit', 'delete']);
export const DEADMAN_MIN_SECONDS = 60;
export const DEADMAN_DEFAULT_SECONDS = 120;
export const STATE_DIR = '/var/lib/nt-ufw';

const TOKEN_RE = /^[a-f0-9]{16}$/;
export const newToken = () => randomBytes(8).toString('hex');
const assertToken = (t) => {
  if (!TOKEN_RE.test(String(t))) throw new AppError(422, 'UFW_TOKEN_INVALID', 'Invalid rollback token');
  return t;
};
const shq = (a) => `'${String(a).replace(/'/g, `'\\''`)}'`;

// ---------- validation ----------

export const SOURCE_RE = /^(any|(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?)$/;
export const COMMENT_RE = /^[A-Za-z0-9 _.,:@#()+-]{1,120}$/;

export function parseSource(src) {
  if (src === 'any' || src == null) return { any: true };
  const m = /^((?:\d{1,3}\.){3}\d{1,3})(?:\/(\d{1,2}))?$/.exec(String(src));
  if (!m) return null;
  const parts = m[1].split('.').map(Number);
  if (parts.some((p) => p > 255)) return null;
  const prefix = m[2] === undefined ? 32 : Number(m[2]);
  if (prefix > 32) return null;
  const n = (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
  return { any: false, n, prefix, text: m[2] === undefined ? m[1] : `${m[1]}/${prefix}` };
}

export function sourceContains(src, ip) {
  const s = parseSource(src);
  if (!s) return false;
  if (s.any) return true;
  const t = parseSource(ip);
  if (!t || t.any) return false;
  const mask = s.prefix === 0 ? 0 : (0xffffffff << (32 - s.prefix)) >>> 0;
  return ((s.n & mask) >>> 0) === ((t.n & mask) >>> 0);
}

/** Throws unless a change is fully valid and allowlisted. Returns a normalised copy. */
export function assertSafeChange(c) {
  const op = String(c?.op ?? '');
  if (op === 'reset') throw new AppError(422, 'UFW_RESET_REFUSED', 'ufw reset is never allowed');
  if (!UFW_OPS.includes(op)) throw new AppError(422, 'UFW_OP_NOT_ALLOWED', `Firewall action ${op || '(none)'} is not allowlisted`);
  const port = Number(c.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new AppError(422, 'UFW_PORT_INVALID', 'Port must be 1-65535');
  const proto = c.proto ?? 'tcp';
  if (proto !== 'tcp' && proto !== 'udp') throw new AppError(422, 'UFW_PROTO_INVALID', 'Protocol must be tcp or udp');
  const source = c.source ?? 'any';
  const ps = parseSource(source);
  if (!ps) throw new AppError(422, 'UFW_SOURCE_INVALID', 'Source must be any, an IPv4 address or an IPv4 CIDR');
  if (c.comment !== undefined && !COMMENT_RE.test(c.comment)) throw new AppError(422, 'UFW_COMMENT_INVALID', 'Comment contains unsupported characters');
  const action = c.action ?? 'allow';
  if (!['allow', 'deny', 'limit'].includes(action)) throw new AppError(422, 'UFW_OP_NOT_ALLOWED', 'Rule action must be allow, deny or limit');
  return { op, port, proto, source: ps.any ? 'any' : ps.text, comment: c.comment, action };
}

/** The ufw argument vector for one change, e.g. ['allow','proto','tcp','from','1.2.3.4','to','any','port','80']. */
export function ruleArgs(change, { resolvedAction = null } = {}) {
  const c = assertSafeChange(change);
  const verb = c.op === 'delete' ? ['delete', resolvedAction ?? c.action] : [c.op];
  const spec = c.source === 'any' ? [`${c.port}/${c.proto}`] : ['proto', c.proto, 'from', c.source, 'to', 'any', 'port', String(c.port)];
  const tail = c.op !== 'delete' && c.comment ? ['comment', c.comment] : [];
  return [...verb, ...spec, ...tail];
}

// ---------- parsing ----------

export const STATUS_SCRIPT = [
  'SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"',
  "echo '##conn'; echo \"${SSH_CONNECTION:-}\"",
  "echo '##ufw'; if command -v ufw >/dev/null 2>&1; then echo present; else echo missing; fi",
  "echo '##verbose'; $SUDO ufw status verbose 2>&1",
  "echo '##numbered'; $SUDO ufw status numbered 2>&1",
  "echo '##end'",
].join('\n');

function sections(text) {
  const out = {};
  let cur = null;
  for (const line of String(text).replace(/\r/g, '').split('\n')) {
    const m = /^##(\w+)$/.exec(line);
    if (m) {
      cur = m[1];
      out[cur] = [];
    } else if (cur) out[cur].push(line);
  }
  return out;
}

/** Parses `ufw status numbered` rows. IPv6 mirror rows and non-inbound rows are skipped. */
export function parseNumbered(lines) {
  const rules = [];
  for (const raw of lines) {
    const m = /^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(IN|OUT|FWD))?\s+(.+?)\s*$/.exec(raw);
    if (!m) continue;
    const [, num, to, verb, dir, fromRaw] = m;
    if (/\(v6\)/.test(to) || /\(v6\)/.test(fromRaw)) continue;
    if (dir && dir !== 'IN') continue;
    const from = fromRaw.replace(/\s+#.*$/, '').replace(/\s+on\s+\S+$/, '').trim();
    const pm = /^(\d+(?::\d+)?(?:,\d+)*)(?:\/(tcp|udp))?$/.exec(to.trim());
    const source = /^Anywhere$/i.test(from) ? 'any' : from;
    const action = verb.toLowerCase();
    if (!pm) {
      rules.push({ number: Number(num), action, port: null, proto: 'any', source, raw: raw.trim() });
      continue;
    }
    const proto = pm[2] ?? 'any';
    for (const part of pm[1].split(',')) {
      const range = /^(\d+):(\d+)$/.exec(part);
      rules.push({ number: Number(num), action, port: Number(range ? range[1] : part), ...(range ? { portEnd: Number(range[2]) } : {}), proto, source });
    }
  }
  return rules;
}

/** Full state from the STATUS_SCRIPT output. */
export function parseUfwState(stdout, { fallbackSshPort = 22 } = {}) {
  const s = sections(stdout);
  const conn = (s.conn?.[0] ?? '').trim().split(/\s+/);
  const panelIp = parseSource(conn[0]) && !parseSource(conn[0]).any ? conn[0] : null;
  const connPort = Number(conn[3]);
  const sshPort = Number.isInteger(connPort) && connPort > 0 ? connPort : fallbackSshPort;
  const verbose = (s.verbose ?? []).join('\n');
  const installed = (s.ufw?.[0] ?? '').trim() === 'present';
  const active = /^Status:\s*active/im.test(verbose);
  const def = /^Default:\s*(\w+)\s*\(incoming\)/im.exec(verbose);
  return {
    installed,
    active,
    defaultIncoming: def ? def[1].toLowerCase() : 'deny',
    rules: parseNumbered(s.numbered ?? []),
    sshPort,
    panelIp,
  };
}

// ---------- lockout guard ----------

const protoMatches = (rp, p) => rp === 'any' || rp === p;
const portMatches = (r, port) => r.port != null && port >= r.port && port <= (r.portEnd ?? r.port);

/** First-match ufw evaluation: is `port/tcp` reachable from `ip` under these ordered rules? */
export function portReachable(rules, port, ip, defaultIncoming = 'deny') {
  for (const r of rules) {
    if (!portMatches(r, port) || !protoMatches(r.proto ?? 'tcp', 'tcp')) continue;
    const srcOk = r.source === 'any' || (ip ? sourceContains(r.source, ip) : false);
    if (!srcOk) continue;
    return r.action === 'allow' || r.action === 'limit';
  }
  return defaultIncoming === 'allow';
}

/**
 * Applies `changes` to an ordered rule list the way ufw would (appends; deletes by spec) and returns
 * { next, skipped }. Idempotent: an existing identical rule is not added twice.
 */
export function applyToRules(rules, changes) {
  const next = rules.map((r) => ({ ...r }));
  const skipped = [];
  for (const raw of changes) {
    const c = assertSafeChange(raw);
    const same = (r) => r.port === c.port && (r.proto === c.proto || r.proto === 'any') && r.source === c.source;
    if (c.op === 'delete') {
      const i = next.findIndex((r) => same(r) && (raw.action ? r.action === c.action : true));
      if (i < 0) skipped.push({ ...c, reason: 'absent' });
      else next.splice(i, 1);
    } else if (next.some((r) => same(r) && r.action === c.op)) skipped.push({ ...c, reason: 'present' });
    else next.push({ action: c.op, port: c.port, proto: c.proto, source: c.source });
  }
  return { next, skipped };
}

/** Returns a list of problems; empty means the change keeps SSH (and the panel address) reachable. */
export function lockoutProblems(nextRules, { sshPort, panelIp, defaultIncoming = 'deny', active = true }) {
  if (!active) return [];
  if (!portReachable(nextRules, sshPort, panelIp, defaultIncoming)) {
    return [{ code: 'LOCKOUT_RISK', message: `SSH port ${sshPort}/tcp would no longer be reachable${panelIp ? ` from the panel address ${panelIp}` : ''}` }];
  }
  return [];
}

// ---------- scripts ----------

const SUDO_PRELUDE = 'SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"';

/** Revert script stored on the server and run by the dead-man timer (or by an explicit rollback). Fixed text per token. */
export function buildRevertScript(token, { wasActive }) {
  assertToken(token);
  const d = `${STATE_DIR}/${token}`;
  return [
    '#!/bin/sh',
    `D=${d}`,
    '[ -f "$D/user.rules" ] && cp -a "$D/user.rules" /etc/ufw/user.rules',
    '[ -f "$D/user6.rules" ] && cp -a "$D/user6.rules" /etc/ufw/user6.rules',
    wasActive ? 'ufw --force reload || ufw --force disable' : 'ufw --force disable',
    'touch "$D/reverted"',
  ].join('\n');
}

/**
 * The apply script. `commands` is an array of ufw argument vectors from ruleArgs(). Order of operations:
 * 1 arm the dead-man switch (abort before touching rules if impossible), 2 apply rules, 3 optional enable with SSH
 * allow guaranteed first. Output markers: NT_DEADMAN, NT_ERR, NT_OK.
 */
export function buildApplyScript({ token, commands, sshPort, enable = false, wasActive, seconds = DEADMAN_DEFAULT_SECONDS }) {
  assertToken(token);
  if (!Number.isInteger(sshPort) || sshPort < 1 || sshPort > 65535) throw new AppError(422, 'UFW_PORT_INVALID', 'SSH port invalid');
  const secs = Math.max(DEADMAN_MIN_SECONDS, Math.floor(seconds));
  const mins = Math.ceil(secs / 60);
  const d = `${STATE_DIR}/${token}`;
  const revert = buildRevertScript(token, { wasActive });
  const lines = [
    'set -u',
    SUDO_PRELUDE,
    `D=${d}`,
    '$SUDO mkdir -p "$D" && $SUDO chmod 700 "$D" || { echo "NT_ERR state_dir"; exit 10; }',
    '$SUDO cp -a /etc/ufw/user.rules "$D/user.rules" || { echo "NT_ERR backup"; exit 10; }',
    '$SUDO cp -a /etc/ufw/user6.rules "$D/user6.rules" 2>/dev/null || true',
    `printf '%s\\n' ${shq(revert)} | $SUDO tee "$D/revert.sh" >/dev/null && $SUDO chmod 700 "$D/revert.sh" || { echo "NT_ERR revert_script"; exit 10; }`,
    'ARMED=""',
    `if command -v systemd-run >/dev/null 2>&1 && $SUDO systemd-run --on-active=${secs}s --unit=nt-ufw-revert-${token} /bin/sh "$D/revert.sh" >/dev/null 2>&1; then ARMED=systemd; fi`,
    `if [ -z "$ARMED" ] && command -v at >/dev/null 2>&1; then J=$(printf '/bin/sh %s\\n' "$D/revert.sh" | $SUDO at now + ${mins} minutes 2>&1 | sed -n 's/^job \\([0-9]*\\) .*/\\1/p' | head -1); if [ -n "$J" ]; then printf '%s' "$J" | $SUDO tee "$D/atjob" >/dev/null; ARMED=at; fi; fi`,
    '[ -n "$ARMED" ] || { echo "NT_ERR no_deadman"; exit 11; }',
    'echo "NT_DEADMAN $ARMED"',
  ];
  for (const argv of commands) lines.push(`$SUDO ufw ${argv.map(shq).join(' ')} || { echo "NT_ERR rule"; exit 12; }`);
  if (enable && !wasActive) {
    lines.push(
      `$SUDO ufw show added 2>/dev/null | grep -Eq '^ufw (allow|limit) ${sshPort}(/tcp)?$' || $SUDO ufw allow ${shq(`${sshPort}/tcp`)} || { echo "NT_ERR ssh_allow"; exit 13; }`,
      `$SUDO ufw show added 2>/dev/null | grep -Eq '^ufw (allow|limit) ${sshPort}(/tcp)?$' || { echo "NT_ERR ssh_allow_missing"; exit 13; }`,
      '$SUDO ufw --force enable || { echo "NT_ERR enable"; exit 14; }',
    );
  }
  lines.push('echo "NT_OK"');
  return lines.join('\n');
}

/** Cancels the dead-man timer and removes the state directory (after a successful connectivity check). */
export function buildConfirmScript(token) {
  assertToken(token);
  const d = `${STATE_DIR}/${token}`;
  return [
    SUDO_PRELUDE,
    `D=${d}`,
    '[ -f "$D/reverted" ] && { echo "NT_REVERTED"; exit 20; }',
    `$SUDO systemctl stop nt-ufw-revert-${token}.timer >/dev/null 2>&1 || true`,
    '[ -f "$D/atjob" ] && $SUDO atrm "$(cat "$D/atjob")" >/dev/null 2>&1 || true',
    '$SUDO rm -rf "$D"',
    'echo "NT_CONFIRMED"',
  ].join('\n');
}

/** Runs the stored revert now, cancels the timer, removes state. */
export function buildRollbackScript(token) {
  assertToken(token);
  const d = `${STATE_DIR}/${token}`;
  return [
    SUDO_PRELUDE,
    `D=${d}`,
    '[ -f "$D/revert.sh" ] || { echo "NT_ERR no_state"; exit 21; }',
    '[ -f "$D/reverted" ] || $SUDO /bin/sh "$D/revert.sh"',
    `$SUDO systemctl stop nt-ufw-revert-${token}.timer >/dev/null 2>&1 || true`,
    '[ -f "$D/atjob" ] && $SUDO atrm "$(cat "$D/atjob")" >/dev/null 2>&1 || true',
    '$SUDO rm -rf "$D"',
    'echo "NT_ROLLED_BACK"',
  ].join('\n');
}

// ---------- executor ----------

/**
 * Executor implementing the firewall adapter interface (list/apply/rollback) plus snapshot/confirm/probe.
 * `runRemote(serverId, fn)` is serverAccessService.runRemote (serialised SSH session, closed afterwards).
 * `probe(serverId)` must open a FRESH connection (a new login proves the SSH path still works).
 */
export function createUfwExecutor({ runRemote, probeSsh, deadmanSeconds = DEADMAN_DEFAULT_SECONDS }) {
  async function readState(run) {
    const res = await run(STATUS_SCRIPT, { timeoutMs: 30_000 });
    if (res.timedOut) throw new AppError(504, 'UFW_TIMEOUT', 'Reading the firewall state timed out');
    const state = parseUfwState(res.stdout);
    if (!state.installed) throw new AppError(409, 'UFW_NOT_INSTALLED', 'ufw is not installed on this server');
    if (/ERROR|must be root|password is required/i.test(res.stdout) && state.rules.length === 0 && !state.active) {
      throw new AppError(502, 'UFW_PRIVILEGE', 'The SSH user cannot run ufw (root or passwordless sudo required)');
    }
    return state;
  }

  return {
    simulated: false,
    kind: 'ssh',

    async snapshot(serverId) {
      const state = await runRemote(serverId, ({ run }) => readState(run));
      return { rules: state.rules, context: { sshPort: state.sshPort, panelIp: state.panelIp, defaultIncoming: state.defaultIncoming, active: state.active } };
    },

    async list(serverId) {
      return (await this.snapshot(serverId)).rules;
    },

    /** changes: [{op, port, proto, source, comment?, action?}], options: { enable? }. */
    async apply({ serverId, changes, enable = false }) {
      const safe = changes.map(assertSafeChange);
      return runRemote(serverId, async ({ run }) => {
        const before = await readState(run);
        // Re-check the guard inside the same session that will apply (the state may have moved since the preview).
        const { next } = applyToRules(before.rules, safe.map((c, i) => ({ ...c, ...(changes[i].action ? { action: changes[i].action } : {}) })));
        const withSsh = enable && !before.active && !portReachable(next, before.sshPort, before.panelIp, before.defaultIncoming) ? [{ action: 'allow', port: before.sshPort, proto: 'tcp', source: 'any' }, ...next] : next;
        const problems = lockoutProblems(withSsh, { ...before, active: before.active || enable });
        if (problems.length) throw new AppError(422, problems[0].code, problems[0].message);
        const commands = [];
        safe.forEach((c, i) => {
          if (c.op === 'delete') {
            const hit = before.rules.find((r) => r.port === c.port && (r.proto === c.proto || r.proto === 'any') && r.source === c.source && (!changes[i].action || r.action === c.action));
            if (hit) commands.push(ruleArgs(c, { resolvedAction: hit.action })); // absent rule: idempotent skip
          } else if (!before.rules.some((r) => r.port === c.port && r.proto === c.proto && r.source === c.source && r.action === c.op)) commands.push(ruleArgs(c));
        });
        const token = newToken();
        if (commands.length === 0 && !(enable && !before.active)) return { rollbackToken: null, noop: true, before: before.rules, after: before.rules };
        const script = buildApplyScript({ token, commands, sshPort: before.sshPort, enable, wasActive: before.active, seconds: deadmanSeconds });
        const res = await run(script, { timeoutMs: 60_000 });
        if (res.timedOut || res.code !== 0 || !/NT_OK/.test(res.stdout)) {
          // Best effort: undo whatever was applied before the failure.
          if (/NT_DEADMAN/.test(res.stdout)) await run(buildRollbackScript(token), { timeoutMs: 30_000 }).catch(() => {});
          const why = /NT_ERR (\w+)/.exec(res.stdout)?.[1] ?? (res.timedOut ? 'timeout' : `exit_${res.code}`);
          throw new AppError(why === 'no_deadman' ? 409 : 502, why === 'no_deadman' ? 'UFW_NO_DEADMAN' : 'UFW_APPLY_FAILED', why === 'no_deadman' ? 'Neither systemd-run nor at is available for the dead-man switch; refusing to change rules' : `ufw apply failed (${why})`);
        }
        const after = await readState(run).catch(() => null);
        return { rollbackToken: token, deadmanSeconds: Math.max(DEADMAN_MIN_SECONDS, deadmanSeconds), before: before.rules, after: after?.rules ?? next };
      });
    },

    /** Cancels the dead-man timer once connectivity is proven. */
    async confirm({ serverId, rollbackToken }) {
      if (!rollbackToken) return { confirmed: true };
      const res = await runRemote(serverId, ({ run }) => run(buildConfirmScript(rollbackToken), { timeoutMs: 30_000 }));
      if (/NT_REVERTED/.test(res.stdout)) throw new AppError(409, 'UFW_DEADMAN_FIRED', 'The dead-man switch already restored the previous rules');
      return { confirmed: /NT_CONFIRMED/.test(res.stdout) };
    },

    async rollback({ serverId, rollbackToken }) {
      if (!rollbackToken) return { rolledBack: false };
      const res = await runRemote(serverId, ({ run }) => run(buildRollbackScript(rollbackToken), { timeoutMs: 30_000 }));
      return { rolledBack: /NT_ROLLED_BACK/.test(res.stdout) };
    },

    /** Fresh-connection reachability check used by the service after apply. */
    async probe(serverId) {
      try {
        await probeSsh(serverId);
        return { reachable: true };
      } catch {
        return { reachable: false };
      }
    },
  };
}
