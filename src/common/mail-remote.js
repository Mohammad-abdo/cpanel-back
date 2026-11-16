import { AppError } from './errors/app-error.js';
import { SAFE_ARG, SAFE_SELECTOR, assertSafeArgs, domainAddScript, mailboxRemoveScript, mailboxSetScript, parseKeyValues } from './mail-provision.scripts.js';

/**
 * Per-domain / per-mailbox push to a PROVISIONED mail server over the shared SSH session.
 * Metadata-only mode is kept: when the stack is not provisioned (or the kill switch is on, or no SSH is wired)
 * the call returns { pushed: false, reason } and the caller keeps its panel-side state.
 * Passwords travel on stdin only; nothing here logs or returns them.
 */
export function createMailRemote({ prisma, ssh = null, config = {} }) {
  const killed = () => config.provisioningDisabled === true;

  async function provisioned(serverId) {
    if (!prisma?.serverMailService?.findUnique || !serverId) return false;
    try {
      return Boolean((await prisma.serverMailService.findUnique({ where: { serverId } }))?.provisioned);
    } catch {
      return false;
    }
  }

  async function ready(serverId) {
    if (!ssh?.runRemote) return 'no_executor';
    if (killed()) return 'kill_switch';
    if (!(await provisioned(serverId))) return 'not_provisioned';
    return null;
  }

  async function exec(serverId, script, { args, stdin }) {
    const res = await ssh.runRemote(serverId, (s) => s.run(script, { args, stdin, timeoutMs: 120_000 }));
    if (res.timedOut) throw new AppError(504, 'MAIL_REMOTE_TIMEOUT', 'Mail server did not answer in time');
    if (res.code !== 0) throw new AppError(502, 'MAIL_REMOTE_FAILED', `Mail server command failed${res.stderr ? `: ${String(res.stderr).trim().slice(0, 200)}` : ''}`);
    return parseKeyValues(res.stdout);
  }

  return {
    ready,
    async addDomain(serverId, { domain, selector }) {
      const why = await ready(serverId);
      if (why) return { pushed: false, reason: why };
      if (!SAFE_ARG.test(domain) || !SAFE_SELECTOR.test(selector)) throw new AppError(422, 'MAIL_ARGS_INVALID', 'Invalid domain or selector');
      const kv = await exec(serverId, domainAddScript(), { args: assertSafeArgs([domain, selector]) });
      return { pushed: true, dkimPublicKey: kv.dkim_public || null };
    },
    async setMailbox(serverId, { address, quotaMb, password }) {
      const why = await ready(serverId);
      if (why) return { pushed: false, reason: why };
      const kv = await exec(serverId, mailboxSetScript(), { args: assertSafeArgs([address, Number(quotaMb) || 1024]), stdin: `${password}\n` });
      return { pushed: true, hashScheme: kv.hash_scheme ?? null };
    },
    async removeMailbox(serverId, { address }) {
      const why = await ready(serverId);
      if (why) return { pushed: false, reason: why };
      await exec(serverId, mailboxRemoveScript(), { args: assertSafeArgs([address]) });
      return { pushed: true };
    },
  };
}
