import { AppError } from '../../common/errors/app-error.js';
import { decrypt, encrypt } from '../platform/platform.crypto.js';
import { assertSafeUrl, safeFetch } from './alert-channels.ssrf.js';
import { ALLOW_HOSTS, SEVERITY_RANK, buildRequest, sanitizeError } from './alert-channels.senders.js';

export const MANAGE_PERMISSION = 'notifications.manage';
export const MAX_ATTEMPTS = 5;
export const RATE_LIMIT_PER_MINUTE = 20;
const BACKOFF_BASE_MS = 30_000;
const BACKOFF_MAX_MS = 60 * 60_000;

const SECRET_TEXT = /\b(pass(?:word)?|secret|token|api[-_]?key|authorization)\b\s*[:=]\s*\S+/gi;
const clean = (v, max) => (v == null ? null : String(v).replace(SECRET_TEXT, '$1=[REDACTED]').slice(0, max));

const schemaRequired = () =>
  new AppError(501, 'SCHEMA_REQUIRED', 'Alert channel tables are not available until the Prisma client is regenerated (run prisma generate while the API is stopped)');
const STALE = /Unknown argument|Unknown field|is not a function|Cannot read properties of undefined|doesn't exist|does not exist|AlertChannel/i;

/** Exponential backoff: 30 s, 60 s, 120 s ... capped at 1 h. `attempt` is the number of attempts already made. */
export const backoffMs = (attempt) => Math.min(BACKOFF_BASE_MS * 2 ** Math.max(0, attempt - 1), BACKOFF_MAX_MS);

export function createAlertChannelsService({
  prisma,
  rbac = null,
  auditService = null,
  credentialKey = () => process.env.CREDENTIAL_ENCRYPTION_KEY,
  fetchImpl = globalThis.fetch,
  lookup,
  now = () => new Date(),
  timeoutMs = 8000,
}) {
  const audit = (e) => (auditService?.record ? auditService.record({ resourceType: 'alert_channel', ...e }) : null);
  const delegate = (name) => {
    const d = prisma?.[name];
    if (!d) throw schemaRequired();
    return d;
  };
  const guard = async (fn) => {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (STALE.test(String(e?.message))) throw schemaRequired();
      throw e;
    }
  };
  const enc = (obj) => encrypt(Buffer.from(JSON.stringify(obj), 'utf8'), credentialKey());
  const dec = (blob) => JSON.parse(decrypt(Buffer.from(blob), credentialKey()).toString('utf8'));

  async function requireManage(actor) {
    if (!actor?.id) throw new AppError(401, 'AUTH_REQUIRED', 'Authentication required');
    if (actor.isOwner) return;
    if (rbac?.can && (await rbac.can(actor, { permissionKey: MANAGE_PERMISSION, resourceType: 'platform', resourceId: 'global' }))) return;
    throw new AppError(403, 'FORBIDDEN', 'You do not have permission to manage notification channels');
  }

  /** Public shape. The secret is never returned; only whether it is set and the non-secret target host / chat id. */
  function mask(row) {
    return {
      id: row.id,
      name: row.name,
      type: row.type,
      enabled: row.enabled,
      minSeverity: row.minSeverity,
      eventKinds: row.eventKinds ?? null,
      dedupeSeconds: row.dedupeSeconds,
      config: row.configJson ?? {},
      secretSet: true,
      secretMasked: '********',
      lastTestAt: row.lastTestAt ?? null,
      lastTestStatus: row.lastTestStatus ?? null,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  }

  const presentDelivery = (d) => ({
    id: d.id,
    channelId: d.channelId,
    eventKind: d.eventKind,
    severity: d.severity,
    status: d.status,
    attempt: d.attempt,
    nextAttemptAt: d.nextAttemptAt ?? null,
    error: d.error ?? null,
    sentAt: d.sentAt ?? null,
    createdAt: d.createdAt,
  });

  async function validateUrls(type, secret) {
    const allowHosts = ALLOW_HOSTS[type];
    if (type === 'slack' || type === 'discord') await assertSafeUrl(secret.webhookUrl, { allowHosts, ...(lookup ? { lookup } : {}) });
    if (type === 'webhook') await assertSafeUrl(secret.url, { allowHosts, ...(lookup ? { lookup } : {}) });
  }

  function splitInput(type, input, previousSecret = {}, previousConfig = {}) {
    const bad = {
      telegram: ['webhookUrl', 'url', 'signingSecret'],
      slack: ['botToken', 'chatId', 'url', 'signingSecret'],
      discord: ['botToken', 'chatId', 'url', 'signingSecret'],
      webhook: ['botToken', 'chatId', 'webhookUrl'],
    }[type];
    for (const k of bad) if (input[k] !== undefined) throw new AppError(422, 'FIELD_NOT_FOR_TYPE', `${k} does not apply to ${type} channels`);
    const secret = { ...previousSecret };
    const config = { ...previousConfig };
    if (type === 'telegram') {
      if (input.botToken) secret.botToken = input.botToken;
      if (input.chatId) config.chatId = input.chatId;
    } else if (type === 'webhook') {
      if (input.url) secret.url = input.url;
      if (input.signingSecret) secret.signingSecret = input.signingSecret;
    } else if (input.webhookUrl) secret.webhookUrl = input.webhookUrl;
    const target = secret.webhookUrl ?? secret.url;
    if (target) config.host = new URL(target).hostname;
    return { secret, config };
  }

  /** Sends one message through a channel row and returns {ok, status, error, retryable}. Never throws. */
  async function send(channel, message, deliveryId) {
    let secret = null;
    try {
      secret = dec(channel.secretEnc);
      const req = buildRequest(channel.type, secret, channel.configJson ?? {}, message, { deliveryId, now });
      const res = await safeFetch(req.url, {
        method: 'POST',
        headers: req.headers,
        body: req.body,
        timeoutMs,
        allowHosts: ALLOW_HOSTS[channel.type],
        fetchImpl,
        ...(lookup ? { lookup } : {}),
      });
      if (res.ok) return { ok: true, httpStatus: res.status };
      const retryable = res.status >= 500 || res.status === 408 || res.status === 429;
      return { ok: false, retryable, error: `HTTP ${res.status}` };
    } catch (err) {
      const blocked = err instanceof AppError;
      return { ok: false, retryable: !blocked, error: sanitizeError(err, secret ? Object.values(secret) : []) };
    }
  }

  async function runAttempt(delivery, channel) {
    const message = { eventKind: delivery.eventKind, severity: delivery.severity, ...(delivery.payloadJson ?? {}) };
    const out = await send(channel, message, delivery.id);
    const attempt = delivery.attempt + 1;
    const at = now();
    let patch;
    if (out.ok) patch = { status: 'sent', attempt, sentAt: at, nextAttemptAt: null, error: null };
    else if (out.retryable && attempt < MAX_ATTEMPTS) patch = { status: 'failed', attempt, nextAttemptAt: new Date(at.getTime() + backoffMs(attempt)), error: out.error };
    else patch = { status: 'dead', attempt, nextAttemptAt: null, error: out.error };
    const saved = await delegate('alertChannelDelivery').update({ where: { id: delivery.id }, data: patch });
    return { ...delivery, ...patch, ...(saved ?? {}) };
  }

  const svc = {
    mask,
    backoffMs,

    async list(actor) {
      await requireManage(actor);
      const rows = await guard(() => delegate('alertChannel').findMany({ where: { archivedAt: null }, orderBy: { createdAt: 'desc' } }));
      return rows.map(mask);
    },

    async get(id, actor) {
      await requireManage(actor);
      return mask(await svc._load(id));
    },

    async _load(id) {
      const row = await guard(() => delegate('alertChannel').findUnique({ where: { id } }));
      if (!row || row.archivedAt) throw new AppError(404, 'CHANNEL_NOT_FOUND', 'Notification channel not found');
      return row;
    },

    async create(input, actor) {
      await requireManage(actor);
      const { secret, config } = splitInput(input.type, input);
      await validateUrls(input.type, secret);
      const row = await guard(() =>
        delegate('alertChannel').create({
          data: {
            name: input.name,
            type: input.type,
            secretEnc: enc(secret),
            configJson: config,
            minSeverity: input.minSeverity ?? 'info',
            eventKinds: input.eventKinds?.length ? input.eventKinds : null,
            enabled: input.enabled ?? true,
            dedupeSeconds: input.dedupeSeconds ?? 300,
            createdById: actor.id,
          },
        }),
      );
      await audit({ actorId: actor.id, action: 'alert_channel.create', resourceId: row.id, result: 'success', after: { name: row.name, type: row.type, enabled: row.enabled, minSeverity: row.minSeverity } });
      return mask(row);
    },

    async update(id, input, actor) {
      await requireManage(actor);
      const row = await svc._load(id);
      const hasSecretInput = ['botToken', 'chatId', 'webhookUrl', 'url', 'signingSecret'].some((k) => input[k] !== undefined);
      const data = {};
      for (const k of ['name', 'minSeverity', 'enabled', 'dedupeSeconds']) if (input[k] !== undefined) data[k] = input[k];
      if (input.eventKinds !== undefined) data.eventKinds = input.eventKinds?.length ? input.eventKinds : null;
      if (hasSecretInput) {
        const { secret, config } = splitInput(row.type, input, dec(row.secretEnc), row.configJson ?? {});
        await validateUrls(row.type, secret);
        data.secretEnc = enc(secret);
        data.configJson = config;
      }
      const saved = await guard(() => delegate('alertChannel').update({ where: { id }, data }));
      await audit({ actorId: actor.id, action: 'alert_channel.update', resourceId: id, result: 'success', after: { fields: Object.keys(input), secretReplaced: hasSecretInput } });
      return mask({ ...row, ...saved });
    },

    /** Archives the channel and wipes the stored secret. Delivery history is kept. */
    async remove(id, actor) {
      await requireManage(actor);
      await svc._load(id);
      await guard(() => delegate('alertChannel').update({ where: { id }, data: { archivedAt: now(), enabled: false, secretEnc: Buffer.alloc(0) } }));
      await audit({ actorId: actor.id, action: 'alert_channel.delete', resourceId: id, result: 'success' });
      return { ok: true };
    },

    /** Test-send: immediate, no dedupe/filters, no automatic retry. The outcome is logged like any delivery. */
    async test(id, actor) {
      await requireManage(actor);
      const row = await svc._load(id);
      const d = delegate('alertChannelDelivery');
      const payloadJson = { title: 'NodeTeam test notification', body: 'This is a test message from NodeTeam Control.', resourceType: 'alert_channel', resourceId: id };
      const delivery = await d.create({ data: { channelId: id, eventKind: 'test', severity: 'info', status: 'pending', attempt: 0, payloadJson } });
      const out = await send(row, { eventKind: 'test', severity: 'info', ...payloadJson }, delivery.id);
      const at = now();
      const status = out.ok ? 'sent' : 'dead';
      await d.update({ where: { id: delivery.id }, data: { status, attempt: 1, sentAt: out.ok ? at : null, error: out.ok ? null : out.error } });
      await delegate('alertChannel').update({ where: { id }, data: { lastTestAt: at, lastTestStatus: out.ok ? 'ok' : 'failed' } });
      await audit({ actorId: actor.id, action: 'alert_channel.test', resourceId: id, result: out.ok ? 'success' : 'failure', after: { status, error: out.ok ? undefined : out.error } });
      return { ok: out.ok, status, deliveryId: delivery.id, error: out.ok ? null : out.error };
    },

    async deliveries(id, { limit = 20, cursor, status } = {}, actor) {
      await requireManage(actor);
      await svc._load(id);
      const rows = await guard(() =>
        delegate('alertChannelDelivery').findMany({
          where: { channelId: id, ...(status ? { status } : {}) },
          take: limit + 1,
          ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
          orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        }),
      );
      const items = rows.slice(0, limit).map(presentDelivery);
      return { items, nextCursor: rows.length > limit ? items[items.length - 1].id : null };
    },

    /**
     * Fan an event out to every enabled channel whose severity/event filters match. Never throws (a failing channel
     * must not break the business operation). Applies per-channel dedupe and a per-minute rate limit; suppressed
     * events are logged with status `suppressed`. First delivery attempt happens inline; retries run via retryDue().
     */
    async dispatch(event) {
      const out = { matched: 0, sent: 0, failed: 0, suppressed: 0 };
      try {
        const severity = SEVERITY_RANK[event.severity] !== undefined ? event.severity : 'warning';
        const channels = await delegate('alertChannel').findMany({ where: { enabled: true, archivedAt: null } });
        const d = delegate('alertChannelDelivery');
        const at = now();
        const payloadJson = { title: clean(event.title, 200), body: clean(event.body, 1000), resourceType: event.resourceType ?? null, resourceId: event.resourceId ?? null };
        const dedupeKey = String(event.dedupeKey ?? `${event.kind}:${event.resourceId ?? payloadJson.title}`).slice(0, 191);
        for (const ch of channels) {
          if (SEVERITY_RANK[severity] < (SEVERITY_RANK[ch.minSeverity] ?? 0)) continue;
          if (Array.isArray(ch.eventKinds) && ch.eventKinds.length && !ch.eventKinds.includes(event.kind)) continue;
          out.matched += 1;
          const base = { channelId: ch.id, eventKind: event.kind, severity, payloadJson, dedupeKey };
          let reason = null;
          if (ch.dedupeSeconds > 0) {
            const dup = await d.findFirst({ where: { channelId: ch.id, dedupeKey, status: { in: ['sent', 'pending', 'failed'] }, createdAt: { gte: new Date(at.getTime() - ch.dedupeSeconds * 1000) } } });
            if (dup) reason = 'deduplicated';
          }
          if (!reason) {
            const recent = await d.count({ where: { channelId: ch.id, status: { not: 'suppressed' }, createdAt: { gte: new Date(at.getTime() - 60_000) } } });
            if (recent >= RATE_LIMIT_PER_MINUTE) reason = 'rate_limited';
          }
          if (reason) {
            await d.create({ data: { ...base, status: 'suppressed', error: reason } });
            out.suppressed += 1;
            continue;
          }
          const delivery = await d.create({ data: { ...base, status: 'pending', attempt: 0 } });
          const res = await runAttempt(delivery, ch);
          if (res.status === 'sent') out.sent += 1;
          else out.failed += 1;
        }
      } catch {
        /* best effort */
      }
      return out;
    },

    /** Retry sweeper (scheduler job): re-attempts failed deliveries whose backoff has elapsed. */
    async retryDue(at = now(), { limit = 50 } = {}) {
      const d = delegate('alertChannelDelivery');
      const due = await d.findMany({ where: { status: 'failed', nextAttemptAt: { lte: at } }, orderBy: { nextAttemptAt: 'asc' }, take: limit });
      const out = { retried: 0, sent: 0, dead: 0 };
      for (const delivery of due) {
        const ch = await delegate('alertChannel').findUnique({ where: { id: delivery.channelId } });
        if (!ch || ch.archivedAt || !ch.enabled) {
          await d.update({ where: { id: delivery.id }, data: { status: 'dead', nextAttemptAt: null, error: 'channel_unavailable' } });
          out.dead += 1;
          continue;
        }
        const res = await runAttempt(delivery, ch);
        out.retried += 1;
        if (res.status === 'sent') out.sent += 1;
        if (res.status === 'dead') out.dead += 1;
      }
      return out;
    },
  };
  return svc;
}
