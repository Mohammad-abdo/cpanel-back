import { AppError } from '../../common/errors/app-error.js';
import { EVENT_KINDS, CHANNEL_TYPES } from './notifications.validator.js';
import { dispatchAlertChannels } from '../alert-channels/alert-channels.dispatch.js';

const SECRET_TEXT = /\b(pass(?:word)?|secret|token|api[-_]?key|authorization)\b\s*[:=]\s*\S+/gi;

/** Strip secret-looking key=value fragments from free text before storage. */
export function redactText(value, max = 500) {
  if (value == null) return null;
  return String(value).replace(SECRET_TEXT, '$1=[REDACTED]').slice(0, max);
}

/**
 * Internal helper for other modules. Never throws: a failed notification must not break the
 * business operation that triggered it. Respects the user's in_app preference for the event kind.
 */
export async function notify({ userId, type, title, body, resourceType, resourceId }, { prisma }) {
  try {
    if (!userId || !type || !title || !prisma?.notification?.create) return null;
    const pref = prisma.notificationPreference?.findUnique
      ? await prisma.notificationPreference.findUnique({
          where: { userId_eventKind_channelType: { userId, eventKind: type, channelType: 'in_app' } },
        })
      : null;
    if (pref && pref.enabled === false) return null;
    return await prisma.notification.create({
      data: {
        userId,
        kind: String(type).slice(0, 80),
        title: redactText(title, 200),
        body: redactText(body),
        linkJson: resourceType ? { resourceType, resourceId: resourceId ?? null } : undefined,
      },
    });
  } catch {
    return null;
  }
}

/** Outbound channels (Telegram/Slack/Discord/webhook, TASK-042). Fire-and-forget, never throws, never awaited. */
export function notifyChannels(event, { prisma }) {
  dispatchAlertChannels(event, { prisma });
}

/** Notify every active Owner (except `exceptUserId`). Same never-throw contract. */
export async function notifyOwners(event, { prisma, exceptUserId = null }) {
  if (event?.channels !== false) notifyChannels(event, { prisma });
  try {
    if (!prisma?.user?.findMany) return;
    const owners = await prisma.user.findMany({
      where: { ownerFlag: true, status: 'active', disabledAt: null },
      select: { id: true },
    });
    for (const o of owners) {
      if (o.id !== exceptUserId) await notify({ ...event, userId: o.id }, { prisma });
    }
  } catch {
    /* best effort */
  }
}

export function createNotificationsService({ prisma }) {
  const svc = {
    async list(user, { limit, cursor, unread }) {
      const where = { userId: user.id, ...(unread === 'true' ? { readAt: null } : {}) };
      const rows = await prisma.notification.findMany({
        where,
        take: limit + 1,
        ...(cursor ? { skip: 1, cursor: { id: cursor } } : {}),
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      });
      const items = rows.slice(0, limit);
      const unreadCount = await prisma.notification.count({ where: { userId: user.id, readAt: null } });
      return { items, nextCursor: rows.length > limit ? items[items.length - 1].id : null, unreadCount };
    },

    async markRead(user, id) {
      const res = await prisma.notification.updateMany({
        where: { id, userId: user.id, readAt: null },
        data: { readAt: new Date() },
      });
      if (res.count === 0) {
        const exists = await prisma.notification.findFirst({ where: { id, userId: user.id }, select: { id: true } });
        if (!exists) throw new AppError(404, 'NOTIFICATION_NOT_FOUND', 'Notification not found');
      }
      return { ok: true };
    },

    async markAllRead(user) {
      const res = await prisma.notification.updateMany({
        where: { userId: user.id, readAt: null },
        data: { readAt: new Date() },
      });
      return { ok: true, updated: res.count };
    },

    /** Full matrix of event kind x channel; missing rows default to enabled. */
    async getPreferences(user) {
      const rows = await prisma.notificationPreference.findMany({ where: { userId: user.id } });
      const saved = new Map(rows.map((r) => [`${r.eventKind}|${r.channelType}`, r.enabled]));
      return EVENT_KINDS.flatMap((eventKind) =>
        CHANNEL_TYPES.map((channelType) => ({
          eventKind,
          channelType,
          enabled: saved.get(`${eventKind}|${channelType}`) ?? true,
        })),
      );
    },

    async updatePreferences(user, { preferences }) {
      for (const p of preferences) {
        await prisma.notificationPreference.upsert({
          where: { userId_eventKind_channelType: { userId: user.id, eventKind: p.eventKind, channelType: p.channelType } },
          create: { userId: user.id, eventKind: p.eventKind, channelType: p.channelType, enabled: p.enabled },
          update: { enabled: p.enabled },
        });
      }
      return svc.getPreferences(user);
    },
  };
  return svc;
}
