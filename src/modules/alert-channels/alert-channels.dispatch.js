import { createAlertChannelsService } from './alert-channels.service.js';

const cache = new WeakMap();

/** Maps internal notification types to channel event kinds. Unlisted types are not sent to external channels. */
const KIND_MAP = {
  'alert.opened': 'alert.opened',
  'incident.created': 'incident.created',
  'incident.assigned': 'incident.assigned',
  'deployment.failed': 'deployment.failed',
  'backup.failed': 'backup.failed',
  'certificate.expiring': 'certificate.expiring',
  'approval.requested': 'approval.requested',
};

/**
 * Fire-and-forget fan-out to outbound channels. Never throws and is never awaited by callers:
 * a slow or broken channel must not delay or fail the business operation that raised the event.
 */
export function dispatchAlertChannels(event, { prisma, service = null } = {}) {
  try {
    const kind = KIND_MAP[event?.type ?? event?.kind];
    if (!kind || !prisma?.alertChannel?.findMany) return null;
    let svc = service;
    if (!svc) {
      svc = cache.get(prisma);
      if (!svc) {
        svc = createAlertChannelsService({ prisma });
        cache.set(prisma, svc);
      }
    }
    return svc
      .dispatch({ kind, severity: event.severity, title: event.title, body: event.body, resourceType: event.resourceType, resourceId: event.resourceId, dedupeKey: event.dedupeKey })
      .catch(() => null);
  } catch {
    return null;
  }
}
