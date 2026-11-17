import { createHmac } from 'node:crypto';

export const CHANNEL_TYPES = ['telegram', 'slack', 'discord', 'webhook'];
export const SEVERITIES = ['info', 'warning', 'critical'];
export const SEVERITY_RANK = { info: 0, warning: 1, critical: 2 };
export const ALERT_EVENT_KINDS = [
  'alert.opened',
  'incident.created',
  'incident.assigned',
  'deployment.failed',
  'backup.failed',
  'certificate.expiring',
  'approval.requested',
];

/** Host allow-lists per provider; the generic webhook is only limited by the SSRF guard. */
export const ALLOW_HOSTS = {
  telegram: ['api.telegram.org'],
  slack: ['hooks.slack.com'],
  discord: ['discord.com', 'discordapp.com'],
  webhook: null,
};

const trim = (v, n) => String(v ?? '').slice(0, n);

export function messageText(m) {
  const sev = m.severity ? `[${String(m.severity).toUpperCase()}] ` : '';
  return trim(`${sev}${m.title}${m.body ? `\n${m.body}` : ''}`, 1800);
}

/** HMAC-SHA256 over `${timestamp}.${rawBody}`; receivers recompute, compare in constant time and reject old timestamps. */
export function signPayload(secret, timestamp, rawBody) {
  return `sha256=${createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex')}`;
}

/** Builds the HTTP request for a channel. `secret` is the decrypted object: {botToken}|{webhookUrl}|{url,signingSecret}. */
export function buildRequest(type, secret, config, message, { deliveryId, now = () => new Date() } = {}) {
  const json = { 'content-type': 'application/json' };
  if (type === 'telegram') {
    return {
      url: `https://api.telegram.org/bot${secret.botToken}/sendMessage`,
      headers: json,
      body: JSON.stringify({ chat_id: config?.chatId, text: messageText(message), disable_web_page_preview: true }),
    };
  }
  if (type === 'slack') return { url: secret.webhookUrl, headers: json, body: JSON.stringify({ text: messageText(message) }) };
  if (type === 'discord') return { url: secret.webhookUrl, headers: json, body: JSON.stringify({ content: messageText(message).slice(0, 1900) }) };
  const at = now();
  const body = JSON.stringify({
    id: deliveryId ?? null,
    event: message.eventKind,
    severity: message.severity ?? 'info',
    title: trim(message.title, 200),
    body: message.body ? trim(message.body, 1000) : null,
    resourceType: message.resourceType ?? null,
    resourceId: message.resourceId ?? null,
    at: at.toISOString(),
  });
  const ts = String(Math.floor(at.getTime() / 1000));
  return {
    url: secret.url,
    headers: {
      ...json,
      'x-nodeteam-delivery': deliveryId ?? '',
      'x-nodeteam-timestamp': ts,
      'x-nodeteam-signature': signPayload(secret.signingSecret, ts, body),
    },
    body,
  };
}

/** Removes secrets and URLs from an error string before it is stored or returned. */
export function sanitizeError(err, secrets = []) {
  let msg = String(err?.code ? `${err.code}: ${err.message}` : (err?.message ?? err ?? 'error'));
  for (const s of secrets) if (s && String(s).length >= 4) msg = msg.split(String(s)).join('[REDACTED]');
  msg = msg.replace(/https?:\/\/[^\s'"]+/gi, '[url]').replace(/bot\d+:[A-Za-z0-9_-]+/g, 'bot[REDACTED]');
  return msg.slice(0, 300);
}
