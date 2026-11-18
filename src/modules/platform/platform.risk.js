/** Risk model from required.md section 7. High and Critical need approval, reason, impact preview, rollback note. */
export const RISK = Object.freeze({ LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' });

export const ACTION_RISK = Object.freeze({
  'domain.create': RISK.MEDIUM,
  'vhost.apply': RISK.HIGH,
  'dns.change': RISK.HIGH,
  'ssl.issue': RISK.HIGH,
  'ssl.renew': RISK.MEDIUM,
  'db.instance.register': RISK.HIGH,
  'db.create': RISK.HIGH,
  'db.user.create': RISK.HIGH,
  'db.drop': RISK.CRITICAL,
  'backup.run': RISK.MEDIUM,
  'backup.retention.apply': RISK.HIGH,
  'backup.restore.isolated': RISK.HIGH,
  'backup.restore.inplace': RISK.CRITICAL,
  'firewall.change': RISK.HIGH,
  'firewall.change.sensitive': RISK.CRITICAL,
  'emergency.owner': RISK.CRITICAL,
  'db.restore.live': RISK.CRITICAL,
  'pm2.stop': RISK.HIGH,
  'pm2.restart': RISK.HIGH,
  'pm2.reload': RISK.HIGH,
  'pm2.delete': RISK.HIGH,
  // Interactive SSH PTY: Critical — full shell on the server; per-session approval.
  'server.terminal.open': RISK.CRITICAL,
  // Phase 10 mail (TASK-034/035): apply is closed by default; firewall exposure is critical.
  'mail.provision.apply': RISK.HIGH,
  'mail.firewall.open': RISK.CRITICAL,
  'mail.dns.publish': RISK.HIGH,
  // TASK-046 exec agent typed commands (stats / file.list / file.read are low and ungated).
  'agent.deploy.step': RISK.HIGH,
  'agent.pm2.control': RISK.HIGH,
  'agent.ufw': RISK.CRITICAL,
  'agent.cron.run': RISK.HIGH,
  'agent.backup.dump': RISK.HIGH,
  'agent.service.restart': RISK.HIGH,
  'agent.terminal': RISK.CRITICAL,
  'agent.update': RISK.CRITICAL,
  'agent.rotate': RISK.HIGH,
  'agent.recover': RISK.HIGH,
  // Phase 11 (TASK-043/044): custom (non-allowlisted) build commands and webhook secret rotation.
  'deploy.command.approve': RISK.HIGH,
  // TASK-055: GitHub App disconnect and webhook secret rotation.
  'github.app.disconnect': RISK.HIGH,
  'github.app.rotate_secret': RISK.HIGH,
  // Phase 11 (TASK-048): custom cron commands and server cleanup apply.
  'cron.custom.command': RISK.HIGH,
  'server.cleanup.apply': RISK.HIGH,
  // Phase 11 (TASK-045/047): publishing a preview hostname (DNS + proxy), applying a Caddy site, and issuing a wildcard certificate.
  'preview.expose': RISK.HIGH,
  'caddy.apply': RISK.HIGH,
  'ssl.wildcard.issue': RISK.HIGH,
  // TASK-053: "Add project to server" (Apache + certbot + PM2). dns.change is reused for DNS records.
  'project.provision': RISK.HIGH,
  'project.decommission': RISK.HIGH,
  'apache.vhost.apply': RISK.HIGH,
  'certbot.issue': RISK.HIGH,
});

export const requiresApproval = (action) => {
  const tier = ACTION_RISK[action];
  return tier === RISK.HIGH || tier === RISK.CRITICAL;
};

/** Permission keys. Keys outside the shared catalog are proposed additions (see TASK-032 report). */
export const PERM = Object.freeze({
  DOMAIN: 'domain.create',
  SSL: 'ssl.issue',
  BACKUP_CREATE: 'project.backup.create',
  BACKUP_RESTORE: 'project.backup.restore',
  DATABASE: 'project.database.manage',
  FIREWALL: 'server.firewall.update',
  INCIDENT: 'security.incident.manage',
  APPROVAL_DECIDE: 'platform.approval.decide',
  ACCESS_REVIEW: 'platform.access.review',
});
