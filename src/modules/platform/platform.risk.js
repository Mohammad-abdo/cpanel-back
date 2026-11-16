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
  // Phase 10 mail (TASK-034/035): apply is closed by default; firewall exposure is critical.
  'mail.provision.apply': RISK.HIGH,
  'mail.firewall.open': RISK.CRITICAL,
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
