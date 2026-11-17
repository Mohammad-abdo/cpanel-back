/**
 * Permission catalog (formerly the @nodeteam/permission-catalog workspace package).
 * Source: docs/07-PERMISSIONS-MATRIX.md (required.md section 7).
 */
export const PERMISSIONS = Object.freeze({
  PROJECT_LOGS_READ: 'project.logs.read',
  PROJECT_DEPLOY_CREATE: 'project.deploy.create',
  PROJECT_RESTART_EXECUTE: 'project.restart.execute',
  PROJECT_ENV_METADATA_READ: 'project.env.metadata.read',
  PROJECT_SECRET_ROTATE: 'project.secret.rotate',
  PROJECT_BACKUP_CREATE: 'project.backup.create',
  PROJECT_BACKUP_RESTORE: 'project.backup.restore',
  PROJECT_DATABASE_MANAGE: 'project.database.manage',
  PROJECT_CONFIGURE: 'project.configure',
  SERVER_METRICS_READ: 'server.metrics.read',
  SERVER_FIREWALL_UPDATE: 'server.firewall.update',
  SERVER_SERVICE_RESTART: 'server.service.restart',
  DOMAIN_CREATE: 'domain.create',
  SSL_ISSUE: 'ssl.issue',
  TEAM_MEMBER_INVITE: 'team.member.invite',
  TEAM_PERMISSION_ASSIGN: 'team.permission.assign',
  AUDIT_LOGS_READ: 'audit.logs.read',
  REPORT_TEAM_EXPORT: 'report.team.export',
  SECURITY_INCIDENT_MANAGE: 'security.incident.manage',
  PLATFORM_ACCESS_REVIEW: 'platform.access.review',
  PLATFORM_APPROVAL_DECIDE: 'platform.approval.decide',
  OPERATION_APPROVE: 'operation.approve',
  MAIL_MANAGE: 'mail.manage',
  NOTIFICATIONS_MANAGE: 'notifications.manage',
});

export const PERMISSION_LIST = Object.freeze(Object.values(PERMISSIONS));

/** Low: reads/metrics. Medium: single-service restart/backup. High: production deploy, DNS/SSL. Critical: restore, firewall. */
export const PERMISSION_RISK = Object.freeze({
  'project.logs.read': 'low',
  'project.env.metadata.read': 'low',
  'server.metrics.read': 'low',
  'audit.logs.read': 'low',
  'report.team.export': 'medium',
  'project.restart.execute': 'medium',
  'project.backup.create': 'medium',
  'project.configure': 'medium',
  'server.service.restart': 'medium',
  'team.member.invite': 'medium',
  'security.incident.manage': 'medium',
  'platform.access.review': 'medium',
  'project.deploy.create': 'high',
  'project.secret.rotate': 'high',
  'project.database.manage': 'high',
  'domain.create': 'high',
  'ssl.issue': 'high',
  'team.permission.assign': 'high',
  'platform.approval.decide': 'high',
  'operation.approve': 'high',
  'mail.manage': 'high',
  'notifications.manage': 'high',
  'project.backup.restore': 'critical',
  'server.firewall.update': 'critical',
});

/** Permissions that only match a grant/role scoped to one exact environment (staging never implies production). */
const ENVIRONMENT_SCOPED = new Set([
  'project.deploy.create',
  'project.restart.execute',
  'project.env.metadata.read',
  'project.secret.rotate',
  'project.backup.create',
  'project.backup.restore',
]);

export function permissionRequiresEnvironment(permissionKey) {
  return ENVIRONMENT_SCOPED.has(permissionKey);
}

export function permissionResourceType(permissionKey) {
  return String(permissionKey).split('.')[0];
}
