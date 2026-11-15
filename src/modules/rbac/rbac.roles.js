import { PERMISSIONS as P } from '@nodeteam/permission-catalog';

/** Seed role definitions (required.md section 7). Owner is never granted through UserRole; it is the user ownerFlag. */
export const ROLE_DEFINITIONS = Object.freeze({
  owner: { name: 'Owner', permissions: Object.values(P) },
  infrastructure_admin: {
    name: 'Infrastructure Admin',
    permissions: [P.SERVER_METRICS_READ, P.SERVER_FIREWALL_UPDATE, P.SERVER_SERVICE_RESTART, P.DOMAIN_CREATE, P.SSL_ISSUE, P.PROJECT_LOGS_READ, P.PROJECT_RESTART_EXECUTE, P.PROJECT_BACKUP_CREATE, P.PROJECT_BACKUP_RESTORE, P.PROJECT_DATABASE_MANAGE, P.PROJECT_CONFIGURE],
  },
  devops: {
    name: 'DevOps',
    permissions: [P.PROJECT_DEPLOY_CREATE, P.PROJECT_RESTART_EXECUTE, P.PROJECT_LOGS_READ, P.PROJECT_ENV_METADATA_READ, P.PROJECT_BACKUP_CREATE, P.PROJECT_CONFIGURE, P.DOMAIN_CREATE, P.SSL_ISSUE, P.SERVER_METRICS_READ],
  },
  team_lead: {
    name: 'Team Lead',
    permissions: [P.TEAM_MEMBER_INVITE, P.TEAM_PERMISSION_ASSIGN, P.REPORT_TEAM_EXPORT, P.PROJECT_LOGS_READ, P.SERVER_METRICS_READ, P.PROJECT_DEPLOY_CREATE, P.PROJECT_RESTART_EXECUTE],
  },
  // Developer holds only read basics; every other action needs an explicit ResourceGrant.
  developer: { name: 'Developer', permissions: [P.PROJECT_LOGS_READ, P.PROJECT_ENV_METADATA_READ, P.SERVER_METRICS_READ] },
  security_analyst: {
    name: 'Security Analyst',
    permissions: [P.AUDIT_LOGS_READ, P.PROJECT_LOGS_READ, P.SERVER_METRICS_READ, P.SECURITY_INCIDENT_MANAGE, P.PLATFORM_ACCESS_REVIEW, P.REPORT_TEAM_EXPORT],
  },
  auditor: { name: 'Auditor', permissions: [P.AUDIT_LOGS_READ, P.PROJECT_LOGS_READ, P.REPORT_TEAM_EXPORT, P.SERVER_METRICS_READ] },
  viewer: { name: 'Viewer', permissions: [P.SERVER_METRICS_READ] },
});

/** Only the Owner role may hold this at any scope wider than a team. Others: team scope only. */
export const TEAM_SCOPED_ONLY = new Set([P.TEAM_PERMISSION_ASSIGN]);

export function roleHasPermission(roleCode, permissionKey) {
  return Boolean(ROLE_DEFINITIONS[roleCode]?.permissions.includes(permissionKey));
}

export function isRoleAssignableTo(roleCode, user) {
  return roleCode !== 'owner' || Boolean(user?.isOwner || user?.ownerFlag);
}
