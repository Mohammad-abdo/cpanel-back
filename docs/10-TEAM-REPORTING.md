# Team Reporting

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 5,6.

## 5. Team Intelligence

Track professional platform/linked events, not personal device activity or keystrokes. Member identity/role/permissions/projects/servers/deployments/restarts/config/domain/SSL changes/denials/approvals/outcomes/last activity/incidents/audit. Reports: individual activity, project contribution, deployment success, changes, incident ownership, security, failed operations, workload, access, weekly/monthly summaries. Every metric opens original events. Link member/assignment/operation/commit/result/health/audit/report. Separate initiator/approver/executor. Unmapped SSH/GitHub identity remains External/Unattributed. GoRide/Medor/Vovus and dashboard counts are illustrative.

## 6. Project reports

Separate from monitoring/logs: uptime/outages, resources, requests/error rate/latency, slow endpoints, recurring errors, deployments/rollback, database health/slow queries, security, backup verification, team activity, incidents/resolution duration. Scheduled weekly PDF/Excel covers health/changes/deployments/errors/outages/resources/backup/SSL/team. Authorized recipients only.

Proposed report formulas pending approval: count distinct Deployment IDs; success rate = successful terminal deployments / all terminal deployments *100; zero denominator N/A. Retries do not increase counts; canceled/in-progress separate. Incidents resolved count distinct incident IDs and recorded owner. Decide period/timezone/inclusive-exclusive bounds/reopened attribution. Reauthorize report recipients and downloads.
