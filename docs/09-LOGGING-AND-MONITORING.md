# Logging And Monitoring

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 4,13.

## 4. Project Observability Center

Collect application/runtime-PM2/web-Apache-Nginx/database/deployment/jobs/security/audit logs. Live Socket.IO or SSE; time/project/server/severity/source filters; requestId/traceId/deploymentId; stack traces; first/last/count; error groups; deployment comparisons; commit/release links; authorized exports; error-rate alerts. Redact secrets before storage/display. Labels server_id/project_id/environment; backend gateway controls query scope/Loki tenancy. Error timing does not prove developer fault. Demo GoRide events are not production evidence.

## 13. Monitoring alerts

Prometheus metrics, Loki logs, MySQL events. Suggested CPU/memory 15s, disk60s, process15-30s, HTTP30-60s, SSL12h, backups after each and daily, security/activity event-driven. Tune to load. Rules sustained CPU5min, RAM/swap, low disk, project/health failure, error rate, SSL expiry, failed/stale backups, SSH spikes, external sensitive changes. Severity/deduplication/acknowledgment/escalation/history.


