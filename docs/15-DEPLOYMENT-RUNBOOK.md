# Deployment Runbook

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 14.

## 14. Non-functional

Isolate control plane; MFA/least privilege/mTLS; encrypted secrets/redaction; bounded retries/idempotency/timeouts; independent audit; multiple servers/distributed workers; pagination/streaming; separate retention; offsite/restore drills; platform recovery/Owner emergency; unit/integration/E2E/security/restore tests. Dashboard outage cannot stop customers. Agent reconnect cannot replay stale jobs.

Planned runbook: isolate staging; provision secrets/certificates; test migrations/backups; deploy API/worker/web; dependency readiness and scoped smoke; test Agent enrollment; read-only rollout before control. Failure: stop new job dispatch without stopping apps; schema-compatible rollback or isolated recovery; verify Owner. Actual commands depend on topology/recovery targets and authorization.
