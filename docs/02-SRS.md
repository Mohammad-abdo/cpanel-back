# Srs

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 14,16.

## 14. Non-functional

Isolate control plane; MFA/least privilege/mTLS; encrypted secrets/redaction; bounded retries/idempotency/timeouts; independent audit; multiple servers/distributed workers; pagination/streaming; separate retention; offsite/restore drills; platform recovery/Owner emergency; unit/integration/E2E/security/restore tests. Dashboard outage cannot stop customers. Agent reconnect cannot replay stale jobs.

## 16. Acceptance

Enforce project isolation across API/socket/logs/downloads. Audit initiator/approver/executor/results. Test error reaches correct project without secrets. Reports match real events without duplicate counts. Successful/failed deployments include health and rollback. Backup then isolated restore matches files/data. Test domain issuance/renewal verified. Agent reconnect has no duplicates/unauthorized execution. Control-plane failure leaves projects running. Platform recovery verifies Owner emergency access.


