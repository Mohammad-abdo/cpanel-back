# Agent Specification

Status: requirements/specifications, not implemented capabilities. Source: required.md sections 2,3,14.

## 2. Architecture

NodeTeam Control is a multi-VPS Infrastructure, DevOps and Team Operations Platform for Ubuntu production servers running Node/PM2, Laravel, Apache and MySQL/PostgreSQL/MongoDB/Redis workloads. Owner controls resources, identities, changes, outcomes, domains, certificates, backups and security. Modular monolith API with separate workers and agents. React displays scoped data; API owns policies/approvals/reports; Prisma/MySQL metadata; Redis queues; Loki raw logs; Prometheus metrics. Gateway uses mTLS/job validation/scoped operations/audit. No direct dashboard root access. Control-plane failure must not stop applications.

## 3. Servers and projects

Server registration, discovery, CPU/RAM/swap/disk/network, processes, Systemd/PM2/Apache/Nginx, disk alerts, ports/connections, approved firewall/maintenance, Healthy/Warning/Critical, per-server access. Discover existing projects without redeploy or path changes. Preview shared-service restart impact. Project fields: name/slug/server/environment/type(Node/Laravel/WordPress/Static/Custom), repo/branch/commit, runtime/process manager, domains/SSL, ports, databases, team, deploys/backups/metrics/logs/alerts. Create/link/configure secrets/deploy/start/stop/restart/rollback/health/archive. Deployment: Queued -> Preparing -> Building -> Deploying -> Health Check -> Success/Failed/Rolled Back; record actor/timing/result per step.

## 14. Non-functional

Isolate control plane; MFA/least privilege/mTLS; encrypted secrets/redaction; bounded retries/idempotency/timeouts; independent audit; multiple servers/distributed workers; pagination/streaming; separate retention; offsite/restore drills; platform recovery/Owner emergency; unit/integration/E2E/security/restore tests. Dashboard outage cannot stop customers. Agent reconnect cannot replay stale jobs.

Proposed protocol envelope (pending approval): protocolVersion/jobId/attemptId/issuedAt/expiresAt/action/resource/payload plus operation/correlation/idempotency identifiers. Check identity/capability/scope/expiry/policy; reject replay; no arbitrary shell. Decide transport/certificate issuance/rotation/revocation.
