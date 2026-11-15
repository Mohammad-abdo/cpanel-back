# Agent Security Review

Label: AGENT_REVIEW (fresh-context AI review, not a human independent review; does not satisfy the human independent-review gate)

No task is marked DONE or PASSED by this document.

## Scope
apps/api/src only: app.js, common/middleware, common/crypto, modules auth, users, rbac, teams, agents, servers, platform, operations, restores, firewall, backups, databases, incidents, audit, logs, reports, deployments, projects, members. Web UI, agents/ and scripts/ were not reviewed.

## Method
Static read of security-critical code and grep for child_process, fs, $queryRaw, fetch, new URL, crypto. No servers were started, no migrations were run, no live API calls were made. `cd apps/api && npx vitest run`: 26 files, 275 tests passed (local only, no production claim).

## Findings (sorted by severity)

| # | Sev | Location | Finding | Exploit scenario | Minimal fix |
|---|-----|----------|---------|------------------|-------------|
| 1 | Critical | auth/auth.routes.js:32,41; auth.service.js:104,140-178 | MFA bypass. A session with pending MFA may enroll and confirm a new TOTP factor (allowPendingMfa), and verifyMfa accepts any verified factor. | Attacker with only a stolen password logs in (pending session), calls enroll, computes the TOTP from the returned secret, confirms it, then calls /mfa/verify with a code from their own factor and gets a fully MFA-satisfied session. | Enroll/confirm must require mfaSatisfied when the user already has a verified factor; allow pending-session enrollment only when the user has zero verified factors. |
| 2 | High | app.js (whole file); auth.routes.js:26 | No rate limiting or lockout anywhere. /auth/login, /auth/mfa/verify (unauthenticated, needs only a sessionId) and /agents/enroll are unthrottled. | Online password guessing, or brute force of the 6-digit TOTP (3 valid codes per 30s) against a known sessionId. | Add express-rate-limit per IP and per account/session; revoke the session after N bad MFA codes. |
| 3 | High | audit/audit.service.js:49-58 | requirePermission lets every authenticated non-owner read the audit log: 'audit.logs.read' returns true with no RBAC check. | Any low-privilege user calls GET /audit/events and reads actors, resources and metadata across all projects. | Replace with rbac.can on a real audit permission. |
| 4 | High | platform/platform.service.js:53-70 | Approval consumption is not atomic (read, check, then update by id). | Two concurrent calls with one approved approvalId both pass the status check and both run the privileged action; single-use is violated. | updateMany({where:{id,status:'approved'}}) and require count===1. |
| 5 | Medium | firewall/firewall.service.js:72,84 | Maintenance window is caller-supplied and not part of the approval binding (binding is the hash of changes only). | An approved change can be applied at any time by supplying a window around "now"; the approver's window is not enforced. | Include windowStart/windowEnd in the binding and compare. |
| 6 | Medium | backups/backups.service.js:181-183 | applyRetention authorizes against caller-supplied environmentId but does not compare it to policy.environmentId (runBackup does at line 87). | A user with backup rights on one environment applies retention to a policy of an environment they have no rights on. | Reject if policy.environmentId && policy.environmentId !== input.environmentId. |
| 7 | Medium | servers.service.js:28-84; backups.service.js:59-65; domains.service.js:55,64; incidents.service.js:57,61; databases.service.js:27-31; certificates.service.js:37-42; security.service.js:64-89; monitoring.service.js:9,35; restores.service.js:45,50 | Project isolation gap. These list/get endpoints sit behind requireSession only, with no project visibility or RBAC check. | A user with no project membership enumerates all servers, domains, databases, backup runs and checksums, certificates, incidents and restore runs. | Apply projects.access visibleProjectIds/requireView filtering or an assertCan read permission. |
| 8 | Medium | auth/auth.service.js:149 | TOTP secrets are stored in plaintext (secretRef); unconfirmed factors accumulate. | A DB read leak yields every MFA seed. | Encrypt with AES-GCM using an env key or a secret manager reference; cap unconfirmed factors. |
| 9 | Low | audit/audit.service.js:4 | Redaction regex covers pass/secret/token/authorization/cookie/api-key only; privateKey, credential, dsn, connectionString, agentKey, fingerprint are not redacted. | A future caller logging {agentKey} or {privateKey} stores the secret in the audit log. | Extend the pattern. |
| 10 | Low | deployments.service.js:51; logs.service.js:80; projects.service.js:99 | Fail-open pattern: no actor means no filter. Safe today because routes require a session. | A future route without requireSession returns every project. | Throw when actor is missing. |
| 11 | Low | common/crypto/password.js:25-29 | Legacy unsalted SHA-256 hashes still verify; scrypt uses default parameters. | A leaked legacy hash is cheap to crack until the next login. | Force reset of legacy hashes; tune scrypt cost. |
| 12 | Low | app.js:12-17 | No explicit CORS policy (default no CORS headers, safe if same-origin), no trust-proxy config, no request logging. Request id is server-generated (good). | n/a | Document the CORS decision; set trust proxy when behind a reverse proxy. |
| 13 | Low | users/users.service.js:92-110 | The last Owner can be disabled, and an Owner can disable self. | Lockout of all Owners. | Block disabling or demoting the last active Owner. |
| 14 | Low | backups.service.js:111-118; platform/platform.crypto.js:85-91 | AES-GCM has no AAD binding to run/kind. | Ciphertexts could be swapped between artifacts; mitigated by the stored checksum. | Pass the artifact name as AAD. |
| 15 | Low | platform/platform.emergency.js (header comment) | Break-glass is recorded but not enforced by rbac (documented in code). | The Owner window grants nothing. | Track as a known gap. |

## Verified OK (by reading code)
- Session tokens: 32 random bytes, stored as SHA-256 hash, 12h expiry, revocation and user-status checks on every request (require-session.js).
- Agent auth: key hash compared with timingSafeEqual, revoked agents rejected, certFingerprint excluded from API responses (servers.service.js:9). Enrollment tokens are random, hashed, TTL 1h, single-use via atomic updateMany claim (agents.service.js).
- Agent report input is bounded by Zod (200 services, 500 ports, strict).
- Approval gate: binds action, resource and change binding, 24h TTL, blocks self-approval at decision, only the requester can execute. Operations module enforces separation of duties and uses an atomic execute claim.
- RBAC: environment-scoped permissions need an environment, no cross-environment match, delegation requires holding the permission, self-grant denied.
- AES-256-GCM: fresh random 12-byte IV per encryption, key length check, fails closed on a missing key or tag mismatch. Backups verify checksum then decrypt; retention keeps at least 3 verified sets.
- Teams: leads cannot appoint or remove leads. Users: non-owner sees only self.
- Logs: per-project/environment RBAC on search, export and stream; CSV formula neutralization. Reports re-check authorization on download.
- No child_process, fs, $queryRaw or outbound fetch found in apps/api/src. new URL is used only for git remote credential stripping (projects.service.js:16). No SSRF, path traversal or shell injection sinks found.
- Helmet enabled, x-powered-by disabled, JSON body limit 64kb, error handler hides internals.

## UNVERIFIED
- Controllers and validators of modules not read line by line (domains vhost input, deployments executor, operations.enqueue envelope); injection through those inputs is not excluded.
- Whether logs toFilter strictly pins stream and search filters to the authorized project/environment.
- Prisma schema constraints and the real adapters (platform.adapters.js is simulated).
- Reverse proxy, TLS and deployment configuration, including any proxy-level rate limiting.
- Reports and activity project scope for every parameter combination.
- Web UI, agents/ and scripts/ were out of scope.

## Remediation log (lead, 2026-11-15)

Fixed locally, each with a unit test in `apps/api/tests/security-fixes.test.js` (Vitest 28 files / 284 tests PASS, mocked Prisma):

| Finding | Fix |
| --- | --- |
| Critical: MFA bypass via pending session enrolling its own factor | `enrollTotp` and `confirmTotpEnrollment` require an MFA-satisfied session once a verified factor exists |
| High: no rate limiting | `common/middleware/rate-limit.js` on `/auth/login` (per IP and per IP+email), `/auth/mfa/verify` (per IP and per session, 5 per 10 min), `/agents/enroll`. In-memory, per process; a shared store is REQUIRES DECISION behind multiple instances or a proxy |
| High: audit log readable by any user | `audit.requirePermission` now requires Owner or an rbac grant/role for `audit.logs.read` |
| High: approval not atomic | `platform.gate` claims the approval with `updateMany` on `status: approved` and requires count 1 |

Still OPEN (not fixed): project-scope checks on list/get endpoints (servers, backup policies/runs, domains, incidents, databases, certificates, security, monitoring, restores); firewall maintenance window not part of the approval binding; `backups.applyRetention` skips the environment check done by `runBackup`. Items marked UNVERIFIED in this report remain unverified. Live behaviour of the fixes is NOT_RUN until the API is restarted. This remains an AI review, not the human independent review.
