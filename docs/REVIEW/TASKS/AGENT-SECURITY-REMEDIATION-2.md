# Agent security remediation 2

Label: AGENT_REVIEW remediation, not independent human review. Live behaviour is NOT_RUN until the API is restarted.

Command: `cd apps/api && npx vitest run` -> 29 files, 292 tests passed.

| Finding | Fix | Tests |
|---|---|---|
| #7 Project isolation on read endpoints | New `src/common/scope.js` (Owner unrestricted; others see ProjectMember / project grant / project role projects, servers hosting them, explicit server grants; missing actor sees nothing). Applied to list/get in servers (incl. metrics), monitoring (fleet, server health), backups (policies, runs, rpo, retention plan), restores (points, get), domains, databases (+instances), certificates (list, expiring), incidents (list, get, timeline, verifyEvidence), security (incidents, events, summary). Out-of-scope ids return 404. Project-less incidents/events/servers are Owner-only unless an explicit server grant exists. | `scope-isolation.test.js`: scope helper (3), servers, incidents, domains |
| Firewall window not bound to approval | Binding now hashes changes plus normalised windowStart/windowEnd. | `phase8-firewall-access`: binds the maintenance window to the approval |
| applyRetention skips environment check | Same ENVIRONMENT_MISMATCH check as runBackup. | `phase7-backups`: applyRetention enforces the policy environment |

Signature changes: read methods take a trailing `actor` (controllers pass `req.user`). Existing tests adapted to pass OWNER for `rpoStatus`, `planRetention`, incident `timeline`/`verifyEvidence`, security `summary`. `backups.planRetention` now has an internal `_plan` used by `applyRetention`; `restores.execute` reads the run directly (mutation path, authorised separately).

Still open: finding #10 fail-open pattern in deployments/logs/projects services (untouched); security `connection()` is global source health, left unscoped; role-scope visibility for environment-scoped roles only is not treated as project visibility.
