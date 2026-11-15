# TASK-028 TEST: Firewall maintenance and access reviews

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase8-firewall-access.test.js` -> 14 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Lockout evaluation for SSH removal or deny; sensitive port exposure rejected; shared-service impact listed
- Apply needs approval; approval bound to the change set; single use; self approval blocked
- Critical risk when SSH rules are touched; maintenance window enforced
- Automatic rollback when the server is unreachable after the change
- Unauthorized and wrong-server grants denied
- Access review classifies stale, disabled-user, high-risk-no-expiry and ownerless grants; revokes via rbac; completes only when decided; self review forbidden

## Implementation under test
apps/api/src/modules/firewall/*, apps/api/src/modules/access-reviews/*

## NOT_RUN or UNKNOWN
- Real ufw or provider firewall, a real lockout test on an isolated VPS, a shared-service inventory (the port list is a static assumption), review cadence (policy UNKNOWN).
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.

## Update 2026-11-15 (split repos)
- Live HTTP against the local API: PASS (`npm run drill:security`, 30/30; see docs/18-PROJECT-STATUS.md, Phase 08 update).
- Scheduled access reviews implemented (3 unit tests); web review screen added for decide/complete.
