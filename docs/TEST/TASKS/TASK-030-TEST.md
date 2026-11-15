# TASK-030 TEST: Security testing, platform recovery and emergency Owner

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase9-platform.test.js` -> 21 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Every route of every phase 06-09 module returns 401 without a session; write routes sit behind the MFA session gate (phase9-security, 14 tests)
- No cookies are read (bearer-only), so ambient-credential CSRF does not apply to these routes
- IDOR: foreign-project domain and database operations denied; approval self-approval, replay, expiry, mismatch and rejection tested
- Redaction, AES-256-GCM properties, key handling and risk model
- Break-glass: Owner only, recovery code hash comparison, lockout after repeated failures, expiry and early end; recovery code never logged (phase9-platform emergency and routes groups, 7 tests)
- Readiness reports unknowns as unknown

## Implementation under test
apps/api/src/modules/platform/platform.emergency.js, apps/api/tests/phase9-security.test.js

## NOT_RUN or UNKNOWN
- External penetration test, session fixation and escalation tests against the real session layer, offsite control-plane restore drill, approved RPO/RTO verification, rbac enforcement of the break-glass window.
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.

## Update 2026-11-15
- See docs/handover/RELEASE-ACCEPTANCE.md (evidence commands) and docs/18-PROJECT-STATUS.md.
