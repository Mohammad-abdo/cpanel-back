# TASK-021 TEST: SSL issue, renewal and expiry

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase6-certificates.test.js` -> 11 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- State classification valid/expiring/expired/failed
- Expiry scan flips stale active status to expired
- Issue needs approval; certificate recorded with expiry; simulated flag reported
- Missing exact-scope ssl.issue denied; wildcard requires dns-01; unresolved DNS refused; archived domain refused
- CA failure marks certificate failed and returns 502
- Renewal not due without force; renewal inside window and recovery of an expired certificate; failed renewal keeps expired state; unauthorized renewal denied

## Implementation under test
apps/api/src/modules/certificates/*

## NOT_RUN or UNKNOWN
- Real ACME/certbot issuance, real web server reload, real expiry monitoring schedule (the scan must be scheduled by a worker; not wired).
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.
