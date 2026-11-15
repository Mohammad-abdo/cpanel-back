# TASK-029 TEST: Multi-VPS scale and connection resilience

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase9-platform.test.js` -> 8 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Connection state connected/degraded/offline/never/revoked (fleet groups, 8 tests)
- Backoff grows, is capped and jittered; retry then succeed or throw
- Concurrency cap and failure isolation
- 1200 simulated servers paginate without duplicates within the 500 page budget; offline counted
- Probe isolates unreachable, error and timeout per server; fleet service is read-only

## Implementation under test
apps/api/src/modules/platform/platform.fleet.js

## NOT_RUN or UNKNOWN
- Measured load budgets on real agents and workers (LOAD_BUDGET holds engineering defaults, not measurements), real outage and reconnect drills, streaming, Socket.IO integration.
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.

## Update 2026-11-15
- See docs/handover/RELEASE-ACCEPTANCE.md (evidence commands) and docs/18-PROJECT-STATUS.md.
