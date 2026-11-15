# TASK-025 TEST: Restore points, isolated recovery and approval

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase7-restores.test.js` -> 11 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Request validates, previews impact and waits for approval without restoring
- Execute without approval refused; only the requester may execute
- Isolated restore completes with data comparison and health check; in-place restore takes a safety backup first and aborts if it fails
- Corrupt set rejected at validation; staging backup into production rejected; manifest and unverified sets rejected
- Data mismatch and failed health check end in failed state

## Implementation under test
apps/api/src/modules/restores/*

## NOT_RUN or UNKNOWN
- Real restore into an isolated scratch environment and real file/data comparison (the simulated adapter compares checksums only). Automatic rollback after a failed in-place restore is not implemented; the safety backup id is returned for manual rollback.
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.
