# TASK-023 TEST: Consistent encrypted DB and config backups

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase7-backups.test.js` -> 9 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Full state machine ends retained and verified; transition table forbids skipping stages (lifecycle group, 9 tests)
- Only AES-256-GCM ciphertext is uploaded; manifest lists every artifact and the dump method (single-transaction)
- Missing key fails closed with no upload; dump failure and upload failure handled with cleanup; inconsistent snapshot rejected (concurrent writes)
- Concurrent run, wrong environment and unauthorized actor refused
- Policy validator forces offsite destination and aes-256-gcm

## Implementation under test
apps/api/src/modules/backups/*

## NOT_RUN or UNKNOWN
- Real restic/mysqldump execution, a real concurrent-write test against MySQL, worker queue integration (runs execute inline through the adapter).
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.
