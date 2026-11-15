# TASK-024 TEST: Offsite retention and artifact verification

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase7-backups.test.js` -> 7 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Tampered ciphertext detected by checksum; forged artifact with rewritten checksum detected by GCM authentication; missing artifact detected; unauthorized verification denied (verification and retention groups, 7 tests)
- RPO status within/breached/none
- Retention always protects the 3 newest verified sets and never deletes more than half; nothing deleted when only protected sets remain
- Retention apply needs approval then removes offsite objects and expires runs

## Implementation under test
apps/api/src/modules/backups/*

## NOT_RUN or UNKNOWN
- Independent offsite storage with separate credentials. The compromised-app guarantee is enforced at application level only; storage-level immutability or object lock is UNKNOWN. Real RPO/RTO measurement and scheduled verification are NOT_RUN.
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.
