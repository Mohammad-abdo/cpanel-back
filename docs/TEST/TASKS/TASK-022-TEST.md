# TASK-022 TEST: Managed project databases and scoped access

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase6-databases.test.js` -> 9 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Create requires approval; staging grant denied on production; reserved names rejected; strict validators
- User grants are scoped to one database, no GRANT OPTION, no destructive privileges; password returned once and absent from storage, audit and adapter call log
- Cross-environment user creation blocked; unauthorized and duplicate users rejected
- Drop requires confirmation name, a fresh verified safety backup of the same project (5 negative variants) and critical approval
- Listing exposes username and scope only

## Implementation under test
apps/api/src/modules/databases/*

## NOT_RUN or UNKNOWN
- Real MySQL administration, real privilege verification with a live server, credential delivery to the project (the password hand-off channel is UNKNOWN).
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.
