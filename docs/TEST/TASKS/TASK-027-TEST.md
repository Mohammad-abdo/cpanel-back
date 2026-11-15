# TASK-027 TEST: Incident lifecycle, evidence and ownership

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase8-incidents-security.test.js` -> 11 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Full lifecycle with timestamps; invalid transitions rejected including from closed (incidents group, 11 tests)
- Assignee must be real and active; resolution note required; cannot assign before triage
- Ownership and permission enforced; severity preserved and only raised; critical incidents closed by Owner
- Reopen only inside 14 days, by owner, close record preserved
- Evidence hash chain detects edits; secrets scrubbed; closed incidents refuse evidence; open-from-event dedupes

## Implementation under test
apps/api/src/modules/incidents/*

## NOT_RUN or UNKNOWN
- Dedicated evidence and action tables (evidence is stored as audit events because the schema has no evidence table); notification delivery.
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.
