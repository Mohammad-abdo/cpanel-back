# TASK-026 TEST: Wazuh Security Center integration

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase8-incidents-security.test.js` -> 5 tests in this task group passed (mocked Prisma, simulated adapters).
- `cd apps/api && npx vitest run` (full suite at last run) -> 23 files, 239 tests passed. The suite includes files from another agent.
- `cd apps/web && npx vite build` -> built successfully. The new pages are not imported by App.jsx yet, so the build does not compile them. They were syntax-checked with esbuild (jsx loader) only.

## Evidence covered
- Level to severity and group to category mapping for SSH, sudo, FIM, malware, ports, services, updates (security group, 5 tests)
- Scoped fixtures ingested, deduplicated, secrets redacted, independent flag set; high and critical alerts open incidents
- Unmapped agents flagged; malformed alerts skipped
- Wazuh unavailable degrades to a status and unauthorized sync denied
- 24 hour summary carries the no-guarantee notice

## Implementation under test
apps/api/src/modules/security/*

## NOT_RUN or UNKNOWN
- Real Wazuh API, real alert volumes, scheduled sync (not wired). Mapping an agent to a server by alias is an assumption.
- Live HTTP calls against the local API for the new routes: NOT_RUN (routes are not mounted yet).
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.
