# TASK-009 independent review packet
Task: TASK-009: Read-only services processes and ports. Phase: 02 - Server Agents & Monitoring. Recorded status in task file: PLANNED. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Read-only services processes and ports for NodeTeam Control. Scope: Systemd/PM2/Apache/Nginx, snapshots, processes/network/storage.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-009.md)
Compare fixture system output; reject unauthorized servers; identify shared-service impact without restart.
## Implementation files
- apps/api/src/modules/servers/
- apps/api/src/modules/agents/
- agents/ubuntu-agent/internal/collector/
## Tests and evidence
- apps/api/tests/agents-servers.test.js (12 tests)
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-008-010-TEST.md
- Evidence: no self-review file
## Acceptance coverage
- Criteria with local test evidence: see Covered/PASS rows in the TEST record; map each criterion to a test name during review (not done here).
- NOT_RUN or open items recorded in the TEST record:
  - Live API end-to-end (register, token, enroll, 3 reports, servers/metrics/fleet read-back; bad/absent credentials rejected) | PASS on 2026-11-15 against live ...
  - mTLS (certificates, CA, pinning) | NOT_RUN / REQUIRES DECISION: interim key credential in use, not mTLS | 
  - Go agent build and Ubuntu discovery of real processes/ports | NOT_RUN: Go toolchain absent; `scripts/dev-agent.mjs` is a dev harness only | 
  - Reconnect replay protection, per-server permission scoping | NOT_RUN | 
  - Production | NOT_RUN | 
## Simulated vs real
- Simulated: Prisma is an in-memory double in tests; executors, DNS, ACME, backup storage and agent actions are simulated unless the TEST record says otherwise. Real: local dev API/MySQL runs only where the TEST record states them. Production: not verified.
## Open risks
- Dependencies not installed or REQUIRES DECISION items (for example BullMQ, mTLS, Loki, Wazuh, Restic) remain open; see the SELF_REVIEW file.
## Reviewer checklist
- [ ] Acceptance criteria independently re-derived and each mapped to a test or evidence file
- [ ] Tests re-run by reviewer (command and result recorded in docs/TEST)
- [ ] Simulated components confirmed as labelled; no production claim
- [ ] AGENTS.md rules checked (module layout, Zod validators, no secrets, English only)
- [ ] Open risks and NOT_RUN items accepted, deferred or turned into tasks
Reviewer name: ____  Date: ____  Verdict: ____ (leave blank until a human completes the review)
