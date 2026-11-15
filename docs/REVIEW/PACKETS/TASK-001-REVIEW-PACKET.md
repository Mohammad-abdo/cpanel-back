# TASK-001 independent review packet
Task: TASK-001: Ubuntu inventory and security recovery baseline. Phase: 00 - Discovery & Technical Foundation. Recorded status in task file: IN_PROGRESS. This packet does NOT change status; no review, pass or DONE is recorded here.
## Objective
Deliver Ubuntu inventory and security recovery baseline for NodeTeam Control. Scope: Resources, projects, PM2/Laravel/Apache, ports, engines, backups, RPO/RTO.
## Acceptance criteria (copied from docs/PLAN/TASKS/TASK-001.md)
Evidence-backed read-only inventory; unknowns explicit; no project-path changes.
## Implementation files
- docs/discovery/INVENTORY.md
- docs/discovery/SERVER-INVENTORY.md
- docs/discovery/SECURITY-BASELINE.md
- docs/discovery/RECOVERY-OBJECTIVES.md
## Tests and evidence
- No automated test files map to this task (documentation/specification task).
- Test files may be shared with other tasks; counts are per file. Full suite last run locally 2026-11-15: 29 files, 292 tests passed (in-memory Prisma double).
- Evidence: docs/TEST/TASKS/TASK-001-TEST.md
- Evidence: docs/REVIEW/TASKS/TASK-001-SELF-REVIEW.md (SELF_REVIEW, not independent)
## Acceptance coverage
- No automated test evidence; criteria are documentation-based and unverified.
- NOT_RUN or open items recorded in the TEST record:
  - Read-only Ubuntu inventory vs worksheet | NOT_RUN — no authorized remote access; Owner authorized 2026-11-15 to leave UNKNOWN | 
  - Security baseline evidence filled | NOT_RUN — values UNKNOWN (authorized proceed) | 
  - RPO/RTO Owner decisions recorded | NOT_RUN — REQUIRES DECISION (authorized proceed) | 
  - Local discovery documentation complete. Production checks remain NOT_RUN / UNKNOWN by Owner authorization 2026-11-15. **Do not treat as PASSED production tes...
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
