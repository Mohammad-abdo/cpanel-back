# Release acceptance matrix (TASK-031)

Status: DRAFT. Acceptance is NOT claimed. This matrix lists what evidence exists for phases 06 to 09 and what is missing. A row is PASSED only when a recorded test or review proves it. Local simulated tests are not production verification.

Legend: LOCAL_SIMULATED = unit tests with mocked Prisma and simulated adapters passed. NOT_RUN = no execution exists. UNKNOWN = no evidence or no decision recorded.

| Area | Requirement source | Evidence | Status |
| --- | --- | --- | --- |
| Domains, vhosts, DNS (TASK-020) | required.md 11, 15 | docs/TEST/TASKS/TASK-020-TEST.md | LOCAL_SIMULATED; real provider/web server NOT_RUN |
| SSL issue, renew, expiry (TASK-021) | required.md 11 | TASK-021-TEST.md | LOCAL_SIMULATED; real ACME NOT_RUN |
| Managed databases, scoped access (TASK-022) | required.md 11 | TASK-022-TEST.md | LOCAL_SIMULATED; real MySQL NOT_RUN |
| Encrypted consistent backups (TASK-023) | required.md 11 | TASK-023-TEST.md | LOCAL_SIMULATED; real restic/mysqldump NOT_RUN |
| Offsite retention and verification (TASK-024) | required.md 11 | TASK-024-TEST.md | LOCAL_SIMULATED; storage independence UNKNOWN |
| Restore, isolated recovery, approval (TASK-025) | required.md 11 | TASK-025-TEST.md | LOCAL_SIMULATED; real restore drill NOT_RUN |
| Wazuh Security Center (TASK-026) | required.md 14 | TASK-026-TEST.md | LOCAL_SIMULATED; real Wazuh NOT_RUN |
| Incident lifecycle (TASK-027) | required.md 14 | TASK-027-TEST.md | LOCAL_SIMULATED |
| Firewall maintenance, access reviews (TASK-028) | required.md 7, 14 | TASK-028-TEST.md | LOCAL_SIMULATED; real lockout test NOT_RUN |
| Multi-VPS scale, resilience (TASK-029) | required.md 16 | TASK-029-TEST.md | LOCAL_SIMULATED; measured load budgets NOT_RUN |
| Security testing, recovery, emergency Owner (TASK-030) | required.md 14, 16 | TASK-030-TEST.md | LOCAL_SIMULATED; penetration test and recovery drill NOT_RUN |
| Independent review of TASK-020 to TASK-030 | AGENTS.md | SELF_REVIEW files only | NOT_RUN |
| Permissions, audit, log, report, deploy evidence | TASK-031 scope | Outside this agent scope (phases 03-05 owned by another agent) | UNKNOWN |
| 15 core documents under docs/ | TASK-031 scope | Not audited by this agent | UNKNOWN |
| Requirements traceability update | TASK-031 scope | docs/REQUIREMENTS-TRACEABILITY.md not edited (outside file ownership) | NOT_RUN |
| Runbook rehearsal | TASK-031 scope | Runbooks in docs/runbooks are written, never rehearsed | NOT_RUN |
| Full regression | TASK-031 scope | Full local vitest run passed at last execution; no browser or integration regression | PARTIAL |
| Sign-off | TASK-031 scope | No sign-off recorded | NOT_RUN |
| Production verification | AGENTS.md | None | NOT_RUN |

## Decision log needed from the Owner
- Approved RPO and RTO per project: UNKNOWN.
- Approver model for a single-Owner install (requester cannot approve own request): UNKNOWN. Today a second user holding `platform.approval.decide` is required.
- Offsite backup target, credentials separation and immutability: UNKNOWN.
- DNS provider and ACME CA/client choice: UNKNOWN.
- Firewall maintenance windows and access review cadence: UNKNOWN.

## Closure rule
TASK-031 stays open until every row above has recorded evidence, an independent review passes, and the Owner signs off. Do not mark DONE earlier.
