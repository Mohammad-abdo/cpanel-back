# Independent review packets

One packet per task (TASK-001 to TASK-031), named `TASK-0xx-REVIEW-PACKET.md`. Each collects the objective, acceptance criteria, implementation files, tests, evidence files, NOT_RUN items, simulated-versus-real notes, open risks and a blank reviewer checklist.

## How a human reviewer uses a packet

1. Read the task contract in `docs/PLAN/TASKS/TASK-0xx.md` and the packet.
2. Re-derive each acceptance criterion yourself and map it to a test name or evidence file. Do not rely on the SELF_REVIEW.
3. Re-run the tests listed in the packet. Record the exact command and result in `docs/TEST/TASKS/`.
4. Check that simulated components are labelled and that no production verification is claimed from local tests.
5. Tick the checklist boxes you verified. Fill in reviewer name, date and verdict (PASS, FAIL or CONDITIONAL) yourself.
6. Write the formal review record under `docs/REVIEW/TASKS/` and link it from the packet.

## DONE gate rule (from AGENTS.md)

A task may be marked DONE only when both an independent review (a reviewer other than the implementer, not SELF_REVIEW or AGENT_REVIEW) and required testing are recorded under `docs/REVIEW` and `docs/TEST`, the canonical task registry and project status are updated, and unmet gates (UNKNOWN, REQUIRES DECISION, NOT_RUN) are not hidden. These packets are preparation material only. They record no review, pass or DONE state, and the reviewer fields are intentionally blank.
