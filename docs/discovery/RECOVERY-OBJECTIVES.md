# Recovery objectives worksheet (TASK-001)

All items below are REQUIRES DECISION until Owner sets them. Do not invent defaults to close the gate.

**Authorization 2026-11-15:** Owner authorized continuing all phases while these remain REQUIRES DECISION / UNKNOWN. Decisions are still required before recovery acceptance; they are not waived—only the block on starting later design/implementation phases is lifted.

| Decision | Value | Owner decision date |
| --- | --- | --- |
| Platform / control-plane RPO | REQUIRES DECISION | |
| Platform / control-plane RTO | REQUIRES DECISION | |
| Typical project RPO (default policy) | REQUIRES DECISION | |
| Typical project RTO (default policy) | REQUIRES DECISION | |
| Acceptable maintenance window | REQUIRES DECISION | |
| Offsite backup provider / destination category | REQUIRES DECISION | |
| Offsite retention period | REQUIRES DECISION | |
| Immutable / object-lock required? | REQUIRES DECISION | |
| Control-plane hosting isolation requirement | REQUIRES DECISION | |
| Emergency Owner access procedure owner | REQUIRES DECISION | |
| Production rollback responsibility | REQUIRES DECISION | |
| Isolated restore environment availability | REQUIRES DECISION | |

## Guidance (not decisions)

`required.md` §8 requires per-project backup policy fields (frequency, retention, encryption, destination, verification, RPO/RTO) and separate backup credentials. Exact numbers must come from Owner.
