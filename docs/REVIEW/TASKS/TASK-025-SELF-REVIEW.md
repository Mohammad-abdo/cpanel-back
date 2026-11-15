# TASK-025 SELF_REVIEW: Restore points, isolated recovery and approval

This is a SELF_REVIEW by the implementing agent. It is not independent review and does not satisfy the review gate.

## Scope checked
- Controller, validator (Zod strict), service and routes exist for the owning module; business logic lives in services.
- Privileged actions go through the approval gate (platform.gate) with reason, impact preview, rollback note, separate approver, single use and change binding where applicable.
- Secrets are redacted before storage; no real secrets in source or docs; encryption keys come from the environment.
- Real tooling sits behind injectable adapters; the default adapters are simulated and results are marked as simulated.

## Known weaknesses
- Real restore into an isolated scratch environment and real file/data comparison (the simulated adapter compares checksums only). Automatic rollback after a failed in-place restore is not implemented; the safety backup id is returned for manual rollback.
- Permission keys outside the shared catalog (project.database.manage, security.incident.manage, platform.approval.decide, platform.access.review) are proposed additions. Until they are added to the catalog and granted, only the Owner passes those checks.
- Approval requests carry action, risk tier and change binding inside ApprovalRequest.impactJson because the schema has no dedicated columns.

## Review gate
Independent review: NOT_RUN. Do not mark DONE until it passes.
