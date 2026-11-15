# Changelog

## 2026-11-15
- Phase 04: fixed broken logs routes (`monitoring.errors.js`), wired logs/errors API + Logs/Errors dashboard pages; Vitest 156 passed; web build OK. Loki store still REQUIRES DECISION.
- Laragon local MySQL (no Docker): applied `init` + `auth_credentials` migrations to `nodeteam_control`; seeded Owner `owner@localhost.local`; restored root `package.json`; aligned auth to schema fields `passwordHash` / `tokenHash` / `ownerFlag` / `mfaSatisfied`.
- Established documentation and task planning from source requirements.
- Early backend health/module-generator scaffold implemented; nine tests passed; dependency audit reported zero known vulnerabilities after Vitest update. Historical local evidence only.
- User mandated strict source phase order; added rules, removed prerequisite exception and recorded incomplete TASK-001 inventory.
- Rebuilt31 project-specific task contracts,15 delivery specifications and source traceability; corrected dependencies while preserving IDs/history.
- User required English-only documentation. Converted requirements, sources, references, plans, tasks and review records. Product localization scope remains unchanged. No application code changed for this conversion.
