# Runbook: security incident response

Status: DRAFT, NOT_RUN.

## Signals
Wazuh alerts are ingested through `POST /security/sync`. High and critical alerts open or update an incident. A quiet Wazuh feed is not proof of safety, and an unavailable feed is shown as unavailable.

## Lifecycle
Detected, triaged, assigned, investigating, contained, resolved, closed. Steps cannot be skipped.
- Assign with `POST /incidents/:id/assign` after triage. Only the owner or the Owner role acts afterwards.
- Add evidence with `POST /incidents/:id/evidence`. Evidence is append-only and hash-chained. `GET /incidents/:id/evidence/verify` detects edits or removals. Secret-looking text is scrubbed.
- Severity can only be raised, with a reason. Critical incidents are closed by the Owner with a resolution note.
- A closed incident can be reopened within 14 days by its owner. After that open a new incident.

## Containment actions
Firewall changes follow FIREWALL rules: preview, approval, maintenance window, lockout guard with automatic rollback. Never change production without explicit authorization.
