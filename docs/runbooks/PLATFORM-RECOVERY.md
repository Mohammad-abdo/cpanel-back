# Runbook: control plane recovery (TASK-030)

Status: DRAFT, NOT_RUN. No recovery drill has been executed. Approved RPO and RTO are UNKNOWN.

## Principle
Applications on the VPS keep running if the control plane is down. Agents keep buffering. Recovery restores the control plane (API, MySQL metadata, secrets) from an offsite encrypted backup.

## Preconditions to confirm before an incident
1. `GET /platform/readiness` (Owner session) shows every check as pass. Unknown checks stay unknown until evidence exists.
2. A verified backup exists and its artifacts pass `POST /backups/artifacts/:id/verify`.
3. The offline recovery code and the backup encryption key are stored separately from the platform host. Their locations are UNKNOWN until the Owner records them.

## Procedure (to be rehearsed)
1. Declare the incident and open an incident record.
2. Provision a clean host. Do not reuse a host that may be compromised.
3. Retrieve the newest verified offsite set and its manifest.
4. Verify checksums and decrypt in an isolated area. Stop if any check fails and try the previous verified set.
5. Restore MySQL metadata into the clean host. Start the API with fresh secrets (rotation needs explicit Owner authorization).
6. Confirm the Owner account exists and can sign in with MFA. If not, follow EMERGENCY-OWNER.md.
7. Re-enroll or reconnect agents. Confirm the fleet view shows servers connecting.
8. Record actual commands, timings and results in docs/TEST. Compare against the approved RPO and RTO once they exist.

## Evidence required to close
Drill date, backup set id, measured recovery time, data loss window, Owner sign-in proof. None exists yet.
