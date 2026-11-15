# Live authorization and MFA test (local dev API)

Scope: local verification only. This is NOT production verification and not independent review.

## Command

    node scripts/live-authz-check.mjs

Target: http://127.0.0.1:4000/api/v1 (local Laragon dev DB, demo data). The script refuses non-localhost APIs, uses
fetch only, never prints tokens or secrets, and exits non-zero on failure. Each run creates one throwaway user
`demo-mfa-user-<timestamp>@localhost.local` (kept, never deleted). Owner and demo-approver passwords are not changed.

## Result (final run)

PASS 65, FAIL 0, NOT_RUN 0.

Areas covered:
- Visibility (non-owner demo-approver): servers, projects, deployments, domains, certificates, databases, backup
  policies/runs, incidents, security events/incidents, restore points contain no Owner-only rows; own RBAC grants only;
  GET by id of Owner project/server/domain/deployment/incident returns 404; non-owner create server/project, register
  database instance, create team return 403; RBAC grant to self rejected; audit events read 403.
- Separation of duties: High-risk DNS change returns 202 approvalRequired; replay before approval 409
  APPROVAL_NOT_APPROVED; Owner self-approval 403 SELF_APPROVAL_DENIED; approver approves; approval for change A
  replayed as change B 409 APPROVAL_MISMATCH; replayed for another domain 409 APPROVAL_MISMATCH; non-requester 403;
  replay succeeds once; second replay 409 APPROVAL_CONSUMED.
- MFA: enroll/confirm TOTP; second login mfaRequired, authorized=false; pending token gets 401 MFA_REQUIRED on
  protected and write routes; enroll/confirm with pending session 401 MFA_REQUIRED (bypass fix verified live); wrong
  code 401 MFA_INVALID; correct code authorizes; protected route 200.
- Password: short password 400; wrong current password 401; valid change 200; other sessions revoked, current kept;
  old password rejected; new password logs in.
- Sessions: list, revoke own other session (then 401), cross-user revoke 404 with victim unaffected.
- Agents: report without credentials 401; enroll with garbage token 401.

## Bugs found in apps/api/src

None. Two initial FAILs were test-script errors (invalid permission key in the grant body; cross-domain replay used the
wrong environment id) and were fixed in the script. No regression test was needed.

## Limitations

- demo-approver has no project membership, so every visibility list is empty. This proves no Owner-only leakage but does
  not exercise the positive case (a member seeing only their own project data). That case is covered by
  apps/api/tests/scope-isolation.test.js, not by this live script.
- Rate limiting is not exercised here.

## Unit suite

`cd apps/api && npx vitest run` after the run: see the report (no source changes were made).
