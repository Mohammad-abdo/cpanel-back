# Security test plan (TASK-030)

Status: PLAN. Only the automated local checks marked LOCAL_SIMULATED have been run. Penetration testing is NOT_RUN.

## Automated, run locally (tests/phase9-security.test.js, tests/phase9-platform.test.js)
- Every route of the phase 06 to 09 modules returns 401 without a session. LOCAL_SIMULATED.
- IDOR on foreign-project domains and databases. LOCAL_SIMULATED.
- Approval self-approval, replay, expiry, change mismatch, rejection. LOCAL_SIMULATED.
- Secret redaction, AES-256-GCM tamper detection, key handling. LOCAL_SIMULATED.
- Break-glass authorization and lockout. LOCAL_SIMULATED.
- CSRF: the API reads the Authorization header only and no cookie, so cookie-borne CSRF does not apply to these routes. Browser token storage and XSS exposure are not assessed.

## To run by an independent tester (NOT_RUN)
1. Session fixation, token theft and replay against the real session layer.
2. Privilege escalation through grant delegation across teams and environments.
3. Mass assignment and parameter pollution against every body schema.
4. Rate limiting and brute force on login, MFA and break-glass.
5. Backup artifact tampering on real offsite storage, and deletion attempts with application credentials.
6. SSRF and command injection through adapter inputs once real adapters exist (hostnames, ports, database names).
7. Offsite control-plane restore drill and measurement against approved RPO and RTO (UNKNOWN until approved).

Record expected result, actual result and evidence for each case in docs/TEST. Do not mark anything passed without evidence.
