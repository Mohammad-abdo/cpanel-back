# TASK-020 TEST: Virtual hosts, domains and DNS

Status: TESTED_LOCAL_SIMULATED (not production verified, not independently reviewed)

## Commands run
- `cd apps/api && npx vitest run tests/phase6-domains.test.js` -> **16 passed** (mocked Prisma, simulated adapters).
- Live API (Owner session, 2026-11-15 evening): `GET /domains` 200; `POST /domains/:id/vhost/preview` exercised against a demo domain.

## Evidence covered
- Domain create with exact-scope permission, audited
- Staging grant denied against production; cross-project environment denied; unauthenticated denied
- Duplicate domain rejected; strict validator rejects bad hostnames
- Virtual host preview is read-only and deterministic (nginx and apache renderers)
- Apply and DNS change require approval, a separate approver, reason and rollback note; approval is single use and bound to the exact change
- Invalid config rejected before an approval is requested; apply failure triggers rollback adapter call
- DNS provider failure stores nothing; out-of-zone, bad IPv4 and apex CNAME rejected
- Controller maps approval-required to HTTP 202

## UI slice (2026-11-15 evening)
- `/domains` Manage modal: vhost preview/apply + DNS upsert/remove form; EN/AR strings added.
- Routes were already mounted at `/domains` (prior test note that routes were unmounted is outdated).

## Implementation under test
apps/api/src/modules/domains/*  
apps/web/src/modules/domains/DomainsPage.jsx

## NOT_RUN or UNKNOWN
- Real Apache/Nginx reload, real DNS provider and real zone data (all simulated adapters).
- Full browser click-through of Manage modal: NOT_RUN in this pass.
- Production verification: NOT_RUN. Nothing was executed against a real server, DNS provider, CA, database, backup target, firewall or Wazuh.
- Independent review and independent test execution: NOT_RUN.
