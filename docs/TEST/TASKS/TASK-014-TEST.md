# TASK-014 test evidence

Date: 2026-11-15. Scope: Member profile timeline and identity mapping. Environment: local Windows workspace, Vitest with an in-memory Prisma double.

| Check | Command | Result |
| --- | --- | --- |
| Members tests | `cd apps/api && npx vitest run tests/phase5-members.test.js` | 7 passed, 0 failed |
| Combined phase 03-05 run | `npx vitest run` on the six phase3/4/5 files | 84 passed, 0 failed |
| Router modules import cleanly | `node -e` dynamic import of the routes files | ok |

Covered: initiator/approver roles separate with links to original events; denials and config changes as categories; unmapped GitHub/SSH events Unattributed and resolved only after an Owner mapping; Owner-only mapping; profile visible to self and Owner only without password hash; half-open period boundaries; project timeline visibility and metadata redaction.

## Additional this pass

| Check | Command | Result |
| --- | --- | --- |
| Members re-run | `cd apps/api && npx vitest run tests/phase5-members.test.js` | 7 passed, 0 failed |
| Web build | `npm run build:web` | ok (`/team`, `/team/:userId`, EN/AR) |

## NOT_RUN

- Real SSH/GitHub event collection: NOT_RUN (no collector exists; ActivityEvent rows with metadata.externalIdentity are the assumed input).
- Live HTTP/browser against Laragon with mapping round-trip: NOT_RUN. Production verification: not claimed.
- Note: ExternalIdentity table is now in Prisma migrations; prior SCHEMA_REQUIRED gap is closed for local schema.
