# Project detail page test record

Scope: route `/projects/:projectId` (ProjectDetailPage), plus `GET /projects/:id/overview` and `GET /projects/:id/members`.
Status: local development verification only. No production verification is claimed. SELF_REVIEW only; no independent review has been done.

## Commands and results

| Command | Result |
| --- | --- |
| `cd apps/api && npx vitest run` | PASS, 35 files, 337 tests (includes `tests/phase11-projects-detail.test.js`, 3 tests) |
| `cd apps/web && npx vite build` | PASS, built without errors (chunk size warning only) |

## Browser checks (chrome-devtools MCP, demo-shop, Owner session, vite dev server)

| Check | Result |
| --- | --- |
| All 13 tabs render | PASS, no skeleton left after load, no horizontal overflow at 1280 |
| Console errors | One: `GET /logs/search` returned 501 `SCHEMA_REQUIRED` (LogEntry table not migrated in the dev DB). The Logs tab shows the API message and a Retry button. No migration was run. |
| Failed network calls | Same single 501. All other calls 200 or 304. |
| 1280 px English | PASS (screenshot reviewed; tab strip scrolls horizontally, last tabs partly clipped until scrolled) |
| Arabic RTL, narrow window | PASS after fixing a grid max-content overflow; no element exceeds the viewport |
| 1920 px | NOT_RUN (window could not be resized above the available screen; layout is capped at 1600 px) |
| 390 px | NOT_RUN at exactly 390: the browser window minimum was about 487 px. The 520 px and 860 px breakpoints were exercised at 487 px. |
| Unknown or out-of-scope project id (404 state) | NOT_RUN in browser; API 404 path covered by unit tests |
| Deploy request, rollback, lifecycle, settings save, archive in browser | NOT_RUN (no write actions were executed to keep dev data unchanged) |
| Keyboard focus and reduced motion | Focus rings defined for links, segmented control, row buttons; not verified by keyboard walk-through |
| Non-Owner (member) view | NOT_RUN |

## Known data notes

- Demo data has no health checks, certificates, members or error groups, so those cells show real empty states.
- Activity feed returns incident events not tied to the project id by the existing `/activity/project-timeline` endpoint; shown as returned.
