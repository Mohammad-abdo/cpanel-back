# INFRA-PAGES-TEST

Scope: web pages /services, /network, /storage, /runtime, /team-analytics, /integrations and the read endpoints behind them. Local development only. This is not production verification.

## Commands and results

| Command | Result |
| --- | --- |
| `cd apps/api && npx vitest run` | PASS: 35 files, 337 tests (includes new `tests/phase11-infra-read.test.js`, 7 tests) |
| `cd apps/web && npx vite build` | PASS (chunk size warning only) |
| curl with Owner bearer token against http://127.0.0.1:4000/api/v1 | 200 for `/servers/services`, `/servers/ports`, `/servers/runtimes`, `/firewall/history`, `/platform/integrations`, `/members/analytics`, `/security/connection` (API reloaded the new routes without a manual restart) |
| chrome-devtools: open each of the six pages once | PASS: no console errors or warnings, no `[role=alert]` error lines, data rendered; 1 screenshot (storage) reviewed |
| Team analytics drill-down (click Owner deployments) | PASS: original events listed with source:id links |
| i18n key parity (node script) | PASS: 136 en keys equal 136 ar keys for the new prefixes, no missing dynamic keys |
| Arabic rendered in browser | NOT_RUN: language switch through the UI was not completed; parity was checked by script only |
| Non-Owner (scoped) user behaviour in browser | NOT_RUN: unit tests cover Owner gate for analytics only; scope filtering relies on `createScope` |
| Firewall history with real rows | NOT_RUN: dev DB has no firewall audit events (endpoint returned an empty list) |

## Findings

- `/platform/integrations` reports `log_store` as down on the dev DB ("Log table not reachable"): the LogEntry count query fails locally. Not investigated further (no migrations allowed in this task).
- Backup artifact sizes are not populated in demo data, so the storage page shows "No artifact size reported".
- Team analytics counts equal the existing member profile `eventCounts` (deployment 38, operation 59).
