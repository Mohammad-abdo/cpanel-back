# UI Browser QA

Date: 2026-11-15. Tool: Chrome DevTools MCP against the existing Vite dev server on :5173 (proxy to API :4000). Signed in once as the seeded Owner. This is a local test, not production verification.

## Route matrix

Legend: P = PASS, F = FAIL, N = NOT_RUN. Columns: renders content (EN) / no horizontal scroll at 1920, 1280, 390 / Arabic RTL, no raw keys.

| Route | Renders | 1920 | 1280 | 390 | AR |
|---|---|---|---|---|---|
| / | P | P | P | P | P (fixed enums) |
| /servers | P | P | P | P | P |
| /approvals | P | P | P | P | P (fixed enums) |
| /projects | P | P | P | P | P |
| /deployments | P | P | P | P | P (fixed enums) |
| /logs | P | P | P | P | P |
| /errors | P | P | P | P | P |
| /monitoring | P | P | P | P | P |
| /domains | P | P | P | P | P |
| /ssl | P | P | P | P | P |
| /databases | P | P | P | P | P (module owned by another agent; not edited) |
| /backups | P | P | P | P | P |
| /security | P | P | P | P | P (fixed enums) |
| /incidents | P | P | P | P | P (fixed enums) |
| /reports | P | P | P | P | FAIL: report names stay English (reports module, not edited) |
| /team, /access | P | P | P | P | P |
| /team/:userId | N | N | N | N | N |
| /nonexistent | P (Page not found) | N | N | N | N |
| /my-activity /notifications /services /network /storage /runtime /team-analytics /audit /integrations /settings | Placeholder ModulePage only (checked in AR for key leaks: none) | N | N | N | P |

Only /servers was visually inspected by screenshot at 1920 wide; other widths were measured via scrollWidth vs innerWidth.

## Console and network

- Console errors/warnings after the full sweep: none.
- Network: 47 XHR/fetch calls across the routes, all 2xx/304. No 4xx/5xx observed.
- /logs and /monitoring issued no list requests in the captured window (not investigated).

## Interaction checks

- Mobile 390: sidebar drawer opens via "Open navigation" and renders. Closed-drawer nav links remain in the accessibility tree (not investigated further).
- Desktop collapse toggle: 256px to 64px and back (PASS).
- Ctrl+K focuses the top bar search; typing "serv" lists Servers/Services; Enter navigates to /servers (PASS).
- Keyboard focus: a Tab-focused control showed a 1.6px accent outline; CSS defines :focus-visible for .nt-link, .nt-btn, .nt-icon-btn, .nt-tab, .nt-menu-item. Nav links were not individually tab-tested.
- Sign out from the user menu returns to /login (PASS).
- Arabic: dir=rtl, sidebar on the right, tables and top bar mirrored (screenshot of /incidents).

## Fixes made

1. apps/web/src/theme/index.css: `.nt-brand { flex: none }`. The sidebar and drawer logo was clipped at the top because the flex column shrank the brand block.
2. apps/web/src/services/format.js: `label()` now looks up `enum.<value>` in the locale messages and falls back to the previous prettified text. This translates status, severity, environment, role and action values that previously stayed English in Arabic. It is a small edit outside the allowed folder list because label() is shared by every module.
3. apps/web/src/i18n/messages.js: added about 60 `enum.*` keys to both en and ar.

Verification: `cd apps/web && npx vite build` passed after the changes. Fixed pages (/incidents in AR, sidebar logo) were re-checked in the browser.

## Open issues

- Reports module: report type names ("Project summary", "Deployment success", ...) and report cron strings are not localized (apps/web/src/modules/reports, not edited).
- Audit event action codes on Overview (auth.login, operation.approve, security.sync) stay raw in both languages.
- Unmapped enum values still fall back to English; add `enum.<value>` keys as new values appear.
- "Owner" display name and demo-* data names are data and stay English.
- Not tested: /team/:userId, the 1920 and 1280 screenshots beyond metrics, visual review of every page at 390.
