# Account pages test record

Scope: /notifications, /my-activity, /audit, /settings pages and their backend. Local dev only; no production verification is claimed. This is a developer test record, not independent review.

## Commands and results

| Command | Result |
| --- | --- |
| `cd apps/api && npx vitest run` | PASS: 35 files, 337 tests (includes 20 new tests in `tests/phase11-account-notifications.test.js` and `tests/phase11-account-auth.test.js`). One earlier run showed a failure in `phase11-infra-read.test.js` (another owner's file, in flux); it passed on the final run. |
| `cd apps/web && npx vite build` | PASS (built, chunk-size warning only). |
| Live curl against running API (127.0.0.1:4000, already serving the new routes) | See below. |

## Live endpoint checks (Owner session)

- GET /notifications?limit=2: 200, `{items:[],nextCursor:null,unreadCount:0}`
- GET /notifications/preferences: 200, 8-entry matrix (4 events x in_app/email), default enabled
- PUT /notifications/preferences valid: 200; unknown eventKind: 400 VALIDATION_ERROR
- POST /notifications/read-all: 200 `{updated:0}`
- POST /notifications/:randomUuid/read: 404 NOTIFICATION_NOT_FOUND
- GET /notifications without token: 401
- GET /activity/me?limit=3: 200, own events only
- GET /audit/events?limit=2&result=success: 200, rows include `actor` summary
- GET /auth/me: 200 (`mfaEnabled:false`); GET /auth/sessions: 200 (no token hashes, `current` flag)
- DELETE /auth/sessions/:randomUuid: 404 SESSION_NOT_FOUND
- POST /auth/password/change wrong current password: 401 AUTH_INVALID; short new password: 400 VALIDATION_ERROR

## Automated coverage

- Notification scoping (list, read, read-all use the session user id), cursor paging, preference matrix, strict validators, upsert scoped to caller, `notify` redaction, never-throws, preference opt-out.
- Password change: wrong current password denied and audited, policy enforced in service, scrypt hash stored, other sessions revoked, no password in audit payload.
- Sessions: listing excludes token hashes, revoke of another user's session returns 404.
- My timeline always filters by the session user; audit query accepts result and date filters and stays strict.

## NOT_RUN

- Successful live password change (would alter the seeded Owner password; covered by unit tests only).
- Live TOTP enroll and confirm from the Settings page, session revoke of a real session, and live notification creation through approvals, incidents and alerts (covered by unit tests of `notify` only).
- Browser rendering, keyboard and RTL visual checks of the four pages (build only).
- Audit CSV export and clipboard copy in a real browser.
- Email delivery (no channel is connected; preferences are stored only).
