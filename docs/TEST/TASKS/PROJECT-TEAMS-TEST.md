# Project Teams and Members Test Record

Scope: ProjectTeam link model, project member management endpoints, team-linked project visibility, web Team tab.

## Commands and results
- `cd apps/api && npx prisma validate`: valid.
- `npx prisma migrate dev --name project_teams --skip-generate`: applied `20261115173421_project_teams`; SQL is CREATE TABLE, one index, two ADD CONSTRAINT only (no DROP/DELETE/TRUNCATE). Prisma client NOT regenerated.
- `cd apps/api && npx vitest run`: 39 files, 485 tests pass (earlier runs showed transient failures in other agents' http/security tests that passed on rerun). New `tests/phase12-project-teams-service.test.js`: 11 mock-based tests pass.
- `cd apps/web && npx vite build`: built successfully.

## Live behaviour
NOT_RUN. Requires `prisma generate` and an API restart. Until then team endpoints answer 501 SCHEMA_REQUIRED and scope ignores team links (fail-closed).

## Notes
- `project.configure` is environment-scoped in the permission catalog, so manager status is granted when held on any environment of the project.
