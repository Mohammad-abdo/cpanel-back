# TASK-037: Project environments, environment variables and more project types

## Status
IN_PROGRESS
## Priority
HIGH
## Phase
10 - Owner operations extensions (added 2026-11-15 by Owner request)
## Objective
Add environments to any project and keep any number of environment variables (any key and value) per environment; support more kinds of projects.
## Requirements
Owner request 2026-11-15; see [DECISIONS](../../DECISIONS.md).
## Dependencies
TASK-018.
## Scope
POST /projects/:id/environments; ProjectEnvVar per environment (list, set one or many, import from .env text, delete, reveal secret values, export as .env); write the .env file to the server over SFTP when the server has an SSH login. Project types: node, nextjs, nuxt, react, vue, angular, laravel, php, wordpress, static, python, django, flask, fastapi, go, java, spring, dotnet, ruby, rails, docker, custom; process managers add docker, supervisor, gunicorn, uvicorn, passenger.
## Out of Scope
Production execution without the Owner's explicit authorization.
## Security Considerations
Values are AES-256-GCM encrypted with CREDENTIAL_ENCRYPTION_KEY (fails closed). Secret values are masked in lists and only revealed on request to users with project.configure for that exact environment (or the Owner); every change is audited with keys only, never values. Owner decision: replaces "secret values are never accepted, only names".
## Acceptance Criteria
Add/update/delete/import/export work per environment; staging access does not expose production values; values never appear in audit or logs; invalid keys rejected.
## Test Plan
Unit tests with fakes, integration tests against the SSH protocol test server where SSH is involved, live API checks; record expected/actual/evidence.
## Review Requirements
SELF_REVIEW labelled honestly; independent review before DONE.
