# Backend module architecture

User decision: each feature module MUST own its controller, validator, service and routes.

    apps/api/src/modules/<module>/
      <module>.routes.js
      <module>.validator.js
      <module>.controller.js
      <module>.service.js
      <module>.repository.js  # optional persistence boundary

Flow: routes -> authentication/resource policy -> validator -> controller -> service -> repository/Prisma.
Routes compose middleware and paths. Zod validators parse input; controllers use req.validated and translate results into HTTP. Services own business logic and never depend on Express request/response. Repositories isolate Prisma persistence when needed. Shared middleware belongs in common; feature logic stays in its module. Cross-module work calls a public service contract, never another controller.

Only health liveness is public in this slice. Future feature endpoints require sessions and scoped authorization before mounting. No placeholder CRUD endpoints are exposed.

Express 5 propagates rejected async handlers to centralized error middleware: https://expressjs.com/en/guide/error-handling.html

Use npm run module:create -- <name>. Existing modules are never overwritten; traversal and invalid names are rejected. Module mounting is deliberate after contract and permission review.
