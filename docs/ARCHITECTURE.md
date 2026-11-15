# ARCHITECTURE

React JSX Web -> Express JavaScript API -> Prisma/MySQL metadata. Redis/BullMQ workers. Prometheus metrics. Loki logs. Independent Go Agent over mTLS with allowlisted operations. Control plane isolated from production applications. Authorization in API, sockets, exports and Agent. Detailed schema, OpenAPI and Agent protocol remain planned deliverables.


Backend modules MUST own controller, validator, service and routes. [Detailed boundaries](BACKEND-MODULES.md).
