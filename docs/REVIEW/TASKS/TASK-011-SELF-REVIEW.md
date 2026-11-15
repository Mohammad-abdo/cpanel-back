# TASK-011 SELF_REVIEW (not independent review)

Scope: Log ingestion and redaction.

Findings and gaps:
- REQUIRES DECISION: Loki versus a MySQL log table. The default store is a bounded in-memory port (`logs.store.js`) and is not durable. Proposed schema if MySQL is chosen: LogEntry(id, ts, level, message, stack, requestId, traceId, deploymentId, projectId, serverId, environmentId, sourceId, kind, fieldsJson) with indexes on (projectId, environmentId, ts).
- Redaction is pattern based; unusual secret formats can slip through. Patterns must be reviewed.
- A parallel slice of monitoring.errors.js and tests/phase4-logs.test.js was written by another contributor during this task; this review covers the code listed in the test evidence only.
- Independent review and integration tests pending; do not mark DONE.
