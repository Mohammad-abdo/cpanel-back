# TASK-016 SELF_REVIEW (not independent review)

Scope: Scheduled report summaries and renderers.

Findings and gaps:
- REQUIRES DECISION: PDF and Excel dependencies (for example a PDF library and exceljs). The 'PDF/Excel parity' acceptance criterion is verified only between the CSV and JSON renderers.
- Artifact bytes live in an in-memory store and expire with the API process (REQUIRES DECISION: durable storage). Expiry and the report params are kept in store metadata because ReportArtifact has no expiresAt or params column.
- Schema proposal: ReportSchedule.paramsJson, createdById, lastRunAt; ReportRun.scheduleId and idempotencyKey; ReportArtifact.expiresAt and sizeBytes. Today the schedule config is held in recipientsJson and the dedup key is the artifact locationRef prefix.
- Cron support is limited to numeric fields in UTC (weekly and monthly patterns).
- Independent review and integration tests pending; do not mark DONE.
