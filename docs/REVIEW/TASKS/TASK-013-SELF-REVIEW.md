# TASK-013 SELF_REVIEW (not independent review)

Scope: Error groups, alert lifecycle and deployment comparison.

Findings and gaps:
- Schema proposal: Alert.projectId, Alert.acknowledgedById, AlertEvent.actorId and note; ErrorGroup.title, environmentId and lastDeploymentId. Today the actor is recorded in the audit log only.
- Error groups are written by `monitoring.errors.js` (fingerprint is a hash of the redacted message and top stack lines); deployment comparison groups by a normalized message at query time, so the two groupings can differ.
- Timing correlation is explicitly not blame: comparison output carries no actor identity and states so.
- Alerts HTTP surface is now mounted under `/api/v1/monitoring` and the web Monitoring page uses it; escalateDue still has no scheduler.
- Independent review and integration tests pending; do not mark DONE.
