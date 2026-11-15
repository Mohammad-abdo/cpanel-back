# Runbook: backups, retention and restores

Status: DRAFT, NOT_RUN against real storage.

## Backups
1. Create a policy: offsite destination, AES-256-GCM, retention days, RPO and RTO minutes.
2. Run `POST /backups/policies/:id/run`. States: scheduled, queued, snapshot, encrypt, upload, verify, retained. Any failure ends in failed and removes partial uploads.
3. A set holds the requested kinds plus an encrypted manifest. A run is retained only if every artifact downloads, matches its checksum and decrypts.
4. `GET /backups/policies/:id/rpo` shows within_rpo, rpo_breached or no_verified_backup.

## Verification
`POST /backups/artifacts/:id/verify` re-downloads, checks the checksum and the GCM authentication tag. A failure marks the run failed. Treat any failure as a security event and open an incident.

## Retention
`GET /backups/policies/:id/retention` is a dry run. Applying needs approval. The 3 newest verified sets are always kept and one pass never removes more than half of the verified sets.

## Restore
1. Pick a restore point from `GET /restores/points`.
2. `POST /restores` validates the set and returns an impact preview and an approval request. Isolated trials are high risk; in-place restores are critical.
3. A different approver approves.
4. The requester calls `POST /restores/:id/execute`. In-place restores take a verified safety backup first and abort if it fails. After restore the data checksum is compared and a health check runs.
5. If health fails for an in-place restore, roll back manually using the safety backup run id in the error message.

Never restore without authorization. Real restore execution is NOT_RUN.
