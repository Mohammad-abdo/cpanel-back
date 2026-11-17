ALTER TABLE `BackupRun` ADD COLUMN `metricsJson` JSON NULL;
ALTER TABLE `RestoreRun` ADD COLUMN `metricsJson` JSON NULL;
