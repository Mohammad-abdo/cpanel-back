-- Phase 11 TASK-048 per-project cron jobs. Additive only.
CREATE TABLE `CronJob` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `schedule` VARCHAR(191) NOT NULL,
    `commandKey` VARCHAR(191) NULL,
    `customCommand` TEXT NULL,
    `workDir` VARCHAR(191) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT false,
    `timeoutSec` INTEGER NOT NULL DEFAULT 300,
    `nextRunAt` DATETIME(3) NULL,
    `lastRunAt` DATETIME(3) NULL,
    `lastStatus` VARCHAR(191) NULL,
    `approvalId` VARCHAR(191) NULL,
    `createdById` VARCHAR(191) NULL,
    `archivedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `CronJob_projectId_idx`(`projectId`),
    INDEX `CronJob_enabled_nextRunAt_idx`(`enabled`, `nextRunAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `CronRun` (
    `id` VARCHAR(191) NOT NULL,
    `jobId` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `trigger` VARCHAR(191) NOT NULL DEFAULT 'schedule',
    `startedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `finishedAt` DATETIME(3) NULL,
    `exitCode` INTEGER NULL,
    `outputTail` TEXT NULL,
    `actorId` VARCHAR(191) NULL,

    INDEX `CronRun_jobId_startedAt_idx`(`jobId`, `startedAt`),
    INDEX `CronRun_status_startedAt_idx`(`status`, `startedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `CronJob` ADD CONSTRAINT `CronJob_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `CronJob` ADD CONSTRAINT `CronJob_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `CronRun` ADD CONSTRAINT `CronRun_jobId_fkey` FOREIGN KEY (`jobId`) REFERENCES `CronJob`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
