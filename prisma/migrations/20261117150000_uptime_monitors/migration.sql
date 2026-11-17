-- Uptime HTTP(S) monitors (additive).
CREATE TABLE `UptimeMonitor` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NULL,
    `name` VARCHAR(100) NOT NULL,
    `url` VARCHAR(2000) NOT NULL,
    `method` VARCHAR(8) NOT NULL DEFAULT 'GET',
    `intervalSec` INTEGER NOT NULL DEFAULT 60,
    `timeoutMs` INTEGER NOT NULL DEFAULT 10000,
    `expectedStatus` VARCHAR(50) NOT NULL DEFAULT '200-399',
    `keyword` VARCHAR(200) NULL,
    `failureThreshold` INTEGER NOT NULL DEFAULT 2,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `status` VARCHAR(16) NOT NULL DEFAULT 'unknown',
    `lastCheckedAt` DATETIME(3) NULL,
    `lastStatusCode` INTEGER NULL,
    `lastResponseMs` INTEGER NULL,
    `lastError` VARCHAR(300) NULL,
    `consecutiveFailures` INTEGER NOT NULL DEFAULT 0,
    `failingSince` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `UptimeMonitor_projectId_idx`(`projectId`),
    INDEX `UptimeMonitor_enabled_status_idx`(`enabled`, `status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `UptimeCheck` (
    `id` VARCHAR(191) NOT NULL,
    `monitorId` VARCHAR(191) NOT NULL,
    `checkedAt` DATETIME(3) NOT NULL,
    `ok` BOOLEAN NOT NULL,
    `statusCode` INTEGER NULL,
    `responseMs` INTEGER NULL,
    `error` VARCHAR(300) NULL,

    INDEX `UptimeCheck_monitorId_checkedAt_idx`(`monitorId`, `checkedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `UptimeMonitor` ADD CONSTRAINT `UptimeMonitor_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `UptimeCheck` ADD CONSTRAINT `UptimeCheck_monitorId_fkey` FOREIGN KEY (`monitorId`) REFERENCES `UptimeMonitor`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;