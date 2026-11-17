-- TASK-042 outbound alert channels (additive). Secrets are AES-256-GCM ciphertext only.
CREATE TABLE `AlertChannel` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(120) NOT NULL,
    `type` VARCHAR(20) NOT NULL,
    `secretEnc` BLOB NOT NULL,
    `configJson` JSON NULL,
    `minSeverity` VARCHAR(20) NOT NULL DEFAULT 'info',
    `eventKinds` JSON NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `dedupeSeconds` INTEGER NOT NULL DEFAULT 300,
    `lastTestAt` DATETIME(3) NULL,
    `lastTestStatus` VARCHAR(20) NULL,
    `createdById` VARCHAR(191) NULL,
    `archivedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `AlertChannel_enabled_archivedAt_idx`(`enabled`, `archivedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `AlertChannelDelivery` (
    `id` VARCHAR(191) NOT NULL,
    `channelId` VARCHAR(191) NOT NULL,
    `eventKind` VARCHAR(80) NOT NULL,
    `severity` VARCHAR(20) NOT NULL DEFAULT 'info',
    `status` VARCHAR(20) NOT NULL DEFAULT 'pending',
    `attempt` INTEGER NOT NULL DEFAULT 0,
    `nextAttemptAt` DATETIME(3) NULL,
    `error` VARCHAR(500) NULL,
    `payloadJson` JSON NULL,
    `dedupeKey` VARCHAR(191) NULL,
    `sentAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `AlertChannelDelivery_channelId_createdAt_idx`(`channelId`, `createdAt`),
    INDEX `AlertChannelDelivery_status_nextAttemptAt_idx`(`status`, `nextAttemptAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `AlertChannelDelivery` ADD CONSTRAINT `AlertChannelDelivery_channelId_fkey` FOREIGN KEY (`channelId`) REFERENCES `AlertChannel`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
