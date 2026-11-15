-- CreateTable
CREATE TABLE `LogEntry` (
    `id` VARCHAR(191) NOT NULL,
    `seq` INTEGER NOT NULL AUTO_INCREMENT,
    `projectId` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NULL,
    `environmentId` VARCHAR(191) NULL,
    `source` VARCHAR(191) NOT NULL,
    `kind` VARCHAR(191) NULL,
    `severity` VARCHAR(191) NOT NULL,
    `message` TEXT NOT NULL,
    `requestId` VARCHAR(191) NULL,
    `traceId` VARCHAR(191) NULL,
    `deploymentId` VARCHAR(191) NULL,
    `stack` TEXT NULL,
    `fieldsJson` JSON NULL,
    `occurredAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `LogEntry_seq_key`(`seq`),
    INDEX `LogEntry_projectId_occurredAt_idx`(`projectId`, `occurredAt`),
    INDEX `LogEntry_severity_occurredAt_idx`(`severity`, `occurredAt`),
    INDEX `LogEntry_requestId_idx`(`requestId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
