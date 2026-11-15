-- AlterTable
ALTER TABLE `alert` ADD COLUMN `acknowledgedById` VARCHAR(191) NULL,
    ADD COLUMN `projectId` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `alertevent` ADD COLUMN `actorId` VARCHAR(191) NULL,
    ADD COLUMN `note` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `approvalrequest` ADD COLUMN `action` VARCHAR(191) NULL,
    ADD COLUMN `bindingHash` VARCHAR(191) NULL,
    ADD COLUMN `expiresAt` DATETIME(3) NULL,
    ADD COLUMN `riskTier` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `backuppolicy` ADD COLUMN `kindsJson` JSON NULL;

-- AlterTable
ALTER TABLE `backuprun` ADD COLUMN `trigger` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `deployment` ADD COLUMN `rollbackOfId` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `dnsrecord` ADD COLUMN `providerRef` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `domain` ADD COLUMN `environmentId` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `reportartifact` ADD COLUMN `expiresAt` DATETIME(3) NULL,
    ADD COLUMN `sizeBytes` INTEGER NULL;

-- AlterTable
ALTER TABLE `reportrun` ADD COLUMN `idempotencyKey` VARCHAR(191) NULL,
    ADD COLUMN `scheduleId` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `reportschedule` ADD COLUMN `createdById` VARCHAR(191) NULL,
    ADD COLUMN `lastRunAt` DATETIME(3) NULL,
    ADD COLUMN `paramsJson` JSON NULL;

-- AlterTable
ALTER TABLE `restorerun` ADD COLUMN `approvalRequestId` VARCHAR(191) NULL,
    ADD COLUMN `mode` VARCHAR(191) NULL,
    ADD COLUMN `previewJson` JSON NULL,
    ADD COLUMN `safetyBackupRunId` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `securityincident` ADD COLUMN `projectId` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `sslcertificate` ADD COLUMN `challenge` VARCHAR(191) NULL,
    ADD COLUMN `lastError` VARCHAR(191) NULL;

-- CreateTable
CREATE TABLE `ExternalIdentity` (
    `id` VARCHAR(191) NOT NULL,
    `provider` VARCHAR(191) NOT NULL,
    `externalId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'unmapped',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ExternalIdentity_provider_externalId_key`(`provider`, `externalId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
