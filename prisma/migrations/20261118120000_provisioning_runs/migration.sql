-- TASK-053: provisioning runs (Add project to server). Additive.

CREATE TABLE IF NOT EXISTS `ProvisioningRun` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NULL,
    `mode` VARCHAR(20) NOT NULL DEFAULT 'provision',
    `status` VARCHAR(24) NOT NULL DEFAULT 'queued',
    `executor` VARCHAR(12) NOT NULL DEFAULT 'simulated',
    `slug` VARCHAR(64) NOT NULL,
    `primaryDomain` VARCHAR(253) NOT NULL,
    `planJson` JSON NOT NULL,
    `stepsJson` JSON NOT NULL,
    `contextJson` JSON NULL,
    `rollbackNote` VARCHAR(1000) NULL,
    `createdById` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `ProvisioningRun_serverId_createdAt_idx`(`serverId`, `createdAt`),
    INDEX `ProvisioningRun_projectId_idx`(`projectId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
