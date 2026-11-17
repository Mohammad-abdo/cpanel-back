-- AlterTable
ALTER TABLE `ServerAgent` ADD COLUMN `keyGeneration` INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN `agentVersion` VARCHAR(191) NULL,
    ADD COLUMN `terminalEnabledAt` DATETIME(3) NULL;

-- CreateTable
CREATE TABLE `AgentCommand` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `agentPublicId` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `argsHash` VARCHAR(191) NOT NULL,
    `argsJson` JSON NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'pending',
    `riskTier` VARCHAR(191) NULL,
    `approvalId` VARCHAR(191) NULL,
    `requestedBy` VARCHAR(191) NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `resultJson` JSON NULL,
    `completedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `AgentCommand_serverId_createdAt_idx`(`serverId`, `createdAt`),
    INDEX `AgentCommand_status_idx`(`status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
