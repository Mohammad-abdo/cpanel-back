-- CreateTable
CREATE TABLE `AgentEnrollment` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `tokenHash` VARCHAR(191) NOT NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `usedAt` DATETIME(3) NULL,
    `createdById` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `AgentEnrollment_tokenHash_key`(`tokenHash`),
    INDEX `AgentEnrollment_serverId_idx`(`serverId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
