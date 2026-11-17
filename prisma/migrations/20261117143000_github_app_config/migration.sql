-- CreateTable
CREATE TABLE `GitHubAppConfig` (
    `id` VARCHAR(191) NOT NULL,
    `appId` INTEGER NULL,
    `clientId` VARCHAR(64) NULL,
    `slug` VARCHAR(40) NULL,
    `installationId` VARCHAR(32) NULL,
    `privateKeyEnc` BLOB NULL,
    `webhookSecretEnc` BLOB NULL,
    `status` VARCHAR(20) NOT NULL DEFAULT 'unconfigured',
    `metaJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;