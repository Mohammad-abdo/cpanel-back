-- CreateTable
CREATE TABLE `RootDomain` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(253) NOT NULL,
    `provider` VARCHAR(20) NOT NULL DEFAULT 'simulated',
    `zoneId` VARCHAR(64) NULL,
    `tokenEnc` BLOB NULL,
    `status` VARCHAR(20) NOT NULL DEFAULT 'active',
    `metaJson` JSON NULL,
    `createdById` VARCHAR(191) NULL,
    `archivedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `RootDomain_name_key`(`name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ProjectPreviewSettings` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT false,
    `rootDomainId` VARCHAR(191) NULL,
    `sourceEnvCode` VARCHAR(40) NULL,
    `envKeysJson` JSON NULL,
    `portStart` INTEGER NOT NULL DEFAULT 20000,
    `portEnd` INTEGER NOT NULL DEFAULT 20999,
    `ttlDays` INTEGER NOT NULL DEFAULT 7,
    `maxActive` INTEGER NOT NULL DEFAULT 5,
    `basicAuth` BOOLEAN NOT NULL DEFAULT false,
    `dnsMode` VARCHAR(12) NOT NULL DEFAULT 'per-pr',
    `commentEnabled` BOOLEAN NOT NULL DEFAULT false,
    `githubTokenEnc` BLOB NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ProjectPreviewSettings_projectId_key`(`projectId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `PreviewEnvironment` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `environmentId` VARCHAR(191) NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `prNumber` INTEGER NOT NULL,
    `branch` VARCHAR(255) NOT NULL,
    `commitSha` VARCHAR(40) NULL,
    `status` VARCHAR(24) NOT NULL DEFAULT 'creating',
    `port` INTEGER NULL,
    `hostname` VARCHAR(253) NOT NULL,
    `url` VARCHAR(300) NOT NULL,
    `deploymentId` VARCHAR(191) NULL,
    `basicAuthUser` VARCHAR(40) NULL,
    `basicAuthHash` VARCHAR(100) NULL,
    `rootDomainId` VARCHAR(191) NULL,
    `dnsStatus` VARCHAR(24) NULL,
    `exposeApprovalId` VARCHAR(36) NULL,
    `commentId` VARCHAR(30) NULL,
    `lastError` VARCHAR(500) NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `closedAt` DATETIME(3) NULL,
    `destroyedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `PreviewEnvironment_status_expiresAt_idx`(`status`, `expiresAt`),
    UNIQUE INDEX `PreviewEnvironment_projectId_prNumber_key`(`projectId`, `prNumber`),
    UNIQUE INDEX `PreviewEnvironment_serverId_port_key`(`serverId`, `port`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
