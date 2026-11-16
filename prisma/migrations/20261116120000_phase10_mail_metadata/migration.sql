-- Phase 10 mail metadata (TASK-034). Additive only.
-- CreateTable
CREATE TABLE `ServerMailService` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'disabled',
    `provisioned` BOOLEAN NOT NULL DEFAULT false,
    `mailHostname` VARCHAR(191) NULL,
    `stackVersion` VARCHAR(191) NULL,
    `portsJson` JSON NULL,
    `lastHealthAt` DATETIME(3) NULL,
    `lastHealthJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ServerMailService_serverId_key`(`serverId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `DomainMailConfig` (
    `id` VARCHAR(191) NOT NULL,
    `domainId` VARCHAR(191) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT false,
    `catchAllMailboxId` VARCHAR(191) NULL,
    `quotaDefaultMb` INTEGER NOT NULL DEFAULT 1024,
    `dkimSelector` VARCHAR(191) NOT NULL DEFAULT 'nt1',
    `dkimPublicKey` TEXT NULL,
    `dnsState` VARCHAR(191) NOT NULL DEFAULT 'pending',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `DomainMailConfig_domainId_key`(`domainId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `MailboxAccount` (
    `id` VARCHAR(191) NOT NULL,
    `domainId` VARCHAR(191) NOT NULL,
    `localPart` VARCHAR(191) NOT NULL,
    `displayName` VARCHAR(191) NULL,
    `quotaMb` INTEGER NOT NULL DEFAULT 1024,
    `status` VARCHAR(191) NOT NULL DEFAULT 'active',
    `passwordHash` VARCHAR(191) NULL,
    `passwordSetAt` DATETIME(3) NULL,
    `provisioned` BOOLEAN NOT NULL DEFAULT false,
    `createdById` VARCHAR(191) NULL,
    `deletedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `MailboxAccount_domainId_status_idx`(`domainId`, `status`),
    UNIQUE INDEX `MailboxAccount_domainId_localPart_key`(`domainId`, `localPart`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `MailboxAuditEvent` (
    `id` VARCHAR(191) NOT NULL,
    `mailboxId` VARCHAR(191) NOT NULL,
    `actorId` VARCHAR(191) NULL,
    `action` VARCHAR(191) NOT NULL,
    `metadataJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `MailboxAuditEvent_mailboxId_createdAt_idx`(`mailboxId`, `createdAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `ServerMailService` ADD CONSTRAINT `ServerMailService_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DomainMailConfig` ADD CONSTRAINT `DomainMailConfig_domainId_fkey` FOREIGN KEY (`domainId`) REFERENCES `Domain`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `MailboxAccount` ADD CONSTRAINT `MailboxAccount_domainId_fkey` FOREIGN KEY (`domainId`) REFERENCES `Domain`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `MailboxAuditEvent` ADD CONSTRAINT `MailboxAuditEvent_mailboxId_fkey` FOREIGN KEY (`mailboxId`) REFERENCES `MailboxAccount`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

