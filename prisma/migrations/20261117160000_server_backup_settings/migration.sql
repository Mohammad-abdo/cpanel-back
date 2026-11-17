-- Server-wide backup settings (vercel-clone parity). Additive.

CREATE TABLE IF NOT EXISTS `ServerBackupSettings` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT false,
    `includeMysql` BOOLEAN NOT NULL DEFAULT true,
    `includePostgres` BOOLEAN NOT NULL DEFAULT false,
    `includeFiles` BOOLEAN NOT NULL DEFAULT false,
    `filesPath` VARCHAR(512) NULL,
    `retainCount` INTEGER NOT NULL DEFAULT 7,
    `scheduleCron` VARCHAR(64) NULL,
    `lastRunAt` DATETIME(3) NULL,
    `lastStatus` VARCHAR(24) NULL,
    `lastError` VARCHAR(500) NULL,
    `metaJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ServerBackupSettings_serverId_key`(`serverId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `ServerBackupSettings`
  ADD CONSTRAINT `ServerBackupSettings_serverId_fkey`
  FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`)
  ON DELETE CASCADE ON UPDATE CASCADE;