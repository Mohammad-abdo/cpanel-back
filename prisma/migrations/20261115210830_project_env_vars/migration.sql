-- CreateTable
CREATE TABLE `ProjectEnvVar` (
    `id` VARCHAR(191) NOT NULL,
    `environmentId` VARCHAR(191) NOT NULL,
    `key` VARCHAR(191) NOT NULL,
    `valueEnc` BLOB NOT NULL,
    `isSecret` BOOLEAN NOT NULL DEFAULT false,
    `updatedById` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ProjectEnvVar_environmentId_key_key`(`environmentId`, `key`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `ProjectEnvVar` ADD CONSTRAINT `ProjectEnvVar_environmentId_fkey` FOREIGN KEY (`environmentId`) REFERENCES `ProjectEnvironment`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
