-- AlterTable
ALTER TABLE `databaseinstance` ADD COLUMN `adminSecretRef` VARCHAR(191) NULL,
    ADD COLUMN `host` VARCHAR(191) NULL,
    ADD COLUMN `port` INTEGER NULL;

-- AlterTable
ALTER TABLE `reportdefinition` ADD COLUMN `kind` VARCHAR(191) NULL,
    ADD COLUMN `paramsJson` JSON NULL,
    ADD COLUMN `projectId` VARCHAR(191) NULL;
