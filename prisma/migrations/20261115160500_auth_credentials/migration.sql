-- AlterTable
ALTER TABLE `User` ADD COLUMN `passwordHash` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `Session` ADD COLUMN `tokenHash` VARCHAR(191) NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX `Session_tokenHash_key` ON `Session`(`tokenHash`);
