-- AlterTable
-- These columns already exist on the local dev DB (applied earlier via `prisma db push`).
-- On that DB run: prisma migrate resolve --applied 20261116090000_database_instance_admin_login
-- MySQL 8 has no ADD COLUMN IF NOT EXISTS; do not deploy this file to a DB that already has the columns.
ALTER TABLE `DatabaseInstance` ADD COLUMN `adminUsername` VARCHAR(191) NULL,
    ADD COLUMN `adminSecretEnc` BLOB NULL;
