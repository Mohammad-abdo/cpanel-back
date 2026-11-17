-- Port reservations (vercel-clone port_reservations parity). Additive.

CREATE TABLE IF NOT EXISTS `PortReservation` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `port` INTEGER NOT NULL,
    `label` VARCHAR(100) NOT NULL,
    `createdById` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`),
    UNIQUE INDEX `PortReservation_serverId_port_key`(`serverId`, `port`),
    INDEX `PortReservation_serverId_idx`(`serverId`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `PortReservation`
  ADD CONSTRAINT `PortReservation_serverId_fkey`
  FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`)
  ON DELETE CASCADE ON UPDATE CASCADE;
