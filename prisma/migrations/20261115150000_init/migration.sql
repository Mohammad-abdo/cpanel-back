-- CreateTable
CREATE TABLE `User` (
    `id` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `displayName` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'active',
    `locale` VARCHAR(191) NOT NULL DEFAULT 'en',
    `timezone` VARCHAR(191) NOT NULL DEFAULT 'UTC',
    `ownerFlag` BOOLEAN NOT NULL DEFAULT false,
    `disabledAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `User_email_key`(`email`),
    INDEX `User_status_idx`(`status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Session` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `ipHash` VARCHAR(191) NULL,
    `userAgentHash` VARCHAR(191) NULL,
    `mfaSatisfied` BOOLEAN NOT NULL DEFAULT false,
    `revokedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `Session_userId_expiresAt_idx`(`userId`, `expiresAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `MfaFactor` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `secretRef` VARCHAR(191) NULL,
    `verifiedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `MfaFactor_userId_type_idx`(`userId`, `type`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ApiToken` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NULL,
    `name` VARCHAR(191) NOT NULL,
    `hash` VARCHAR(191) NOT NULL,
    `scopesJson` JSON NULL,
    `expiresAt` DATETIME(3) NULL,
    `revokedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ApiToken_hash_key`(`hash`),
    INDEX `ApiToken_userId_idx`(`userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Role` (
    `id` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `systemProtected` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `Role_code_key`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Permission` (
    `id` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,
    `resourceType` VARCHAR(191) NOT NULL,
    `riskTier` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `Permission_code_key`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `RolePermission` (
    `id` VARCHAR(191) NOT NULL,
    `roleId` VARCHAR(191) NOT NULL,
    `permissionId` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `RolePermission_roleId_permissionId_key`(`roleId`, `permissionId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `UserRole` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `roleId` VARCHAR(191) NOT NULL,
    `scopeType` VARCHAR(191) NOT NULL DEFAULT '',
    `scopeId` VARCHAR(191) NOT NULL DEFAULT '',

    INDEX `UserRole_userId_idx`(`userId`),
    UNIQUE INDEX `UserRole_userId_roleId_scopeType_scopeId_key`(`userId`, `roleId`, `scopeType`, `scopeId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ResourceGrant` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `permissionCode` VARCHAR(191) NOT NULL,
    `resourceType` VARCHAR(191) NOT NULL,
    `resourceId` VARCHAR(191) NOT NULL,
    `environmentId` VARCHAR(191) NULL,
    `conditionsJson` JSON NULL,
    `grantedById` VARCHAR(191) NULL,
    `expiresAt` DATETIME(3) NULL,
    `revokedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ResourceGrant_userId_resourceType_resourceId_idx`(`userId`, `resourceType`, `resourceId`),
    INDEX `ResourceGrant_environmentId_idx`(`environmentId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Team` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `slug` VARCHAR(191) NOT NULL,
    `archivedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `Team_slug_key`(`slug`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `TeamMember` (
    `id` VARCHAR(191) NOT NULL,
    `teamId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `teamRole` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `TeamMember_teamId_userId_key`(`teamId`, `userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ProjectMember` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `projectRole` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ProjectMember_projectId_userId_key`(`projectId`, `userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Server` (
    `id` VARCHAR(191) NOT NULL,
    `alias` VARCHAR(191) NOT NULL,
    `hostname` VARCHAR(191) NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'unknown',
    `agentBoundAt` DATETIME(3) NULL,
    `archivedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `Server_alias_key`(`alias`),
    INDEX `Server_status_idx`(`status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ServerAgent` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `agentPublicId` VARCHAR(191) NOT NULL,
    `certFingerprint` VARCHAR(191) NOT NULL,
    `capabilitiesJson` JSON NULL,
    `lastSeenAt` DATETIME(3) NULL,
    `revokedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ServerAgent_serverId_key`(`serverId`),
    UNIQUE INDEX `ServerAgent_agentPublicId_key`(`agentPublicId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ServerService` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `manager` VARCHAR(191) NOT NULL,
    `state` VARCHAR(191) NULL,
    `metaJson` JSON NULL,
    `updatedAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ServerService_serverId_name_idx`(`serverId`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ServerPort` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `port` INTEGER NOT NULL,
    `proto` VARCHAR(191) NOT NULL,
    `processHint` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ServerPort_serverId_port_proto_key`(`serverId`, `port`, `proto`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ServerSnapshot` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `capturedAt` DATETIME(3) NOT NULL,
    `summaryJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ServerSnapshot_serverId_capturedAt_idx`(`serverId`, `capturedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Project` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `slug` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'active',
    `archivedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `Project_status_idx`(`status`),
    UNIQUE INDEX `Project_serverId_slug_key`(`serverId`, `slug`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ProjectEnvironment` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,
    `displayName` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ProjectEnvironment_projectId_code_key`(`projectId`, `code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ProjectRuntime` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `runtime` VARCHAR(191) NULL,
    `processManager` VARCHAR(191) NULL,
    `metaJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ProjectRuntime_projectId_key`(`projectId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ProjectRepository` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `remoteUrl` VARCHAR(191) NULL,
    `defaultBranch` VARCHAR(191) NULL,
    `lastCommitSha` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ProjectRepository_projectId_key`(`projectId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Deployment` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `environmentId` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `commitSha` VARCHAR(191) NULL,
    `initiatedById` VARCHAR(191) NULL,
    `correlationId` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `Deployment_projectId_createdAt_idx`(`projectId`, `createdAt`),
    INDEX `Deployment_correlationId_idx`(`correlationId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `DeploymentStep` (
    `id` VARCHAR(191) NOT NULL,
    `deploymentId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `startedAt` DATETIME(3) NULL,
    `finishedAt` DATETIME(3) NULL,
    `actorId` VARCHAR(191) NULL,
    `detailJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `DeploymentStep_deploymentId_name_idx`(`deploymentId`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `DeploymentApproval` (
    `id` VARCHAR(191) NOT NULL,
    `deploymentId` VARCHAR(191) NOT NULL,
    `approverId` VARCHAR(191) NULL,
    `decision` VARCHAR(191) NOT NULL,
    `reason` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `DeploymentApproval_deploymentId_idx`(`deploymentId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `OperationJob` (
    `id` VARCHAR(191) NOT NULL,
    `operationId` VARCHAR(191) NOT NULL,
    `correlationId` VARCHAR(191) NOT NULL,
    `idempotencyKey` VARCHAR(191) NOT NULL,
    `action` VARCHAR(191) NOT NULL,
    `resourceType` VARCHAR(191) NOT NULL,
    `resourceId` VARCHAR(191) NOT NULL,
    `environmentId` VARCHAR(191) NULL,
    `riskTier` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `initiatorId` VARCHAR(191) NULL,
    `approverId` VARCHAR(191) NULL,
    `expiresAt` DATETIME(3) NULL,
    `payloadJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `OperationJob_operationId_key`(`operationId`),
    UNIQUE INDEX `OperationJob_idempotencyKey_key`(`idempotencyKey`),
    INDEX `OperationJob_status_createdAt_idx`(`status`, `createdAt`),
    INDEX `OperationJob_correlationId_idx`(`correlationId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `OperationExecution` (
    `id` VARCHAR(191) NOT NULL,
    `operationJobId` VARCHAR(191) NOT NULL,
    `attemptId` VARCHAR(191) NOT NULL,
    `agentId` VARCHAR(191) NULL,
    `startedAt` DATETIME(3) NULL,
    `finishedAt` DATETIME(3) NULL,
    `result` VARCHAR(191) NULL,
    `detailJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `OperationExecution_operationJobId_attemptId_key`(`operationJobId`, `attemptId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ApprovalRequest` (
    `id` VARCHAR(191) NOT NULL,
    `resourceType` VARCHAR(191) NOT NULL,
    `resourceId` VARCHAR(191) NOT NULL,
    `operationJobId` VARCHAR(191) NULL,
    `requesterId` VARCHAR(191) NULL,
    `approverId` VARCHAR(191) NULL,
    `status` VARCHAR(191) NOT NULL,
    `reason` VARCHAR(191) NULL,
    `impactJson` JSON NULL,
    `rollbackPlan` VARCHAR(191) NULL,
    `decidedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ApprovalRequest_status_createdAt_idx`(`status`, `createdAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Domain` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NULL,
    `serverId` VARCHAR(191) NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'active',
    `archivedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `Domain_name_key`(`name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `DnsRecord` (
    `id` VARCHAR(191) NOT NULL,
    `domainId` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `valueSummary` VARCHAR(191) NOT NULL,
    `ttl` INTEGER NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `DnsRecord_domainId_type_idx`(`domainId`, `type`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `SslCertificate` (
    `id` VARCHAR(191) NOT NULL,
    `domainId` VARCHAR(191) NOT NULL,
    `provider` VARCHAR(191) NULL,
    `expiresAt` DATETIME(3) NULL,
    `status` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `SslCertificate_expiresAt_idx`(`expiresAt`),
    INDEX `SslCertificate_domainId_idx`(`domainId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `DatabaseInstance` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NULL,
    `engine` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'unknown',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `DatabaseInstance_engine_status_idx`(`engine`, `status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ManagedDatabase` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `instanceId` VARCHAR(191) NOT NULL,
    `dbName` VARCHAR(191) NOT NULL,
    `environmentId` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ManagedDatabase_projectId_environmentId_dbName_key`(`projectId`, `environmentId`, `dbName`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `DatabaseUser` (
    `id` VARCHAR(191) NOT NULL,
    `managedDatabaseId` VARCHAR(191) NOT NULL,
    `username` VARCHAR(191) NOT NULL,
    `privilegesJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `DatabaseUser_managedDatabaseId_username_key`(`managedDatabaseId`, `username`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `BackupPolicy` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `environmentId` VARCHAR(191) NULL,
    `frequency` VARCHAR(191) NULL,
    `retentionDays` INTEGER NULL,
    `encryption` VARCHAR(191) NULL,
    `destinationCategory` VARCHAR(191) NULL,
    `rpoMinutes` INTEGER NULL,
    `rtoMinutes` INTEGER NULL,
    `archivedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `BackupPolicy_projectId_idx`(`projectId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `BackupRun` (
    `id` VARCHAR(191) NOT NULL,
    `policyId` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `startedAt` DATETIME(3) NULL,
    `finishedAt` DATETIME(3) NULL,
    `verificationStatus` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `BackupRun_policyId_startedAt_idx`(`policyId`, `startedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `BackupArtifact` (
    `id` VARCHAR(191) NOT NULL,
    `backupRunId` VARCHAR(191) NOT NULL,
    `kind` VARCHAR(191) NOT NULL,
    `locationRef` VARCHAR(191) NOT NULL,
    `checksum` VARCHAR(191) NULL,
    `sizeBytes` BIGINT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `BackupArtifact_backupRunId_idx`(`backupRunId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `RestoreRun` (
    `id` VARCHAR(191) NOT NULL,
    `artifactId` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `isolatedTrial` BOOLEAN NOT NULL DEFAULT true,
    `approvedById` VARCHAR(191) NULL,
    `correlationId` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `RestoreRun_artifactId_createdAt_idx`(`artifactId`, `createdAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `MetricRule` (
    `id` VARCHAR(191) NOT NULL,
    `scopeType` VARCHAR(191) NOT NULL,
    `scopeId` VARCHAR(191) NOT NULL,
    `metric` VARCHAR(191) NOT NULL,
    `thresholdJson` JSON NULL,
    `severity` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `MetricRule_scopeType_scopeId_idx`(`scopeType`, `scopeId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `HealthCheck` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NULL,
    `serverId` VARCHAR(191) NULL,
    `kind` VARCHAR(191) NOT NULL,
    `intervalSec` INTEGER NOT NULL DEFAULT 60,
    `status` VARCHAR(191) NOT NULL DEFAULT 'unknown',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `HealthCheck_projectId_idx`(`projectId`),
    INDEX `HealthCheck_serverId_idx`(`serverId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Alert` (
    `id` VARCHAR(191) NOT NULL,
    `ruleId` VARCHAR(191) NULL,
    `severity` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `fingerprint` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `Alert_fingerprint_key`(`fingerprint`),
    INDEX `Alert_status_severity_idx`(`status`, `severity`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `AlertEvent` (
    `id` VARCHAR(191) NOT NULL,
    `alertId` VARCHAR(191) NOT NULL,
    `fromStatus` VARCHAR(191) NULL,
    `toStatus` VARCHAR(191) NOT NULL,
    `at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `AlertEvent_alertId_at_idx`(`alertId`, `at`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `LogSource` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NULL,
    `serverId` VARCHAR(191) NULL,
    `kind` VARCHAR(191) NOT NULL,
    `labelJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `LogSource_projectId_idx`(`projectId`),
    INDEX `LogSource_serverId_idx`(`serverId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `LogStream` (
    `id` VARCHAR(191) NOT NULL,
    `logSourceId` VARCHAR(191) NOT NULL,
    `externalRef` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `LogStream_logSourceId_idx`(`logSourceId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `LogBookmark` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NULL,
    `name` VARCHAR(191) NOT NULL,
    `queryJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `LogBookmark_userId_idx`(`userId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ErrorGroup` (
    `id` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,
    `fingerprint` VARCHAR(191) NOT NULL,
    `firstSeenAt` DATETIME(3) NOT NULL,
    `lastSeenAt` DATETIME(3) NOT NULL,
    `count` INTEGER NOT NULL DEFAULT 1,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ErrorGroup_projectId_fingerprint_key`(`projectId`, `fingerprint`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `SecurityEvent` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NULL,
    `severity` VARCHAR(191) NOT NULL,
    `category` VARCHAR(191) NOT NULL,
    `occurredAt` DATETIME(3) NOT NULL,
    `source` VARCHAR(191) NULL,
    `payloadJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `SecurityEvent_serverId_occurredAt_idx`(`serverId`, `occurredAt`),
    INDEX `SecurityEvent_category_occurredAt_idx`(`category`, `occurredAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `SecurityIncident` (
    `id` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `severity` VARCHAR(191) NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `detectedAt` DATETIME(3) NOT NULL,
    `closedAt` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `SecurityIncident_status_severity_idx`(`status`, `severity`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `IncidentAssignment` (
    `id` VARCHAR(191) NOT NULL,
    `incidentId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `assignedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `IncidentAssignment_incidentId_idx`(`incidentId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ReportDefinition` (
    `id` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `paramsSchemaJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    UNIQUE INDEX `ReportDefinition_code_key`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ReportRun` (
    `id` VARCHAR(191) NOT NULL,
    `definitionId` VARCHAR(191) NOT NULL,
    `requestedById` VARCHAR(191) NULL,
    `status` VARCHAR(191) NOT NULL,
    `periodStart` DATETIME(3) NULL,
    `periodEnd` DATETIME(3) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ReportRun_definitionId_createdAt_idx`(`definitionId`, `createdAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ReportSchedule` (
    `id` VARCHAR(191) NOT NULL,
    `definitionId` VARCHAR(191) NOT NULL,
    `cron` VARCHAR(191) NOT NULL,
    `recipientsJson` JSON NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `ReportSchedule_definitionId_idx`(`definitionId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ReportArtifact` (
    `id` VARCHAR(191) NOT NULL,
    `reportRunId` VARCHAR(191) NOT NULL,
    `format` VARCHAR(191) NOT NULL,
    `locationRef` VARCHAR(191) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ReportArtifact_reportRunId_idx`(`reportRunId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ActivityEvent` (
    `id` VARCHAR(191) NOT NULL,
    `actorId` VARCHAR(191) NULL,
    `serverId` VARCHAR(191) NULL,
    `projectId` VARCHAR(191) NULL,
    `environmentId` VARCHAR(191) NULL,
    `operationJobId` VARCHAR(191) NULL,
    `category` VARCHAR(191) NOT NULL,
    `action` VARCHAR(191) NOT NULL,
    `resourceType` VARCHAR(191) NOT NULL,
    `resourceId` VARCHAR(191) NULL,
    `result` VARCHAR(191) NOT NULL,
    `source` VARCHAR(191) NOT NULL,
    `correlationId` VARCHAR(191) NULL,
    `metadata` JSON NULL,
    `occurredAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `ActivityEvent_actorId_occurredAt_idx`(`actorId`, `occurredAt`),
    INDEX `ActivityEvent_projectId_occurredAt_idx`(`projectId`, `occurredAt`),
    INDEX `ActivityEvent_serverId_occurredAt_idx`(`serverId`, `occurredAt`),
    INDEX `ActivityEvent_category_action_occurredAt_idx`(`category`, `action`, `occurredAt`),
    INDEX `ActivityEvent_correlationId_idx`(`correlationId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `AuditEvent` (
    `id` VARCHAR(191) NOT NULL,
    `actorId` VARCHAR(191) NULL,
    `actorType` VARCHAR(191) NOT NULL,
    `action` VARCHAR(191) NOT NULL,
    `resourceType` VARCHAR(191) NOT NULL,
    `resourceId` VARCHAR(191) NULL,
    `environmentId` VARCHAR(191) NULL,
    `operationJobId` VARCHAR(191) NULL,
    `approvalRequestId` VARCHAR(191) NULL,
    `initiatorId` VARCHAR(191) NULL,
    `approverId` VARCHAR(191) NULL,
    `executorId` VARCHAR(191) NULL,
    `result` VARCHAR(191) NOT NULL,
    `ipHash` VARCHAR(191) NULL,
    `userAgentHash` VARCHAR(191) NULL,
    `correlationId` VARCHAR(191) NOT NULL,
    `beforeJson` JSON NULL,
    `afterJson` JSON NULL,
    `occurredAt` DATETIME(3) NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `AuditEvent_occurredAt_idx`(`occurredAt`),
    INDEX `AuditEvent_actorId_occurredAt_idx`(`actorId`, `occurredAt`),
    INDEX `AuditEvent_resourceType_resourceId_occurredAt_idx`(`resourceType`, `resourceId`, `occurredAt`),
    INDEX `AuditEvent_correlationId_idx`(`correlationId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `AccessReview` (
    `id` VARCHAR(191) NOT NULL,
    `reviewerId` VARCHAR(191) NULL,
    `subjectUserId` VARCHAR(191) NULL,
    `periodStart` DATETIME(3) NOT NULL,
    `periodEnd` DATETIME(3) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `findingsJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Notification` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `kind` VARCHAR(191) NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `body` VARCHAR(191) NULL,
    `readAt` DATETIME(3) NULL,
    `linkJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `Notification_userId_createdAt_idx`(`userId`, `createdAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `NotificationChannel` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NULL,
    `type` VARCHAR(191) NOT NULL,
    `configRef` VARCHAR(191) NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `NotificationChannel_type_idx`(`type`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `NotificationPreference` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `eventKind` VARCHAR(191) NOT NULL,
    `channelType` VARCHAR(191) NOT NULL,
    `enabled` BOOLEAN NOT NULL DEFAULT true,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `NotificationPreference_userId_eventKind_channelType_key`(`userId`, `eventKind`, `channelType`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `Session` ADD CONSTRAINT `Session_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `MfaFactor` ADD CONSTRAINT `MfaFactor_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ApiToken` ADD CONSTRAINT `ApiToken_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `RolePermission` ADD CONSTRAINT `RolePermission_roleId_fkey` FOREIGN KEY (`roleId`) REFERENCES `Role`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `RolePermission` ADD CONSTRAINT `RolePermission_permissionId_fkey` FOREIGN KEY (`permissionId`) REFERENCES `Permission`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserRole` ADD CONSTRAINT `UserRole_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserRole` ADD CONSTRAINT `UserRole_roleId_fkey` FOREIGN KEY (`roleId`) REFERENCES `Role`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ResourceGrant` ADD CONSTRAINT `ResourceGrant_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ResourceGrant` ADD CONSTRAINT `ResourceGrant_grantedById_fkey` FOREIGN KEY (`grantedById`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `TeamMember` ADD CONSTRAINT `TeamMember_teamId_fkey` FOREIGN KEY (`teamId`) REFERENCES `Team`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `TeamMember` ADD CONSTRAINT `TeamMember_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ProjectMember` ADD CONSTRAINT `ProjectMember_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ProjectMember` ADD CONSTRAINT `ProjectMember_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ServerAgent` ADD CONSTRAINT `ServerAgent_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ServerService` ADD CONSTRAINT `ServerService_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ServerPort` ADD CONSTRAINT `ServerPort_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ServerSnapshot` ADD CONSTRAINT `ServerSnapshot_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Project` ADD CONSTRAINT `Project_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ProjectEnvironment` ADD CONSTRAINT `ProjectEnvironment_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ProjectRuntime` ADD CONSTRAINT `ProjectRuntime_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ProjectRepository` ADD CONSTRAINT `ProjectRepository_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Deployment` ADD CONSTRAINT `Deployment_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Deployment` ADD CONSTRAINT `Deployment_environmentId_fkey` FOREIGN KEY (`environmentId`) REFERENCES `ProjectEnvironment`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Deployment` ADD CONSTRAINT `Deployment_initiatedById_fkey` FOREIGN KEY (`initiatedById`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DeploymentStep` ADD CONSTRAINT `DeploymentStep_deploymentId_fkey` FOREIGN KEY (`deploymentId`) REFERENCES `Deployment`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DeploymentStep` ADD CONSTRAINT `DeploymentStep_actorId_fkey` FOREIGN KEY (`actorId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DeploymentApproval` ADD CONSTRAINT `DeploymentApproval_deploymentId_fkey` FOREIGN KEY (`deploymentId`) REFERENCES `Deployment`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DeploymentApproval` ADD CONSTRAINT `DeploymentApproval_approverId_fkey` FOREIGN KEY (`approverId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OperationJob` ADD CONSTRAINT `OperationJob_initiatorId_fkey` FOREIGN KEY (`initiatorId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OperationJob` ADD CONSTRAINT `OperationJob_approverId_fkey` FOREIGN KEY (`approverId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OperationJob` ADD CONSTRAINT `OperationJob_environmentId_fkey` FOREIGN KEY (`environmentId`) REFERENCES `ProjectEnvironment`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OperationExecution` ADD CONSTRAINT `OperationExecution_operationJobId_fkey` FOREIGN KEY (`operationJobId`) REFERENCES `OperationJob`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OperationExecution` ADD CONSTRAINT `OperationExecution_agentId_fkey` FOREIGN KEY (`agentId`) REFERENCES `ServerAgent`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ApprovalRequest` ADD CONSTRAINT `ApprovalRequest_operationJobId_fkey` FOREIGN KEY (`operationJobId`) REFERENCES `OperationJob`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ApprovalRequest` ADD CONSTRAINT `ApprovalRequest_requesterId_fkey` FOREIGN KEY (`requesterId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ApprovalRequest` ADD CONSTRAINT `ApprovalRequest_approverId_fkey` FOREIGN KEY (`approverId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Domain` ADD CONSTRAINT `Domain_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Domain` ADD CONSTRAINT `Domain_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DnsRecord` ADD CONSTRAINT `DnsRecord_domainId_fkey` FOREIGN KEY (`domainId`) REFERENCES `Domain`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `SslCertificate` ADD CONSTRAINT `SslCertificate_domainId_fkey` FOREIGN KEY (`domainId`) REFERENCES `Domain`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DatabaseInstance` ADD CONSTRAINT `DatabaseInstance_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ManagedDatabase` ADD CONSTRAINT `ManagedDatabase_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ManagedDatabase` ADD CONSTRAINT `ManagedDatabase_instanceId_fkey` FOREIGN KEY (`instanceId`) REFERENCES `DatabaseInstance`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ManagedDatabase` ADD CONSTRAINT `ManagedDatabase_environmentId_fkey` FOREIGN KEY (`environmentId`) REFERENCES `ProjectEnvironment`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DatabaseUser` ADD CONSTRAINT `DatabaseUser_managedDatabaseId_fkey` FOREIGN KEY (`managedDatabaseId`) REFERENCES `ManagedDatabase`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `BackupPolicy` ADD CONSTRAINT `BackupPolicy_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `BackupRun` ADD CONSTRAINT `BackupRun_policyId_fkey` FOREIGN KEY (`policyId`) REFERENCES `BackupPolicy`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `BackupArtifact` ADD CONSTRAINT `BackupArtifact_backupRunId_fkey` FOREIGN KEY (`backupRunId`) REFERENCES `BackupRun`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `RestoreRun` ADD CONSTRAINT `RestoreRun_artifactId_fkey` FOREIGN KEY (`artifactId`) REFERENCES `BackupArtifact`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `RestoreRun` ADD CONSTRAINT `RestoreRun_approvedById_fkey` FOREIGN KEY (`approvedById`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `HealthCheck` ADD CONSTRAINT `HealthCheck_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `HealthCheck` ADD CONSTRAINT `HealthCheck_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Alert` ADD CONSTRAINT `Alert_ruleId_fkey` FOREIGN KEY (`ruleId`) REFERENCES `MetricRule`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `AlertEvent` ADD CONSTRAINT `AlertEvent_alertId_fkey` FOREIGN KEY (`alertId`) REFERENCES `Alert`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `LogSource` ADD CONSTRAINT `LogSource_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `LogSource` ADD CONSTRAINT `LogSource_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `LogStream` ADD CONSTRAINT `LogStream_logSourceId_fkey` FOREIGN KEY (`logSourceId`) REFERENCES `LogSource`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `LogBookmark` ADD CONSTRAINT `LogBookmark_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ErrorGroup` ADD CONSTRAINT `ErrorGroup_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `SecurityEvent` ADD CONSTRAINT `SecurityEvent_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `IncidentAssignment` ADD CONSTRAINT `IncidentAssignment_incidentId_fkey` FOREIGN KEY (`incidentId`) REFERENCES `SecurityIncident`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `IncidentAssignment` ADD CONSTRAINT `IncidentAssignment_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ReportRun` ADD CONSTRAINT `ReportRun_definitionId_fkey` FOREIGN KEY (`definitionId`) REFERENCES `ReportDefinition`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ReportRun` ADD CONSTRAINT `ReportRun_requestedById_fkey` FOREIGN KEY (`requestedById`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ReportSchedule` ADD CONSTRAINT `ReportSchedule_definitionId_fkey` FOREIGN KEY (`definitionId`) REFERENCES `ReportDefinition`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ReportArtifact` ADD CONSTRAINT `ReportArtifact_reportRunId_fkey` FOREIGN KEY (`reportRunId`) REFERENCES `ReportRun`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ActivityEvent` ADD CONSTRAINT `ActivityEvent_actorId_fkey` FOREIGN KEY (`actorId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ActivityEvent` ADD CONSTRAINT `ActivityEvent_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `Server`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ActivityEvent` ADD CONSTRAINT `ActivityEvent_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ActivityEvent` ADD CONSTRAINT `ActivityEvent_environmentId_fkey` FOREIGN KEY (`environmentId`) REFERENCES `ProjectEnvironment`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ActivityEvent` ADD CONSTRAINT `ActivityEvent_operationJobId_fkey` FOREIGN KEY (`operationJobId`) REFERENCES `OperationJob`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `AuditEvent` ADD CONSTRAINT `AuditEvent_actorId_fkey` FOREIGN KEY (`actorId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `AccessReview` ADD CONSTRAINT `AccessReview_reviewerId_fkey` FOREIGN KEY (`reviewerId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `AccessReview` ADD CONSTRAINT `AccessReview_subjectUserId_fkey` FOREIGN KEY (`subjectUserId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Notification` ADD CONSTRAINT `Notification_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `NotificationChannel` ADD CONSTRAINT `NotificationChannel_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `NotificationPreference` ADD CONSTRAINT `NotificationPreference_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
