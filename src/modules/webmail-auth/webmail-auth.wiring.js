import { prisma } from '../../config/prisma.js';
import { serverAccessService } from '../server-access/server-access.routes.js';
import { createWebmailAuthService } from './webmail-auth.service.js';

export const webmailAuthService = createWebmailAuthService({ prisma, ssh: serverAccessService });
