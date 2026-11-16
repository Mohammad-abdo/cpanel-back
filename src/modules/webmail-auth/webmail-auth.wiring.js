import { prisma } from '../../config/prisma.js';
import { createWebmailAuthService } from './webmail-auth.service.js';

export const webmailAuthService = createWebmailAuthService({ prisma });
