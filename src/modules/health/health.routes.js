import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { healthQuerySchema } from './health.validator.js';
import { getHealth } from './health.controller.js';
export const healthRouter = Router();
healthRouter.get('/', validate(healthQuerySchema, 'query'), getHealth);
