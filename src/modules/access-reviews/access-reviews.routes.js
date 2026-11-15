import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import { decideBodySchema, listReviewsQuerySchema, reviewIdParamsSchema, startReviewBodySchema } from './access-reviews.validator.js';
import { createAccessReviewsController } from './access-reviews.controller.js';
import { createAccessReviewsService } from './access-reviews.service.js';
import { getDeps } from '../platform/platform.wiring.js';
import { wrap } from '../platform/platform.http.js';

const c = createAccessReviewsController(createAccessReviewsService(getDeps()));
const write = requireSession({ requireMfa: true });
const params = validate(reviewIdParamsSchema, 'params');

/** Mount at /access-reviews */
export const accessReviewsRouter = Router();

accessReviewsRouter.get('/', requireSession(), validate(listReviewsQuerySchema, 'query'), wrap(c.list));
accessReviewsRouter.post('/', write, validate(startReviewBodySchema, 'body'), wrap(c.start));
accessReviewsRouter.get('/:id', requireSession(), params, wrap(c.get));
accessReviewsRouter.post('/:id/decisions', write, params, validate(decideBodySchema, 'body'), wrap(c.decide));
accessReviewsRouter.post('/:id/complete', write, params, wrap(c.complete));
