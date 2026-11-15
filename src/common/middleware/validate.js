import { AppError } from '../errors/app-error.js';
export function validate(schema, target = 'body') {
  return (req, res, next) => {
    const parsed = schema.safeParse(req[target]);
    if (!parsed.success) return next(new AppError(400, 'VALIDATION_ERROR', 'Invalid request input.'));
    req.validated = { ...req.validated, [target]: parsed.data };
    next();
  };
}
