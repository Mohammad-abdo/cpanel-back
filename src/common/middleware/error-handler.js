import { AppError } from '../errors/app-error.js';
export function notFound(req, res, next) {
  next(new AppError(404, 'NOT_FOUND', 'Resource not found.'));
}
export function errorHandler(error, req, res, next) {
  if (res.headersSent) return next(error);
  const malformed = error.type === 'entity.parse.failed';
  const tooLarge = error.type === 'entity.too.large';
  const known = error instanceof AppError;
  const status = known ? error.status : malformed ? 400 : tooLarge ? 413 : 500;
  res.status(status).json({ error: {
    code: known ? error.code : malformed ? 'INVALID_JSON' : tooLarge ? 'PAYLOAD_TOO_LARGE' : 'INTERNAL_ERROR',
    message: known ? error.message : malformed ? 'Invalid JSON body.' : tooLarge ? 'Request body too large.' : 'An unexpected error occurred.',
    requestId: req.requestId,
  }});
}
