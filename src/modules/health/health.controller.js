import { getLiveness } from './health.service.js';
export function getHealth(req, res) {
  res.set('Cache-Control', 'no-store').status(200).json({ data: getLiveness() });
}
