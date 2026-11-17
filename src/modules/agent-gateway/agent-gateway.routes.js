import { Router } from 'express';
import { validate } from '../../common/middleware/validate.js';
import { requireSession } from '../../common/middleware/require-session.js';
import {
  historyQuerySchema,
  recoverBodySchema,
  rotateBodySchema,
  sendCommandBodySchema,
  serverIdParamsSchema,
  terminalBodySchema,
} from './agent-gateway.validator.js';
import { createAgentGatewayController } from './agent-gateway.controller.js';
import { getAgentGatewayService } from './agent-gateway.wiring.js';

const lazy = () => createAgentGatewayController(getAgentGatewayService());
const run = (name) => (req, res, next) => {
  lazy()[name](req, res).catch(next);
};
const mfa = requireSession({ requireMfa: true });

/** Mounted at /servers. Every route is Owner + MFA; risky commands are additionally approval-gated in the service. */
export const agentGatewayRouter = Router();
agentGatewayRouter.get('/:id/agent', mfa, validate(serverIdParamsSchema, 'params'), run('status'));
agentGatewayRouter.get('/:id/agent/commands', mfa, validate(serverIdParamsSchema, 'params'), validate(historyQuerySchema, 'query'), run('history'));
agentGatewayRouter.post('/:id/agent/commands', mfa, validate(serverIdParamsSchema, 'params'), validate(sendCommandBodySchema, 'body'), run('send'));
agentGatewayRouter.post('/:id/agent/rotate', mfa, validate(serverIdParamsSchema, 'params'), validate(rotateBodySchema, 'body'), run('rotate'));
agentGatewayRouter.post('/:id/agent/terminal', mfa, validate(serverIdParamsSchema, 'params'), validate(terminalBodySchema, 'body'), run('terminal'));
agentGatewayRouter.post('/:id/agent/recover', mfa, validate(serverIdParamsSchema, 'params'), validate(recoverBodySchema, 'body'), run('recover'));
