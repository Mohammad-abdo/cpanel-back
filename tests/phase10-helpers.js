import { createMailboxBodySchema } from '../src/modules/mailboxes/mailboxes.validator.js';
import { enableMailServerBodySchema, provisionApplyBodySchema } from '../src/modules/mail-server/mail-server.validator.js';
import { updateMailDomainBodySchema } from '../src/modules/mail-domain/mail-domain.validator.js';

export function createBodyValidators() {
  return {
    create: createMailboxBodySchema,
    enableServer: enableMailServerBodySchema,
    applyServer: provisionApplyBodySchema,
    updateDomain: updateMailDomainBodySchema,
  };
}
