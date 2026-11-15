/**
 * Actor for scheduled jobs. It has no user id (audit rows record actorId null) and passes Owner
 * checks; services accept it only where a job legitimately acts without a user (scheduled backups,
 * verification, retention planning). It can never be produced from an HTTP session.
 */
export const SYSTEM_ACTOR = Object.freeze({ id: null, isOwner: true, system: true });

export const isSystemActor = (actor) => actor === SYSTEM_ACTOR;
