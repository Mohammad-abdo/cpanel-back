# TASK-006 self-review

Type: SELF_REVIEW (not independent). Date: 2026-11-15. Independent review: pending.
Result: APPROVED_WITH_NOTES for local slice.

## Delivered
- rbac: exact-scope hasGrant, `can()` helper, delegation rule (assign right + hold permission), self-grant denial, revoke, expiry honoured, non-owner list limited to own grants.
- teams module (controller/validator/service/routes): Owner creates teams; lead manages own team, cannot create/remove leads.

## Notes
- Resource-level enforcement is not yet wired into other modules; `rbac.can()` must be adopted per module in later tasks.
- Role-based (UserRole/RolePermission) evaluation not implemented yet; ResourceGrant only. REQUIRES DECISION before claiming full RBAC.
- Audit events for grant/team changes belong to TASK-007.
