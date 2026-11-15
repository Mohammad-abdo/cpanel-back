# DECISIONS

User requested all documentation inside docs; PLAN/REVIEW/TEST/DONE are nested accordingly. Source stack is a requirement, not verified compatibility. Decisions pending: server inventory, MUI 9 availability/compatibility, exact versions, DNS/email/offsite providers, retention, budget, RPO/RTO, SLOs, MFA recovery and emergency approvals. Source relationship diagram contains export CSS artifacts and needs reconstruction.

TASK-001 blocking Owner inputs (see docs/discovery): production host aliases/roles; authorization for read-only remote inventory (or filled SERVER-INVENTORY rows); RPO/RTO and related recovery fields in RECOVERY-OBJECTIVES.md.

2026-11-15 Owner authorization: user instructed to continue through all roadmap phases while production inventory/security baseline remain UNKNOWN and RPO/RTO remain REQUIRES DECISION. Proceeding in phase order with honest UNKNOWN markers; this does not invent production facts or authorize production deploy/firewall/secret/restore actions.
