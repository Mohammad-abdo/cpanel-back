# Security baseline worksheet (TASK-001)

Values remain UNKNOWN until evidence is supplied or an authorized read-only inventory is completed. No secrets in this file.

**Authorization 2026-11-15:** Owner authorized continuing all phases with production inventory / baseline left UNKNOWN. Do not invent control values or mark baseline PASSED.

| Control area | Current value | Evidence / source |
| --- | --- | --- |
| Access method to production hosts | UNKNOWN | |
| Who is authorized to inventory / change hosts | UNKNOWN | |
| OS patch state / update cadence | UNKNOWN | |
| Exposed service categories (web, DB, SSH, panels) | UNKNOWN | |
| SSH policy (key-only, allowlist, fail2ban, etc.) | UNKNOWN | |
| Privilege model (sudo, shared root, per-admin) | UNKNOWN | |
| Firewall ownership and change process | UNKNOWN | |
| Backup account separation from app accounts | UNKNOWN | |
| Audit log sources available today | UNKNOWN | |
| Existing monitoring / alerting | UNKNOWN | |
| Wazuh or other SIEM present | UNKNOWN | |
| Control-plane isolation from customer apps | UNKNOWN | |

## Notes

- Discovery is read-only. No firewall, user, or secret changes without explicit authorization.
- Examples in `required.md` are plan language, not verified production facts.
