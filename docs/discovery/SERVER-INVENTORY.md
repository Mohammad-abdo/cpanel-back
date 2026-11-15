# Production server inventory worksheet (TASK-001)

Fill one block per Ubuntu host. Use UNKNOWN where evidence is missing. No secrets.

**Authorization 2026-11-15:** Owner authorized continuing all phases with production inventory left UNKNOWN. Rows below remain UNKNOWN; do not invent host facts.

## Host template

### Host identity

| Field | Value |
| --- | --- |
| Alias | UNKNOWN |
| Role | UNKNOWN |
| Public hostname / IP category | UNKNOWN |
| Access authorized for read-only inventory | UNKNOWN |
| Ubuntu version | UNKNOWN |
| Kernel / patch state summary | UNKNOWN |

### Capacity

| Field | Value |
| --- | --- |
| vCPU | UNKNOWN |
| RAM | UNKNOWN |
| Disk capacity | UNKNOWN |
| Disk free | UNKNOWN |
| Swap | UNKNOWN |

### Shared services (versions only)

| Service | Present | Version | Notes / shared impact |
| --- | --- | --- | --- |
| Apache | UNKNOWN | UNKNOWN | |
| Nginx | UNKNOWN | UNKNOWN | |
| PM2 | UNKNOWN | UNKNOWN | |
| systemd units of interest | UNKNOWN | UNKNOWN | |
| MySQL | UNKNOWN | UNKNOWN | |
| PostgreSQL | UNKNOWN | UNKNOWN | |
| MongoDB | UNKNOWN | UNKNOWN | |
| Redis | UNKNOWN | UNKNOWN | |

### Network (categories only)

| Field | Value |
| --- | --- |
| Listening port categories | UNKNOWN |
| Firewall ownership | UNKNOWN |
| SSH policy summary | UNKNOWN |

### Projects on this host

| Name/Slug | Type (Node/Laravel/…) | Runtime / PM | Domains (names) | DB engine refs | Backup dest category |
| --- | --- | --- | --- | --- | --- |
| UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |

### Backup / restore evidence

| Field | Value |
| --- | --- |
| Backup tool in use | UNKNOWN |
| Last successful backup (date) | UNKNOWN |
| Last restore test (date / result) | UNKNOWN |

---

## Hosts recorded

_No production hosts recorded yet._

## Blocking inputs needed from Owner

1. How many Ubuntu VPS hosts exist today, and their non-secret aliases/roles?
2. May we run an authorized **read-only** inventory (SSH or equivalent) against them?
3. If remote access is not available now, paste filled rows above from existing ops notes.
