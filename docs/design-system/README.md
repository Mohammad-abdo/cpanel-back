# NodeTeam design system (TASK-003)

Status: **design contract**, not implemented UI. Source: `required.md` §12. Product UI: Arabic/English, RTL/LTR, light/dark, desktop-first responsive. Documentation language: English.

No production screenshots or host facts claimed.

---

## 1. Brand palette (tokens)

| Token | Hex | Role |
| --- | --- | --- |
| `--nt-bg` | `#0B1220` | App background (dark navy) |
| `--nt-surface` | `#121D2E` | Surfaces, panels, elevated regions |
| `--nt-teal` | `#16B8A6` | Primary actions, healthy/success |
| `--nt-blue` | `#5B8DEF` | Monitoring accents, links, info |
| `--nt-amber` | `#F59E0B` | Warnings |
| `--nt-critical` | propose `#EF4444` | Critical/errors — **REQUIRES DECISION** exact red |

### Light theme mapping (design)

| Dark token | Light counterpart (propose) |
| --- | --- |
| `--nt-bg` | `#F5F7FB` |
| `--nt-surface` | `#FFFFFF` |
| Accents | Same teal/blue/amber/critical with contrast-checked text |

Light/dark both required. Exact light neutrals: **REQUIRES DECISION** if brand wants off-white vs pure white.

### Semantic aliases

```
--nt-color-success → teal
--nt-color-info → blue
--nt-color-warning → amber
--nt-color-danger → critical
--nt-color-fg / --nt-color-muted → theme-dependent text
--nt-border-subtle → low-contrast divider on surface
```

Do not store secrets or environment-specific URLs in token files.

---

## 2. Typography

| Role | Guidance |
| --- | --- |
| Product UI | Distinctive, readable pair supporting Arabic + Latin (font pick **REQUIRES DECISION**) |
| Display / page title | Semibold–bold; one primary headline per view |
| Body | Regular; comfortable line-height ≥ 1.45 |
| Meta / tables | Slightly smaller; tabular nums for metrics |
| Code / logs | Monospace; no decorative animation on log panes |
| Docs (this tree) | English only |

Avoid default Inter/Roboto/Arial as the sole brand voice when implementing (per product design rules); final family still **REQUIRES DECISION**.

Scale (propose): `12 / 14 / 16 / 20 / 24 / 32` px with rem tokens `--nt-font-xs` … `--nt-font-2xl`.

---

## 3. Grid and layout

| Rule | Value |
| --- | --- |
| Desktop-first | Primary layouts at ≥1280px; collapse gracefully |
| Columns | 12-column grid; content max width propose `1440px` |
| Gutter | `16px` (md) / `24px` (lg) |
| Sidebar | Fixed width propose `240px` RTL/LTR aware |
| Page padding | `16–24px` |
| Density | Comfortable for ops; tables may use compact row height |

MUI Grid2 / Stack for structure; Tailwind for spacing utilities — see layer rules.

---

## 4. CSS layer rules (MUI / Emotion / Tailwind)

Order of authority (high → low for conflict resolution):

1. **Accessibility / reduced-motion overrides**
2. **MUI theme + Emotion** for components that need MUI behavior (Data Grid, Dialog, Form controls, Tabs)
3. **Tailwind layout utilities** for spacing, flex/grid shell, responsive breakpoints
4. **Base resets / CSS variables**

Rules:

- Configure Emotion cache and Tailwind so utility classes do not fight MUI `sx` unpredictably (document chosen precedence in implementation TASK-004+).
- Prefer MUI for interactive compound widgets; Tailwind for layout chrome.
- Motion (`motion/react`): functional page/section transitions only; **no heavy animations on Logs or live Monitoring**.
- Respect `prefers-reduced-motion: reduce` — disable non-essential transitions; keep opacity fades ≤150ms or none.

Exact Emotion+Tailwind bootstrap: **REQUIRES DECISION** (implementation detail in web app scaffold).

---

## 5. RTL / LTR

| Concern | Rule |
| --- | --- |
| Locales | `ar` → RTL; `en` → LTR |
| Layout | Logical properties (`margin-inline`, `padding-inline`, `inset-inline-start`) |
| Sidebar | Mirrors to inline-start |
| Icons with direction | Flip chevrons/arrows; do not mirror brand marks or charts incorrectly |
| Numbers / code | Keep LTR isolates where needed (`dir="ltr"` on log lines, IPs, IDs) |

---

## 6. Light / dark

- Theme toggle persisted per user preference (store mechanism later).
- Charts/logs must remain readable in both themes (contrast AA target for text).
- Status colors stay hue-stable; adjust only lightness for contrast.

---

## 7. Reduced motion

| Setting | Behavior |
| --- | --- |
| `prefers-reduced-motion: reduce` | Disable parallax, large layout shifts, repeating pulses |
| Log streaming | No motion-driven scroll hijack |
| Toasts / status | Instant or minimal fade |

---

## 8. Component states (required on every major view)

| State | UI expectation |
| --- | --- |
| **Loading** | Skeleton or scoped spinner; do not blank entire shell; preserve layout |
| **Empty** | One short explanation + primary next action when permitted |
| **Error** | Clear message + retry if safe; correlate with `correlationId` when from API |
| **Forbidden** | Explicit access denial (not empty); no hidden affordances that imply capability |
| **Stale / disconnected** | Banner when Agent/socket disconnected; read-only where policy requires |
| **Success** | Quiet confirmation after mutations; link to operation/audit when relevant |

Approvals screens must show initiator, impact, reason, rollback. Restore screens must show what will be replaced. Reports numbers must deep-link to source events.

---

## 9. Sidebar information architecture

Six groups (see `docs/08-UI-SCREENS.md` for full IA):

1. WORKSPACE  
2. INFRASTRUCTURE  
3. PROJECTS  
4. HOSTING  
5. INTELLIGENCE  
6. ADMINISTRATION  

Overview is the default project-representative surface before diving into secondary tabs.

---

## 10. Open decisions

| ID | Topic | Status |
| --- | --- | --- |
| D-UI-001 | Exact typeface pair (AR+EN) | REQUIRES DECISION |
| D-UI-002 | Critical red hex | REQUIRES DECISION (propose `#EF4444`) |
| D-UI-003 | Light theme neutrals | REQUIRES DECISION |
| D-UI-004 | Emotion cache + Tailwind preflight strategy | REQUIRES DECISION |
| D-UI-005 | Default theme (light vs dark) for first login | REQUIRES DECISION |

---

## 11. Acceptance checklist (design)

- [x] Palette tokens documented
- [x] Typography / grid / layer rules
- [x] RTL/LTR, light/dark, reduced motion
- [x] Loading / empty / error / forbidden states
- [ ] Independent visual review pending
- [ ] Implementation out of scope for TASK-003
