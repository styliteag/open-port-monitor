# UI v3 Glossary

Single source of truth for user-facing terminology. Frontend code must take these strings
from one terminology module (`frontend/src/lib/terminology.ts`, created in Phase 0) so
labels never drift between pages. API and DB names do **not** change — the mapping below
is permanent.

## Areas (navigation)

| Term | Meaning |
|------|---------|
| **Overview** | Read-only executive status page: traffic lights, risk trend, top risks. |
| **Monitor** | Daily work: Dashboard, Alerts, Hosts, Scans. |
| **Configuration** | Occasional setup: Networks, Scanners, Scan Templates, Alerting. |
| **Administration** | Admin-only: Users & Roles, Organization, System. |

## Alert states & actions

| UI term | Effect (shown as button subtitle) | API / DB reality |
|---------|-----------------------------------|------------------|
| **Open** | Needs a decision. | `dismissed=false` |
| **Allow** (action) | Creates a rule: this port is expected here; it will never alert again. Scope (network/global) chosen explicitly in the dialog. | `POST /alerts/bulk-accept-network` or `bulk-accept-global` → port rule + `dismissed=true` |
| **Allowed** (state) | Covered by an allow rule. | computed: matching `port_rules` / `global_port_rules` with `rule_type='accepted'` |
| **Mute** (action) | Hides this alert; the next scan will raise it again. | `PUT /alerts/{id}/dismiss` → `dismissed=true`, no rule |
| **Muted** (state) | Muted until the next scan finds it again. | `dismissed=true` without rule |
| **Assign** | A colleague takes ownership. | `assigned_to_user_id` |
| **Reopen** | Back to Open. | `PUT /alerts/{id}/reopen` → `dismissed=false` |
| **Revoke rule** | Deletes the allow rule; future scans alert again. | `DELETE /api/port-rules/{scope}/{id}` |

Removed term: **Blocked** — was never a state, only a `severity='critical'` filter. UI v3
uses the severity filter directly.

No workflow status: `resolution_status` (open/in_progress/resolved, later drafts added
`fix_planned`) was dropped in migration `006_remove_resolution_status`. UI v3 has no
workflow dimension; `docs/alert-states.md` and AGENTS.md sections describing it are
stale. Details: [alert-state-action-matrix.md](alert-state-action-matrix.md).

## Retained technical terms (never paraphrased)

**GVM**, **NSE**, **nuclei**, **OID**, **masscan**, **nmap** — they map 1:1 to real
products/identifiers (ADR 0006). Clarity comes from context copy, not renaming.

## Page concepts

| Term | Meaning |
|------|---------|
| **Triage Dashboard** | Landing page for technicians: open alerts by severity, scanner health, last/next scans, trend module, one click into the inbox. |
| **Inbox** | Split-view alert triage: list left, detail right, keyboard-driven (j/k, A, M, S). |
| **Scan Templates** | Configuration hub bundling NSE profiles, NSE script library/editor, and the GVM library. |
| **Alerting** | Configuration hub bundling alert rules, severity rules, and SSH alert defaults. |
| **System** | Administration hub for utilities (hostname cache, defaults). |
| **Network Wizard** | Guided creation: Basics → Scan type → Schedule → Alerting → Review. Editing uses the same groups as tabs. |
